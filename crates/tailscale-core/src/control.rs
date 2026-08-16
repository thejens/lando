//! Control-plane RPCs carried over HTTP/2 inside the Noise session.
//!
//! Registration is fully non-interactive with a pre-auth key (`tskey-auth-…`):
//! there is no browser step, which is the whole reason a headless device can
//! join a tailnet at all.
//!
//! **The auth key must not be needed after the first registration.** One-off
//! keys are consumed immediately on use and reusable ones expire after at most
//! 90 days, so a device that re-registers from scratch on every boot bricks
//! itself the first time it reboots unattended. Persist the machine key and
//! node key; presenting the *same* node key again is treated by the server as
//! a refresh rather than a new node.

use crate::json::{self, JsonError, Value};
use crate::key::{DiscoPublic, NodePublic};

pub const REGISTER_PATH: &str = "/machine/register";
pub const MAP_PATH: &str = "/machine/map";

/// Marks the optional JSON block the server sends immediately after the Noise
/// handshake, *before* the HTTP/2 stream begins.
pub const EARLY_PAYLOAD_MAGIC: &[u8] = b"\xff\xff\xffTS";

/// Result of looking for an early payload at the head of the session stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyPayload<'a> {
    /// No early payload; HTTP/2 starts at byte zero.
    Absent,
    /// Not enough bytes yet to decide. Read more and retry.
    Incomplete,
    /// A complete payload. Skip `consumed` bytes before parsing HTTP/2.
    Present { consumed: usize, json: &'a [u8] },
}

/// Detects and measures the ts2021 early payload.
///
/// The layout is `\xff\xff\xffTS`, a 4-byte big-endian length, then JSON —
/// currently `{"nodeKeyChallenge":"chalpub:…"}`. It is easy to miss because it
/// is optional and undocumented, and missing it is silently fatal: the bytes
/// get fed to the HTTP/2 parser, which then desynchronises and hangs waiting
/// for a frame that never comes.
///
/// The challenge is only needed for node-key-proof signatures, which this
/// client does not send, so the payload is currently parsed to be skipped.
pub fn parse_early_payload(buf: &[u8]) -> EarlyPayload<'_> {
    let magic = EARLY_PAYLOAD_MAGIC;
    let common = buf.len().min(magic.len());
    if buf[..common] != magic[..common] {
        return EarlyPayload::Absent;
    }
    if buf.len() < magic.len() + 4 {
        return EarlyPayload::Incomplete;
    }
    let len = u32::from_be_bytes([
        buf[magic.len()],
        buf[magic.len() + 1],
        buf[magic.len() + 2],
        buf[magic.len() + 3],
    ]) as usize;
    let start = magic.len() + 4;
    if buf.len() < start + len {
        return EarlyPayload::Incomplete;
    }
    EarlyPayload::Present {
        consumed: start + len,
        json: &buf[start..start + len],
    }
}

/// What the device tells the control plane about itself.
///
/// Every field upstream carries `omitzero`, so sending a minimal set is legal.
/// `routable_ips` is here for the eventual subnet-router mode; it is the field
/// that makes the LAN reachable at its real addresses, and it does nothing
/// until an admin approves the route (or an `autoApprovers` policy covers it).
#[derive(Debug, Clone, Copy)]
pub struct Hostinfo<'a> {
    pub hostname: &'a str,
    pub ipn_version: &'a str,
    /// A `version.OS` value. Deliberately a *known* value rather than an
    /// honest one — the admin console and various clients switch on this, and
    /// an unrecognised string risks odd display or handling for no benefit.
    pub os: &'a str,
    pub os_version: &'a str,
    pub machine: &'a str,
    pub routable_ips: &'a [&'a str],
    /// Relay region we are homed on, reported inside `NetInfo`.
    ///
    /// This is how peers learn where to reach us. The server relays it to them
    /// as a `DERP` placeholder address and strips `NetInfo` itself, so the
    /// field is invisible in a peer's netmap even when it is working.
    pub preferred_derp: u32,
    /// Measured round-trip to the home relay, in milliseconds.
    ///
    /// Reported as `DERPLatency`. The admin console shows this under Relays,
    /// and a node with no latency data appears to have no relay at all.
    pub derp_latency_ms: Option<u32>,
    /// Whether UDP reaches the internet. Reported rather than assumed: the
    /// console surfaces it, and it is what tells the control plane a direct
    /// path is even worth attempting.
    pub working_udp: bool,
}

impl Default for Hostinfo<'_> {
    fn default() -> Self {
        Self {
            hostname: "lando",
            // Must parse as a Tailscale version. A string the server cannot
            // parse gets the *entire* Hostinfo dropped -- silently -- which
            // costs the NetInfo inside it and with it any home relay, leaving
            // peers with nowhere to send.
            ipn_version: "1.98.9",
            os: "linux",
            os_version: "",
            machine: "thumbv8m",
            routable_ips: &[],
            preferred_derp: 0,
            derp_latency_ms: None,
            working_udp: false,
        }
    }
}

impl Hostinfo<'_> {
    fn write(&self, w: &mut json::Writer) -> Result<(), JsonError> {
        w.begin_object()?;
        w.field_str("IPNVersion", self.ipn_version)?;
        w.field_str("OS", self.os)?;
        if !self.os_version.is_empty() {
            w.field_str("OSVersion", self.os_version)?;
        }
        w.field_str("Hostname", self.hostname)?;
        w.field_str("Machine", self.machine)?;
        if self.preferred_derp != 0 {
            // A complete NetInfo, not just the one field we care about. Every
            // entry here has its own column in the admin console, and a
            // partially-filled struct appears to be ignored wholesale rather
            // than accepted in part.
            w.key("NetInfo")?;
            w.begin_object()?;
            w.field_bool("MappingVariesByDestIP", false)?;
            w.field_bool("WorkingIPv6", false)?;
            w.field_bool("OSHasIPv6", false)?;
            w.field_bool("WorkingUDP", self.working_udp)?;
            w.field_bool("HavePortMap", false)?;
            w.field_bool("UPnP", false)?;
            w.field_bool("PMP", false)?;
            w.field_bool("PCP", false)?;
            w.field_u64("PreferredDERP", self.preferred_derp as u64)?;
            if let Some(ms) = self.derp_latency_ms {
                // DERPLatency is keyed by region and address family, in
                // seconds — rendered by hand because the JSON writer has no
                // float support and does not need one for anything else.
                w.key("DERPLatency")?;
                w.begin_object()?;
                let mut key: [u8; 16] = [0; 16];
                let region = write_region_key(self.preferred_derp, &mut key);
                w.key(core::str::from_utf8(region).map_err(|_| JsonError::Malformed)?)?;
                let mut secs = [0u8; 12];
                let rendered = write_seconds(ms, &mut secs);
                w.raw_value(rendered)?;
                w.end_object()?;
            }
            w.field_str("LinkType", "wifi")?;
            w.end_object()?;
        }
        if !self.routable_ips.is_empty() {
            w.key("RoutableIPs")?;
            w.begin_array()?;
            for cidr in self.routable_ips {
                w.str_value(cidr)?;
            }
            w.end_array()?;
        }
        w.end_object()
    }
}

/// A registration attempt.
///
/// Two ways in, and the device needs only the first:
///
/// * **Pre-auth key** — set `auth_key`. Fully non-interactive, which is the
///   only option for a headless board.
/// * **Interactive** — leave both `auth_key` and `followup` unset; the server
///   replies with an `AuthURL`. Send a second request with the same `node_key`
///   and `followup` set to that URL, and the server holds the response open
///   until a browser completes the login. This is what `tailscale up` does,
///   and it is useful during development because it borrows an existing
///   browser session instead of needing a key minted in advance.
#[derive(Debug, Clone, Copy)]
pub struct Register<'a> {
    pub capability_version: u16,
    pub node_key: &'a NodePublic,
    pub auth_key: Option<&'a str>,
    pub followup: Option<&'a str>,
    pub hostinfo: &'a Hostinfo<'a>,
    pub ephemeral: bool,
}

/// Serializes a `RegisterRequest` into `out`, returning its length.
///
/// `OldNodeKey` and `NLKey` are omitted entirely rather than sent as zero
/// values: Go leaves absent fields at their zero value on decode, which is
/// exactly what we want, and a zero-valued key has no well-defined wire form.
pub fn write_register_request(out: &mut [u8], req: &Register) -> Result<usize, JsonError> {
    let mut key_buf = [0u8; 80];
    let n = req
        .node_key
        .write(&mut key_buf)
        .map_err(|_| JsonError::ShortBuffer)?;
    let key_str = core::str::from_utf8(&key_buf[..n]).map_err(|_| JsonError::Malformed)?;

    let mut w = json::Writer::new(out);
    w.begin_object()?;
    w.field_u64("Version", req.capability_version as u64)?;
    w.field_str("NodeKey", key_str)?;
    if let Some(auth_key) = req.auth_key {
        w.key("Auth")?;
        w.begin_object()?;
        w.field_str("AuthKey", auth_key)?;
        w.end_object()?;
    }
    if let Some(url) = req.followup {
        w.field_str("Followup", url)?;
    }
    w.key("Hostinfo")?;
    req.hostinfo.write(&mut w)?;
    if req.ephemeral {
        w.field_bool("Ephemeral", true)?;
    }
    w.end_object()?;
    Ok(w.len())
}

/// A netmap request.
///
/// `Stream` turns this into a long-poll: the server holds the response open
/// and pushes a new frame whenever the tailnet changes. Holding it open is
/// also what makes the node report *online* — that status is driven by this
/// poll, not by registration, so a node that registers and disconnects shows
/// as offline forever.
#[derive(Debug, Clone, Copy)]
pub struct MapRequest<'a> {
    pub capability_version: u16,
    pub node_key: &'a NodePublic,
    pub disco_key: &'a DiscoPublic,
    pub hostinfo: &'a Hostinfo<'a>,
    /// Long-poll rather than one-shot.
    ///
    /// **A streaming request is read-only.** Upstream specifies that when
    /// `Stream` is set and `Version >= 68` the server treats the request as
    /// read-only and ignores `Hostinfo`, `Endpoints` and everything else that
    /// describes us. So none of the fields below reach the control plane on a
    /// streaming poll — they are only read from a one-shot request.
    ///
    /// This failure is completely silent: the node still goes online, and the
    /// admin console simply shows no endpoints, no relay and no connectivity
    /// data, as though the client had never described itself. Send changes
    /// with a one-shot [`MapRequest`] (`stream: false`, `omit_peers: true`),
    /// which is the documented way to update endpoints without disturbing an
    /// existing long poll.
    pub stream: bool,
    /// Ask the server to send periodic keep-alive frames.
    pub keep_alive: bool,
    /// Drop peer data. Useful for a first connection where only presence
    /// matters, and a real saving on a device that cannot hold a large netmap.
    pub omit_peers: bool,
    /// Real endpoints peers can reach us on, as `ip:port` strings.
    ///
    /// A peer with a direct endpoint needs no relay at all, which is the
    /// cheapest way to be reachable on a LAN — and avoids a TLS stack the
    /// relay path would otherwise require.
    pub endpoints: &'a [&'a str],
    /// Parallel to `endpoints`, one [`endpoint_type`] per entry.
    ///
    /// The control plane pairs these by position, and an absent or
    /// mismatched array is grounds to discard the endpoints entirely — with
    /// no error, so the node simply appears to have none.
    pub endpoint_types: &'a [u8],
}

/// Renders `"<region>-v4"`, the key DERPLatency is indexed by.
fn write_region_key(region: u32, out: &mut [u8; 16]) -> &[u8] {
    let mut digits = [0u8; 10];
    let mut n = region;
    let mut i = 10;
    if n == 0 {
        i -= 1;
        digits[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = 10 - i;
    out[..len].copy_from_slice(&digits[i..]);
    out[len..len + 3].copy_from_slice(b"-v4");
    &out[..len + 3]
}

/// Renders milliseconds as a decimal number of seconds, e.g. 55 -> "0.055".
fn write_seconds(ms: u32, out: &mut [u8; 12]) -> &[u8] {
    let whole = ms / 1000;
    let frac = ms % 1000;
    out[0] = b'0' + (whole % 10) as u8;
    out[1] = b'.';
    out[2] = b'0' + (frac / 100) as u8;
    out[3] = b'0' + ((frac / 10) % 10) as u8;
    out[4] = b'0' + (frac % 10) as u8;
    &out[..5]
}

/// How an endpoint was learned. The control plane pairs these with
/// `MapRequest.Endpoints` by position.
pub mod endpoint_type {
    pub const UNKNOWN: u8 = 0;
    /// Discovered from a local interface — a LAN address.
    pub const LOCAL: u8 = 1;
    pub const STUN: u8 = 2;
    pub const PORTMAPPED: u8 = 3;
    pub const STUN4_LOCAL_PORT: u8 = 4;
    pub const EXPLICIT_CONF: u8 = 5;
}

/// Serializes a `MapRequest` into `out`, returning its length.
///
/// `Compress` is sent explicitly as `""` to opt out of zstd. The official Go
/// client always asks for zstd and unconditionally decompresses, so this path
/// is not exercised upstream — but the server honours it, and skipping it
/// removes a decompressor and its window buffer from the firmware entirely.
pub fn write_map_request(out: &mut [u8], req: &MapRequest) -> Result<usize, JsonError> {
    let mut node_buf = [0u8; 80];
    let n = req
        .node_key
        .write(&mut node_buf)
        .map_err(|_| JsonError::ShortBuffer)?;
    let node_str = core::str::from_utf8(&node_buf[..n]).map_err(|_| JsonError::Malformed)?;

    let mut disco_buf = [0u8; 80];
    let n = req
        .disco_key
        .write(&mut disco_buf)
        .map_err(|_| JsonError::ShortBuffer)?;
    let disco_str = core::str::from_utf8(&disco_buf[..n]).map_err(|_| JsonError::Malformed)?;

    let mut w = json::Writer::new(out);
    w.begin_object()?;
    w.field_u64("Version", req.capability_version as u64)?;
    w.field_str("Compress", "")?;
    w.field_bool("KeepAlive", req.keep_alive)?;
    w.field_str("NodeKey", node_str)?;
    w.field_str("DiscoKey", disco_str)?;
    if req.stream {
        w.field_bool("Stream", true)?;
    }
    if req.omit_peers {
        w.field_bool("OmitPeers", true)?;
    }
    if !req.endpoints.is_empty() {
        w.key("Endpoints")?;
        w.begin_array()?;
        for ep in req.endpoints {
            w.str_value(ep)?;
        }
        w.end_array()?;

        if !req.endpoint_types.is_empty() {
            w.key("EndpointTypes")?;
            w.begin_array()?;
            for t in req.endpoint_types {
                w.u64_value(*t as u64)?;
            }
            w.end_array()?;
        }
    }
    w.key("Hostinfo")?;
    req.hostinfo.write(&mut w)?;
    w.end_object()?;
    Ok(w.len())
}

/// One slice of a `MapResponse`, as produced by [`MapFrames`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapFrame<'a> {
    /// Total length of the frame this chunk belongs to.
    pub total_len: u32,
    pub chunk: &'a [u8],
    /// True on the final chunk of the frame.
    pub end: bool,
}

/// Splits the map response byte stream into frames.
///
/// Each frame is a **4-byte little-endian** length followed by that many bytes
/// of JSON. Little-endian is worth noting: every other length on this
/// connection — Noise records, HTTP/2 frames — is big-endian, so this is the
/// one place the habit is wrong.
///
/// Bodies stream rather than accumulate. A netmap can be far larger than the
/// RAM of the target device, so nothing here ever holds a whole frame.
#[derive(Debug, Default)]
pub struct MapFrames {
    len_buf: [u8; 4],
    len_have: usize,
    remaining: u32,
    total: u32,
}

impl MapFrames {
    pub const fn new() -> Self {
        Self {
            len_buf: [0; 4],
            len_have: 0,
            remaining: 0,
            total: 0,
        }
    }

    /// Consumes bytes, returning how many were used and at most one chunk.
    /// `(0, None)` means more input is needed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> (usize, Option<MapFrame<'a>>) {
        let mut pos = 0;
        if self.remaining == 0 {
            let need = 4 - self.len_have;
            let take = need.min(input.len());
            self.len_buf[self.len_have..self.len_have + take].copy_from_slice(&input[..take]);
            self.len_have += take;
            pos += take;
            if self.len_have < 4 {
                return (pos, None);
            }
            self.len_have = 0;
            self.total = u32::from_le_bytes(self.len_buf);
            self.remaining = self.total;
            if self.total == 0 {
                // A zero-length frame is the server's keep-alive tick.
                return (
                    pos,
                    Some(MapFrame {
                        total_len: 0,
                        chunk: &[],
                        end: true,
                    }),
                );
            }
        }

        let avail = input.len() - pos;
        if avail == 0 {
            return (pos, None);
        }
        let take = (self.remaining as usize).min(avail);
        let chunk = &input[pos..pos + take];
        self.remaining -= take as u32;
        pos += take;
        (
            pos,
            Some(MapFrame {
                total_len: self.total,
                chunk,
                end: self.remaining == 0,
            }),
        )
    }
}

/// What a netmap tells us about one peer.
///
/// Only the fields needed to reach it. Everything else in a `Node` — user
/// profile, capabilities, timestamps — is deliberately ignored, because on a
/// device with 520 KB of RAM the netmap is the largest thing that arrives and
/// keeping less of it is the whole game.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo<'a> {
    pub node_key: NodePublic,
    /// Absent for peers that predate disco or have not reported one.
    pub disco_key: Option<DiscoPublic>,
    /// Relay the peer is reachable through, or 0 if unknown. A peer with no
    /// home relay cannot be reached indirectly at all.
    pub home_derp: u32,
    pub online: bool,
    /// Raw JSON array of CIDRs this peer accepts traffic for. Kept unparsed
    /// because routing decisions belong to the layer above.
    pub allowed_ips: &'a [u8],
}

/// Iterates the peers in a netmap.
///
/// Reads **both** `Peers` and `PeersChanged`. This matters: the control plane
/// routinely answers with only `PeersChanged`, and a client that looks solely
/// at `Peers` concludes the tailnet is empty — with no error to explain why.
///
/// Malformed or unkeyed entries are skipped rather than failing the whole
/// netmap: one peer the server describes in a way we do not understand should
/// not cost us every other peer.
pub fn peers(netmap: &[u8]) -> impl Iterator<Item = PeerInfo<'_>> + '_ {
    let list = |k: &str| match json::field(netmap, k) {
        Ok(Some(Value::Raw(r))) => r,
        _ => &[][..],
    };
    json::elements(list("Peers"))
        .chain(json::elements(list("PeersChanged")))
        .filter_map(|entry| {
            let Value::Raw(node) = entry else { return None };
            let get = |k: &str| json::field(node, k).ok().flatten();
            let node_key = NodePublic::parse(get("Key")?.as_str()?).ok()?;
            Some(PeerInfo {
                node_key,
                disco_key: get("DiscoKey")
                    .and_then(|v| v.as_str())
                    .and_then(|s| DiscoPublic::parse(s).ok()),
                home_derp: get("HomeDERP")
                    .and_then(|v| match v {
                        Value::Number(n) => n.parse::<u32>().ok(),
                        _ => None,
                    })
                    .or_else(|| get("DERP").and_then(|v| derp_region(v.as_str()?)))
                    .unwrap_or(0),
                online: get("Online").and_then(|v| v.as_bool()).unwrap_or(false),
                // `AllowedIPs` is often absent, in which case the peer's own
                // addresses are the only routes it accepts.
                allowed_ips: match get("AllowedIPs").or_else(|| get("Addresses")) {
                    Some(Value::Raw(r)) => r,
                    _ => &[],
                },
            })
        })
}

/// Extracts the region from the `DERP` field, which encodes a peer's home
/// relay as a placeholder address of the form `127.3.3.40:<region>` rather
/// than as a plain number.
fn derp_region(s: &str) -> Option<u32> {
    // The prefix is checked, not assumed. This reads a peer's `DERP` field,
    // which is documented to hold the placeholder — but taking the port off
    // whatever happens to be there would turn a real address into a plausible
    // region number, and a wrong region is silent misrouting rather than an
    // error.
    s.strip_prefix("127.3.3.40:")?.parse().ok()
}

/// The parts of `RegisterResponse` a headless device acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterResponse<'a> {
    pub machine_authorized: bool,
    pub node_key_expired: bool,
    /// Non-empty means interactive login is required — with a valid pre-auth
    /// key it should always be empty, so a value here is a provisioning fault,
    /// not something a headless device can resolve.
    pub auth_url: &'a str,
    pub error: &'a str,
}

impl RegisterResponse<'_> {
    /// True when the node is registered and usable.
    pub fn is_success(&self) -> bool {
        self.error.is_empty() && self.auth_url.is_empty() && !self.node_key_expired
    }
}

pub fn parse_register_response(body: &[u8]) -> Result<RegisterResponse<'_>, JsonError> {
    let s = |k: &str| -> Result<&str, JsonError> {
        Ok(json::field(body, k)?
            .and_then(|v| v.as_str())
            .unwrap_or(""))
    };
    let b = |k: &str| -> Result<bool, JsonError> {
        Ok(json::field(body, k)?
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    };
    Ok(RegisterResponse {
        machine_authorized: b("MachineAuthorized")?,
        node_key_expired: b("NodeKeyExpired")?,
        auth_url: s("AuthURL")?,
        error: s("Error")?,
    })
}

/// Extracts a nested field's string value from a raw object slice, for the few
/// places we care about something inside `User`, `Login` or `Node`.
pub fn nested_str<'a>(raw: Value<'a>, key: &str) -> Option<&'a str> {
    match raw {
        Value::Raw(bytes) => json::field(bytes, key).ok().flatten()?.as_str(),
        _ => None,
    }
}

/// As [`nested_str`], but for a nested object or array returned verbatim.
pub fn nested_raw<'a>(raw: Value<'a>, key: &str) -> Option<&'a [u8]> {
    match raw {
        Value::Raw(bytes) => match json::field(bytes, key).ok()?? {
            Value::Raw(inner) => Some(inner),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::NodePrivate;

    fn as_str(buf: &[u8]) -> &str {
        core::str::from_utf8(buf).unwrap()
    }

    /// Builds a request with the common defaults, leaving the caller to vary
    /// only what the test is about.
    fn req<'a>(node: &'a NodePublic, hostinfo: &'a Hostinfo<'a>) -> Register<'a> {
        Register {
            capability_version: 145,
            node_key: node,
            auth_key: None,
            followup: None,
            hostinfo,
            ephemeral: false,
        }
    }

    #[test]
    fn register_request_has_the_required_shape() {
        let node = NodePrivate::from_bytes([5u8; 32]).public();
        let hi = Hostinfo {
            hostname: "lando",
            ..Default::default()
        };
        let mut buf = [0u8; 1024];
        let n = write_register_request(
            &mut buf,
            &Register {
                auth_key: Some("tskey-auth-abc123"),
                ..req(&node, &hi)
            },
        )
        .unwrap();
        let s = as_str(&buf[..n]);

        assert!(s.starts_with(r#"{"Version":145,"NodeKey":"nodekey:"#));
        assert!(s.contains(r#""Auth":{"AuthKey":"tskey-auth-abc123"}"#));
        assert!(s.contains(r#""Hostname":"lando""#));
        // Absent rather than zero-valued: Go decodes missing fields to zero.
        assert!(!s.contains("OldNodeKey"));
        assert!(!s.contains("NLKey"));
        // Ephemeral is omitted when false, matching the upstream omitempty.
        assert!(!s.contains("Ephemeral"));
        // It must be valid JSON we can read back.
        assert_eq!(
            json::field(&buf[..n], "Version").unwrap(),
            Some(Value::Number("145"))
        );
    }

    #[test]
    fn advertises_routable_ips_when_present() {
        let node = NodePrivate::from_bytes([5u8; 32]).public();
        let hi = Hostinfo {
            routable_ips: &["192.168.1.0/24"],
            ..Default::default()
        };
        let mut buf = [0u8; 1024];
        let n = write_register_request(
            &mut buf,
            &Register {
                auth_key: Some("k"),
                ephemeral: true,
                ..req(&node, &hi)
            },
        )
        .unwrap();
        let s = as_str(&buf[..n]);
        assert!(s.contains(r#""RoutableIPs":["192.168.1.0/24"]"#));
        assert!(s.contains(r#""Ephemeral":true"#));
    }

    /// The interactive path omits `Auth` entirely on the first request, then
    /// echoes the returned URL back in `Followup`.
    #[test]
    fn interactive_flow_omits_auth_then_sends_followup() {
        let node = NodePrivate::from_bytes([5u8; 32]).public();
        let hi = Hostinfo::default();
        let mut buf = [0u8; 1024];

        let n = write_register_request(&mut buf, &req(&node, &hi)).unwrap();
        let s = as_str(&buf[..n]);
        assert!(!s.contains("Auth"), "no Auth object on the first request");
        assert!(!s.contains("Followup"));

        let n = write_register_request(
            &mut buf,
            &Register {
                followup: Some("https://login.tailscale.com/a/abc123"),
                ..req(&node, &hi)
            },
        )
        .unwrap();
        let s = as_str(&buf[..n]);
        assert!(s.contains(r#""Followup":"https://login.tailscale.com/a/abc123""#));
        assert!(!s.contains(r#""Auth""#));
    }

    /// An auth key with a quote in it must not be able to break out of the
    /// JSON string — it arrives from a USB provisioning blob, not a constant.
    #[test]
    fn escapes_hostile_auth_keys() {
        let node = NodePrivate::from_bytes([5u8; 32]).public();
        let hi = Hostinfo::default();
        let mut buf = [0u8; 1024];
        let n = write_register_request(
            &mut buf,
            &Register {
                auth_key: Some(r#"a","X":"b"#),
                ..req(&node, &hi)
            },
        )
        .unwrap();
        // The injected key must land as a value, not as a new field.
        assert_eq!(json::field(&buf[..n], "X").unwrap(), None);
    }

    /// Captured from the live control plane: this is what actually precedes
    /// the HTTP/2 preface, and mis-skipping it hangs the connection.
    #[test]
    fn skips_the_early_payload() {
        let json = br#"{"nodeKeyChallenge":"chalpub:dcae1cfa"}"#;
        const TRAILER: [u8; 4] = [0, 0, 0x24, 0x04]; // start of an h2 SETTINGS frame
        let mut buf = [0u8; 128];
        let head = EARLY_PAYLOAD_MAGIC.len() + 4;
        buf[..EARLY_PAYLOAD_MAGIC.len()].copy_from_slice(EARLY_PAYLOAD_MAGIC);
        buf[EARLY_PAYLOAD_MAGIC.len()..head].copy_from_slice(&(json.len() as u32).to_be_bytes());
        buf[head..head + json.len()].copy_from_slice(json);
        buf[head + json.len()..head + json.len() + 4].copy_from_slice(&TRAILER);
        let total = head + json.len() + 4;

        match parse_early_payload(&buf[..total]) {
            EarlyPayload::Present { consumed, json: j } => {
                assert_eq!(consumed, head + json.len());
                assert_eq!(j, json);
                assert_eq!(&buf[consumed..total], &TRAILER);
            }
            other => panic!("expected a payload, got {other:?}"),
        }
    }

    #[test]
    fn early_payload_absent_and_partial_cases() {
        // An h2 SETTINGS frame starts with a zero length, not the magic.
        assert_eq!(parse_early_payload(&[0, 0, 0x24, 0x04]), EarlyPayload::Absent);
        // A strict prefix of the magic is undecidable.
        assert_eq!(parse_early_payload(b"\xff\xff"), EarlyPayload::Incomplete);
        assert_eq!(parse_early_payload(b""), EarlyPayload::Incomplete);
        // Magic present but the body has not all arrived.
        assert_eq!(
            parse_early_payload(b"\xff\xff\xffTS\x00\x00\x00\x40short"),
            EarlyPayload::Incomplete
        );
        // Diverges from the magic at byte 3.
        assert_eq!(parse_early_payload(b"\xff\xff\xffXX"), EarlyPayload::Absent);
    }

    #[test]
    fn map_request_opts_out_of_compression() {
        let node = NodePrivate::from_bytes([5u8; 32]).public();
        let disco = crate::key::DiscoPrivate::from_bytes([6u8; 32]).public();
        let hi = Hostinfo::default();
        let mut buf = [0u8; 1024];
        let n = write_map_request(
            &mut buf,
            &MapRequest {
                capability_version: 145,
                node_key: &node,
                disco_key: &disco,
                hostinfo: &hi,
                stream: true,
                keep_alive: true,
                omit_peers: false,
                endpoints: &[],
                endpoint_types: &[],
            },
        )
        .unwrap();
        let s = as_str(&buf[..n]);
        // Explicitly empty, not absent: this is what drops the zstd decoder.
        assert!(s.contains(r#""Compress":"""#));
        assert!(s.contains(r#""Stream":true"#));
        assert!(s.contains(r#""KeepAlive":true"#));
        assert!(s.contains(r#""DiscoKey":"discokey:"#));
        assert!(!s.contains("OmitPeers"));
    }

    /// Advertising a home relay is what makes a node reachable; without it
    /// peers have nowhere to send and simply stay silent.
    ///
    /// The shape matters as much as the contents: this has to be a *one-shot*
    /// request, because the server discards `Hostinfo` and `Endpoints` on a
    /// streaming one.
    #[test]
    fn map_request_advertises_the_home_relay() {
        let node = NodePrivate::from_bytes([5u8; 32]).public();
        let disco = crate::key::DiscoPrivate::from_bytes([6u8; 32]).public();
        let mut buf = [0u8; 1024];
        let hi = Hostinfo {
            preferred_derp: 12,
            derp_latency_ms: Some(55),
            working_udp: true,
            ..Default::default()
        };
        let n = write_map_request(
            &mut buf,
            &MapRequest {
                capability_version: 145,
                node_key: &node,
                disco_key: &disco,
                hostinfo: &hi,
                stream: false,
                keep_alive: false,
                omit_peers: true,
                endpoints: &["192.168.86.42:41641"],
                endpoint_types: &[endpoint_type::LOCAL],
            },
        )
        .unwrap();
        let out = as_str(&buf[..n]);
        // A complete NetInfo, not just the one field: the control plane
        // appears to ignore a partially-filled struct wholesale.
        assert!(out.contains(r#""PreferredDERP":12"#));
        assert!(out.contains(r#""WorkingUDP":true"#));
        assert!(out.contains(r#""MappingVariesByDestIP":false"#));
        assert!(out.contains(r#""DERPLatency":{"12-v4":0.055}"#));
        assert!(out.contains(r#""LinkType":"wifi""#));
        assert!(out.contains(r#""Endpoints":["192.168.86.42:41641"]"#));
        // Anything that would make the server treat this as read-only.
        assert!(!out.contains("Stream"));
        assert!(!out.contains("ReadOnly"));
    }

    /// `127.3.3.40:N` is how the server says "reachable via relay region N"
    /// in a peer's endpoint list. We only ever read it; advertising our own
    /// relay goes through `Hostinfo.NetInfo.PreferredDERP` instead.
    #[test]
    fn derp_placeholder_is_read_back() {
        assert_eq!(derp_region("127.3.3.40:1"), Some(1));
        assert_eq!(derp_region("127.3.3.40:255"), Some(255));
        assert_eq!(derp_region("192.168.86.41:41641"), None);
    }

    /// The length prefix is little-endian here, unlike every other length on
    /// this connection.
    #[test]
    fn map_frames_are_little_endian() {
        let mut f = MapFrames::new();
        let mut input = [0u8; 4 + 5];
        input[..4].copy_from_slice(&5u32.to_le_bytes());
        input[4..].copy_from_slice(b"hello");

        let (used, frame) = f.feed(&input);
        assert_eq!(used, 9);
        let frame = frame.unwrap();
        assert_eq!(frame.total_len, 5);
        assert_eq!(frame.chunk, b"hello");
        assert!(frame.end);
    }

    #[test]
    fn map_frames_stream_across_reads() {
        let mut f = MapFrames::new();
        // Length split across two reads, then a body split across two more.
        let len = 10u32.to_le_bytes();
        assert_eq!(f.feed(&len[..2]), (2, None));
        let (used, frame) = f.feed(&len[2..]);
        assert_eq!(used, 2);
        assert!(frame.is_none(), "length alone yields no chunk");

        let (used, frame) = f.feed(b"abcd");
        assert_eq!(used, 4);
        let frame = frame.unwrap();
        assert_eq!(frame.chunk, b"abcd");
        assert!(!frame.end);

        let (used, frame) = f.feed(b"efghij");
        assert_eq!(used, 6);
        assert!(frame.unwrap().end);
    }

    /// Two frames arriving in one read must not be merged.
    #[test]
    fn map_frames_split_back_to_back_frames() {
        let mut f = MapFrames::new();
        let mut input = [0u8; 4 + 2 + 4 + 3];
        input[..4].copy_from_slice(&2u32.to_le_bytes());
        input[4..6].copy_from_slice(b"ab");
        input[6..10].copy_from_slice(&3u32.to_le_bytes());
        input[10..].copy_from_slice(b"cde");

        let (used, frame) = f.feed(&input);
        assert_eq!(frame.unwrap().chunk, b"ab");
        let (used2, frame) = f.feed(&input[used..]);
        assert_eq!(frame.unwrap().chunk, b"cde");
        assert_eq!(used + used2, input.len());
    }

    #[test]
    fn zero_length_frame_is_a_keepalive() {
        let mut f = MapFrames::new();
        let len = 0u32.to_le_bytes();
        let (used, frame) = f.feed(&len);
        assert_eq!(used, 4);
        let frame = frame.unwrap();
        assert_eq!(frame.total_len, 0);
        assert!(frame.end);
        assert!(frame.chunk.is_empty());
    }

    #[test]
    fn extracts_peers_from_a_netmap() {
        let nm = br#"{
          "Node":{"Name":"self"},
          "Peers":[
            {"ID":1,"Key":"nodekey:0101010101010101010101010101010101010101010101010101010101010101",
             "DiscoKey":"discokey:0202020202020202020202020202020202020202020202020202020202020202",
             "HomeDERP":7,"Online":true,"AllowedIPs":["100.64.0.1/32"]},
            {"ID":2,"Key":"nodekey:0303030303030303030303030303030303030303030303030303030303030303",
             "HomeDERP":0,"AllowedIPs":[]}
          ]}"#;

        let found: [Option<PeerInfo>; 2] = {
            let mut it = peers(nm);
            [it.next(), it.next()]
        };
        let a = found[0].unwrap();
        assert_eq!(a.node_key.as_bytes()[0], 0x01);
        assert_eq!(a.disco_key.unwrap().as_bytes()[0], 0x02);
        assert_eq!(a.home_derp, 7);
        assert!(a.online);
        assert_eq!(a.allowed_ips, br#"["100.64.0.1/32"]"#);

        let b = found[1].unwrap();
        assert_eq!(b.node_key.as_bytes()[0], 0x03);
        assert_eq!(b.disco_key, None, "DiscoKey is optional");
        assert_eq!(b.home_derp, 0);
        assert!(!b.online);

        assert_eq!(peers(nm).count(), 2);
    }

    /// One peer described in a way we do not understand must not cost us the
    /// rest of the netmap.
    #[test]
    fn malformed_peers_are_skipped_not_fatal() {
        let nm = br#"{"Peers":[
            {"ID":1},
            {"Key":"not-a-node-key"},
            {"Key":"nodekey:0404040404040404040404040404040404040404040404040404040404040404"}
        ]}"#;
        let found: [Option<PeerInfo>; 1] = [peers(nm).next()];
        assert_eq!(found[0].unwrap().node_key.as_bytes()[0], 0x04);
        assert_eq!(peers(nm).count(), 1);
    }

    #[test]
    fn absent_peers_field_yields_nothing() {
        assert_eq!(peers(br#"{"Node":{}}"#).count(), 0);
        assert_eq!(peers(br#"{"Peers":[]}"#).count(), 0);
    }

    /// The control plane routinely answers with only `PeersChanged`. Reading
    /// just `Peers` makes a populated tailnet look empty, with no error.
    #[test]
    fn reads_peers_changed_as_well_as_peers() {
        let nm = br#"{"PeersChanged":[
            {"Key":"nodekey:0505050505050505050505050505050505050505050505050505050505050505",
             "DiscoKey":"discokey:0606060606060606060606060606060606060606060606060606060606060606",
             "DERP":"127.3.3.40:12","Online":true,"Addresses":["100.64.0.5/32"]}
        ]}"#;
        let found: [Option<PeerInfo>; 1] = [peers(nm).next()];
        let p = found[0].unwrap();
        assert_eq!(p.node_key.as_bytes()[0], 0x05);
        assert_eq!(p.disco_key.unwrap().as_bytes()[0], 0x06);
        // The home relay arrives as a placeholder address, not a number.
        assert_eq!(p.home_derp, 12);
        // Falls back to Addresses when AllowedIPs is absent.
        assert_eq!(p.allowed_ips, br#"["100.64.0.5/32"]"#);
    }

    #[test]
    fn both_peer_lists_are_read() {
        let nm = br#"{
          "Peers":[{"Key":"nodekey:0707070707070707070707070707070707070707070707070707070707070707"}],
          "PeersChanged":[{"Key":"nodekey:0808080808080808080808080808080808080808080808080808080808080808"}]
        }"#;
        assert_eq!(peers(nm).count(), 2);
    }

    #[test]
    fn derp_placeholder_address_parses() {
        assert_eq!(derp_region("127.3.3.40:7"), Some(7));
        assert_eq!(derp_region("127.3.3.40:0"), Some(0));
        assert_eq!(derp_region("garbage"), None);
    }

    #[test]
    fn parses_a_successful_response() {
        let body = br#"{"User":{"ID":7},"Login":{"LoginName":"user@example.com"},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","Error":""}"#;
        let r = parse_register_response(body).unwrap();
        assert!(r.machine_authorized);
        assert!(r.is_success());
        assert_eq!(
            nested_str(json::field(body, "Login").unwrap().unwrap(), "LoginName"),
            Some("user@example.com")
        );
    }

    #[test]
    fn surfaces_errors_and_pending_auth() {
        let r = parse_register_response(br#"{"Error":"invalid key"}"#).unwrap();
        assert!(!r.is_success());
        assert_eq!(r.error, "invalid key");

        let r =
            parse_register_response(br#"{"AuthURL":"https://login.tailscale.com/a/xyz"}"#).unwrap();
        assert!(!r.is_success());
        assert!(r.auth_url.starts_with("https://"));
    }
}
