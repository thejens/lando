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
}

impl Default for Hostinfo<'_> {
    fn default() -> Self {
        Self {
            hostname: "lando",
            ipn_version: concat!("1.0.0-lando-", env!("CARGO_PKG_VERSION")),
            os: "linux",
            os_version: "",
            machine: "thumbv8m",
            routable_ips: &[],
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
    pub stream: bool,
    /// Ask the server to send periodic keep-alive frames.
    pub keep_alive: bool,
    /// Drop peer data. Useful for a first connection where only presence
    /// matters, and a real saving on a device that cannot hold a large netmap.
    pub omit_peers: bool,
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
