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
use crate::key::NodePublic;

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
/// places we care about something inside `User` or `Login`.
pub fn nested_str<'a>(raw: Value<'a>, key: &str) -> Option<&'a str> {
    match raw {
        Value::Raw(bytes) => json::field(bytes, key).ok().flatten()?.as_str(),
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
