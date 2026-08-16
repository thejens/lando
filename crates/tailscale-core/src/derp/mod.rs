//! DERP: Tailscale's relay protocol.
//!
//! DERP is what makes a device behind NAT reachable with no router
//! configuration at all. The device dials *out* to a relay over TLS on 443 and
//! parks the connection; peers that cannot reach it directly send through the
//! relay. It is the same shape as any outbound-tunnel design, except the relay
//! is Tailscale's rather than something you host.
//!
//! The relay sees only ciphertext: everything it forwards is already
//! end-to-end WireGuard-encrypted, and no credential ever transits it —
//! authentication is a NaCl box against the node key. That is why running this
//! without TLS certificate verification is a defensible trade on a device with
//! no trust store, and why it would not have been on a design that shipped a
//! bearer token.
//!
//! This module is the wire format only. TLS and sockets belong to whatever
//! drives it, so the same framing serves both the host binary and the firmware.

pub mod frame;
pub mod handshake;

pub use frame::{parse_server_key, Frame, FrameReader, FrameType, MAX_FRAME_LEN};
pub use handshake::{client_info_payload, open, seal};

/// Sent by the server as the first thing on a new connection, ahead of its
/// public key.
pub const MAGIC: &[u8] = "DERP🔑".as_bytes();

/// Default relay port. DERP is TLS-only on the public fleet; a self-hosted
/// `derper` can also run plaintext on 3340, which is worth knowing if you ever
/// need to watch the protocol without decrypting TLS.
pub const PORT: u16 = 443;
pub const PLAINTEXT_DEV_PORT: u16 = 3340;

/// The HTTP path used to upgrade an ordinary TLS connection into DERP.
pub const UPGRADE_PATH: &str = "/derp";
pub const UPGRADE_PROTOCOL: &str = "DERP";
