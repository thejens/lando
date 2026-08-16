//! WireGuard: the data plane that makes the node actually reachable.
//!
//! `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, sharing its primitives with the
//! ts2021 control channel but agreeing with it on almost nothing else. Two
//! traps worth stating up front, because both fail silently:
//!
//!   * **Nonces here are little-endian.** ts2021 record nonces are big-endian.
//!     Same cipher, same 12-byte layout, opposite byte order.
//!   * **`mac1` uses BLAKE2s in keyed mode, not HMAC.** The KDF uses HMAC.
//!     Substituting one for the other produces handshakes a peer discards
//!     without reply, which is indistinguishable from a firewall drop.

pub mod handshake;
pub mod transport;

pub use handshake::{Initiation, Initiator, Responder, SessionKeys};
pub use transport::{ReplayWindow, Session};

use crate::crypto;
use crate::key::NodePublic;

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
/// type + reserved + receiver + counter, before any ciphertext.
pub const TRANSPORT_HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

/// Field offsets within a handshake initiation.
pub mod init {
    pub const SENDER: usize = 4;
    pub const EPHEMERAL: usize = 8;
    pub const STATIC: usize = 40;
    pub const TIMESTAMP: usize = 88;
    pub const MAC1: usize = 116;
    pub const MAC2: usize = 132;
}

/// Field offsets within a handshake response.
pub mod resp {
    pub const SENDER: usize = 4;
    pub const RECEIVER: usize = 8;
    pub const EPHEMERAL: usize = 12;
    pub const EMPTY: usize = 44;
    pub const MAC1: usize = 60;
    pub const MAC2: usize = 76;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgError {
    /// Message length or type byte does not match any WireGuard message.
    Malformed,
    /// AEAD authentication failed — wrong key, or a tampered message.
    Decrypt,
    /// `mac1` did not verify: the message was not addressed to our static key.
    BadMac,
    /// Handshake timestamp was not newer than the last one seen from this
    /// peer, so the message is a replay.
    ReplayedHandshake,
    /// Transport counter fell outside the replay window.
    ReplayedTransport,
    /// The 2^64 message limit for a key was reached; rekeying is required.
    NonceExhausted,
    ShortBuffer,
}

/// A 12-byte TAI64N timestamp.
///
/// WireGuard peers keep the greatest timestamp seen per static key and discard
/// any handshake whose timestamp is not strictly greater. That makes this the
/// single most dangerous piece of state on a device with no battery-backed
/// clock: boot with a zeroed clock after a peer has already seen a real one,
/// and every handshake is silently refused until *the peer* restarts. The
/// symptom looks exactly like a firewall problem.
///
/// The value need not be real time — only strictly increasing per static key.
/// A counter persisted to flash therefore satisfies the protocol without a
/// clock at all, which is why [`Tai64n::from_counter`] exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Tai64n(pub [u8; 12]);

impl Tai64n {
    /// TAI64 labels the second 2^62 as the epoch, plus 10 leap seconds.
    const EPOCH: u64 = 0x4000_0000_0000_000A;

    pub fn from_unix(seconds: u64, nanos: u32) -> Self {
        let mut out = [0u8; 12];
        out[..8].copy_from_slice(&(Self::EPOCH + seconds).to_be_bytes());
        out[8..].copy_from_slice(&nanos.to_be_bytes());
        Self(out)
    }

    /// Builds a timestamp from a monotonic counter rather than a clock.
    ///
    /// Persist the counter and bump it generously on every boot. Both fields
    /// are big-endian, so lexicographic byte order matches numeric order and
    /// peers compare these correctly without parsing them.
    pub fn from_counter(counter: u64) -> Self {
        Self::from_unix(counter, 0)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    pub fn from_bytes(b: [u8; 12]) -> Self {
        Self(b)
    }

    /// True when `self` would be accepted by a peer that last saw `previous`.
    pub fn is_newer_than(&self, previous: &Tai64n) -> bool {
        self.0 > previous.0
    }
}

/// `MAC(HASH(LABEL_MAC1 || peer_static_public), message_up_to_mac1)`.
///
/// Lets a receiver reject messages not addressed to its static key before
/// doing any expensive Curve25519 work — the protocol's DoS defence.
pub fn mac1(peer_static: &NodePublic, message_prefix: &[u8]) -> [u8; crypto::MAC_LEN] {
    let key = crypto::hash_parts(&[LABEL_MAC1, peer_static.as_bytes()]);
    crypto::keyed_mac(&key, &[message_prefix])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::NodePrivate;

    #[test]
    fn tai64n_is_ordered_and_big_endian() {
        let a = Tai64n::from_counter(1);
        let b = Tai64n::from_counter(2);
        assert!(b.is_newer_than(&a));
        assert!(!a.is_newer_than(&b));
        assert!(!a.is_newer_than(&a), "equal is not newer — replay is rejected");

        // Big-endian, so byte order and numeric order agree.
        assert!(Tai64n::from_counter(0x100).0 > Tai64n::from_counter(0xFF).0);
    }

    #[test]
    fn tai64n_uses_the_tai_epoch() {
        let t = Tai64n::from_unix(0, 0);
        assert_eq!(
            u64::from_be_bytes(t.0[..8].try_into().unwrap()),
            0x4000_0000_0000_000A
        );
    }

    /// A zeroed clock after a peer has seen a real timestamp is the silent
    /// failure this whole type exists to prevent.
    #[test]
    fn zeroed_clock_is_rejected_against_a_real_timestamp() {
        let real = Tai64n::from_unix(1_700_000_000, 0);
        let after_reboot = Tai64n::from_unix(0, 0);
        assert!(!after_reboot.is_newer_than(&real));
    }

    #[test]
    fn mac1_is_bound_to_the_recipient() {
        let a = NodePrivate::from_bytes([1; 32]).public();
        let b = NodePrivate::from_bytes([2; 32]).public();
        let msg = [9u8; 116];
        assert_ne!(mac1(&a, &msg), mac1(&b, &msg));
        assert_eq!(mac1(&a, &msg), mac1(&a, &msg));
    }
}
