//! Curve25519 key types used across the Tailscale protocols.
//!
//! Tailscale distinguishes several keys that are all Curve25519 underneath but
//! must never be interchanged: the *machine* key identifies the device to the
//! control plane (it is the Noise static), the *node* key identifies the node
//! within the tailnet and is the WireGuard static, and the *disco* key
//! authenticates endpoint discovery. They are separate types here for the same
//! reason they are separate types upstream — mixing them up produces a
//! handshake that fails with no useful diagnostic.
//!
//! Each pair carries the wire prefix Tailscale serializes it with, so a key
//! pasted into the wrong field is rejected at parse time rather than silently
//! producing a valid-looking handshake against the wrong identity.

use x25519_dalek::{PublicKey as XPublic, StaticSecret};

/// Length of every Curve25519 key in this module.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Hex payload was not exactly 64 characters, or contained a non-hex digit.
    BadHex,
    /// The type prefix (`mkey:`, `nodekey:`, …) was missing or wrong.
    BadPrefix,
    /// Output buffer too small to hold the serialized form.
    ShortBuffer,
}

fn nibble(c: u8) -> Result<u8, KeyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(KeyError::BadHex),
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Defines a private/public Curve25519 pair with its Tailscale wire prefix.
macro_rules! define_key_pair {
    ($private:ident, $public:ident, $prefix:expr) => {
        #[doc = concat!("A Curve25519 public key serialized as `", $prefix, "<hex>`.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $public(pub [u8; KEY_LEN]);

        #[doc = concat!("The private half of a [`", stringify!($public), "`].")]
        ///
        /// Deliberately not `Copy`: private keys should move, so an accidental
        /// duplicate is a compile error rather than an extra copy in memory.
        #[derive(Clone)]
        pub struct $private([u8; KEY_LEN]);

        impl $private {
            /// The wire prefix for this key type.
            pub const PREFIX: &'static str = $prefix;

            /// Wraps raw key material. Clamping is applied by X25519 at use
            /// time, so the stored bytes are whatever the caller supplied —
            /// matching upstream, which also persists the unclamped form.
            pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
                Self(b)
            }

            /// Generates a fresh key. On the Pico this is fed by the RP2350
            /// hardware TRNG; on a host by the OS CSPRNG. There is no
            /// software-entropy fallback, deliberately — a weak key here is a
            /// silent, total compromise.
            pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
                let mut b = [0u8; KEY_LEN];
                rng.fill_bytes(&mut b);
                Self(b)
            }

            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            pub fn public(&self) -> $public {
                let secret = StaticSecret::from(self.0);
                $public(XPublic::from(&secret).to_bytes())
            }

            /// Raw X25519. Returns the shared secret with no hashing applied —
            /// the caller must run it through a KDF.
            pub fn dh(&self, peer: &$public) -> [u8; KEY_LEN] {
                let secret = StaticSecret::from(self.0);
                secret.diffie_hellman(&XPublic::from(peer.0)).to_bytes()
            }
        }

        impl $public {
            /// The wire prefix for this key type.
            pub const PREFIX: &'static str = $prefix;

            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Parses the prefixed wire form, e.g. `mkey:7d2792f9…`.
            pub fn parse(s: &str) -> Result<Self, KeyError> {
                let hex = s.strip_prefix($prefix).ok_or(KeyError::BadPrefix)?;
                Self::parse_hex(hex)
            }

            /// Parses bare hex with no prefix.
            pub fn parse_hex(hex: &str) -> Result<Self, KeyError> {
                let bytes = hex.as_bytes();
                if bytes.len() != KEY_LEN * 2 {
                    return Err(KeyError::BadHex);
                }
                let mut out = [0u8; KEY_LEN];
                for (i, chunk) in bytes.chunks_exact(2).enumerate() {
                    out[i] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
                }
                Ok(Self(out))
            }

            /// Writes the prefixed wire form into `out`, returning its length.
            pub fn write(&self, out: &mut [u8]) -> Result<usize, KeyError> {
                let total = $prefix.len() + KEY_LEN * 2;
                if out.len() < total {
                    return Err(KeyError::ShortBuffer);
                }
                out[..$prefix.len()].copy_from_slice($prefix.as_bytes());
                for (i, b) in self.0.iter().enumerate() {
                    out[$prefix.len() + i * 2] = HEX[(b >> 4) as usize];
                    out[$prefix.len() + i * 2 + 1] = HEX[(b & 0xf) as usize];
                }
                Ok(total)
            }
        }
    };
}

define_key_pair!(MachinePrivate, MachinePublic, "mkey:");
define_key_pair!(NodePrivate, NodePublic, "nodekey:");
define_key_pair!(DiscoPrivate, DiscoPublic, "discokey:");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_live_control_key() {
        // From https://controlplane.tailscale.com/key?v=2 — stable since at
        // least Jan 2023.
        let k = MachinePublic::parse(
            "mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b",
        )
        .unwrap();
        assert_eq!(k.0[0], 0x7d);
        assert_eq!(k.0[31], 0x3b);
    }

    /// The prefixes are the whole point of having distinct types: a node key
    /// offered where a machine key belongs must not parse.
    #[test]
    fn prefixes_are_enforced_across_types() {
        let hex = "7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b";
        let machine = alloc_str("mkey:", hex);
        let node = alloc_str("nodekey:", hex);

        assert!(MachinePublic::parse(core::str::from_utf8(&machine.0[..machine.1]).unwrap()).is_ok());
        assert_eq!(
            MachinePublic::parse(core::str::from_utf8(&node.0[..node.1]).unwrap()),
            Err(KeyError::BadPrefix)
        );
        assert!(NodePublic::parse(core::str::from_utf8(&node.0[..node.1]).unwrap()).is_ok());
    }

    /// Helper that concatenates without `alloc`.
    fn alloc_str(prefix: &str, hex: &str) -> ([u8; 96], usize) {
        let mut b = [0u8; 96];
        b[..prefix.len()].copy_from_slice(prefix.as_bytes());
        b[prefix.len()..prefix.len() + hex.len()].copy_from_slice(hex.as_bytes());
        (b, prefix.len() + hex.len())
    }

    #[test]
    fn round_trips_through_the_wire_form() {
        let k = NodePrivate::from_bytes([0x42; 32]).public();
        let mut buf = [0u8; 128];
        let n = k.write(&mut buf).unwrap();
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.starts_with("nodekey:"));
        assert_eq!(NodePublic::parse(s).unwrap(), k);
    }

    #[test]
    fn rejects_bad_hex_and_short_buffers() {
        assert_eq!(MachinePublic::parse_hex("zz"), Err(KeyError::BadHex));
        let k = MachinePrivate::from_bytes([1; 32]).public();
        let mut tiny = [0u8; 8];
        assert_eq!(k.write(&mut tiny), Err(KeyError::ShortBuffer));
    }

    #[test]
    fn dh_agrees_in_both_directions() {
        let a = MachinePrivate::from_bytes([1u8; 32]);
        let b = MachinePrivate::from_bytes([2u8; 32]);
        assert_eq!(a.dh(&b.public()), b.dh(&a.public()));
    }
}
