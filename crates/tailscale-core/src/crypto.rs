//! Primitives shared by the ts2021 control channel and WireGuard.
//!
//! Both protocols are Noise variants over the same suite — Curve25519,
//! ChaCha20-Poly1305, BLAKE2s — so the hash, MAC and KDF live here rather than
//! being duplicated. What differs between them is framing and nonce order, not
//! these building blocks.

use blake2::digest::{FixedOutput, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};

/// BLAKE2s block size, needed for the HMAC pad construction.
const BLAKE2S_BLOCK: usize = 64;

pub const HASH_LEN: usize = 32;
/// WireGuard's MACs are truncated to 16 bytes.
pub const MAC_LEN: usize = 16;

pub fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

/// BLAKE2s over a sequence of parts, avoiding a concatenation buffer.
pub fn hash_parts(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s (RFC 2104 over BLAKE2s).
///
/// Hand-rolled because RustCrypto's BLAKE2 has a `Lazy` buffer kind — it
/// supports a native keyed mode — which `hmac::Hmac` cannot wrap. Note this is
/// *not* BLAKE2s's keyed mode: Noise, WireGuard and Go's
/// `hkdf.New(newBLAKE2s, …)` all specify plain HMAC, and the two constructions
/// are not interchangeable. (WireGuard's `MAC()` does use the keyed mode — see
/// [`keyed_mac`].)
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut padded = [0u8; BLAKE2S_BLOCK];
    if key.len() > BLAKE2S_BLOCK {
        padded[..HASH_LEN].copy_from_slice(&hash(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLAKE2S_BLOCK];
    let mut opad = [0x5cu8; BLAKE2S_BLOCK];
    for i in 0..BLAKE2S_BLOCK {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }

    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner: [u8; HASH_LEN] = inner.finalize().into();

    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// HKDF (RFC 5869) with BLAKE2s and an empty `info`, producing `N` 32-byte
/// outputs — the shape both Noise's `HKDF()` and WireGuard's `KDF_n()` need.
pub fn kdf<const N: usize>(key: &[u8], input: &[u8]) -> [[u8; HASH_LEN]; N] {
    let prk = hmac(key, &[input]);
    let mut out = [[0u8; HASH_LEN]; N];
    for i in 0..N {
        let counter = [(i + 1) as u8];
        out[i] = if i == 0 {
            hmac(&prk, &[&counter])
        } else {
            hmac(&prk, &[&out[i - 1], &counter])
        };
    }
    out
}

/// BLAKE2s in *keyed* mode with a 16-byte digest — WireGuard's `MAC()`.
///
/// Distinct from [`hmac`]: WireGuard uses HMAC for its KDF but the native
/// keyed mode for `mac1`/`mac2`. Substituting one for the other produces
/// handshakes that are silently discarded by the peer.
pub fn keyed_mac(key: &[u8], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut m = <Blake2sMac<blake2::digest::consts::U16> as KeyInit>::new_from_slice(key)
        .expect("blake2s mac key length");
    for p in parts {
        Mac::update(&mut m, p);
    }
    m.finalize_fixed().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-checked against Python's `hmac` + `hashlib.blake2s`, an
    /// independent implementation — a self-consistency test would not catch a
    /// construction that is uniformly wrong.
    #[test]
    fn hmac_matches_reference() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hmac(&key, &[b"tailscale"]),
            hex32("26dc379e5a2c2143f17cc1eec53fc7e1d5d2ec2a3f7470a8f261fb5271bbfcc4")
        );
        // Keys longer than the 64-byte block are hashed down first.
        let long: [u8; 100] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hmac(&long, &[b"x"]),
            hex32("7c5a4a1c1150b1eadcba56974986fd860c4aca9cd69fa0c65c9f67dadad9883a")
        );
    }

    #[test]
    fn kdf_matches_reference() {
        let out = kdf::<2>(&[0xAA; 32], &[0xBB; 32]);
        assert_eq!(
            out[0],
            hex32("fe332fdec9cd425f88cdabe009f2d78aff433e89c9d38673f5158bc3f15cff34")
        );
        assert_eq!(
            out[1],
            hex32("3e81c8bf9aaa02a751a3e2b6312cbf0900289ff68c6db75e3548eca281b0a75c")
        );
        // Empty IKM — the Split case, easy to get wrong by swapping key/input.
        let out = kdf::<2>(&[0xCC; 32], &[]);
        assert_eq!(
            out[0],
            hex32("9e0ffdb8cdbc6c9b346c6ff26db6c19274dbd993b1f83db3950be8b6b3948f3a")
        );
    }

    /// The keyed mode must not equal HMAC with the same key and message —
    /// confusing the two is the failure this guards against.
    #[test]
    fn keyed_mac_differs_from_hmac() {
        let key = [7u8; 32];
        let mac = keyed_mac(&key, &[b"message"]);
        let mac_h = hmac(&key, &[b"message"]);
        assert_eq!(mac.len(), MAC_LEN);
        assert_ne!(mac[..], mac_h[..MAC_LEN]);
    }

    #[test]
    fn hash_parts_equals_concatenated_hash() {
        assert_eq!(hash_parts(&[b"abc", b"def"]), hash(b"abcdef"));
    }

    fn hex32(s: &str) -> [u8; 32] {
        crate::key::MachinePublic::parse_hex(s).unwrap().0
    }
}
