//! The DERP client handshake.
//!
//! Three frames, in order:
//!
//!   1. Server sends `ServerKey`  — magic + its public key.
//!   2. Client sends `ClientInfo` — its public key, a nonce, and a sealed JSON blob.
//!   3. Server sends `ServerInfo` — a nonce and a sealed JSON blob.
//!
//! The seal is NaCl `crypto_box`: X25519 to a shared secret, then
//! XSalsa20-Poly1305. Note that this is the *third* AEAD in this codebase and
//! the only one that is not ChaCha20-based.
//!
//! **Byte order matters here in a way that is easy to miss.** NaCl places the
//! 16-byte Poly1305 tag *before* the ciphertext, while the RustCrypto AEAD
//! convention appends it *after*. The detached API is used deliberately so the
//! layout is assembled explicitly rather than inherited, and the tests check it
//! against a vector produced by libsodium rather than by this code.

use crypto_box::aead::AeadInPlace;
use crypto_box::{PublicKey, SalsaBox, SecretKey};

use super::frame::{DerpError, KEY_LEN};
use crate::json;

/// NaCl nonce length. Longer than the 12 bytes ChaCha20-Poly1305 uses, because
/// XSalsa20 exists precisely to permit random nonces safely.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// The DERP protocol version this client speaks.
pub const PROTOCOL_VERSION: u32 = 2;

/// Bytes a sealed payload adds over its plaintext: nonce plus tag.
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

fn boxer(client_secret: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> SalsaBox {
    SalsaBox::new(
        &PublicKey::from(*peer_public),
        &SecretKey::from(*client_secret),
    )
}

/// Seals `plaintext` into `out` as `nonce || tag || ciphertext`.
///
/// The caller supplies the nonce so this stays deterministic under test; in
/// production it must be random per message.
pub fn seal(
    client_secret: &[u8; KEY_LEN],
    peer_public: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, DerpError> {
    let total = SEAL_OVERHEAD + plaintext.len();
    if out.len() < total {
        return Err(DerpError::ShortBuffer);
    }
    out[..NONCE_LEN].copy_from_slice(nonce);
    let body = &mut out[NONCE_LEN + TAG_LEN..total];
    body.copy_from_slice(plaintext);

    let tag = boxer(client_secret, peer_public)
        .encrypt_in_place_detached(nonce.into(), &[], body)
        .map_err(|_| DerpError::Crypto)?;
    // NaCl order: tag ahead of the ciphertext, not appended to it.
    out[NONCE_LEN..NONCE_LEN + TAG_LEN].copy_from_slice(&tag);
    Ok(total)
}

/// Opens a `nonce || tag || ciphertext` payload in place.
///
/// Returns the plaintext, which lives in the tail of `payload`.
pub fn open<'a>(
    client_secret: &[u8; KEY_LEN],
    peer_public: &[u8; KEY_LEN],
    payload: &'a mut [u8],
) -> Result<&'a [u8], DerpError> {
    if payload.len() < SEAL_OVERHEAD {
        return Err(DerpError::Crypto);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&payload[NONCE_LEN..NONCE_LEN + TAG_LEN]);

    let body = &mut payload[SEAL_OVERHEAD..];
    boxer(client_secret, peer_public)
        .decrypt_in_place_detached((&nonce).into(), &[], body, (&tag).into())
        .map_err(|_| DerpError::Crypto)?;
    Ok(&payload[SEAL_OVERHEAD..])
}

/// Builds the `ClientInfo` frame payload: `client_public || nonce || tag || ciphertext`.
///
/// Only `Version` is sent. The other fields the server understands are for
/// mesh peers, probers and telemetry, none of which apply to a device that
/// exists to relay its own traffic.
pub fn client_info_payload(
    client_secret: &[u8; KEY_LEN],
    client_public: &[u8; KEY_LEN],
    server_public: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    out: &mut [u8],
) -> Result<usize, DerpError> {
    let mut info = [0u8; 64];
    let mut w = json::Writer::new(&mut info);
    w.begin_object().map_err(|_| DerpError::ShortBuffer)?;
    w.field_u64("Version", PROTOCOL_VERSION as u64)
        .map_err(|_| DerpError::ShortBuffer)?;
    w.end_object().map_err(|_| DerpError::ShortBuffer)?;
    let info_len = w.len();

    if out.len() < KEY_LEN {
        return Err(DerpError::ShortBuffer);
    }
    out[..KEY_LEN].copy_from_slice(client_public);
    let sealed = seal(
        client_secret,
        server_public,
        nonce,
        &info[..info_len],
        &mut out[KEY_LEN..],
    )?;
    Ok(KEY_LEN + sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-size hex decoder — the crate stays `no_std` under test, so `Vec`
    /// is not available here.
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let b = s.as_bytes();
        core::array::from_fn(|i| {
            let d = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("bad hex"),
            };
            (d(b[i * 2]) << 4) | d(b[i * 2 + 1])
        })
    }

    /// Checked against a vector generated by libsodium (via PyNaCl), not by
    /// this code. A self-produced vector would not catch the tag-ordering
    /// mistake this test exists to rule out: NaCl puts the Poly1305 tag before
    /// the ciphertext, the RustCrypto AEAD convention puts it after.
    #[test]
    fn seal_matches_libsodium() {
        let sk_a = [1u8; 32];
        // pk_b is the public key for secret [2u8; 32]; both come from PyNaCl.
        let pk_b: [u8; 32] =
            hex("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59");
        let nonce: [u8; NONCE_LEN] = core::array::from_fn(|i| i as u8);
        let msg = br#"{"Version":2}"#;

        let mut out = [0u8; 128];
        let n = seal(&sk_a, &pk_b, &nonce, msg, &mut out).unwrap();

        // libsodium emits tag || ciphertext after the nonce.
        let expected: [u8; 29] = hex("0b541e395eaf52256569a525f88b7dca99edd5a6e8428f59d77442f5b1");
        assert_eq!(&out[..NONCE_LEN], &nonce[..]);
        assert_eq!(
            &out[NONCE_LEN..n],
            &expected[..],
            "sealed bytes must match libsodium exactly"
        );
    }

    #[test]
    fn seal_and_open_round_trip() {
        let sk_a = [3u8; 32];
        let sk_b = [4u8; 32];
        let pk_a = *crypto_box::SecretKey::from(sk_a).public_key().as_bytes();
        let pk_b = *crypto_box::SecretKey::from(sk_b).public_key().as_bytes();
        let nonce = [9u8; NONCE_LEN];

        let mut sealed = [0u8; 128];
        let n = seal(&sk_a, &pk_b, &nonce, b"hello derp", &mut sealed).unwrap();

        // The peer opens it with the mirrored key pair.
        let opened = open(&sk_b, &pk_a, &mut sealed[..n]).unwrap();
        assert_eq!(opened, b"hello derp");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let sk_a = [3u8; 32];
        let sk_b = [4u8; 32];
        let pk_a = *crypto_box::SecretKey::from(sk_a).public_key().as_bytes();
        let pk_b = *crypto_box::SecretKey::from(sk_b).public_key().as_bytes();

        let mut sealed = [0u8; 128];
        let n = seal(&sk_a, &pk_b, &[1u8; NONCE_LEN], b"hello", &mut sealed).unwrap();
        sealed[SEAL_OVERHEAD] ^= 0x01;
        assert_eq!(open(&sk_b, &pk_a, &mut sealed[..n]).err(), Some(DerpError::Crypto));
    }

    #[test]
    fn client_info_frame_is_well_formed() {
        let sk = [5u8; 32];
        let pk = *crypto_box::SecretKey::from(sk).public_key().as_bytes();
        let server_sk = [6u8; 32];
        let server_pk = *crypto_box::SecretKey::from(server_sk).public_key().as_bytes();
        let nonce = [7u8; NONCE_LEN];

        let mut out = [0u8; 256];
        let n = client_info_payload(&sk, &pk, &server_pk, &nonce, &mut out).unwrap();
        assert_eq!(&out[..KEY_LEN], &pk[..], "client public key leads");

        // The server must be able to open it and read the version.
        let opened = open(&server_sk, &pk, &mut out[KEY_LEN..n]).unwrap();
        assert_eq!(opened, br#"{"Version":2}"#);
    }

    #[test]
    fn short_buffers_are_refused() {
        let mut tiny = [0u8; 8];
        assert_eq!(
            seal(&[1u8; 32], &[2u8; 32], &[0u8; NONCE_LEN], b"x", &mut tiny).err(),
            Some(DerpError::ShortBuffer)
        );
    }
}
