//! disco — endpoint discovery.
//!
//! This is not the latency optimisation it looks like. A peer probes a
//! candidate endpoint with a disco ping and will not send WireGuard there
//! until it gets a pong, so a node that cannot answer disco is unreachable on
//! every direct path regardless of what its netmap advertises. The symptom is
//! total silence: the peer reports a timeout and the target never sees a
//! packet.
//!
//! Messages travel as cleartext header plus a NaCl box:
//!
//! ```text
//! magic  [6]  "TS" + U+1F4AC
//! sender [32] the sender's disco public key
//! nonce  [24]
//! box    [..] tag ‖ ciphertext, keyed by the two disco keys
//! ```
//!
//! Note the nonce sits in the *header* here, unlike the DERP handshake where
//! it is carried inside the sealed blob — same primitive, different framing.

use crypto_box::aead::AeadInPlace;
use crypto_box::{PublicKey, SalsaBox, SecretKey};

use crate::key::{DiscoPublic, NodePublic, KEY_LEN};

/// `TS` followed by U+1F4AC, six bytes on the wire.
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// magic + sender key + nonce.
pub const HEADER_LEN: usize = MAGIC.len() + KEY_LEN + NONCE_LEN;

pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_CALL_ME_MAYBE: u8 = 0x03;

/// Message version. Receivers must ignore trailing bytes, so a newer sender
/// stays readable.
const V0: u8 = 0;

/// `TxID` + 16-byte v4-mapped address + big-endian port.
const PONG_BODY: usize = 12 + 16 + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoError {
    NotDisco,
    Crypto,
    Malformed,
    ShortBuffer,
}

/// The cleartext part of a disco packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub sender: DiscoPublic,
    pub nonce: [u8; NONCE_LEN],
}

/// A ping we are expected to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    /// Echoed back verbatim; it is how the peer matches pong to ping.
    pub tx_id: [u8; 12],
    /// Present on modern senders, absent on old ones.
    pub node_key: Option<NodePublic>,
}

/// Splits the cleartext header from the sealed remainder.
///
/// Returns `NotDisco` for anything without the magic, so callers can pass
/// every inbound UDP packet through and let WireGuard have the rest.
pub fn parse_header(packet: &[u8]) -> Result<(Header, &[u8]), DiscoError> {
    if packet.len() < HEADER_LEN || packet[..MAGIC.len()] != MAGIC {
        return Err(DiscoError::NotDisco);
    }
    let mut sender = [0u8; KEY_LEN];
    sender.copy_from_slice(&packet[MAGIC.len()..MAGIC.len() + KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&packet[MAGIC.len() + KEY_LEN..HEADER_LEN]);
    Ok((
        Header {
            sender: DiscoPublic(sender),
            nonce,
        },
        &packet[HEADER_LEN..],
    ))
}

fn boxer(secret: &[u8; KEY_LEN], peer: &DiscoPublic) -> SalsaBox {
    SalsaBox::new(&PublicKey::from(peer.0), &SecretKey::from(*secret))
}

/// Opens a sealed disco payload into `out`, returning the plaintext length.
///
/// NaCl puts the tag before the ciphertext, which is the opposite of the
/// RustCrypto AEAD convention, so the split is done explicitly.
pub fn open<'a>(
    our_disco_secret: &[u8; KEY_LEN],
    header: &Header,
    sealed: &[u8],
    out: &'a mut [u8],
) -> Result<&'a [u8], DiscoError> {
    if sealed.len() < TAG_LEN {
        return Err(DiscoError::Malformed);
    }
    let body = sealed.len() - TAG_LEN;
    if out.len() < body {
        return Err(DiscoError::ShortBuffer);
    }
    let (tag, ciphertext) = sealed.split_at(TAG_LEN);
    out[..body].copy_from_slice(ciphertext);
    boxer(our_disco_secret, &header.sender)
        .decrypt_in_place_detached(
            (&header.nonce).into(),
            &[],
            &mut out[..body],
            tag.into(),
        )
        .map_err(|_| DiscoError::Crypto)?;
    Ok(&out[..body])
}

/// Interprets an opened payload as a ping.
pub fn parse_ping(plaintext: &[u8]) -> Result<Ping, DiscoError> {
    // type, version, then the body. Trailing bytes are ignored on purpose.
    if plaintext.len() < 2 + 12 || plaintext[0] != TYPE_PING {
        return Err(DiscoError::Malformed);
    }
    let body = &plaintext[2..];
    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&body[..12]);
    let node_key = if body.len() >= 12 + KEY_LEN {
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&body[12..12 + KEY_LEN]);
        Some(NodePublic(k))
    } else {
        None
    };
    Ok(Ping { tx_id, node_key })
}

/// Builds a complete pong packet — header and sealed body — into `out`.
///
/// `src` is the address the ping arrived *from*, which is the whole point of
/// the exchange: it tells the peer which of its candidate endpoints actually
/// works.
pub fn write_pong(
    our_disco_secret: &[u8; KEY_LEN],
    our_disco_public: &DiscoPublic,
    peer: &DiscoPublic,
    nonce: &[u8; NONCE_LEN],
    tx_id: &[u8; 12],
    src_ip: [u8; 4],
    src_port: u16,
    out: &mut [u8],
) -> Result<usize, DiscoError> {
    let total = HEADER_LEN + TAG_LEN + 2 + PONG_BODY;
    if out.len() < total {
        return Err(DiscoError::ShortBuffer);
    }

    out[..MAGIC.len()].copy_from_slice(&MAGIC);
    out[MAGIC.len()..MAGIC.len() + KEY_LEN].copy_from_slice(&our_disco_public.0);
    out[MAGIC.len() + KEY_LEN..HEADER_LEN].copy_from_slice(nonce);

    // Body is built after the tag slot, then the tag is written in front.
    let body_at = HEADER_LEN + TAG_LEN;
    out[body_at] = TYPE_PONG;
    out[body_at + 1] = V0;
    let p = body_at + 2;
    out[p..p + 12].copy_from_slice(tx_id);
    // Addresses go on the wire as 16 bytes; IPv4 is v4-mapped IPv6.
    out[p + 12..p + 24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    out[p + 24..p + 28].copy_from_slice(&src_ip);
    out[p + 28..p + 30].copy_from_slice(&src_port.to_be_bytes());

    let tag = boxer(our_disco_secret, peer)
        .encrypt_in_place_detached(nonce.into(), &[], &mut out[body_at..total])
        .map_err(|_| DiscoError::Crypto)?;
    out[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(&tag);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DiscoPrivate;

    fn keys() -> ([u8; 32], DiscoPublic, [u8; 32], DiscoPublic) {
        let a = [3u8; 32];
        let b = [4u8; 32];
        (
            a,
            DiscoPrivate::from_bytes(a).public(),
            b,
            DiscoPrivate::from_bytes(b).public(),
        )
    }

    /// Builds the packet a peer would send us.
    fn make_ping(
        sender_secret: &[u8; 32],
        sender_public: &DiscoPublic,
        recipient: &DiscoPublic,
        tx_id: [u8; 12],
        out: &mut [u8],
    ) -> usize {
        out[..MAGIC.len()].copy_from_slice(&MAGIC);
        out[MAGIC.len()..MAGIC.len() + 32].copy_from_slice(&sender_public.0);
        let nonce = [7u8; NONCE_LEN];
        out[MAGIC.len() + 32..HEADER_LEN].copy_from_slice(&nonce);

        let body_at = HEADER_LEN + TAG_LEN;
        out[body_at] = TYPE_PING;
        out[body_at + 1] = V0;
        out[body_at + 2..body_at + 14].copy_from_slice(&tx_id);
        let total = body_at + 14;
        let tag = super::boxer(sender_secret, recipient)
            .encrypt_in_place_detached((&nonce).into(), &[], &mut out[body_at..total])
            .unwrap();
        out[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(&tag);
        total
    }

    #[test]
    fn header_is_sixty_two_bytes() {
        assert_eq!(HEADER_LEN, 62);
        assert_eq!(MAGIC.len(), 6);
    }

    /// Anything without the magic must be handed back so the caller can treat
    /// it as WireGuard, which shares the same UDP socket.
    #[test]
    fn non_disco_packets_are_rejected_cleanly() {
        assert_eq!(parse_header(&[1u8; 148]).err(), Some(DiscoError::NotDisco));
        assert_eq!(parse_header(&[]).err(), Some(DiscoError::NotDisco));
    }

    #[test]
    fn opens_and_parses_a_ping() {
        let (a_sec, a_pub, b_sec, b_pub) = keys();
        let mut packet = [0u8; 256];
        let n = make_ping(&a_sec, &a_pub, &b_pub, [9u8; 12], &mut packet);

        let (header, sealed) = parse_header(&packet[..n]).unwrap();
        assert_eq!(header.sender, a_pub);

        let mut scratch = [0u8; 128];
        let plain = open(&b_sec, &header, sealed, &mut scratch).unwrap();
        let ping = parse_ping(plain).unwrap();
        assert_eq!(ping.tx_id, [9u8; 12]);
    }

    #[test]
    fn a_tampered_ping_does_not_open() {
        let (a_sec, a_pub, b_sec, b_pub) = keys();
        let mut packet = [0u8; 256];
        let n = make_ping(&a_sec, &a_pub, &b_pub, [1u8; 12], &mut packet);
        packet[HEADER_LEN + TAG_LEN + 3] ^= 0x01;
        let (header, sealed) = parse_header(&packet[..n]).unwrap();
        let mut scratch = [0u8; 128];
        assert_eq!(
            open(&b_sec, &header, sealed, &mut scratch).err(),
            Some(DiscoError::Crypto)
        );
    }

    /// The pong must be openable by the peer that sent the ping, and must
    /// echo the transaction id — that is how the peer matches the reply.
    #[test]
    fn pong_round_trips_to_the_pinger() {
        let (a_sec, a_pub, b_sec, b_pub) = keys();
        let tx = [5u8; 12];

        let mut out = [0u8; 256];
        let n = write_pong(
            &b_sec,
            &b_pub,
            &a_pub,
            &[2u8; NONCE_LEN],
            &tx,
            [192, 168, 1, 9],
            41641,
            &mut out,
        )
        .unwrap();

        let (header, sealed) = parse_header(&out[..n]).unwrap();
        assert_eq!(header.sender, b_pub);

        let mut scratch = [0u8; 128];
        let plain = open(&a_sec, &header, sealed, &mut scratch).unwrap();
        assert_eq!(plain[0], TYPE_PONG);
        assert_eq!(&plain[2..14], &tx[..], "transaction id echoed");
        // v4-mapped IPv6, then the port big-endian.
        assert_eq!(&plain[14..26], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&plain[26..30], &[192, 168, 1, 9]);
        assert_eq!(u16::from_be_bytes([plain[30], plain[31]]), 41641);
    }

    #[test]
    fn refuses_a_short_buffer() {
        let (_, a_pub, b_sec, b_pub) = keys();
        let mut tiny = [0u8; 16];
        assert_eq!(
            write_pong(
                &b_sec, &b_pub, &a_pub, &[0u8; NONCE_LEN], &[0u8; 12],
                [0, 0, 0, 0], 0, &mut tiny
            )
            .err(),
            Some(DiscoError::ShortBuffer)
        );
    }
}
