//! Cross-implementation interop against boringtun.
//!
//! The unit tests in `wireguard::handshake` round-trip our initiator against
//! our own responder. That proves self-consistency and nothing more: every KDF,
//! DH ordering and hash-mixing detail could be uniformly wrong and those tests
//! would still pass.
//!
//! These tests run the handshake against boringtun — Cloudflare's independent
//! Rust implementation of WireGuard — so agreement here means the wire format
//! is genuinely correct rather than merely self-consistent. boringtun is a
//! dev-dependency only and never reaches the firmware build.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use tailscale_core::key::{NodePrivate, NodePublic};
use tailscale_core::wireguard::handshake::{Initiator, Responder};
use tailscale_core::wireguard::transport::Session;
use tailscale_core::wireguard::Tai64n;

/// A minimal well-formed IPv4 packet, so boringtun's tunnel-side parsing has
/// something valid to hand back.
fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45; // version 4, IHL 5
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[100, 64, 0, 1]);
    p[16..20].copy_from_slice(&[100, 64, 0, 2]);
    p[20..].copy_from_slice(payload);
    p
}

fn boringtun_peer(own: &NodePrivate, peer_pub: &NodePublic, index: u32) -> Tunn {
    Tunn::new(
        StaticSecret::from(*own.as_bytes()),
        PublicKey::from(*peer_pub.as_bytes()),
        None,
        None,
        index,
        None,
    )
}

/// Our initiator against boringtun's responder.
#[test]
fn our_initiation_is_accepted_by_boringtun() {
    let ours = NodePrivate::from_bytes([11u8; 32]);
    let theirs = NodePrivate::from_bytes([22u8; 32]);
    let ephemeral = NodePrivate::from_bytes([33u8; 32]);

    let mut peer = boringtun_peer(&theirs, &ours.public(), 0x5555);

    let (initiator, initiation) = Initiator::new(
        &ours,
        &theirs.public(),
        ephemeral,
        0x1234_5678,
        Tai64n::from_counter(42),
    )
    .expect("build initiation");

    // boringtun must recognise our initiation and answer it.
    let mut out = vec![0u8; 2048];
    let response = match peer.decapsulate(None, &initiation, &mut out) {
        TunnResult::WriteToNetwork(r) => r.to_vec(),
        other => panic!("boringtun rejected our initiation: {other:?}"),
    };

    let keys = initiator
        .consume_response(&response)
        .expect("boringtun's response must complete our handshake");

    // Both sides now hold session keys. Prove they actually match by sending a
    // transport packet through boringtun and reading it back out.
    let mut session = Session::new(&keys);
    let payload = ipv4_packet(b"lando->wg");
    let mut packet = vec![0u8; 2048];
    let n = session.encrypt(&payload, &mut packet).expect("encrypt");

    let mut plain = vec![0u8; 2048];
    match peer.decapsulate(None, &packet[..n], &mut plain) {
        TunnResult::WriteToTunnelV4(got, _) => {
            assert_eq!(&got[..payload.len()], &payload[..]);
        }
        other => panic!("boringtun could not decrypt our transport packet: {other:?}"),
    }
}

/// boringtun's initiator against our responder — the reverse direction, which
/// is the one that matters for a device peers dial into.
#[test]
fn boringtun_initiation_is_accepted_by_us() {
    let ours = NodePrivate::from_bytes([44u8; 32]);
    let theirs = NodePrivate::from_bytes([55u8; 32]);
    let ephemeral = NodePrivate::from_bytes([66u8; 32]);

    let mut peer = boringtun_peer(&theirs, &ours.public(), 0x7777);

    // Ask boringtun to start a handshake addressed to us.
    let mut out = vec![0u8; 2048];
    let initiation = match peer.format_handshake_initiation(&mut out, false) {
        TunnResult::WriteToNetwork(m) => m.to_vec(),
        other => panic!("boringtun would not start a handshake: {other:?}"),
    };

    let (responder, learned) =
        Responder::consume_initiation(&ours, &initiation).expect("accept boringtun's initiation");
    assert_eq!(
        learned.peer_static,
        theirs.public(),
        "we must recover boringtun's static key from the encrypted field"
    );

    let (response, keys) = responder.respond(ephemeral, 0x9999).expect("respond");

    let mut plain = vec![0u8; 2048];
    match peer.decapsulate(None, &response, &mut plain) {
        // An accepted response yields either nothing to send or a keepalive.
        TunnResult::Done | TunnResult::WriteToNetwork(_) => {}
        other => panic!("boringtun rejected our handshake response: {other:?}"),
    }

    // boringtun now sends us a transport packet; we must be able to read it.
    let payload = ipv4_packet(b"wg->lando");
    let mut packet = vec![0u8; 2048];
    let encrypted = match peer.encapsulate(&payload, &mut packet) {
        TunnResult::WriteToNetwork(m) => m.to_vec(),
        other => panic!("boringtun would not encapsulate: {other:?}"),
    };

    let mut session = Session::new(&keys);
    let mut buf = encrypted.clone();
    let got = session
        .decrypt(&mut buf)
        .expect("decrypt boringtun's transport packet");
    assert_eq!(&got[..payload.len()], &payload[..]);
}
