//! The datapath: WireGuard carried over a DERP relay.
//!
//! This is where the three protocols meet. The control plane keeps the node
//! online and supplies the peer list, the relay carries packets in and out,
//! and WireGuard secures them end to end — the relay only ever sees ciphertext.
//!
//! As responder we learn a peer's identity from its handshake initiation
//! itself, so answering does not require the netmap. The netmap is still
//! consulted, but as an authorisation check rather than a prerequisite: a
//! handshake from a key the control plane never mentioned is refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tailscale_core::key::{NodePrivate, NodePublic};
use tailscale_core::wireguard::handshake::Responder;
use tailscale_core::wireguard::peer::Instant;
use tailscale_core::wireguard::{Peer, Session, MSG_INITIATION, MSG_RESPONSE, MSG_TRANSPORT};

use crate::derp::{DerpClient, Event};
use crate::state::hex;

/// Peers the control plane has told us about, shared with the map-poll thread.
pub type PeerSet = Arc<Mutex<Vec<NodePublic>>>;

/// Sessions in flight, keyed by the peer's node key.
struct Sessions {
    peers: HashMap<[u8; 32], Peer>,
    sessions: HashMap<[u8; 32], Session>,
    /// Our chosen index for each peer, so inbound transport packets demux.
    next_index: u32,
}

impl Sessions {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            sessions: HashMap::new(),
            next_index: 1,
        }
    }

    fn take_index(&mut self) -> u32 {
        let i = self.next_index;
        self.next_index = self.next_index.wrapping_add(1).max(1);
        i
    }
}

fn now_millis(start: std::time::Instant) -> Instant {
    start.elapsed().as_millis() as u64
}

/// Runs the relay datapath until the connection drops.
pub fn run(
    relay: &str,
    node_key: &NodePrivate,
    known_peers: PeerSet,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    let public = node_key.public();

    println!("relay        : {relay}:443");
    let mut client = DerpClient::connect(relay, node_key.as_bytes(), public.as_bytes())?;
    println!("derp         : connected, server {}", hex(&client.server_key()[..8]));
    println!();
    println!("Waiting for WireGuard traffic over the relay...");

    let mut state = Sessions::new();

    loop {
        match client.next_event()? {
            Event::Packet { src, data } => {
                if let Err(e) = handle_packet(
                    &mut client,
                    &mut state,
                    node_key,
                    &src,
                    &data,
                    &known_peers,
                    now_millis(started),
                ) {
                    println!("  [{}] {e}", hex(&src[..6]));
                }
            }
            Event::PeerPresent(k) => println!("  peer present: {}", hex(&k[..6])),
            Event::PeerGone(k) => println!("  peer gone   : {}", hex(&k[..6])),
            Event::KeepAlive => {}
            Event::Other(kind) => println!("  relay frame : {kind:?}"),
        }
    }
}

fn handle_packet(
    client: &mut DerpClient,
    state: &mut Sessions,
    node_key: &NodePrivate,
    src: &[u8; 32],
    data: &[u8],
    known_peers: &PeerSet,
    now: Instant,
) -> Result<(), String> {
    let Some(&kind) = data.first() else {
        return Err("empty relayed packet".into());
    };
    match kind {
        MSG_INITIATION => {
            // The control plane is the authority on who may talk to us. A
            // handshake is cheap to answer but a session is not, and an
            // unlisted key has no business establishing one.
            let authorised = {
                let peers = known_peers.lock().unwrap();
                peers.is_empty() || peers.iter().any(|p| p.as_bytes() == src)
            };
            if !authorised {
                return Err(format!(
                    "refusing handshake from {} — not in the netmap",
                    hex(&src[..8])
                ));
            }

            let (responder, learned) = Responder::consume_initiation(node_key, data)
                .map_err(|e| format!("bad initiation: {e:?}"))?;
            println!(
                "  <- handshake initiation from {}",
                hex(&learned.peer_static.as_bytes()[..8])
            );

            let peer = state
                .peers
                .entry(*learned.peer_static.as_bytes())
                .or_insert_with(|| Peer::new(learned.peer_static));
            peer.accept_handshake_timestamp(learned.timestamp)
                .map_err(|e| format!("replayed handshake: {e:?}"))?;

            let index = state.take_index();
            let ephemeral = NodePrivate::generate(&mut rand_core::OsRng);
            let (response, keys) = responder
                .respond(ephemeral, index)
                .map_err(|e| format!("building response: {e:?}"))?;

            client.send_packet(src, &response)?;
            println!("  -> handshake response (index {index})");

            let peer = state.peers.get_mut(learned.peer_static.as_bytes()).unwrap();
            peer.install_session(&keys, now, false);
            state
                .sessions
                .insert(*learned.peer_static.as_bytes(), Session::new(&keys));
            println!("  ** session established with {}", hex(&src[..8]));
            Ok(())
        }
        MSG_RESPONSE => {
            println!("  <- handshake response (we did not initiate; ignoring)");
            Ok(())
        }
        MSG_TRANSPORT => {
            let session = state
                .sessions
                .get_mut(src)
                .ok_or_else(|| "transport packet with no session".to_string())?;
            let mut buf = data.to_vec();
            let plain = session
                .decrypt(&mut buf)
                .map_err(|e| format!("decrypt failed: {e:?}"))?;
            describe_inner(plain);
            Ok(())
        }
        other => Err(format!("unhandled WireGuard message type {other}")),
    }
}

/// Reports what arrived inside the tunnel, enough to tell a keepalive from
/// real traffic.
fn describe_inner(plain: &[u8]) {
    if plain.iter().all(|&b| b == 0) {
        println!("  <- keepalive ({} bytes)", plain.len());
        return;
    }
    match plain.first().map(|b| b >> 4) {
        Some(4) if plain.len() >= 20 => {
            let proto = plain[9];
            let src = &plain[12..16];
            let dst = &plain[16..20];
            println!(
                "  <- IPv4 proto {proto} {}.{}.{}.{} -> {}.{}.{}.{} ({} bytes)",
                src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], plain.len()
            );
        }
        Some(6) => println!("  <- IPv6 packet ({} bytes)", plain.len()),
        _ => println!("  <- {} bytes inside the tunnel", plain.len()),
    }
}
