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
use tailscale_core::tsmp;
use tailscale_core::wireguard::handshake::Responder;
use tailscale_core::wireguard::peer::Instant;
use tailscale_core::wireguard::{Peer, Session, MSG_INITIATION, MSG_RESPONSE, MSG_TRANSPORT};

use crate::derp::{DerpClient, Event};
use crate::state::hex;
use crate::tunnel::TunnelStack;

/// Port the SOCKS5 proxy listens on inside the tunnel.
pub const SOCKS_PORT: u16 = 1080;
/// Concurrent tunnel connections. smoltcp has no accept queue, so this is a
/// fixed pool and therefore a hard concurrency limit.
const SOCKET_POOL: usize = 4;

/// Peers the control plane has told us about, shared with the map-poll thread.
pub type PeerSet = Arc<Mutex<Vec<NodePublic>>>;

/// Sessions in flight, keyed by the peer's node key.
struct Sessions {
    peers: HashMap<[u8; 32], Peer>,
    sessions: HashMap<[u8; 32], Session>,
    /// Our chosen index for each peer, so inbound transport packets demux.
    next_index: u32,
    /// The TCP stack inside the tunnel, created once our own tunnel address is
    /// known. That address is learned from the destination of the first packet
    /// a peer sends us, which avoids threading netmap state down here and is
    /// correct even for a node holding several addresses.
    stack: Option<TunnelStack>,
    /// Peer the tunnel stack's traffic belongs to. Single-peer for now: with
    /// several, outbound packets would be routed by destination address
    /// against each peer's allowed IPs.
    tunnel_peer: Option<[u8; 32]>,
}

impl Sessions {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            sessions: HashMap::new(),
            next_index: 1,
            stack: None,
            tunnel_peer: None,
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
        // A tick with no event still advances the TCP stack, which is what
        // moves a LAN reply back into the tunnel.
        let event = client.next_event()?;
        let now = now_millis(started);
        match event {
            None => drain_stack(&mut client, &mut state, now)?,
            Some(Event::Packet { src, data }) => {
                if let Err(e) = handle_packet(
                    &mut client,
                    &mut state,
                    node_key,
                    &src,
                    &data,
                    &known_peers,
                    now,
                ) {
                    println!("  [{}] {e}", hex(&src[..6]));
                }
            }
            Some(Event::PeerPresent(k)) => println!("  peer present: {}", hex(&k[..6])),
            Some(Event::PeerGone(k)) => println!("  peer gone   : {}", hex(&k[..6])),
            Some(Event::KeepAlive) => {}
            Some(Event::Other(kind)) => println!("  relay frame : {kind:?}"),
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

            // `tailscale ping` speaks TSMP rather than ICMP, so answering it is
            // what makes the node reachable to the standard tooling. Copied out
            // because the reply is encrypted with the same session that owns
            // the plaintext borrow.
            // Hand anything that is not TSMP to the TCP stack. Copied out of
            // the session buffer because replies re-borrow the same session.
            let inbound = plain.to_vec();
            let ping = tsmp::parse_ping(plain);
            if ping.is_none() {
                feed_stack(client, state, src, &inbound, now)?;
                return Ok(());
            }
            if let Some(ping) = ping {
                let mut pong = [0u8; 64];
                let n = tsmp::write_pong(&ping, &mut pong)
                    .ok_or_else(|| "pong buffer too small".to_string())?;
                let mut packet = [0u8; 256];
                let sent = session
                    .encrypt(&pong[..n], &mut packet)
                    .map_err(|e| format!("encrypting pong: {e:?}"))?;
                client.send_packet(src, &packet[..sent])?;
                println!("  -> TSMP pong");
            }
            Ok(())
        }
        other => Err(format!("unhandled WireGuard message type {other}")),
    }
}

/// Runs one turn of the TCP stack for a packet that arrived in the tunnel,
/// then relays whatever the stack wants to send back.
fn feed_stack(
    client: &mut DerpClient,
    state: &mut Sessions,
    src: &[u8; 32],
    packet: &[u8],
    now: Instant,
) -> Result<(), String> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Ok(());
    }
    if state.stack.is_none() {
        let addr = smoltcp::wire::Ipv4Address::new(packet[16], packet[17], packet[18], packet[19]);
        println!("  ** tunnel stack listening on {addr}:{SOCKS_PORT}");
        state.stack = Some(TunnelStack::new(addr, SOCKS_PORT, SOCKET_POOL));
    }
    state.tunnel_peer = Some(*src);
    let stack = state.stack.as_mut().expect("just created");
    stack.device.push_inbound(packet);
    drain_stack(client, state, now)
}

/// Advances the TCP stack and relays whatever it wants to send.
///
/// Runs on every tick as well as on inbound packets, because a LAN reply
/// arrives with no corresponding tunnel packet to trigger it.
fn drain_stack(
    client: &mut DerpClient,
    state: &mut Sessions,
    now: Instant,
) -> Result<(), String> {
    let (Some(stack), Some(peer)) = (state.stack.as_mut(), state.tunnel_peer) else {
        return Ok(());
    };
    stack.poll(now as i64);
    stack.serve();
    stack.poll(now as i64);
    stack.relisten(SOCKS_PORT);

    let mut pending = Vec::new();
    while let Some(out) = stack.device.pop_outbound() {
        pending.push(out);
    }
    if pending.is_empty() {
        return Ok(());
    }
    let session = state
        .sessions
        .get_mut(&peer)
        .ok_or_else(|| "no session for stack output".to_string())?;
    for out in pending {
        let mut packet = vec![0u8; out.len() + 64];
        let n = session
            .encrypt(&out, &mut packet)
            .map_err(|e| format!("encrypting tunnel packet: {e:?}"))?;
        client.send_packet(&peer, &packet[..n])?;
    }
    Ok(())
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
