//! WireGuard, on embassy.
//!
//! Answers handshakes and carries tunnel traffic. Two transports reach this
//! code: a plain UDP socket, which only works for peers with a path to this
//! device, and DERP, which is what a NAT'd device needs. Both feed the same
//! [`Node`], because the peer state is one state machine no matter which way
//! the bytes arrived — a session established over UDP has to stay usable when
//! the peer later reaches us through a relay.
//!
//! Every protocol decision is `tailscale-core`'s. What lives here is the
//! socket, the buffers, and the per-peer table.

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::Stack;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use core::cell::RefCell;

use tailscale_core::disco;
use tailscale_core::key::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};
use tailscale_core::tsmp;
use tailscale_core::wireguard::handshake::Responder;
use tailscale_core::wireguard::{Session, MSG_INITIATION, MSG_TRANSPORT};

use crate::logln;

/// Port we listen on. 41641 is Tailscale's default, so a peer that guesses an
/// endpoint without being told still finds us.
pub const PORT: u16 = 41641;

/// Shared node state. Blocking rather than async because [`Node::handle`] does
/// no I/O: it takes a packet and returns a reply, leaving the sending to
/// whichever transport called it. Nothing is held across an await.
pub type Shared = Mutex<CriticalSectionRawMutex, RefCell<Node>>;

/// What handling a packet produced.
pub enum Action {
    /// Ciphertext to send straight back the way the packet came.
    Reply(usize),
    /// A decrypted IP packet addressed to the LAN, for the tunnel to route.
    Deliver(usize),
}

/// Where a packet came from, and so where its reply must go.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Arrived directly on the UDP socket.
    Udp(embassy_net::IpEndpoint),
    /// Relayed, from the peer holding this node key.
    Derp([u8; 32]),
}

/// One peer we have a session with. Single-entry for now: this device exists
/// to be reached by one controller, and a table costs RAM per entry.
struct PeerSlot {
    key: NodePublic,
    session: Session,
    source: Source,
}

/// The WireGuard responder, independent of how packets reach it.
pub struct Node {
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    disco_public: DiscoPublic,
    /// Nonces must never repeat for a key. A counter seeded from the TRNG is
    /// sufficient here and costs nothing to carry.
    nonce: [u8; disco::NONCE_LEN],
    peer: Option<PeerSlot>,
    next_index: u32,
}

impl Node {
    pub fn new(node_key: &NodePrivate, disco_key: &DiscoPrivate, index_seed: u32) -> Self {
        let mut nonce = [0u8; disco::NONCE_LEN];
        nonce[..4].copy_from_slice(&index_seed.to_le_bytes());
        Self {
            node_key: node_key.clone(),
            disco_key: disco_key.clone(),
            disco_public: disco_key.public(),
            nonce,
            peer: None,
            next_index: index_seed | 1,
        }
    }

    /// Handles one inbound packet, writing any reply into `out`.
    ///
    /// Deliberately synchronous: the caller owns the transport, so the same
    /// logic serves UDP and DERP without either being able to block the other.
    pub fn handle(&mut self, packet: &[u8], from: Source, out: &mut [u8]) -> Option<Action> {
        // disco and WireGuard share a transport; the magic tells them apart.
        // Answering disco is what makes a peer willing to send WireGuard here
        // at all -- without a pong it never validates the endpoint.
        if let Ok((header, sealed)) = disco::parse_header(packet) {
            let mut scratch = [0u8; 256];
            let plain = disco::open(self.disco_key.as_bytes(), &header, sealed, &mut scratch).ok()?;
            let ping = disco::parse_ping(plain).ok()?;
            // The pong echoes the address we saw the ping arrive from. Over a
            // relay there is no such address, so report the placeholder the
            // rest of Tailscale uses to mean "via relay region N" — telling a
            // peer its address is 0.0.0.0 would be worse than telling it
            // nothing.
            let (src, port) = match from {
                Source::Udp(ep) => {
                    let embassy_net::IpAddress::Ipv4(v4) = ep.addr;
                    (v4.octets(), ep.port)
                }
                Source::Derp(_) => ([127, 3, 3, 40], crate::DERP_REGION as u16),
            };
            // Bump before use so no two pongs share a nonce.
            bump(&mut self.nonce);
            let len = disco::write_pong(
                self.disco_key.as_bytes(),
                &self.disco_public,
                &header.sender,
                &self.nonce,
                &ping.tx_id,
                src,
                port,
                out,
            )
            .ok()?;
            logln!("disco: ping answered, endpoint validated");
            return Some(Action::Reply(len));
        }

        match *packet.first()? {
            MSG_INITIATION => {
                let (responder, learned) =
                    Responder::consume_initiation(&self.node_key, packet).ok()?;
                let index = self.next_index;
                self.next_index = self.next_index.wrapping_add(2).max(1);

                // A fresh ephemeral per handshake; reuse would cost forward
                // secrecy for the whole session.
                let mut seed = [0u8; 32];
                seed[..4].copy_from_slice(&index.to_le_bytes());
                seed[4..8].copy_from_slice(&(packet.len() as u32).to_le_bytes());
                let ephemeral = NodePrivate::from_bytes(seed);

                let (response, keys) = responder.respond(ephemeral, index).ok()?;
                out.get_mut(..response.len())?.copy_from_slice(&response);
                logln!("wg: session established with a peer (index {})", index);
                self.peer = Some(PeerSlot {
                    key: learned.peer_static,
                    session: Session::new(&keys),
                    source: from,
                });
                Some(Action::Reply(response.len()))
            }
            MSG_TRANSPORT => {
                let slot = self.peer.as_mut()?;
                // A peer that moved between transports keeps its session; only
                // the return path changes.
                slot.source = from;
                let mut buf = [0u8; 1600];
                buf.get_mut(..packet.len())?.copy_from_slice(packet);
                let plain = slot.session.decrypt(&mut buf[..packet.len()]).ok()?;

                // `tailscale ping` speaks TSMP, so answering it is what makes
                // the node visibly reachable to the standard tooling.
                if let Some(ping) = tsmp::parse_ping(plain) {
                    let mut pong = [0u8; 64];
                    let len = tsmp::write_pong(&ping, &mut pong)?;
                    let sent = slot.session.encrypt(&pong[..len], out).ok()?;
                    let _ = slot.key;
                    logln!("wg: TSMP ping answered");
                    return Some(Action::Reply(sent));
                }
                // Anything else is traffic for the LAN. Copied out because the
                // caller owns the tunnel and this borrow ends here.
                let len = plain.len();
                out.get_mut(..len)?.copy_from_slice(plain);
                Some(Action::Deliver(len))
            }
            _ => None,
        }
    }
    /// Encrypts a packet from the tunnel for the peer, reporting where to send
    /// it. `None` when there is no session, which is the normal state until a
    /// peer has handshaked.
    pub fn encrypt(&mut self, packet: &[u8], out: &mut [u8]) -> Option<(usize, Source)> {
        let slot = self.peer.as_mut()?;
        let n = slot.session.encrypt(packet, out).ok()?;
        Some((n, slot.source))
    }
}

/// Serves WireGuard over UDP until the socket fails.
pub async fn serve(stack: Stack<'static>, node: &Shared, tunnel: &crate::TunnelShared) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 8];
    let mut rx_buf = [0u8; 2048];
    let mut tx_meta = [PacketMetadata::EMPTY; 8];
    let mut tx_buf = [0u8; 2048];
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);

    if socket.bind(PORT).is_err() {
        logln!("wg: could not bind udp {}", PORT);
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_secs(60)).await;
        }
    }
    logln!("wg: listening on udp {}", PORT);

    let mut packet = [0u8; 1600];
    let mut out = [0u8; 1600];
    loop {
        // Waking on a timer as well as on a packet, because this loop owns the
        // only send path: the tunnel produces replies on its own schedule, and
        // draining them only when something else happens to arrive means a
        // SYN-ACK can sit queued until unrelated traffic shakes it loose.
        let arrival = embassy_futures::select::select(
            socket.recv_from(&mut packet),
            embassy_time::Timer::after(embassy_time::Duration::from_millis(5)),
        )
        .await;

        if let embassy_futures::select::Either::First(Ok((n, meta))) = arrival {
            let action = node.lock(|n2| {
                n2.borrow_mut()
                    .handle(&packet[..n], Source::Udp(meta.endpoint), &mut out)
            });
            match action {
                Some(Action::Reply(len)) => {
                    let _ = socket.send_to(&out[..len], meta.endpoint).await;
                }
                Some(Action::Deliver(len)) => {
                    tunnel.lock(|t| t.borrow_mut().deliver(&out[..len]));
                }
                None => {}
            }
        }

        // Drain whatever the tunnel produced in response. Done here rather
        // than in the tunnel task because this is where the peer's session
        // lives, and only one place may hold the nonce counter.
        loop {
            let Some(packet) = tunnel.lock(|t| t.borrow_mut().take_outbound()) else {
                break;
            };
            let mut cipher = [0u8; 1600];
            let Some((len, source)) = node.lock(|n2| n2.borrow_mut().encrypt(&packet, &mut cipher))
            else {
                break;
            };
            match source {
                Source::Udp(ep) => {
                    let _ = socket.send_to(&cipher[..len], ep).await;
                }
                // Reached through the relay, which another task owns.
                Source::Derp(_) => {
                    let _ = DERP_OUT.try_send(Relayed::new(&cipher[..len]));
                }
            }
        }
    }
}

/// Packets bound for a peer that is reached through the relay.
///
/// A channel rather than a direct call because the relay connection is owned
/// by its own task: it has to keep reading frames while this side is writing,
/// and sharing the TLS connection between them would mean interleaving reads
/// and writes on one buffer.
pub static DERP_OUT: embassy_sync::channel::Channel<CriticalSectionRawMutex, Relayed, 2> =
    embassy_sync::channel::Channel::new();

/// One packet on its way to the relay.
pub struct Relayed {
    buf: [u8; 1600],
    len: usize,
}

impl Relayed {
    fn new(packet: &[u8]) -> Self {
        let mut buf = [0u8; 1600];
        let len = packet.len().min(buf.len());
        buf[..len].copy_from_slice(&packet[..len]);
        Self { buf, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Increments a nonce, treated as a little-endian counter.
fn bump(nonce: &mut [u8; disco::NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}
