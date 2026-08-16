//! WireGuard over UDP, on embassy.
//!
//! Answers handshakes and carries tunnel traffic on a plain UDP socket. That
//! only reaches peers with a path to this device — on a LAN, or through a port
//! forward — and a NAT'd device needs DERP instead. The direct path is worth
//! having first regardless: it is the cheapest way to be reachable, and it
//! requires no TLS stack at all.
//!
//! Every protocol decision is `tailscale-core`'s. What lives here is the
//! socket, the buffers, and the per-peer table.

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::Stack;

use tailscale_core::key::{NodePrivate, NodePublic};
use tailscale_core::tsmp;
use tailscale_core::wireguard::handshake::Responder;
use tailscale_core::wireguard::{Session, MSG_INITIATION, MSG_TRANSPORT};

use crate::logln;

/// Port we listen on. 41641 is Tailscale's default, so a peer that guesses an
/// endpoint without being told still finds us.
pub const PORT: u16 = 41641;

/// One peer we have a session with. Single-entry for now: this device exists
/// to be reached by one controller, and a table costs RAM per entry.
struct PeerSlot {
    key: NodePublic,
    session: Session,
    endpoint: (embassy_net::IpAddress, u16),
}

/// Serves WireGuard until the socket fails.
pub async fn serve(stack: Stack<'static>, node_key: &NodePrivate, index_seed: u32) -> ! {
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

    let mut peer: Option<PeerSlot> = None;
    let mut next_index = index_seed | 1;
    let mut packet = [0u8; 1600];

    loop {
        let Ok((n, meta)) = socket.recv_from(&mut packet).await else {
            continue;
        };
        let from = (meta.endpoint.addr, meta.endpoint.port);
        let Some(&kind) = packet.first() else { continue };

        match kind {
            MSG_INITIATION => {
                let Ok((responder, learned)) =
                    Responder::consume_initiation(node_key, &packet[..n])
                else {
                    logln!("wg: bad initiation from {}", from.0);
                    continue;
                };
                let index = next_index;
                next_index = next_index.wrapping_add(2).max(1);

                // A fresh ephemeral per handshake; reuse would cost forward
                // secrecy for the whole session.
                let mut seed = [0u8; 32];
                seed[..4].copy_from_slice(&index.to_le_bytes());
                seed[4..8].copy_from_slice(&(n as u32).to_le_bytes());
                let ephemeral = NodePrivate::from_bytes(seed);

                let Ok((response, keys)) = responder.respond(ephemeral, index) else {
                    continue;
                };
                if socket.send_to(&response, meta.endpoint).await.is_err() {
                    continue;
                }
                logln!("wg: session established with a peer (index {})", index);
                peer = Some(PeerSlot {
                    key: learned.peer_static,
                    session: Session::new(&keys),
                    endpoint: from,
                });
            }
            MSG_TRANSPORT => {
                let Some(slot) = peer.as_mut() else { continue };
                let mut buf = [0u8; 1600];
                buf[..n].copy_from_slice(&packet[..n]);
                let Ok(plain) = slot.session.decrypt(&mut buf[..n]) else {
                    continue;
                };

                // `tailscale ping` speaks TSMP, so answering it is what makes
                // the node visibly reachable to the standard tooling.
                if let Some(ping) = tsmp::parse_ping(plain) {
                    let mut pong = [0u8; 64];
                    let Some(len) = tsmp::write_pong(&ping, &mut pong) else {
                        continue;
                    };
                    let mut out = [0u8; 256];
                    let Ok(sent) = slot.session.encrypt(&pong[..len], &mut out) else {
                        continue;
                    };
                    let dst = embassy_net::IpEndpoint::new(slot.endpoint.0, slot.endpoint.1);
                    let _ = socket.send_to(&out[..sent], dst).await;
                    logln!("wg: TSMP ping answered");
                } else {
                    let _ = slot.key;
                }
            }
            _ => {}
        }
    }
}
