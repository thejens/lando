//! An mDNS proxy, so a LAN can be discovered from the tailnet.
//!
//! Discovery is the one thing the subnet route cannot carry. mDNS is UDP
//! multicast to `224.0.0.251:5353`, and a tailnet has no multicast: a client's
//! browse never leaves its own link, and `.local` is hardcoded to multicast in
//! every mainstream resolver, so it cannot be pointed at a unicast server
//! either. Nothing makes a phone's browse arrive here.
//!
//! What *can* work is being asked directly. A client that can be given an
//! address — `dig @lando-pico -p 5353 …`, a script, a home-automation server —
//! sends an ordinary unicast query, and this answers it on behalf of the LAN:
//! the query is re-asked as multicast on the LAN, and the answers are relayed
//! back. That is the whole ceiling of what is achievable, and it is the
//! difference between finding nothing and listing everything.
//!
//! The trick that keeps this small is the **QU bit**. Setting it asks
//! responders to reply by unicast to the sender, so answers arrive on an
//! ordinary UDP socket and the device never joins a multicast group. Sending to
//! a multicast address needs no group membership either — smoltcp maps it
//! straight onto an Ethernet multicast address, with no ARP.

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Stack};
use embassy_time::{Duration, Instant, Timer};

use tailscale_core::mdns;

use crate::logln;

/// How long to gather answers before giving up on stragglers.
///
/// mDNS responders answer on their own schedule and are entitled to delay to
/// avoid colliding with each other, so this is a collection window rather than
/// a timeout: the first answer usually arrives in milliseconds and the last
/// can take most of a second.
const GATHER: Duration = Duration::from_millis(1200);

/// Largest datagram either side will carry.
const MAX: usize = 1400;

/// Serves mDNS queries arriving over the tunnel, until the socket fails.
pub async fn serve(stack: Stack<'static>, tunnel: &crate::TunnelShared) -> ! {
    // The LAN side has to hold a whole browse: every responder answers at
    // once, and one that does not fit is simply lost.
    let mut rx_meta = [PacketMetadata::EMPTY; 12];
    let mut rx_buf = [0u8; 4096];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_buf = [0u8; MAX];
    let mut lan = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);

    // Any local port: responders reply to whatever they were asked from, and
    // binding 5353 on the LAN side would collide with the host's own responder
    // if one ever ran here.
    if lan.bind(0).is_err() {
        logln!("mdns: could not bind a LAN port");
        loop {
            Timer::after(Duration::from_secs(60)).await;
        }
    }
    logln!("mdns: proxy ready on udp {}", mdns::PORT);

    let group = IpEndpoint::new(
        IpAddress::v4(
            mdns::GROUP[0],
            mdns::GROUP[1],
            mdns::GROUP[2],
            mdns::GROUP[3],
        ),
        mdns::PORT,
    );

    let mut query = [0u8; MAX];
    let mut answer = [0u8; MAX];
    loop {
        // Wait for a query to arrive over the tunnel.
        let Some((len, client)) = tunnel.lock(|t| t.borrow_mut().take_mdns_query(&mut query)) else {
            Timer::after(Duration::from_millis(20)).await;
            continue;
        };

        // Discard anything still queued from a previous browse. Responders
        // keep answering after the gather window closes, and those datagrams
        // sit in the socket until read — served against the *next* query they
        // do not answer, which the client rejects while the answers it wanted
        // are still behind them.
        let mut stale = 0u32;
        while stale < 64 {
            // A queued datagram is returned immediately, so the timer only
            // wins once the socket is empty.
            let drained = embassy_futures::select::select(
                lan.recv_from(&mut answer),
                Timer::after(Duration::from_millis(2)),
            )
            .await;
            match drained {
                embassy_futures::select::Either::First(_) => stale += 1,
                embassy_futures::select::Either::Second(()) => break,
            }
        }
        if stale > 0 {
            logln!("mdns: discarded {} late answer(s)", stale);
        }

        // Ask for unicast answers, so they arrive on this socket rather than
        // on a multicast group we would otherwise have to join.
        let id = mdns::transaction_id(&query[..len]).unwrap_or(0);
        if mdns::request_unicast_replies(&mut query[..len]).is_err() {
            continue;
        }
        if lan.send_to(&query[..len], group).await.is_err() {
            logln!("mdns: LAN query failed");
            continue;
        }

        // Relay whatever answers arrive within the window. Each is forwarded
        // as its own datagram: mDNS answers are independent messages from
        // independent responders, and merging them would mean rewriting
        // records rather than moving bytes.
        let deadline = Instant::now() + GATHER;
        let mut relayed = 0u32;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.as_ticks() == 0 {
                break;
            }
            let received = embassy_futures::select::select(
                lan.recv_from(&mut answer),
                Timer::after(remaining),
            )
            .await;
            let embassy_futures::select::Either::First(Ok((n, _))) = received else {
                break;
            };
            if !mdns::is_response(&answer[..n]) {
                continue;
            }
            // Responders may answer with an ID of zero; the client matches on
            // the one it sent, so carry that rather than theirs.
            mdns::set_transaction_id(&mut answer[..n], id);
            // And they echo the question with the QU bit we added still set,
            // which the client never asked for and will reject the answer
            // over. Put it back the way the client wrote it.
            let _ = mdns::restore_multicast_questions(&mut answer[..n]);
            tunnel.lock(|t| t.borrow_mut().send_mdns_answer(&answer[..n], client));
            relayed += 1;
        }
        logln!("mdns: {} answer(s) relayed", relayed);
    }
}
