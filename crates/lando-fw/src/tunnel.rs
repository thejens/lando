//! Subnet routing: tailnet TCP in, LAN TCP out.
//!
//! Packets arriving over WireGuard are addressed to LAN hosts — `192.168.86.41`,
//! not to this device — because the tailnet believes this node routes the
//! subnet. Two ways to honour that: forward the IP packets themselves with
//! address translation, or terminate each TCP connection here and open a fresh
//! one to the same destination. This does the latter.
//!
//! Re-originating is the tractable choice on a microcontroller. Forwarding raw
//! IP means tracking translation state per flow and rewriting checksums, and it
//! needs a raw send path onto the LAN that `embassy-net` does not offer.
//! Terminating means smoltcp handles sequencing and retransmission on the
//! tailnet side, `embassy-net` handles it on the LAN side, and this file only
//! copies bytes between them. The cost is that only TCP crosses — UDP, and so
//! SSDP discovery, needs its own path.
//!
//! The trick that makes it work is smoltcp's AnyIP: without it an interface
//! only accepts packets addressed to itself, and every routed packet would be
//! dropped before reaching a socket. With it, a socket listening on a port
//! accepts a connection to any destination, and `local_endpoint` reports which
//! address the peer was actually trying to reach — which is precisely the
//! address to dial on the LAN.

use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, Ipv4Address};

use crate::logln;

/// Ports we accept connections on.
///
/// A listener is needed per port because smoltcp binds ports, not ranges, so
/// this list is the limit of what the subnet route actually reaches. 37193 is
/// the Lyngdorf's UPnP control port; the rest are the ports a LAN device is
/// most likely to answer on.
/// Ports repeat on purpose, and repeat generously.
///
/// smoltcp has no accept queue: a port with no free listener does not queue
/// the connection, it refuses it. A browser opens around six connections per
/// host for one page, so a short table does not merely slow a page down — it
/// drops whichever resources arrive after the listeners run out, which renders
/// as a page with its text but none of its images.
/// The count per port is the concurrency limit for that port, exactly: a
/// connection arriving with no free listener is refused, not queued. Ports are
/// weighted by how a client actually uses them — a browser opens many
/// connections to 80 and 443, while a control protocol on 37193 is mostly
/// sequential but should not fail a burst either.
pub const PORTS: [u16; 28] = [
    80, 80, 80, 80, 80, 80, 80, 80, 80, 80, //
    443, 443, 443, 443, 443, 443, 443, 443, //
    1400, 1400, 1400, 1400, //
    37193, 37193, 37193, 37193, 37193, 37193,
];

/// Per-socket buffers.
///
/// Deliberately small, and traded against listener count: every byte here is
/// multiplied by [`PORTS`], and a refused connection costs a whole resource
/// where a small window only costs throughput. This device forwards control
/// traffic, not bulk transfers.
const TCP_RX: usize = 768;
const TCP_TX: usize = 768;

/// Largest IP packet either side will carry.
const MTU: usize = 1400;
/// Queue depth each way.
///
/// This has to absorb a whole burst, because a browser opens its connections
/// at once and a dropped SYN is not retried for a second or more. Two slots
/// meant most of a parallel page load was discarded before anything polled the
/// interface, which looked like the LAN host refusing connections.
const QUEUE: usize = 12;

type Packet = Vec<u8, MTU>;

/// The tailnet side of the device, as a smoltcp phy.
///
/// "Transmit" here means "hand back to WireGuard for encryption", and
/// "receive" means "a peer sent us this, already decrypted".
#[derive(Default)]
pub struct TunnelDevice {
    inbound: Vec<Packet, QUEUE>,
    outbound: Vec<Packet, QUEUE>,
}

pub struct RxToken(Packet);
pub struct TxToken<'a> {
    outbound: &'a mut Vec<Packet, QUEUE>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf: Packet = Vec::new();
        let _ = buf.resize(len, 0);
        let result = f(&mut buf);
        // Dropping on a full queue is deliberate: TCP will retransmit, where
        // blocking here would stall the interface poll that drains it.
        let _ = self.outbound.push(buf);
        result
    }
}

impl Device for TunnelDevice {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.inbound.is_empty() {
            return None;
        }
        let packet = self.inbound.remove(0);
        Some((
            RxToken(packet),
            TxToken {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.outbound.is_full() {
            return None;
        }
        Some(TxToken {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // IP rather than Ethernet: what crosses WireGuard is bare IP, with no
        // link layer and so no addresses to resolve.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

/// Storage for the socket set, which smoltcp requires to outlive the interface.
pub struct Storage {
    sockets: [SocketStorage<'static>; PORTS.len()],
    rx: [[u8; TCP_RX]; PORTS.len()],
    tx: [[u8; TCP_TX]; PORTS.len()],
}

impl Storage {
    pub const fn new() -> Self {
        Self {
            sockets: [SocketStorage::EMPTY; PORTS.len()],
            rx: [[0; TCP_RX]; PORTS.len()],
            tx: [[0; TCP_TX]; PORTS.len()],
        }
    }
}

pub struct Tunnel {
    pub device: TunnelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    listeners: Vec<(SocketHandle, u16), { PORTS.len() }>,
    /// Sockets a worker is already splicing. Without this two workers pick up
    /// the same connection and copy each other's bytes into it.
    claimed: [bool; PORTS.len()],
    dropped: u32,
}

impl Tunnel {
    /// Builds the tailnet-side stack, listening on every port in [`PORTS`].
    ///
    /// The interface deliberately has no address of its own. Under AnyIP it
    /// accepts every destination regardless, and each accepted socket answers
    /// from the address the peer dialled — so an address here would only ever
    /// describe traffic aimed at this node, which `wg` has already answered
    /// (TSMP) before anything reaches the tunnel.
    pub fn new(storage: &'static mut Storage) -> Self {
        let mut device = TunnelDevice::default();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        // Without this the interface drops every packet not addressed to
        // itself — which, for a subnet router, is all of them.
        iface.set_any_ip(true);

        let mut sockets = SocketSet::new(&mut storage.sockets[..]);
        let mut listeners = Vec::new();
        for (i, (rx, tx)) in storage.rx.iter_mut().zip(storage.tx.iter_mut()).enumerate() {
            let socket = tcp::Socket::new(
                tcp::SocketBuffer::new(&mut rx[..]),
                tcp::SocketBuffer::new(&mut tx[..]),
            );
            let handle = sockets.add(socket);
            let port = PORTS[i];
            if sockets.get_mut::<tcp::Socket>(handle).listen(port).is_ok() {
                let _ = listeners.push((handle, port));
            }
        }

        Self {
            device,
            iface,
            sockets,
            listeners,
            claimed: [false; PORTS.len()],
            dropped: 0,
        }
    }

    /// Queues a decrypted packet from a peer and advances the stack.
    ///
    /// Polling here rather than leaving it to the tunnel task is what keeps
    /// the queue shallow: packets arrive in bursts, and waiting up to a poll
    /// interval to drain them turns a burst into loss.
    pub fn deliver(&mut self, packet: &[u8]) {
        let mut buf: Packet = Vec::new();
        if buf.extend_from_slice(packet).is_ok() && self.device.inbound.push(buf).is_err() {
            self.dropped = self.dropped.wrapping_add(1);
        }
        self.poll(Instant::now());
    }

    /// Packets dropped for want of queue space, which is otherwise invisible:
    /// TCP hides it as latency until it becomes total failure.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Takes one packet bound for a peer, ready to encrypt.
    pub fn take_outbound(&mut self) -> Option<Packet> {
        if self.device.outbound.is_empty() {
            None
        } else {
            Some(self.device.outbound.remove(0))
        }
    }

    pub fn poll(&mut self, now: Instant) {
        let t = SmolInstant::from_millis(now.as_millis() as i64);
        self.iface.poll(t, &mut self.device, &mut self.sockets);
    }

    /// Claims a socket with a connection waiting to be served, together with
    /// the address the peer was trying to reach.
    fn claim(&mut self) -> Option<(usize, SocketHandle, Ipv4Address, u16)> {
        for (i, (handle, _)) in self.listeners.iter().enumerate() {
            if self.claimed[i] {
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if !socket.may_recv() && !socket.may_send() {
                continue;
            }
            // `local_endpoint` is the destination the peer addressed, which
            // AnyIP let through — this is the whole point of the design.
            let Some(local) = socket.local_endpoint() else {
                continue;
            };
            // Only IPv4 is compiled in, so the address needs no discrimination.
            let IpAddress::Ipv4(addr) = local.addr;
            let handle = *handle;
            self.claimed[i] = true;
            return Some((i, handle, addr, local.port));
        }
        None
    }

    /// Counts listeners by state, for diagnosis.
    ///
    /// Exhaustion of any pool here is silent — connections simply stop being
    /// accepted — so the counts have to be observable to be debuggable.
    pub fn stats(&mut self) -> (usize, usize, usize, u32) {
        let claimed = self.claimed.iter().filter(|c| **c).count();
        let mut listening = 0;
        let mut active = 0;
        for (handle, _) in self.listeners.clone().iter() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket.is_listening() {
                listening += 1;
            }
            if socket.is_active() {
                active += 1;
            }
        }
        (claimed, listening, active, self.dropped)
    }

    fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    /// Returns the socket to service after a connection ends.
    ///
    /// The poll between abort and listen is load-bearing: `abort` queues a RST
    /// and the socket is not closed until the interface has run, so listening
    /// immediately fails. Swallowing that error retires the socket silently —
    /// the first connection on a port works and every later one is refused,
    /// which looks like the LAN host rejecting connections rather than a
    /// listener that never came back.
    fn relisten(&mut self, slot: usize, handle: SocketHandle, port: u16) -> bool {
        self.socket(handle).abort();
        self.poll(Instant::now());
        let socket = self.socket(handle);
        if socket.is_open() {
            socket.close();
            self.poll(Instant::now());
        }
        let socket = self.socket(handle);
        let ok = socket.listen(port).is_ok();
        self.claimed[slot] = false;
        ok
    }
}

/// Runs the tunnel: polls the tailnet stack and services one connection at a
/// time, splicing it onto the LAN.
///
/// One at a time is a deliberate v1 limit rather than a protocol one. Each
/// concurrent connection costs a second pair of buffers on both sides, and the
/// traffic this exists for — SOAP calls to an amplifier — is sequential. The
/// structure holds the limit in one place so raising it is a matter of RAM.
pub async fn serve(stack: Stack<'static>, tunnel: &crate::TunnelShared) -> ! {
    // Fixed workers rather than a task per connection: without an allocator
    // the concurrency limit has to be a constant, and making it visible here
    // is better than discovering it as a stall. Five rather than three because
    // a browser opens around six connections for one page, and a worker is
    // occupied for the whole life of a connection, not just its request.
    // More listeners than workers on purpose. A listener is the only backlog
    // there is, so a connection with no free listener is refused outright,
    // where one with no free worker merely waits.
    let ((a, _, _, _, _), _, _) = embassy_futures::join::join3(
        embassy_futures::join::join5(
            worker(stack, tunnel),
            worker(stack, tunnel),
            worker(stack, tunnel),
            worker(stack, tunnel),
            worker(stack, tunnel),
        ),
        embassy_futures::join::join3(
            worker(stack, tunnel),
            worker(stack, tunnel),
            worker(stack, tunnel),
        ),
        monitor(tunnel),
    )
    .await;
    a
}

/// Reports pool occupancy whenever it changes.
///
/// Silent exhaustion is the failure mode of every pool here, so this exists to
/// make it loud.
async fn monitor(tunnel: &crate::TunnelShared) -> ! {
    let mut last = (usize::MAX, usize::MAX, usize::MAX, u32::MAX);
    loop {
        let now = tunnel.lock(|t| t.borrow_mut().stats());
        if now != last {
            logln!(
                "tunnel: {} busy, {} listening, {} active, {} dropped",
                now.0,
                now.1,
                now.2,
                now.3
            );
            last = now;
        }
        Timer::after(Duration::from_millis(250)).await;
    }
}

/// Serves one connection at a time.
async fn worker(stack: Stack<'static>, tunnel: &crate::TunnelShared) -> ! {
    loop {
        let pending = tunnel.lock(|t| {
            let mut t = t.borrow_mut();
            t.poll(Instant::now());
            t.claim()
        });

        let Some((slot, handle, dst, port)) = pending else {
            // Nothing to serve. Poll often enough to keep TCP timers honest
            // without spinning the executor.
            Timer::after(Duration::from_millis(20)).await;
            continue;
        };

        logln!("tunnel: connection for {}:{}", dst, port);
        splice(stack, tunnel, handle, dst, port).await;
        let relistening = tunnel.lock(|t| t.borrow_mut().relisten(slot, handle, port));
        if !relistening {
            logln!("tunnel: port {} did not return to service", port);
        }
        logln!("tunnel: {}:{} closed", dst, port);
    }
}

/// Copies bytes between one tunnel socket and one LAN socket until either ends.
async fn splice(
    stack: Stack<'static>,
    tunnel: &crate::TunnelShared,
    handle: SocketHandle,
    dst: Ipv4Address,
    port: u16,
) {
    let mut rx = [0u8; 1024];
    let mut tx = [0u8; 1024];
    let mut lan = TcpSocket::new(stack, &mut rx, &mut tx);
    lan.set_timeout(Some(Duration::from_secs(30)));

    let addr = embassy_net::Ipv4Address::from(dst.octets());
    // Distinguish "the LAN host refused us" from "the stack had no socket to
    // dial with": they look identical from the tailnet side, and only one of
    // them is a fault in this device.
    if let Err(e) = lan.connect((addr, port)).await {
        logln!("tunnel: dial {}:{} failed: {:?}", dst, port, e);
        return;
    }

    let why = relay(tunnel, handle, &mut lan).await;
    logln!("tunnel: {}:{} ended ({})", dst, port, why);

    // Release the socket rather than letting it wind down on its own. A
    // gracefully closed socket sits in TIME_WAIT and its slot in the stack's
    // pool is unavailable until that expires, so a run of requests drains the
    // pool and later connections are silently never accepted. Flushing first
    // means nothing already written is discarded by the reset.
    let _ = embedded_io_async::Write::flush(&mut lan).await;
    lan.abort();
}

/// Copies bytes in both directions until either side finishes.
async fn relay(
    tunnel: &crate::TunnelShared,
    handle: SocketHandle,
    lan: &mut TcpSocket<'_>,
) -> &'static str {
    let mut buf = [0u8; 512];
    // Bytes read from the LAN that the tailnet socket has not accepted yet.
    // A short write is ordinary flow control — the peer's window is simply
    // full — so the remainder is held and retried. Treating it as an error
    // truncates the response instead, which looks like the LAN host closing
    // the connection early.
    let mut held = [0u8; 512];
    // A backstop against any path that leaks a worker: no bytes either way for
    // this long and the connection is over, whatever either side believes.
    let mut last_activity = Instant::now();
    // Indices rather than a slice: the same buffer is read into again once
    // drained, which a borrow of it would forbid.
    let mut pending = 0usize..0usize;
    loop {
        let (from_peer, closed) = tunnel.lock(|t| {
            let mut t = t.borrow_mut();
            // Keep the tailnet stack turning: it is what moves the bytes this
            // loop depends on, so a splice that stops polling deadlocks itself.
            t.poll(Instant::now());
            let socket = t.socket(handle);
            if !socket.is_active() {
                return (0, 2);
            }
            let n = if socket.can_recv() {
                socket.recv_slice(&mut buf).unwrap_or(0)
            } else {
                0
            };
            // The client having sent FIN with nothing left buffered is the end
            // of the exchange. Without this check a keep-alive connection is
            // never torn down: the LAN host holds its side open by design, so
            // the loop waits forever on a reply that is not coming and the
            // worker is consumed for good. A handful of requests then exhausts
            // the pool and everything after them hangs.
            let peer_done = !socket.may_recv() && n == 0;
            (n, if !socket.is_active() { 2 } else if peer_done { 1 } else { 0 })
        });
        if closed == 2 {
            return "tunnel socket inactive";
        }
        if closed == 1 {
            return "client finished";
        }
        if from_peer > 0 {
            last_activity = Instant::now();
            if embedded_io_async::Write::write_all(&mut *lan, &buf[..from_peer])
                .await
                .is_err()
            {
                return "lan write failed";
            }
        }
        if Instant::now() - last_activity > Duration::from_secs(20) {
            return "idle";
        }

        // Drain what is already held before taking more from the LAN, or the
        // reply arrives out of order.
        if !pending.is_empty() {
            let chunk = &held[pending.start..pending.end];
            let sent = tunnel.lock(|t| {
                let mut t = t.borrow_mut();
                let socket = t.socket(handle);
                if socket.can_send() {
                    socket.send_slice(chunk).unwrap_or(0)
                } else {
                    0
                }
            });
            pending.start += sent;
            if pending.is_empty() {
                continue;
            }
            // Still blocked: let the interface poll above move the window.
            Timer::after(Duration::from_millis(5)).await;
            continue;
        }

        // The LAN side is read with a deadline rather than awaited outright:
        // this loop also owns polling the tailnet stack, so blocking here
        // would stall the path the reply has to travel back along.
        let read = embassy_futures::select::select(
            embedded_io_async::Read::read(&mut *lan, &mut held),
            Timer::after(Duration::from_millis(10)),
        )
        .await;
        if let embassy_futures::select::Either::First(result) = read {
            match result {
                Ok(0) => {
                    // The LAN host is done. Let the tailnet side flush what it
                    // still holds before tearing the connection down, or the
                    // tail of the response is lost.
                    flush(tunnel, handle).await;
                    return "lan closed";
                }
                Err(_) => {
                    flush(tunnel, handle).await;
                    return "lan error";
                }
                Ok(n) => {
                    last_activity = Instant::now();
                    pending = 0..n;
                }
            }
        }
    }
}

/// Polls until the tailnet socket has sent everything queued, or gives up.
///
/// Bounded because a peer that stops reading must not pin the single
/// connection slot indefinitely.
async fn flush(tunnel: &crate::TunnelShared, handle: SocketHandle) {
    for _ in 0..50 {
        let done = tunnel.lock(|t| {
            let mut t = t.borrow_mut();
            t.poll(Instant::now());
            let socket = t.socket(handle);
            !socket.is_active() || socket.send_queue() == 0
        });
        if done {
            return;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
}
