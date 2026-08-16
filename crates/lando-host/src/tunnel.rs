//! A TCP stack living inside the WireGuard tunnel.
//!
//! WireGuard hands us bare IPv4 packets, so anything above ICMP needs a real
//! stack. `smoltcp` provides one that runs without an OS, which is the same
//! choice the firmware has to make — so the device abstraction here is
//! deliberately the shape embassy-net wants too: two queues, one of packets
//! arriving from peers and one of packets to encrypt and relay back.
//!
//! The medium is `Ip`, not `Ethernet`. There are no MAC addresses inside a
//! WireGuard tunnel and no ARP; a stack configured for Ethernet would sit
//! there waiting to resolve neighbours that do not exist.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};

/// WireGuard's own overhead is 32 bytes on top of the outer datagram, and the
/// relay adds its framing on top of that. 1280 is IPv6's minimum MTU and a
/// safe floor for anything that has to cross the open internet.
const TUNNEL_MTU: usize = 1280;

/// Per-socket buffers. Modest on purpose: the firmware pays for these in SRAM,
/// and a proxy that streams does not need large windows.
const TCP_BUFFER: usize = 8 * 1024;

/// Packets moving between the WireGuard session and the TCP stack.
#[derive(Default)]
pub struct TunnelDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

impl TunnelDevice {
    /// Queues a decrypted packet for the stack to process.
    pub fn push_inbound(&mut self, packet: &[u8]) {
        self.inbound.push_back(packet.to_vec());
    }

    /// Takes the next packet the stack wants sent, for encryption and relay.
    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }
}

pub struct RxToken(Vec<u8>);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct TxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
}

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.outbound.push_back(buf);
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
        let packet = self.inbound.pop_front()?;
        Some((
            RxToken(packet),
            TxToken {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        caps
    }
}

/// The stack, its interface and its sockets.
pub struct TunnelStack {
    pub device: TunnelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Listening sockets. smoltcp has no accept queue, so concurrency is a
    /// fixed pool: each socket listens, serves one connection, then listens
    /// again. The pool size is the concurrency limit, which on the firmware is
    /// a RAM decision rather than a policy one.
    listeners: Vec<smoltcp::iface::SocketHandle>,
    /// Per-socket proxy state, parallel to `listeners`.
    conns: Vec<Conn>,
}

/// Where a tunnel connection is in the SOCKS5 exchange.
///
/// SOCKS5 is used rather than a fixed port-forward because it needs no
/// per-target configuration: the client names the host and port, so one
/// listener reaches the whole LAN.
enum Conn {
    /// Awaiting the version/method greeting.
    Greeting,
    /// Greeting answered; awaiting the CONNECT request.
    ///
    /// A distinct state because the two halves routinely arrive in separate
    /// segments — the client waits for our method selection before sending the
    /// request — and re-parsing the request as a greeting silently corrupts
    /// the exchange rather than failing.
    Request,
    /// Spliced to a LAN host. Non-blocking so one thread serves every socket.
    Relaying(TcpStream),
}

impl TunnelStack {
    pub fn new(address: Ipv4Address, port: u16, pool: usize) -> Self {
        let mut device = TunnelDevice::default();
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            // /32: the tunnel address is ours alone, and every peer is reached
            // through the WireGuard peer table rather than an on-link subnet.
            addrs.push(IpCidr::new(IpAddress::Ipv4(address), 32)).ok();
        });

        let mut sockets = SocketSet::new(Vec::new());
        let mut listeners = Vec::with_capacity(pool);
        for _ in 0..pool {
            let socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            );
            let handle = sockets.add(socket);
            let s = sockets.get_mut::<tcp::Socket>(handle);
            s.listen(port).expect("fresh socket can listen");
            listeners.push(handle);
        }
        let conns = (0..pool).map(|_| Conn::Greeting).collect();

        Self {
            device,
            iface,
            sockets,
            listeners,
            conns,
        }
    }

    /// Advances the stack. Call after queuing inbound packets and whenever
    /// time has passed.
    pub fn poll(&mut self, now_millis: i64) {
        self.iface.poll(
            SmolInstant::from_millis(now_millis),
            &mut self.device,
            &mut self.sockets,
        );
    }

    /// Visits each socket. Test-only: the serving path uses `serve`.
    #[cfg(test)]
    pub fn for_each_ready<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut tcp::Socket),
    {
        for handle in &self.listeners {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            f(socket);
        }
    }

    /// Advances every connection: SOCKS5 negotiation, then byte relaying.
    pub fn serve(&mut self) {
        for i in 0..self.listeners.len() {
            let handle = self.listeners[i];
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);

            // A closed tunnel socket drops its LAN peer with it, or the
            // connection leaks for as long as the process runs.
            if !socket.is_active() {
                self.conns[i] = Conn::Greeting;
                continue;
            }

            match &mut self.conns[i] {
                Conn::Greeting => {
                    if greet(socket) {
                        self.conns[i] = Conn::Request;
                    }
                }
                Conn::Request => {
                    if let Some(stream) = connect(socket) {
                        self.conns[i] = Conn::Relaying(stream);
                    }
                }
                Conn::Relaying(stream) => relay(socket, stream),
            }
        }
    }

    /// Returns a listening socket to service after its connection ends, so the
    /// pool does not leak capacity as clients come and go.
    pub fn relisten(&mut self, port: u16) {
        for handle in &self.listeners {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if !socket.is_open() {
                socket.abort();
                let _ = socket.listen(port);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_round_trips_packets_through_the_queues() {
        let mut d = TunnelDevice::default();
        assert!(d.pop_outbound().is_none());
        d.push_inbound(&[1, 2, 3]);

        // The stack consumes inbound packets via a receive token.
        let (rx, _tx) = d.receive(SmolInstant::from_millis(0)).unwrap();
        let seen = smoltcp::phy::RxToken::consume(rx, |b| b.to_vec());
        assert_eq!(seen, vec![1, 2, 3]);
        assert!(d.receive(SmolInstant::from_millis(0)).is_none());
    }

    #[test]
    fn transmitted_packets_land_in_the_outbound_queue() {
        let mut d = TunnelDevice::default();
        let tx = d.transmit(SmolInstant::from_millis(0)).unwrap();
        smoltcp::phy::TxToken::consume(tx, 4, |b| b.copy_from_slice(&[9, 8, 7, 6]));
        assert_eq!(d.pop_outbound(), Some(vec![9, 8, 7, 6]));
        assert!(d.pop_outbound().is_none());
    }

    /// The tunnel carries bare IP; configuring for Ethernet would leave the
    /// stack waiting on ARP for neighbours that do not exist.
    #[test]
    fn medium_is_ip_not_ethernet() {
        let d = TunnelDevice::default();
        assert_eq!(d.capabilities().medium, Medium::Ip);
        assert_eq!(d.capabilities().max_transmission_unit, TUNNEL_MTU);
    }

    #[test]
    fn stack_starts_with_every_socket_listening() {
        let mut stack = TunnelStack::new(Ipv4Address::new(100, 64, 0, 1), 1080, 3);
        let mut listening = 0;
        stack.for_each_ready(|s| {
            if s.is_listening() {
                listening += 1;
            }
        });
        assert_eq!(listening, 3);
    }
}

/// Consumes the SOCKS5 greeting and answers it. Returns true once answered.
///
/// Only "no authentication" is ever offered: the tunnel already authenticated
/// the peer, and a second credential here would be one more thing to provision
/// on a device with no keyboard.
fn greet(socket: &mut tcp::Socket) -> bool {
    if !socket.can_recv() {
        return false;
    }
    let got = socket
        .recv(|buf| {
            if buf.len() < 2 || buf[0] != 5 {
                return (0, false);
            }
            let n = 2 + buf[1] as usize;
            if buf.len() < n {
                // Wait for the full method list rather than consuming a prefix.
                return (0, false);
            }
            (n, true)
        })
        .unwrap_or(false);
    if !got {
        return false;
    }
    socket.send_slice(&[5, 0]).is_ok()
}

/// Consumes the CONNECT request and opens the LAN connection.
fn connect(socket: &mut tcp::Socket) -> Option<TcpStream> {
    if !socket.can_recv() {
        return None;
    }
    let target = socket
        .recv(|buf| match parse_request(buf) {
            Some((used, addr)) => (used, Some(addr)),
            None => (0, None),
        })
        .ok()
        .flatten()?;

    match TcpStream::connect(target) {
        Ok(stream) => {
            stream.set_nonblocking(true).ok();
            stream.set_nodelay(true).ok();
            // Success, with a zero bound address: clients read the reply code
            // and ignore the rest.
            socket.send_slice(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).ok()?;
            println!("  ** SOCKS5 connect -> {target}");
            Some(stream)
        }
        Err(e) => {
            println!("  ** SOCKS5 connect to {target} failed: {e}");
            // Reply code 5 is "connection refused"; without a reply the client
            // waits for a timeout instead of failing promptly.
            socket.send_slice(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).ok();
            socket.close();
            None
        }
    }
}

/// Parses a SOCKS5 CONNECT request, returning bytes consumed and the target.
fn parse_request(buf: &[u8]) -> Option<(usize, SocketAddr)> {
    if buf.len() < 4 || buf[0] != 5 {
        return None;
    }
    // Only CONNECT. BIND and UDP ASSOCIATE have no meaning for this device.
    if buf[1] != 1 {
        return None;
    }
    match buf[3] {
        // IPv4
        1 if buf.len() >= 10 => {
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((10, SocketAddr::from((ip, port))))
        }
        // Domain name: resolved here, on the LAN side, which is the whole
        // point -- the client may have no way to resolve a local name.
        3 if buf.len() >= 5 => {
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return None;
            }
            let host = core::str::from_utf8(&buf[5..5 + len]).ok()?;
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                .ok()?
                .next()?;
            Some((5 + len + 2, addr))
        }
        _ => None,
    }
}

/// Moves bytes both ways between the tunnel socket and the LAN socket.
fn relay(socket: &mut tcp::Socket, stream: &mut TcpStream) {
    // Tunnel -> LAN.
    if socket.can_recv() {
        let _ = socket.recv(|buf| {
            if buf.is_empty() {
                return (0, ());
            }
            match stream.write(buf) {
                Ok(n) => (n, ()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, ()),
                Err(_) => (buf.len(), ()),
            }
        });
    }

    // LAN -> tunnel. Bounded by what the tunnel socket will accept, so a fast
    // LAN peer cannot outrun the tunnel and force unbounded buffering.
    if socket.can_send() {
        let mut buf = [0u8; 2048];
        let room = socket.send_capacity() - socket.send_queue();
        let want = room.min(buf.len());
        if want > 0 {
            match stream.read(&mut buf[..want]) {
                Ok(0) => socket.close(),
                Ok(n) => {
                    let _ = socket.send_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => socket.close(),
            }
        }
    }
}
