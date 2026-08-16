//! DERP over TLS, on the device.
//!
//! This is what makes a NAT'd device reachable. Two peers that are both behind
//! NAT cannot hole-punch without a side channel to coordinate through — that
//! is how `CallMeMaybe` is delivered — so the relay is required even when the
//! eventual path ends up direct.
//!
//! **Certificates are not verified here.** `embedded-tls` has no `no_std`
//! certificate verification, so this is a constraint of the target rather than
//! a choice. It is defensible only because of what DERP actually carries: no
//! credential transits it (authentication is a NaCl box against the node key),
//! and every relayed byte is already WireGuard-encrypted end to end. A
//! man-in-the-middle therefore obtains ciphertext, traffic metadata, and the
//! ability to drop packets — not decryption, forgery, or access. The host
//! binary verifies properly; only the device makes this trade.

use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_time::Duration;
use embedded_io_async::{Read, Write};
use embedded_tls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext, UnsecureProvider};

use tailscale_core::derp::frame::{write_header, FrameType, HEADER_LEN, KEY_LEN};
use tailscale_core::derp::handshake::{client_info_payload, open, NONCE_LEN};
use tailscale_core::derp::{parse_server_key, Frame, FrameReader, UPGRADE_PATH, UPGRADE_PROTOCOL};

use crate::logln;

/// A TLS record can be 16 KiB plus overhead, and the read buffer has to hold
/// one whole. This is the single largest allocation in the firmware.
const TLS_READ: usize = 16 * 1024 + 512;
const TLS_WRITE: usize = 4 * 1024;

#[derive(Debug)]
pub enum DerpError {
    Dns,
    Connect,
    Tls,
    Io,
    Upgrade,
    Protocol,
}

pub struct Buffers {
    tls_read: [u8; TLS_READ],
    tls_write: [u8; TLS_WRITE],
}

impl Buffers {
    pub const fn new() -> Self {
        Self {
            tls_read: [0; TLS_READ],
            tls_write: [0; TLS_WRITE],
        }
    }
}

/// Connects to a relay and stays on it, carrying packets until it fails.
///
/// The connection must be *held*, not merely established. A relay routes to a
/// node only while that node is connected to it, so returning after the
/// handshake -- and dropping the TLS connection with it -- leaves peers being
/// told to reach us somewhere we are not. Nothing reports an error in that
/// case; traffic is simply dropped.
pub async fn run<'a, R>(
    stack: Stack<'static>,
    host: &str,
    node_secret: &[u8; KEY_LEN],
    node_public: &[u8; KEY_LEN],
    mut rng: R,
    bufs: &'a mut Buffers,
    rx_buf: &'a mut [u8; 2048],
    tx_buf: &'a mut [u8; 2048],
    node: &crate::wg::Shared,
    tunnel: &crate::TunnelShared,
) -> DerpError
where
    R: embedded_tls::CryptoRngCore,
{
    // Drawn before the TLS provider takes ownership of the generator.
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    logln!("derp: resolving {}", host);
    let Ok(addrs) = stack.dns_query(host, DnsQueryType::A).await else {
        return DerpError::Dns;
    };
    let Some(&addr) = addrs.first() else {
        return DerpError::Dns;
    };
    logln!("derp: {} -> {}", host, addr);

    let mut socket = TcpSocket::new(stack, rx_buf, tx_buf);
    // Generous, because the relay is quiet by design: it sends nothing between
    // keep-alives when no peer is talking to us, and a short timeout would tear
    // down a perfectly healthy connection for being idle.
    socket.set_timeout(Some(Duration::from_secs(120)));
    if socket.connect((addr, 443)).await.is_err() {
        return DerpError::Connect;
    }

    // RSA signature schemes must be advertised explicitly. TlsConfig::new
    // only enables them when the `alloc` feature is on, and this is a no_std
    // build — so without this the ClientHello offers ECDSA and Ed25519 only,
    // and a server holding an RSA certificate (which the relays do) has
    // nothing it can sign with and aborts with handshake_failure.
    let config = TlsConfig::new()
        .enable_rsa_signatures()
        .with_server_name(host);
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(socket, &mut bufs.tls_read, &mut bufs.tls_write);
    // Log the specific TlsError: collapsing it hides which layer failed, and
    // "TLS did not work" is not a diagnosis.
    if let Err(e) = tls
        .open(TlsContext::new(
            &config,
            UnsecureProvider::new::<Aes128GcmSha256>(rng),
        ))
        .await
    {
        logln!("derp: tls handshake failed: {:?}", e);
        return DerpError::Tls;
    }
    logln!("derp: tls up (certificate not verified)");

    let mut reader = FrameReader::new();
    let mut staged = [0u8; 1024];
    let mut staged_len = 0usize;
    let server_key = match handshake(
        &mut tls,
        host,
        node_secret,
        node_public,
        &nonce,
        &mut reader,
        &mut staged,
        &mut staged_len,
    )
    .await
    {
        Ok(k) => k,
        Err(e) => return e,
    };
    logln!("derp: relay accepted us");

    match pump(
        &mut tls,
        node,
        &mut reader,
        &mut staged,
        &mut staged_len,
        server_key,
        tunnel,
    )
    .await
    {
        Ok(()) => DerpError::Io,
        Err(e) => e,
    }
}

/// Upgrades the HTTPS connection into DERP and authenticates.
///
/// No credential crosses this link: the box is keyed by our node key, which
/// the relay already knows from the control plane.
#[allow(clippy::too_many_arguments)]
async fn handshake<S>(
    tls: &mut S,
    host: &str,
    node_secret: &[u8; KEY_LEN],
    node_public: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    reader: &mut FrameReader,
    staged: &mut [u8; 1024],
    staged_len: &mut usize,
) -> Result<[u8; KEY_LEN], DerpError>
where
    S: Read + Write,
{
    let mut request = [0u8; 256];
    let n = build_upgrade(host, &mut request);
    tls.write_all(&request[..n]).await.map_err(|_| DerpError::Io)?;
    tls.flush().await.map_err(|_| DerpError::Io)?;

    let mut buf = [0u8; 1024];
    let mut have = 0usize;
    let body_at = loop {
        if have == buf.len() {
            return Err(DerpError::Upgrade);
        }
        let n = tls.read(&mut buf[have..]).await.map_err(|_| DerpError::Io)?;
        if n == 0 {
            return Err(DerpError::Io);
        }
        have += n;
        if let Some(end) = find_headers_end(&buf[..have]) {
            if !buf.starts_with(b"HTTP/1.1 101") {
                return Err(DerpError::Upgrade);
            }
            break end;
        }
    };

    // Anything past the headers is already framed DERP.
    *staged_len = have - body_at;
    staged[..*staged_len].copy_from_slice(&buf[body_at..have]);

    let server_key = loop {
        match next_frame(reader, staged, staged_len, tls).await? {
            (FrameType::ServerKey, payload, len) => {
                break parse_server_key(&payload[..len]).map_err(|_| DerpError::Protocol)?;
            }
            _ => continue,
        }
    };
    logln!("derp: server key received");

    // The nonce was drawn randomly by the caller. Deriving it from anything
    // stable — the server key, say — would repeat it on every connection under
    // the same node key, which is the one thing a NaCl nonce may never do.
    let mut payload = [0u8; 256];
    let n = client_info_payload(node_secret, node_public, &server_key, nonce, &mut payload)
        .map_err(|_| DerpError::Protocol)?;
    write_frame(tls, FrameType::ClientInfo, &payload[..n]).await?;

    loop {
        match next_frame(reader, staged, staged_len, tls).await? {
            (FrameType::ServerInfo, mut payload, len) => {
                open(node_secret, &server_key, &mut payload[..len])
                    .map_err(|_| DerpError::Protocol)?;
                return Ok(server_key);
            }
            _ => continue,
        }
    }
}

/// Carries packets until the connection fails.
///
/// Never returns `Ok` in normal operation: a relay connection ending at all is
/// the failure, because the node is only reachable through it while it lasts.
async fn pump<S>(
    tls: &mut S,
    node: &crate::wg::Shared,
    reader: &mut FrameReader,
    staged: &mut [u8; 1024],
    staged_len: &mut usize,
    _server_key: [u8; KEY_LEN],
    tunnel: &crate::TunnelShared,
) -> Result<(), DerpError>
where
    S: Read + Write,
{
    // Tells the relay this is our home region, so it holds the connection for
    // us rather than treating it as incidental. Peers are routed here on the
    // strength of it.
    write_frame(tls, FrameType::NotePreferred, &[1]).await?;
    logln!("derp: connected, relaying");

    // Learned from the first packet a peer relays to us. Replies are addressed
    // by node key, and the relay has no notion of a "connection" to reply on.
    let mut peer_key: Option<[u8; KEY_LEN]> = None;

    // Every piece of parser state lives here rather than inside the future
    // that waits for bytes.
    //
    // This loop has to read and write on one connection: a peer reached
    // through the relay has replies to send while the relay still has frames
    // to deliver. Waiting on either alone deadlocks the other, so the two are
    // raced — and whichever loses is cancelled mid-flight. Anything held in
    // that future's locals is silently lost when it is.
    //
    // The failure that costs is losing how far through the staging buffer we
    // had read while `reader` has already consumed those bytes: the next
    // attempt re-feeds them, the frame stream desynchronises, and every packet
    // after that is garbage. It presents as the relay working exactly once —
    // the first request succeeds and nothing afterwards does.
    //
    // So the only cancellable await here is the raw read, whose own state
    // lives inside the TLS connection, and the parse runs to completion
    // without awaiting at all.
    let mut out = [0u8; 1600];
    let mut assembled = [0u8; 1600];
    let mut filled = 0usize;
    let mut pos = 0usize;

    loop {
        // Drain outbound first, and unconditionally.
        //
        // The select below only runs when there is nothing left to parse, so
        // a steady arrival of frames would mean never reaching it — outbound
        // packets would queue until the channel filled and were dropped, which
        // stalls exactly the replies the peer is waiting for. Sending here
        // involves no race, so nothing can be cancelled.
        if let Some(peer) = peer_key {
            while let Ok(relayed) = crate::wg::DERP_OUT.try_receive() {
                send_packet(tls, &peer, relayed.as_slice()).await?;
            }
        }

        // Parse whatever is already staged before waiting for more.
        let mut frame = None;
        while pos < *staged_len {
            let (used, parsed) = reader
                .feed(&staged[pos..*staged_len])
                .map_err(|_| DerpError::Protocol)?;
            pos += used;
            match parsed {
                None => {
                    if used == 0 {
                        break;
                    }
                }
                Some(Frame::Control { kind, payload }) => {
                    let src = payload.as_slice();
                    let take = src.len().min(assembled.len());
                    assembled[..take].copy_from_slice(&src[..take]);
                    frame = Some((kind, take));
                    break;
                }
                Some(Frame::Body { kind, chunk, end, .. }) => {
                    let take = chunk.len().min(assembled.len() - filled);
                    assembled[filled..filled + take].copy_from_slice(&chunk[..take]);
                    filled += take;
                    if end {
                        frame = Some((kind, filled));
                        filled = 0;
                        break;
                    }
                }
            }
        }

        // Reclaim the consumed prefix so the buffer does not fill with bytes
        // already parsed.
        if pos > 0 {
            staged.copy_within(pos..*staged_len, 0);
            *staged_len -= pos;
            pos = 0;
        }

        if let Some((kind, len)) = frame {
            handle_frame(tls, node, tunnel, kind, &assembled[..len], &mut out, &mut peer_key)
                .await?;
            continue;
        }

        // Nothing more to parse. All state is in `reader`, `staged` and
        // `filled`, so waiting here loses nothing if it is cancelled.
        if *staged_len == staged.len() {
            return Err(DerpError::Protocol);
        }
        let next = embassy_futures::select::select(
            tls.read(&mut staged[*staged_len..]),
            crate::wg::DERP_OUT.receive(),
        )
        .await;
        match next {
            embassy_futures::select::Either::First(result) => {
                let n = result.map_err(|_| DerpError::Io)?;
                if n == 0 {
                    return Err(DerpError::Io);
                }
                *staged_len += n;
            }
            embassy_futures::select::Either::Second(relayed) => {
                if let Some(peer) = peer_key {
                    send_packet(tls, &peer, relayed.as_slice()).await?;
                }
            }
        }
    }
}

/// Acts on one received frame.
async fn handle_frame<S>(
    tls: &mut S,
    node: &crate::wg::Shared,
    tunnel: &crate::TunnelShared,
    kind: FrameType,
    payload: &[u8],
    out: &mut [u8; 1600],
    peer_key: &mut Option<[u8; KEY_LEN]>,
) -> Result<(), DerpError>
where
    S: Write,
{
    match kind {
        FrameType::RecvPacket if payload.len() > KEY_LEN => {
            // `src node key | packet`. The key is both the sender's identity
            // and the address any reply has to go back to.
            let mut src = [0u8; KEY_LEN];
            src.copy_from_slice(&payload[..KEY_LEN]);
            *peer_key = Some(src);
            let action = node.lock(|n| {
                n.borrow_mut().handle(
                    &payload[KEY_LEN..],
                    crate::wg::Source::Derp(src),
                    out,
                )
            });
            match action {
                Some(crate::wg::Action::Reply(n)) => send_packet(tls, &src, &out[..n]).await?,
                Some(crate::wg::Action::Deliver(n)) => {
                    tunnel.lock(|t| t.borrow_mut().deliver(&out[..n]));
                }
                None => {}
            }
        }
        // Answering keeps the relay from deciding we are gone.
        FrameType::Ping if payload.len() >= 8 => {
            write_frame(tls, FrameType::Pong, &payload[..8]).await?;
        }
        FrameType::KeepAlive => {}
        FrameType::PeerGone => logln!("derp: a peer left the relay"),
        FrameType::Restarting => logln!("derp: relay is restarting"),
        FrameType::Health if !payload.is_empty() => {
            logln!("derp: relay reports a health problem")
        }
        _ => {}
    }
    Ok(())
}

/// Sends a packet to a peer through the relay.
///
/// SendPacket is the mirror of RecvPacket: destination key first, then the
/// packet itself.
async fn send_packet<S>(
    tls: &mut S,
    dst: &[u8; KEY_LEN],
    packet: &[u8],
) -> Result<(), DerpError>
where
    S: Write,
{
    let mut frame = [0u8; 1600 + KEY_LEN];
    let end = KEY_LEN + packet.len();
    if end > frame.len() {
        return Err(DerpError::Protocol);
    }
    frame[..KEY_LEN].copy_from_slice(dst);
    frame[KEY_LEN..end].copy_from_slice(packet);
    write_frame(tls, FrameType::SendPacket, &frame[..end]).await
}

/// Writes one framed message.
async fn write_frame<S>(tls: &mut S, kind: FrameType, payload: &[u8]) -> Result<(), DerpError>
where
    S: Write,
{
    let mut header = [0u8; HEADER_LEN];
    write_header(&mut header, kind, payload.len() as u32).map_err(|_| DerpError::Protocol)?;
    tls.write_all(&header).await.map_err(|_| DerpError::Io)?;
    tls.write_all(payload).await.map_err(|_| DerpError::Io)?;
    tls.flush().await.map_err(|_| DerpError::Io)
}

/// Reads one complete DERP frame, refilling from TLS as needed.
async fn next_frame<S>(
    reader: &mut FrameReader,
    staged: &mut [u8; 1024],
    staged_len: &mut usize,
    tls: &mut S,
) -> Result<(FrameType, [u8; 512], usize), DerpError>
where
    S: Read,
{
    let mut assembled = [0u8; 512];
    let mut filled = 0usize;
    let mut pos = 0usize;
    loop {
        // Refill when the reader stops making progress, not only when the
        // buffer is exhausted. A loop that can spin without awaiting starves
        // every other task in a cooperative executor — the board goes silent
        // with its USB still enumerated, which looks like a hang rather than
        // a busy loop.
        if pos == *staged_len {
            let n = tls.read(staged).await.map_err(|_| DerpError::Io)?;
            if n == 0 {
                return Err(DerpError::Io);
            }
            *staged_len = n;
            pos = 0;
        }
        let (used, frame) = reader
            .feed(&staged[pos..*staged_len])
            .map_err(|_| DerpError::Protocol)?;
        pos += used;
        match frame {
            None => {
                if used == 0 {
                    // Needs more bytes: keep the tail and read.
                    staged.copy_within(pos..*staged_len, 0);
                    *staged_len -= pos;
                    pos = 0;
                    let n = tls
                        .read(&mut staged[*staged_len..])
                        .await
                        .map_err(|_| DerpError::Io)?;
                    if n == 0 {
                        return Err(DerpError::Io);
                    }
                    *staged_len += n;
                }
                continue;
            }
            Some(Frame::Control { kind, payload }) => {
                let src = payload.as_slice();
                let take = src.len().min(assembled.len());
                assembled[..take].copy_from_slice(&src[..take]);
                // Carry the unread tail forward rather than dropping it.
                staged.copy_within(pos..*staged_len, 0);
                *staged_len -= pos;
                return Ok((kind, assembled, take));
            }
            Some(Frame::Body { kind, chunk, end, .. }) => {
                let take = chunk.len().min(assembled.len() - filled);
                assembled[filled..filled + take].copy_from_slice(&chunk[..take]);
                filled += take;
                if end {
                    staged.copy_within(pos..*staged_len, 0);
                    *staged_len -= pos;
                    return Ok((kind, assembled, filled));
                }
            }
        }
    }
}

fn build_upgrade(host: &str, out: &mut [u8]) -> usize {
    let mut n = 0;
    for part in [
        b"GET " as &[u8],
        UPGRADE_PATH.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nConnection: Upgrade\r\nUpgrade: ",
        UPGRADE_PROTOCOL.as_bytes(),
        b"\r\n\r\n",
    ] {
        out[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    n
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}
