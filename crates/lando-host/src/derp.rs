//! DERP over TLS, host side.
//!
//! `tailscale-core::derp` owns the wire format; this owns the socket, the TLS
//! session and the buffering. The firmware will provide its own equivalent
//! over `embedded-tls`.
//!
//! **Certificates are verified here.** The firmware will not be able to —
//! `embedded-tls` has no `no_std` certificate verification — but that is a
//! constraint of the target, not a property of the design, so the host does
//! not inherit it. Keeping the host strict means a MITM shows up as a failure
//! during development rather than being normalised.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;

use tailscale_core::derp::frame::{write_header, FrameType, HEADER_LEN, KEY_LEN};
use tailscale_core::derp::handshake::{client_info_payload, open, NONCE_LEN};
use tailscale_core::derp::{parse_server_key, Frame, FrameReader, UPGRADE_PATH, UPGRADE_PROTOCOL};

pub type Error = String;

/// Something the relay told us.
#[derive(Debug)]
pub enum Event {
    /// A packet relayed from a peer, with that peer's node key.
    Packet { src: [u8; KEY_LEN], data: Vec<u8> },
    KeepAlive,
    PeerGone([u8; KEY_LEN]),
    PeerPresent([u8; KEY_LEN]),
    /// A frame we do not model. Reported so it is visible, not silently eaten.
    Other(FrameType),
}

pub struct DerpClient {
    tls: StreamOwned<ClientConnection, TcpStream>,
    reader: FrameReader,
    /// Decrypted bytes read from TLS but not yet consumed by the framer.
    pending: Vec<u8>,
    pos: usize,
    server_key: [u8; KEY_LEN],
}

impl DerpClient {
    /// Dials a relay and completes the DERP handshake.
    pub fn connect(
        host: &str,
        node_secret: &[u8; KEY_LEN],
        node_public: &[u8; KEY_LEN],
    ) -> Result<Self, Error> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| format!("bad server name {host:?}: {e}"))?;
        let conn = ClientConnection::new(Arc::new(config), name)
            .map_err(|e| format!("tls setup: {e}"))?;

        let sock = TcpStream::connect((host, 443))
            .map_err(|e| format!("connecting to {host}:443: {e}"))?;
        sock.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        sock.set_nodelay(true).ok();

        let mut client = Self {
            tls: StreamOwned::new(conn, sock),
            reader: FrameReader::new(),
            pending: Vec::new(),
            pos: 0,
            server_key: [0u8; KEY_LEN],
        };

        client.upgrade(host)?;
        client.server_key = client.read_server_key()?;
        client.send_client_info(node_secret, node_public)?;
        client.read_server_info(node_secret)?;
        Ok(client)
    }

    pub fn server_key(&self) -> &[u8; KEY_LEN] {
        &self.server_key
    }

    /// Switches the HTTPS connection into the DERP binary protocol.
    fn upgrade(&mut self, host: &str) -> Result<(), Error> {
        let request = format!(
            "GET {UPGRADE_PATH} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: {UPGRADE_PROTOCOL}\r\n\
             \r\n"
        );
        self.tls
            .write_all(request.as_bytes())
            .map_err(|e| format!("sending DERP upgrade: {e}"))?;
        self.tls.flush().map_err(|e| e.to_string())?;

        // Read until the headers end. Anything past them is already framed
        // DERP and must be kept.
        let mut buf = vec![0u8; 4096];
        let mut have = 0usize;
        loop {
            if have == buf.len() {
                return Err("upgrade response exceeded buffer".into());
            }
            let n = self
                .tls
                .read(&mut buf[have..])
                .map_err(|e| format!("reading DERP upgrade: {e}"))?;
            if n == 0 {
                return Err("relay closed during upgrade".into());
            }
            have += n;
            if let Some(end) = find_headers_end(&buf[..have]) {
                let status = String::from_utf8_lossy(&buf[..end.min(64)]);
                if !status.starts_with("HTTP/1.1 101") {
                    return Err(format!(
                        "relay refused the upgrade: {}",
                        String::from_utf8_lossy(&buf[..have.min(400)])
                    ));
                }
                self.pending.extend_from_slice(&buf[end..have]);
                return Ok(());
            }
        }
    }

    fn read_server_key(&mut self) -> Result<[u8; KEY_LEN], Error> {
        match self.next_raw_frame()? {
            (FrameType::ServerKey, payload) => {
                parse_server_key(&payload).map_err(|e| format!("bad ServerKey frame: {e:?}"))
            }
            (kind, _) => Err(format!("expected ServerKey, got {kind:?}")),
        }
    }

    fn send_client_info(
        &mut self,
        node_secret: &[u8; KEY_LEN],
        node_public: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        let mut nonce = [0u8; NONCE_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);

        let mut payload = [0u8; 256];
        let n = client_info_payload(node_secret, node_public, &self.server_key, &nonce, &mut payload)
            .map_err(|e| format!("building ClientInfo: {e:?}"))?;
        self.write_frame(FrameType::ClientInfo, &payload[..n])
    }

    fn read_server_info(&mut self, node_secret: &[u8; KEY_LEN]) -> Result<Vec<u8>, Error> {
        let (kind, mut payload) = self.next_raw_frame()?;
        if kind != FrameType::ServerInfo {
            return Err(format!("expected ServerInfo, got {kind:?}"));
        }
        let json = open(node_secret, &self.server_key, &mut payload)
            .map_err(|e| format!("opening ServerInfo: {e:?}"))?;
        Ok(json.to_vec())
    }

    /// Sends a packet to a peer through the relay.
    ///
    /// Unused until the WireGuard datapath is wired to the relay; kept here
    /// because it is the send half of `next_event` and belongs with it.
    #[allow(dead_code)]
    pub fn send_packet(&mut self, dst: &[u8; KEY_LEN], packet: &[u8]) -> Result<(), Error> {
        let mut payload = Vec::with_capacity(KEY_LEN + packet.len());
        payload.extend_from_slice(dst);
        payload.extend_from_slice(packet);
        self.write_frame(FrameType::SendPacket, &payload)
    }

    /// Blocks for the next relay event.
    pub fn next_event(&mut self) -> Result<Event, Error> {
        loop {
            let (kind, payload) = self.next_raw_frame()?;
            return Ok(match kind {
                FrameType::RecvPacket if payload.len() >= KEY_LEN => {
                    let mut src = [0u8; KEY_LEN];
                    src.copy_from_slice(&payload[..KEY_LEN]);
                    Event::Packet {
                        src,
                        data: payload[KEY_LEN..].to_vec(),
                    }
                }
                FrameType::KeepAlive => Event::KeepAlive,
                FrameType::PeerGone if payload.len() >= KEY_LEN => {
                    let mut k = [0u8; KEY_LEN];
                    k.copy_from_slice(&payload[..KEY_LEN]);
                    Event::PeerGone(k)
                }
                FrameType::PeerPresent if payload.len() >= KEY_LEN => {
                    let mut k = [0u8; KEY_LEN];
                    k.copy_from_slice(&payload[..KEY_LEN]);
                    Event::PeerPresent(k)
                }
                other => Event::Other(other),
            });
        }
    }

    fn write_frame(&mut self, kind: FrameType, payload: &[u8]) -> Result<(), Error> {
        let mut header = [0u8; HEADER_LEN];
        write_header(&mut header, kind, payload.len() as u32)
            .map_err(|e| format!("framing: {e:?}"))?;
        self.tls
            .write_all(&header)
            .and_then(|_| self.tls.write_all(payload))
            .and_then(|_| self.tls.flush())
            .map_err(|e| format!("writing {kind:?}: {e}"))
    }

    /// Reads one complete frame, assembling streamed bodies.
    ///
    /// The host can afford to assemble; the firmware will consume chunks as
    /// they arrive, which is why the framing itself streams.
    fn next_raw_frame(&mut self) -> Result<(FrameType, Vec<u8>), Error> {
        let mut assembled: Vec<u8> = Vec::new();
        loop {
            if self.pos == self.pending.len() {
                self.pending.clear();
                self.pos = 0;
                let mut chunk = vec![0u8; 8192];
                let n = self
                    .tls
                    .read(&mut chunk)
                    .map_err(|e| format!("reading from relay: {e}"))?;
                if n == 0 {
                    return Err("relay closed the connection".into());
                }
                self.pending.extend_from_slice(&chunk[..n]);
            }

            let (used, frame) = self
                .reader
                .feed(&self.pending[self.pos..])
                .map_err(|e| format!("DERP framing: {e:?}"))?;
            self.pos += used;
            match frame {
                None => continue,
                Some(Frame::Control { kind, payload }) => {
                    return Ok((kind, payload.as_slice().to_vec()))
                }
                Some(Frame::Body {
                    kind, chunk, end, ..
                }) => {
                    assembled.extend_from_slice(chunk);
                    if end {
                        return Ok((kind, assembled));
                    }
                }
            }
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}
