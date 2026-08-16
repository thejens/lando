//! Host-side I/O for the ts2021 control channel.
//!
//! `tailscale-core` owns every protocol decision; this file owns only sockets
//! and buffers. The firmware will provide its own equivalent over embassy, and
//! the two must not drift in behaviour — anything that looks like a protocol
//! rule belongs in the core crate, not here.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tailscale_core::control;
use tailscale_core::h2::{self, FrameReader, Item};
use tailscale_core::key::{MachinePrivate, MachinePublic};
use tailscale_core::noise::{
    self, Handshake, Session, HEADER_LEN, MAX_PLAINTEXT_SIZE, MSG_TYPE_ERROR, MSG_TYPE_RECORD,
    RESPONSE_LEN,
};
use tailscale_core::upgrade::{build_request, parse_response, UpgradeError, MAX_REQUEST_LEN};

/// Receive window we advertise. Deliberately modest: the window is our
/// backpressure, and on the Pico we cannot absorb a burst the server is
/// entitled to send. We issue WINDOW_UPDATEs as data is consumed.
const INITIAL_WINDOW: u32 = 64 * 1024;
/// The spec forbids advertising anything below 16 KiB, so this is the floor.
const MAX_FRAME: u32 = 16 * 1024;

pub type Error = String;

/// Wire tracing, enabled with `LANDO_TRACE=1`.
///
/// Everything on this connection is inside Noise, so `tcpdump` shows only
/// ciphertext — this is the only way to see the HTTP/2 exchange.
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("LANDO_TRACE").is_ok())
}

fn trace_frames(dir: &str, mut bytes: &[u8]) {
    if !tracing() {
        return;
    }
    if bytes.starts_with(h2::PREFACE) {
        eprintln!("{dir} PREFACE");
        bytes = &bytes[h2::PREFACE.len()..];
    }
    while bytes.len() >= h2::FRAME_HEADER_LEN {
        let len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
        let kind = bytes[3];
        let flags = bytes[4];
        let sid = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7fff_ffff;
        eprintln!(
            "{dir} {:<13} len={len} flags=0x{flags:02x} stream={sid}",
            frame_name(kind)
        );
        let end = (h2::FRAME_HEADER_LEN + len).min(bytes.len());
        bytes = &bytes[end..];
    }
}

fn frame_name(kind: u8) -> &'static str {
    match kind {
        0x0 => "DATA",
        0x1 => "HEADERS",
        0x2 => "PRIORITY",
        0x3 => "RST_STREAM",
        0x4 => "SETTINGS",
        0x5 => "PUSH_PROMISE",
        0x6 => "PING",
        0x7 => "GOAWAY",
        0x8 => "WINDOW_UPDATE",
        0x9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

/// A Noise-encrypted byte stream over TCP.
pub struct NoiseTransport {
    stream: TcpStream,
    session: Session,
    /// Decrypted plaintext not yet consumed by the layer above.
    rx: Vec<u8>,
    rx_pos: usize,
}

impl NoiseTransport {
    /// Connects, performs the HTTP upgrade on port 80 and completes the Noise
    /// IK handshake.
    pub fn connect(
        host: &str,
        control_key: &MachinePublic,
        machine_key: MachinePrivate,
        capability_version: u16,
    ) -> Result<Self, Error> {
        let ephemeral = MachinePrivate::generate(&mut rand_core::OsRng);
        let (handshake, initiation) =
            Handshake::start(machine_key, control_key, capability_version, ephemeral);

        let mut request = [0u8; MAX_REQUEST_LEN];
        let req_len = build_request(host, &initiation, &mut request)
            .map_err(|e| format!("building upgrade request: {e:?}"))?;

        let mut stream =
            TcpStream::connect((host, 80)).map_err(|e| format!("connecting to {host}:80: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).ok();
        stream
            .write_all(&request[..req_len])
            .map_err(|e| format!("sending upgrade: {e}"))?;

        // The server may coalesce the 101, the Noise response, and even its
        // opening SETTINGS frame into one segment, so nothing read here may be
        // discarded — leftovers are carried into the session buffer below.
        let mut buf = vec![0u8; 8192];
        let mut have = 0usize;
        let body_start = loop {
            let n = read_into(&mut stream, &mut buf, &mut have)?;
            if n == 0 {
                return Err("connection closed before upgrade completed".into());
            }
            match parse_response(&buf[..have]) {
                Ok(end) => break end,
                Err(UpgradeError::Incomplete) => continue,
                Err(UpgradeError::NotSwitching) => {
                    let text = String::from_utf8_lossy(&buf[..have]);
                    return Err(format!("server refused the upgrade:\n{text}"));
                }
                Err(e) => return Err(format!("parsing upgrade response: {e:?}")),
            }
        };

        while have - body_start < RESPONSE_LEN {
            // A type-3 frame is an unauthenticated plaintext error. Surface it
            // rather than failing to decrypt something that was never a
            // handshake response.
            if have - body_start >= HEADER_LEN && buf[body_start] == MSG_TYPE_ERROR {
                let len = u16::from_be_bytes([buf[body_start + 1], buf[body_start + 2]]) as usize;
                let end = (body_start + HEADER_LEN + len).min(have);
                let msg = String::from_utf8_lossy(&buf[body_start + HEADER_LEN..end]);
                return Err(format!("control plane rejected the handshake: {msg:?}"));
            }
            if read_into(&mut stream, &mut buf, &mut have)? == 0 {
                return Err("connection closed during Noise handshake".into());
            }
        }

        let session = handshake
            .finish(&buf[body_start..body_start + RESPONSE_LEN])
            .map_err(|e| format!("completing Noise handshake: {e:?}"))?;

        let mut transport = Self {
            stream,
            session,
            rx: Vec::new(),
            rx_pos: 0,
        };

        // Anything past the handshake response is already-encrypted session
        // data; decrypt it now or the h2 stream starts mid-frame.
        let leftover_start = body_start + RESPONSE_LEN;
        if have > leftover_start {
            transport.absorb(&buf[leftover_start..have].to_vec())?;
        }
        Ok(transport)
    }

    pub fn handshake_hash(&self) -> [u8; 32] {
        *self.session.handshake_hash()
    }

    /// Widens the read timeout for requests the server deliberately holds
    /// open: the interactive `Followup` registration, and the map long-poll.
    pub fn set_read_timeout(&mut self, d: Duration) -> Result<(), Error> {
        self.stream
            .set_read_timeout(Some(d))
            .map_err(|e| e.to_string())
    }

    /// Encrypts and sends `plaintext`, splitting it across records as needed.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        trace_frames("->", plaintext);
        let mut frame = [0u8; noise::MAX_MESSAGE_SIZE];
        for chunk in plaintext.chunks(MAX_PLAINTEXT_SIZE) {
            let n = self
                .session
                .write_record(chunk, &mut frame)
                .map_err(|e| format!("encrypting record: {e:?}"))?;
            self.stream
                .write_all(&frame[..n])
                .map_err(|e| format!("writing record: {e}"))?;
        }
        self.stream.flush().map_err(|e| e.to_string())
    }

    /// Consumes the optional early payload so the HTTP/2 parser starts on a
    /// frame boundary. Must run before any frame is fed to the reader.
    pub fn skip_early_payload(&mut self) -> Result<(), Error> {
        loop {
            match control::parse_early_payload(self.buffered()) {
                control::EarlyPayload::Absent => return Ok(()),
                control::EarlyPayload::Present { consumed, json } => {
                    if tracing() {
                        eprintln!("<- early payload: {:?}", String::from_utf8_lossy(json));
                    }
                    self.consume(consumed);
                    return Ok(());
                }
                control::EarlyPayload::Incomplete => self.pump()?,
            }
        }
    }

    /// Plaintext decrypted but not yet consumed.
    pub fn buffered(&self) -> &[u8] {
        &self.rx[self.rx_pos..]
    }

    pub fn consume(&mut self, n: usize) {
        self.rx_pos += n;
        if self.rx_pos == self.rx.len() {
            self.rx.clear();
            self.rx_pos = 0;
        } else if self.rx_pos > 16 * 1024 {
            self.rx.drain(..self.rx_pos);
            self.rx_pos = 0;
        }
    }

    /// Reads and decrypts one more Noise record, appending to the buffer.
    pub fn pump(&mut self) -> Result<(), Error> {
        let mut header = [0u8; HEADER_LEN];
        self.read_exact(&mut header)?;
        let (kind, len) = noise::parse_header(&header);
        if len > noise::MAX_CIPHERTEXT_SIZE {
            return Err(format!("record claims {len} bytes, over the 4 KiB cap"));
        }
        let mut body = vec![0u8; len];
        self.read_exact(&mut body)?;

        match kind {
            MSG_TYPE_RECORD => {
                let n = self
                    .session
                    .read_record(&mut body)
                    .map_err(|e| format!("decrypting record: {e:?}"))?;
                trace_frames("<-", &body[..n]);
                self.rx.extend_from_slice(&body[..n]);
                Ok(())
            }
            MSG_TYPE_ERROR => Err(format!(
                "control plane error: {:?}",
                String::from_utf8_lossy(&body)
            )),
            other => Err(format!("unexpected Noise frame type {other}")),
        }
    }

    /// Decrypts bytes already read from the socket during the handshake.
    fn absorb(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while bytes.len() >= HEADER_LEN {
            let (kind, len) = noise::parse_header(&bytes[..HEADER_LEN].try_into().unwrap());
            if bytes.len() < HEADER_LEN + len {
                return Err("truncated record coalesced with handshake".into());
            }
            let mut body = bytes[HEADER_LEN..HEADER_LEN + len].to_vec();
            if kind != MSG_TYPE_RECORD {
                return Err(format!("unexpected Noise frame type {kind} after handshake"));
            }
            let n = self
                .session
                .read_record(&mut body)
                .map_err(|e| format!("decrypting coalesced record: {e:?}"))?;
            if tracing() {
                eprintln!(
                    "<- (coalesced) {} bytes: {:?}",
                    n,
                    String::from_utf8_lossy(&body[..n.min(200)])
                );
            }
            self.rx.extend_from_slice(&body[..n]);
            bytes = &bytes[HEADER_LEN + len..];
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.stream
            .read_exact(buf)
            .map_err(|e| format!("reading from control plane: {e}"))
    }
}

fn read_into(stream: &mut TcpStream, buf: &mut [u8], have: &mut usize) -> Result<usize, Error> {
    if *have == buf.len() {
        return Err("upgrade response exceeded buffer".into());
    }
    let n = stream.read(&mut buf[*have..]).map_err(|e| e.to_string())?;
    *have += n;
    Ok(n)
}

/// HTTP/2 over the Noise session.
pub struct H2Conn {
    transport: NoiseTransport,
    reader: FrameReader,
    next_stream: u32,
}

impl H2Conn {
    /// Sends the preface and our SETTINGS, then waits for the server's.
    pub fn start(transport: NoiseTransport) -> Result<Self, Error> {
        let mut conn = Self {
            transport,
            reader: FrameReader::new(),
            next_stream: 1,
        };

        let mut buf = [0u8; 128];
        let mut w = h2::Writer::new(&mut buf);
        w.preface().map_err(|e| format!("{e:?}"))?;
        w.settings(INITIAL_WINDOW, MAX_FRAME)
            .map_err(|e| format!("{e:?}"))?;
        let n = w.len();
        conn.transport.send(&buf[..n])?;

        // Sent before reading, so the server is guaranteed to have something
        // in flight and the early-payload probe below cannot deadlock.
        conn.transport.skip_early_payload()?;
        Ok(conn)
    }

    pub fn handshake_hash(&self) -> [u8; 32] {
        self.transport.handshake_hash()
    }

    pub fn set_read_timeout(&mut self, d: Duration) -> Result<(), Error> {
        self.transport.set_read_timeout(d)
    }

    /// Issues a POST and feeds every response body chunk to `on_data`.
    ///
    /// Returns once the server closes the stream. Response HEADERS are skipped
    /// without being decoded — see the `h2` module for why that is safe.
    pub fn post(
        &mut self,
        authority: &str,
        path: &str,
        body: &[u8],
        mut on_data: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let stream_id = self.next_stream;
        self.next_stream += 2;

        let mut head = [0u8; 512];
        let mut w = h2::Writer::new(&mut head);
        w.post_headers(stream_id, authority, path, body.len())
            .map_err(|e| format!("encoding headers: {e:?}"))?;
        let n = w.len();
        self.transport.send(&head[..n])?;

        // Body frames are capped so each fits inside one Noise record, which
        // keeps the firmware's send path to a single fixed buffer.
        let mut frame = vec![0u8; MAX_PLAINTEXT_SIZE];
        let chunk_max = MAX_PLAINTEXT_SIZE - h2::FRAME_HEADER_LEN;
        let mut chunks = body.chunks(chunk_max).peekable();
        if chunks.peek().is_none() {
            let mut w = h2::Writer::new(&mut frame);
            w.data(stream_id, &[], true).map_err(|e| format!("{e:?}"))?;
            let n = w.len();
            self.transport.send(&frame[..n])?;
        } else {
            while let Some(chunk) = chunks.next() {
                let last = chunks.peek().is_none();
                let mut w = h2::Writer::new(&mut frame);
                w.data(stream_id, chunk, last)
                    .map_err(|e| format!("{e:?}"))?;
                let n = w.len();
                self.transport.send(&frame[..n])?;
            }
        }

        self.read_until_end_of(stream_id, &mut on_data)
    }

    fn read_until_end_of(
        &mut self,
        stream_id: u32,
        on_data: &mut impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        loop {
            if self.transport.buffered().is_empty() {
                self.transport.pump()?;
            }
            // Copied so the reader can borrow it while control-frame handling
            // borrows the transport mutably to reply. Wasteful on a long map
            // stream, but this path is host-only; the firmware will feed the
            // reader directly from its receive buffer.
            let pending = self.transport.buffered().to_vec();
            let mut offset = 0;
            let mut done = false;

            while offset < pending.len() {
                let (used, item) = self.reader.feed(&pending[offset..]);
                offset += used;
                let Some(item) = item else {
                    if used == 0 {
                        break;
                    }
                    continue;
                };
                match item {
                    // `ControlFrame` owns its payload, so nothing here borrows
                    // the reader and we can reply in place.
                    Item::Control(cf) => self.handle_control(&cf)?,
                    Item::Body { header, chunk, end } => {
                        if header.kind == h2::frame_type::DATA && header.stream_id == stream_id {
                            on_data(chunk)?;
                        }
                        // END_STREAM lives on the frame header, so it reads as
                        // set for *every* chunk of that frame. Only the final
                        // chunk actually ends the stream.
                        if end && header.end_stream() && header.stream_id == stream_id {
                            done = true;
                        }
                    }
                }
            }

            self.transport.consume(offset);
            self.replenish_window()?;
            if done {
                return Ok(());
            }
        }
    }

    fn handle_control(&mut self, cf: &h2::ControlFrame) -> Result<(), Error> {
        let mut buf = [0u8; 64];
        match cf.header.kind {
            h2::frame_type::SETTINGS if cf.header.flags & h2::flag::ACK == 0 => {
                let mut w = h2::Writer::new(&mut buf);
                w.settings_ack().map_err(|e| format!("{e:?}"))?;
                let n = w.len();
                self.transport.send(&buf[..n])
            }
            h2::frame_type::PING if cf.header.flags & h2::flag::ACK == 0 => {
                let mut w = h2::Writer::new(&mut buf);
                w.ping_ack(cf.payload()).map_err(|e| format!("{e:?}"))?;
                let n = w.len();
                self.transport.send(&buf[..n])
            }
            h2::frame_type::GOAWAY => {
                let code = cf
                    .payload()
                    .get(4..8)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(0);
                let debug = String::from_utf8_lossy(cf.payload().get(8..).unwrap_or(&[]));
                Err(format!("server sent GOAWAY, error {code}: {debug:?}"))
            }
            h2::frame_type::RST_STREAM => {
                let code = cf
                    .payload()
                    .get(..4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(0);
                Err(format!("server reset the stream, error {code}"))
            }
            _ => Ok(()),
        }
    }

    /// Returns consumed flow-control credit so the server keeps sending.
    fn replenish_window(&mut self) -> Result<(), Error> {
        let owed = self.reader.take_pending_window();
        if owed == 0 {
            return Ok(());
        }
        let mut buf = [0u8; 32];
        let mut w = h2::Writer::new(&mut buf);
        w.window_update(0, owed).map_err(|e| format!("{e:?}"))?;
        let n = w.len();
        self.transport.send(&buf[..n])
    }
}
