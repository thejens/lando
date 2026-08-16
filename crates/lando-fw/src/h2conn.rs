//! HTTP/2 over the Noise session, on embassy.
//!
//! Mirrors `lando-host`'s transport so the two stay comparable: the framing,
//! HPACK encoding and record layer are all `tailscale-core`, and what lives
//! here is the socket plumbing plus the buffers whose size is a real cost on
//! this part.
//!
//! Response HEADERS frames are skipped rather than decoded — see the core's
//! `h2` module for why that is safe — which is what keeps an HPACK decoder,
//! its Huffman tables and its dynamic-table state off the device entirely.

use embassy_net::tcp::TcpSocket;
use embedded_io_async::Write;

use tailscale_core::control::{parse_early_payload, EarlyPayload};
use tailscale_core::h2::{self, FrameReader, Item};
use tailscale_core::noise::{self, Session, HEADER_LEN, MAX_PLAINTEXT_SIZE};

use crate::logln;

/// Receive window we advertise. Modest deliberately: the window is our
/// backpressure, and this device cannot absorb a burst the server would
/// otherwise be entitled to send.
const INITIAL_WINDOW: u32 = 16 * 1024;
/// The spec forbids advertising below 16 KiB, so this is the floor.
const MAX_FRAME: u32 = 16 * 1024;

#[derive(Debug)]
pub enum H2Error {
    Io,
    Noise,
    Frame,
    Server,
    TooLarge,
}

/// An HTTP/2 connection running inside a Noise session.
pub struct H2Conn {
    session: Session,
    reader: FrameReader,
    next_stream: u32,
    /// Plaintext decrypted from Noise but not yet fed to the frame reader.
    pending: [u8; noise::MAX_MESSAGE_SIZE],
    pending_len: usize,
    pending_pos: usize,
    /// Ciphertext read from the socket but not yet a complete record.
    ///
    /// Records do not align with TCP segments, so a read routinely ends
    /// mid-record. Holding the tail here — rather than assuming whole records
    /// arrive together — is what keeps the stream in step.
    raw: [u8; 2 * noise::MAX_MESSAGE_SIZE],
    raw_len: usize,
}

impl H2Conn {
    /// Sends the connection preface and our SETTINGS, then consumes the
    /// ts2021 early payload so HTTP/2 starts on a frame boundary.
    pub async fn start(
        socket: &mut TcpSocket<'_>,
        session: Session,
        leftover: &[u8],
    ) -> Result<Self, H2Error> {
        let mut conn = Self {
            session,
            reader: FrameReader::new(),
            next_stream: 1,
            pending: [0; noise::MAX_MESSAGE_SIZE],
            pending_len: 0,
            pending_pos: 0,
            raw: [0; 2 * noise::MAX_MESSAGE_SIZE],
            raw_len: 0,
        };

        let mut buf = [0u8; 128];
        let mut w = h2::Writer::new(&mut buf);
        w.preface().map_err(|_| H2Error::Frame)?;
        w.settings(INITIAL_WINDOW, MAX_FRAME)
            .map_err(|_| H2Error::Frame)?;
        let n = w.len();
        conn.send(socket, &buf[..n]).await?;

        // Decrypt whatever arrived alongside the handshake response before
        // reading anything further, or the record stream starts misaligned.
        conn.absorb(leftover)?;

        // Sent before reading, so the server has something in flight and the
        // early-payload probe cannot deadlock waiting for a byte.
        conn.skip_early_payload(socket).await?;
        Ok(conn)
    }

    /// Encrypts and sends `plaintext`, splitting across Noise records.
    async fn send(&mut self, socket: &mut TcpSocket<'_>, plaintext: &[u8]) -> Result<(), H2Error> {
        let mut frame = [0u8; noise::MAX_MESSAGE_SIZE];
        for chunk in plaintext.chunks(MAX_PLAINTEXT_SIZE) {
            let n = self
                .session
                .write_record(chunk, &mut frame)
                .map_err(|_| H2Error::Noise)?;
            socket
                .write_all(&frame[..n])
                .await
                .map_err(|_| H2Error::Io)?;
        }
        Ok(())
    }

    /// Stages ciphertext already read from the socket.
    fn absorb(&mut self, bytes: &[u8]) -> Result<(), H2Error> {
        if self.raw_len + bytes.len() > self.raw.len() {
            return Err(H2Error::TooLarge);
        }
        self.raw[self.raw_len..self.raw_len + bytes.len()].copy_from_slice(bytes);
        self.raw_len += bytes.len();
        self.drain_records()
    }

    /// Decrypts every complete record in `raw`, leaving any partial tail.
    fn drain_records(&mut self) -> Result<(), H2Error> {
        // Reclaim consumed plaintext once, up front, so the room check below
        // reflects what is actually available.
        if self.pending_pos > 0 {
            self.pending.copy_within(self.pending_pos..self.pending_len, 0);
            self.pending_len -= self.pending_pos;
            self.pending_pos = 0;
        }
        let mut pos = 0;
        while self.raw_len - pos >= HEADER_LEN {
            let header: [u8; HEADER_LEN] = self.raw[pos..pos + HEADER_LEN].try_into().unwrap();
            let (kind, len) = noise::parse_header(&header);
            if len > noise::MAX_CIPHERTEXT_SIZE {
                return Err(H2Error::TooLarge);
            }
            if self.raw_len - pos < HEADER_LEN + len {
                break; // wait for the rest of this record
            }
            if kind == noise::MSG_TYPE_ERROR {
                return Err(H2Error::Server);
            }
            // Leave the record staged if its plaintext will not fit. This is
            // the backpressure that keeps a 4 KB plaintext buffer workable
            // against a netmap far larger than it.
            if self.pending_len + len > self.pending.len() {
                break;
            }
            let mut body = [0u8; noise::MAX_CIPHERTEXT_SIZE];
            body[..len].copy_from_slice(&self.raw[pos + HEADER_LEN..pos + HEADER_LEN + len]);
            let n = self
                .session
                .read_record(&mut body[..len])
                .map_err(|_| H2Error::Noise)?;

            self.pending[self.pending_len..self.pending_len + n].copy_from_slice(&body[..n]);
            self.pending_len += n;
            pos += HEADER_LEN + len;
        }
        self.raw.copy_within(pos..self.raw_len, 0);
        self.raw_len -= pos;
        Ok(())
    }

    /// Reads from the socket until at least one more record is decrypted.
    async fn pump(&mut self, socket: &mut TcpSocket<'_>) -> Result<(), H2Error> {
        let before = self.pending_len - self.pending_pos;
        // Records may already be staged and simply blocked on room.
        self.drain_records()?;
        if self.pending_len - self.pending_pos > before {
            return Ok(());
        }
        loop {
            if self.raw_len == self.raw.len() {
                return Err(H2Error::TooLarge);
            }
            let n = socket
                .read(&mut self.raw[self.raw_len..])
                .await
                .map_err(|_| H2Error::Io)?;
            if n == 0 {
                return Err(H2Error::Io);
            }
            self.raw_len += n;
            self.drain_records()?;
            if self.pending_len - self.pending_pos > before {
                return Ok(());
            }
        }
    }

    async fn skip_early_payload(&mut self, socket: &mut TcpSocket<'_>) -> Result<(), H2Error> {
        loop {
            let buffered = &self.pending[self.pending_pos..self.pending_len];
            match parse_early_payload(buffered) {
                EarlyPayload::Absent => return Ok(()),
                EarlyPayload::Present { consumed, .. } => {
                    self.pending_pos += consumed;
                    return Ok(());
                }
                EarlyPayload::Incomplete => self.pump(socket).await?,
            }
        }
    }

    /// Issues a POST and collects the response body into `out`.
    ///
    /// Bounded by the caller's buffer rather than streamed: registration
    /// responses are small, and the streaming path is only needed for the
    /// netmap.
    pub async fn post(
        &mut self,
        socket: &mut TcpSocket<'_>,
        authority: &str,
        path: &str,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, H2Error> {
        let mut written = 0usize;
        self.post_stream(socket, authority, path, body, |chunk| {
            let room = out.len().saturating_sub(written);
            let take = room.min(chunk.len());
            out[written..written + take].copy_from_slice(&chunk[..take]);
            written += take;
        })
        .await?;
        Ok(written)
    }

    /// Issues a POST and hands every response body chunk to `on_data`.
    ///
    /// Returns when the server ends the stream — which for a long-poll it
    /// never does, so this is also the shape the netmap uses: the connection
    /// stays open and chunks arrive as the tailnet changes.
    pub async fn post_stream(
        &mut self,
        socket: &mut TcpSocket<'_>,
        authority: &str,
        path: &str,
        body: &[u8],
        mut on_data: impl FnMut(&[u8]),
    ) -> Result<(), H2Error> {
        let stream_id = self.next_stream;
        self.next_stream += 2;

        let mut head = [0u8; 320];
        let mut w = h2::Writer::new(&mut head);
        w.post_headers(stream_id, authority, path, body.len())
            .map_err(|_| H2Error::Frame)?;
        let n = w.len();
        self.send(socket, &head[..n]).await?;

        let mut frame = [0u8; MAX_PLAINTEXT_SIZE];
        for (i, chunk) in body.chunks(MAX_PLAINTEXT_SIZE - h2::FRAME_HEADER_LEN).enumerate() {
            let last = (i + 1) * (MAX_PLAINTEXT_SIZE - h2::FRAME_HEADER_LEN) >= body.len();
            let mut w = h2::Writer::new(&mut frame);
            w.data(stream_id, chunk, last).map_err(|_| H2Error::Frame)?;
            let n = w.len();
            self.send(socket, &frame[..n]).await?;
        }

        loop {
            if self.pending_pos == self.pending_len {
                self.pump(socket).await?;
            }
            // Copied out because reacting to a frame re-borrows the session.
            let mut scratch = [0u8; noise::MAX_MESSAGE_SIZE];
            let avail = self.pending_len - self.pending_pos;
            scratch[..avail].copy_from_slice(&self.pending[self.pending_pos..self.pending_len]);

            let mut offset = 0;
            let mut done = false;
            let mut acks: [Option<h2::ControlFrame>; 4] = [None, None, None, None];
            let mut ack_count = 0;

            while offset < avail {
                let (used, item) = self.reader.feed(&scratch[offset..avail]);
                offset += used;
                let Some(item) = item else {
                    if used == 0 {
                        break;
                    }
                    continue;
                };
                match item {
                    Item::Control(cf) => {
                        if ack_count < acks.len() {
                            acks[ack_count] = Some(cf);
                            ack_count += 1;
                        }
                    }
                    Item::Body { header, chunk, end } => {
                        if header.kind == h2::frame_type::DATA && header.stream_id == stream_id {
                            on_data(chunk);
                        }
                        // END_STREAM sits on the frame header, so it reads as
                        // set for every chunk; only the last one ends it.
                        if end && header.end_stream() && header.stream_id == stream_id {
                            done = true;
                        }
                    }
                }
            }
            self.pending_pos += offset;

            for cf in acks.iter().flatten() {
                self.handle_control(socket, cf).await?;
            }
            let owed = self.reader.take_pending_window();
            if owed > 0 {
                let mut buf = [0u8; 32];
                let mut w = h2::Writer::new(&mut buf);
                w.window_update(0, owed).map_err(|_| H2Error::Frame)?;
                let n = w.len();
                self.send(socket, &buf[..n]).await?;
            }
            if done {
                return Ok(());
            }
        }
    }

    async fn handle_control(
        &mut self,
        socket: &mut TcpSocket<'_>,
        cf: &h2::ControlFrame,
    ) -> Result<(), H2Error> {
        let mut buf = [0u8; 64];
        match cf.header.kind {
            h2::frame_type::SETTINGS if cf.header.flags & h2::flag::ACK == 0 => {
                let mut w = h2::Writer::new(&mut buf);
                w.settings_ack().map_err(|_| H2Error::Frame)?;
                let n = w.len();
                self.send(socket, &buf[..n]).await
            }
            h2::frame_type::PING if cf.header.flags & h2::flag::ACK == 0 => {
                let mut w = h2::Writer::new(&mut buf);
                w.ping_ack(cf.payload()).map_err(|_| H2Error::Frame)?;
                let n = w.len();
                self.send(socket, &buf[..n]).await
            }
            h2::frame_type::GOAWAY | h2::frame_type::RST_STREAM => {
                logln!("h2: server closed the stream");
                Err(H2Error::Server)
            }
            _ => Ok(()),
        }
    }
}

