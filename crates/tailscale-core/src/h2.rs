//! The minimal HTTP/2 needed to speak to Tailscale's control plane.
//!
//! Inside the Noise session the control plane speaks **cleartext HTTP/2 with
//! prior knowledge** — the client sends the 24-byte preface and SETTINGS
//! directly, with no h2c upgrade dance. RPCs are ordinary POSTs to
//! `/machine/register` and `/machine/map`.
//!
//! Three deliberate reductions keep this small enough for a microcontroller:
//!
//!   1. **HEADERS frames are never decoded.** We skip their payload entirely
//!      and assume a 200. That removes HPACK decoding, Huffman decoding and
//!      dynamic-table state — by far the bulk of a general h2 implementation.
//!      We additionally send `SETTINGS_HEADER_TABLE_SIZE = 0` so the server is
//!      forbidden from indexing, which makes the omission safe rather than
//!      merely convenient.
//!   2. **Only HPACK *encoding* is implemented**, in its simplest legal form:
//!      static-table indices and literals with no Huffman coding.
//!   3. **Payloads stream.** A frame is parsed as a 9-byte header followed by
//!      chunks, so a multi-megabyte `MapResponse` never needs a buffer. The
//!      spec forbids advertising a max frame size below 16 KiB, so buffering
//!      whole frames would have cost 16 KiB of SRAM for no benefit.
//!
//! `WINDOW_UPDATE` is not optional. The server's send window closes after
//! 65535 bytes and the connection then stalls silently, which looks exactly
//! like a hung long-poll.

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const FRAME_HEADER_LEN: usize = 9;

pub mod frame_type {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
}

pub mod flag {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

pub mod setting {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
}

/// Largest control frame we retain in full. SETTINGS and PING are tiny; a
/// GOAWAY carrying a long debug string is truncated rather than buffered.
const CONTROL_FRAME_MAX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub kind: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn end_stream(&self) -> bool {
        self.flags & flag::END_STREAM != 0
    }
}

/// A small frame, captured whole.
///
/// The payload is owned rather than borrowed from the reader, so callers can
/// hold an item and keep feeding without the borrow checker objecting. Control
/// frames are at most [`CONTROL_FRAME_MAX`] bytes and arrive rarely, so the
/// copy is not worth avoiding.
#[derive(Debug, Clone, Copy)]
pub struct ControlFrame {
    pub header: FrameHeader,
    payload: [u8; CONTROL_FRAME_MAX],
    payload_len: usize,
}

impl ControlFrame {
    /// The frame body, truncated if it exceeded [`CONTROL_FRAME_MAX`] — which
    /// in practice only happens for a GOAWAY carrying a long debug string.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }
}

/// One thing the reader produced.
#[derive(Debug)]
pub enum Item<'a> {
    Control(ControlFrame),
    /// Part of a streamed payload (DATA, HEADERS, or anything unrecognised).
    /// `end` marks the final chunk of that frame.
    Body {
        header: FrameHeader,
        chunk: &'a [u8],
        end: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    /// Accumulating a small control frame before emitting it whole.
    Buffering,
    /// Streaming a payload straight through to the caller.
    Streaming,
    /// Discarding the overflow of an oversized control frame.
    Draining,
}

/// Incremental HTTP/2 frame reader.
///
/// Feed it whatever bytes arrived; it consumes what it can and returns at most
/// one item per call. Call repeatedly until it consumes nothing.
pub struct FrameReader {
    state: State,
    header_buf: [u8; FRAME_HEADER_LEN],
    header_have: usize,
    current: FrameHeader,
    remaining: u32,
    control: [u8; CONTROL_FRAME_MAX],
    control_len: usize,
    /// Bytes of DATA payload consumed since the last window update was issued.
    pending_window: u32,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub const fn new() -> Self {
        Self {
            state: State::Header,
            header_buf: [0; FRAME_HEADER_LEN],
            header_have: 0,
            current: FrameHeader {
                length: 0,
                kind: 0,
                flags: 0,
                stream_id: 0,
            },
            remaining: 0,
            control: [0; CONTROL_FRAME_MAX],
            control_len: 0,
            pending_window: 0,
        }
    }

    /// Snapshots the buffered control payload into an owned frame.
    fn control_frame(&self, header: FrameHeader) -> ControlFrame {
        ControlFrame {
            header,
            payload: self.control,
            payload_len: self.control_len,
        }
    }

    /// Total DATA bytes received since the last [`Self::take_pending_window`].
    ///
    /// The caller must convert this into `WINDOW_UPDATE` frames or the peer
    /// will stop sending once its window is exhausted.
    pub fn take_pending_window(&mut self) -> u32 {
        core::mem::take(&mut self.pending_window)
    }

    /// Consumes bytes from `input`, returning how many were used and at most
    /// one item. A return of `(0, None)` means more input is needed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> (usize, Option<Item<'a>>) {
        let mut pos = 0;
        loop {
            match self.state {
                State::Header => {
                    let need = FRAME_HEADER_LEN - self.header_have;
                    let take = need.min(input.len() - pos);
                    self.header_buf[self.header_have..self.header_have + take]
                        .copy_from_slice(&input[pos..pos + take]);
                    self.header_have += take;
                    pos += take;
                    if self.header_have < FRAME_HEADER_LEN {
                        return (pos, None);
                    }
                    self.header_have = 0;
                    self.current = FrameHeader {
                        length: u32::from_be_bytes([
                            0,
                            self.header_buf[0],
                            self.header_buf[1],
                            self.header_buf[2],
                        ]),
                        kind: self.header_buf[3],
                        flags: self.header_buf[4],
                        // Top bit is reserved and must be ignored, not rejected.
                        stream_id: u32::from_be_bytes([
                            self.header_buf[5],
                            self.header_buf[6],
                            self.header_buf[7],
                            self.header_buf[8],
                        ]) & 0x7fff_ffff,
                    };
                    self.remaining = self.current.length;
                    self.control_len = 0;

                    if self.current.length == 0 {
                        // Empty frames are common: SETTINGS ACK, and DATA with
                        // only END_STREAM to close a stream.
                        let header = self.current;
                        self.state = State::Header;
                        return (
                            pos,
                            Some(if is_control(header.kind) {
                                Item::Control(self.control_frame(header))
                            } else {
                                Item::Body {
                                    header,
                                    chunk: &[],
                                    end: true,
                                }
                            }),
                        );
                    }
                    self.state = if is_control(self.current.kind) {
                        State::Buffering
                    } else {
                        State::Streaming
                    };
                }

                State::Buffering => {
                    let avail = input.len() - pos;
                    if avail == 0 {
                        return (pos, None);
                    }
                    let space = CONTROL_FRAME_MAX - self.control_len;
                    let take = (self.remaining as usize).min(avail).min(space);
                    self.control[self.control_len..self.control_len + take]
                        .copy_from_slice(&input[pos..pos + take]);
                    self.control_len += take;
                    self.remaining -= take as u32;
                    pos += take;

                    if self.remaining == 0 {
                        let header = self.current;
                        self.state = State::Header;
                        return (pos, Some(Item::Control(self.control_frame(header))));
                    }
                    if self.control_len == CONTROL_FRAME_MAX {
                        self.state = State::Draining;
                    }
                }

                State::Draining => {
                    let take = (self.remaining as usize).min(input.len() - pos);
                    self.remaining -= take as u32;
                    pos += take;
                    if self.remaining > 0 {
                        return (pos, None);
                    }
                    let header = self.current;
                    self.state = State::Header;
                    return (pos, Some(Item::Control(self.control_frame(header))));
                }

                State::Streaming => {
                    let avail = input.len() - pos;
                    if avail == 0 {
                        return (pos, None);
                    }
                    let take = (self.remaining as usize).min(avail);
                    let chunk = &input[pos..pos + take];
                    self.remaining -= take as u32;
                    pos += take;
                    let end = self.remaining == 0;
                    let header = self.current;
                    if end {
                        self.state = State::Header;
                    }
                    // Flow control accounts for the whole DATA payload,
                    // including any padding we hand back to the caller.
                    if header.kind == frame_type::DATA {
                        self.pending_window += take as u32;
                    }
                    return (pos, Some(Item::Body { header, chunk, end }));
                }
            }
        }
    }
}

fn is_control(kind: u8) -> bool {
    matches!(
        kind,
        frame_type::SETTINGS
            | frame_type::PING
            | frame_type::WINDOW_UPDATE
            | frame_type::GOAWAY
            | frame_type::RST_STREAM
    )
}

// ---------------------------------------------------------------- writing

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2Error {
    ShortBuffer,
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), H2Error> {
        if self.pos + bytes.len() > self.buf.len() {
            return Err(H2Error::ShortBuffer);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    fn put_u8(&mut self, b: u8) -> Result<(), H2Error> {
        self.put(&[b])
    }

    pub fn preface(&mut self) -> Result<(), H2Error> {
        self.put(PREFACE)
    }

    fn frame_header(
        &mut self,
        length: u32,
        kind: u8,
        flags: u8,
        stream_id: u32,
    ) -> Result<(), H2Error> {
        let l = length.to_be_bytes();
        self.put(&[l[1], l[2], l[3], kind, flags])?;
        self.put(&stream_id.to_be_bytes())
    }

    /// Our SETTINGS. `HEADER_TABLE_SIZE = 0` forbids the server from using the
    /// HPACK dynamic table, which is what makes ignoring HEADERS frames safe.
    pub fn settings(&mut self, initial_window: u32, max_frame: u32) -> Result<(), H2Error> {
        let entries: [(u16, u32); 4] = [
            (setting::HEADER_TABLE_SIZE, 0),
            (setting::ENABLE_PUSH, 0),
            (setting::INITIAL_WINDOW_SIZE, initial_window),
            (setting::MAX_FRAME_SIZE, max_frame),
        ];
        self.frame_header((entries.len() * 6) as u32, frame_type::SETTINGS, 0, 0)?;
        for (id, val) in entries {
            self.put(&id.to_be_bytes())?;
            self.put(&val.to_be_bytes())?;
        }
        Ok(())
    }

    pub fn settings_ack(&mut self) -> Result<(), H2Error> {
        self.frame_header(0, frame_type::SETTINGS, flag::ACK, 0)
    }

    pub fn ping_ack(&mut self, payload: &[u8]) -> Result<(), H2Error> {
        let mut data = [0u8; 8];
        let n = payload.len().min(8);
        data[..n].copy_from_slice(&payload[..n]);
        self.frame_header(8, frame_type::PING, flag::ACK, 0)?;
        self.put(&data)
    }

    pub fn window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), H2Error> {
        self.frame_header(4, frame_type::WINDOW_UPDATE, 0, stream_id)?;
        self.put(&(increment & 0x7fff_ffff).to_be_bytes())
    }

    pub fn data(&mut self, stream_id: u32, payload: &[u8], end_stream: bool) -> Result<(), H2Error> {
        let flags = if end_stream { flag::END_STREAM } else { 0 };
        self.frame_header(payload.len() as u32, frame_type::DATA, flags, stream_id)?;
        self.put(payload)
    }

    /// A `POST` request HEADERS frame for the control-plane RPCs.
    ///
    /// The header block is fixed in shape, so it is emitted directly rather
    /// than through a general HPACK encoder.
    pub fn post_headers(
        &mut self,
        stream_id: u32,
        authority: &str,
        path: &str,
        content_length: usize,
    ) -> Result<(), H2Error> {
        // Build the block first: the frame header needs its length up front.
        let mut block = [0u8; 256];
        let mut b = Writer::new(&mut block);
        b.put_u8(0x83)?; // indexed static 3  -> :method: POST
        b.put_u8(0x86)?; // indexed static 6  -> :scheme: http
        b.literal(4, path.as_bytes())?; // :path
        b.literal(1, authority.as_bytes())?; // :authority
        b.literal_named(b"content-type", b"application/json")?;
        let mut len_buf = [0u8; 20];
        let len_str = write_usize(content_length, &mut len_buf);
        b.literal_named(b"content-length", len_str)?;
        let block_len = b.len();

        self.frame_header(
            block_len as u32,
            frame_type::HEADERS,
            flag::END_HEADERS,
            stream_id,
        )?;
        self.put(&block[..block_len])
    }

    /// Literal header field, never indexed, with the name taken from the static
    /// table. Values are emitted without Huffman coding.
    fn literal(&mut self, name_index: u8, value: &[u8]) -> Result<(), H2Error> {
        // Pattern 0001xxxx: literal without indexing, 4-bit name index.
        self.encode_integer(name_index as u32, 4, 0x10)?;
        self.encode_integer(value.len() as u32, 7, 0x00)?;
        self.put(value)
    }

    /// Literal header field with a new (uncompressed) name.
    fn literal_named(&mut self, name: &[u8], value: &[u8]) -> Result<(), H2Error> {
        self.put_u8(0x10)?; // literal without indexing, name index 0 => new name
        self.encode_integer(name.len() as u32, 7, 0x00)?;
        self.put(name)?;
        self.encode_integer(value.len() as u32, 7, 0x00)?;
        self.put(value)
    }

    /// HPACK integer encoding (RFC 7541 §5.1) with an `n`-bit prefix.
    fn encode_integer(&mut self, value: u32, prefix_bits: u8, flags: u8) -> Result<(), H2Error> {
        let max = (1u32 << prefix_bits) - 1;
        if value < max {
            return self.put_u8(flags | value as u8);
        }
        self.put_u8(flags | max as u8)?;
        let mut rest = value - max;
        while rest >= 128 {
            self.put_u8((rest % 128) as u8 + 128)?;
            rest /= 128;
        }
        self.put_u8(rest as u8)
    }
}

/// Decimal-renders a `usize` into `buf`, returning the used prefix.
fn write_usize(mut v: usize, buf: &mut [u8; 20]) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf.copy_within(i..20, 0);
    &buf[..20 - i]
}

/// Parses a SETTINGS payload into `(id, value)` pairs.
pub fn settings_iter(payload: &[u8]) -> impl Iterator<Item = (u16, u32)> + '_ {
    payload.chunks_exact(6).map(|c| {
        (
            u16::from_be_bytes([c[0], c[1]]),
            u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(length: u32, kind: u8, flags: u8, stream_id: u32) -> [u8; 9] {
        let l = length.to_be_bytes();
        let s = stream_id.to_be_bytes();
        [l[1], l[2], l[3], kind, flags, s[0], s[1], s[2], s[3]]
    }

    #[test]
    fn reads_a_settings_frame_whole() {
        let mut r = FrameReader::new();
        let mut input = [0u8; 9 + 12];
        input[..9].copy_from_slice(&hdr(12, frame_type::SETTINGS, 0, 0));
        input[9..15].copy_from_slice(&[0, 4, 0, 1, 0, 0]); // INITIAL_WINDOW_SIZE
        input[15..21].copy_from_slice(&[0, 5, 0, 0, 0x40, 0]); // MAX_FRAME_SIZE

        let (used, item) = r.feed(&input);
        assert_eq!(used, input.len());
        match item {
            Some(Item::Control(cf)) => {
                assert_eq!(cf.header.kind, frame_type::SETTINGS);
                let mut seen = [(0u16, 0u32); 2];
                let mut n = 0;
                for s in settings_iter(cf.payload()) {
                    seen[n] = s;
                    n += 1;
                }
                assert_eq!(n, 2);
                assert_eq!(seen, [(4u16, 65536u32), (5, 16384)]);
            }
            other => panic!("expected control frame, got {other:?}"),
        }
    }

    /// The whole point of the streaming reader: a payload split across reads
    /// must arrive as chunks without ever being buffered whole.
    #[test]
    fn streams_data_across_reads() {
        let mut r = FrameReader::new();
        let head = hdr(10, frame_type::DATA, flag::END_STREAM, 1);

        let (used, item) = r.feed(&head);
        assert_eq!(used, 9);
        assert!(item.is_none(), "header alone yields no item");

        let (used, item) = r.feed(b"hello");
        assert_eq!(used, 5);
        match item {
            Some(Item::Body { chunk, end, .. }) => {
                assert_eq!(chunk, b"hello");
                assert!(!end);
            }
            other => panic!("expected body, got {other:?}"),
        }

        let (used, item) = r.feed(b"world");
        assert_eq!(used, 5);
        match item {
            Some(Item::Body { chunk, end, header }) => {
                assert_eq!(chunk, b"world");
                assert!(end);
                assert!(header.end_stream());
            }
            other => panic!("expected final body, got {other:?}"),
        }

        assert_eq!(r.take_pending_window(), 10);
        assert_eq!(r.take_pending_window(), 0, "window debt is drained once");
    }

    #[test]
    fn handles_empty_frames() {
        let mut r = FrameReader::new();
        let input = hdr(0, frame_type::SETTINGS, flag::ACK, 0);
        let (used, item) = r.feed(&input);
        assert_eq!(used, 9);
        match item {
            Some(Item::Control(cf)) => {
                assert_eq!(cf.header.flags, flag::ACK);
                assert!(cf.payload().is_empty());
            }
            other => panic!("expected settings ack, got {other:?}"),
        }
    }

    /// A GOAWAY with a long debug string must not be buffered in full, but the
    /// reader still has to consume every byte or the stream desynchronises.
    #[test]
    fn drains_oversized_control_frames() {
        let mut r = FrameReader::new();
        let big = 300u32;
        let mut input = [0u8; 9 + 300];
        input[..9].copy_from_slice(&hdr(big, frame_type::GOAWAY, 0, 0));
        let (used, item) = r.feed(&input);
        assert_eq!(used, input.len(), "all bytes consumed");
        match item {
            Some(Item::Control(cf)) => {
                assert_eq!(cf.header.kind, frame_type::GOAWAY);
                assert_eq!(cf.payload().len(), CONTROL_FRAME_MAX);
            }
            other => panic!("expected truncated goaway, got {other:?}"),
        }
    }

    #[test]
    fn hpack_integer_uses_the_continuation_form() {
        // RFC 7541 C.1.2: 1337 with a 5-bit prefix encodes as 0x1F 0x9A 0x0A.
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        w.encode_integer(1337, 5, 0x00).unwrap();
        assert_eq!(&buf[..3], &[0x1f, 0x9a, 0x0a]);

        // RFC 7541 C.1.1: 10 with a 5-bit prefix fits in the prefix itself.
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        w.encode_integer(10, 5, 0x00).unwrap();
        assert_eq!(&buf[..1], &[0x0a]);

        // The 7-bit prefix we actually use for string lengths.
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        w.encode_integer(1337, 7, 0x00).unwrap();
        assert_eq!(&buf[..3], &[0x7f, 0xba, 0x09]);
    }

    #[test]
    fn post_headers_are_well_formed() {
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.post_headers(1, "controlplane.tailscale.com", "/machine/register", 42)
            .unwrap();
        let n = w.len();
        assert_eq!(buf[3], frame_type::HEADERS);
        assert_eq!(buf[4], flag::END_HEADERS);
        assert_eq!(u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]), 1);
        // Declared block length matches what was actually written.
        let declared = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
        assert_eq!(declared, n - FRAME_HEADER_LEN);
        // Static-table indices for :method POST and :scheme http lead.
        assert_eq!(buf[9], 0x83);
        assert_eq!(buf[10], 0x86);
        let body = &buf[..n];
        assert!(find(body, b"/machine/register").is_some());
        assert!(find(body, b"controlplane.tailscale.com").is_some());
        assert!(find(body, b"application/json").is_some());
        assert!(find(body, b"42").is_some());
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn renders_content_length() {
        let mut b = [0u8; 20];
        assert_eq!(write_usize(0, &mut b), b"0");
        assert_eq!(write_usize(42, &mut b), b"42");
        assert_eq!(write_usize(1048576, &mut b), b"1048576");
    }
}
