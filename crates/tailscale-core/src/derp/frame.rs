//! DERP framing: `type u8 | length u32 be | payload`.
//!
//! Payloads stream rather than accumulate. A relayed packet is MTU-sized, but
//! the length field is 32 bits and comes from the network, so a reader that
//! trusts it and allocates is handing a remote party a memory switch. Small
//! control frames are captured whole; anything carrying a packet is delivered
//! in chunks.

use super::MAGIC;

pub const HEADER_LEN: usize = 5;

/// Largest frame we will process. Well above a relayed MTU-sized packet and
/// far below what the 32-bit length field could ask for.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// Frames captured whole are bounded by this; larger ones stream.
const CONTROL_FRAME_MAX: usize = 512;

/// Length of a public key as it appears inside DERP frames.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    ServerKey = 0x01,
    ClientInfo = 0x02,
    ServerInfo = 0x03,
    SendPacket = 0x04,
    RecvPacket = 0x05,
    KeepAlive = 0x06,
    NotePreferred = 0x07,
    PeerGone = 0x08,
    PeerPresent = 0x09,
    ForwardPacket = 0x0a,
    WatchConns = 0x10,
    ClosePeer = 0x11,
    Ping = 0x12,
    Pong = 0x13,
    Health = 0x14,
    Restarting = 0x15,
    /// Anything we do not model. Consumed and ignored rather than treated as a
    /// protocol error, so a server-side addition cannot wedge the connection.
    Unknown = 0xff,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::ServerKey,
            0x02 => Self::ClientInfo,
            0x03 => Self::ServerInfo,
            0x04 => Self::SendPacket,
            0x05 => Self::RecvPacket,
            0x06 => Self::KeepAlive,
            0x07 => Self::NotePreferred,
            0x08 => Self::PeerGone,
            0x09 => Self::PeerPresent,
            0x0a => Self::ForwardPacket,
            0x10 => Self::WatchConns,
            0x11 => Self::ClosePeer,
            0x12 => Self::Ping,
            0x13 => Self::Pong,
            0x14 => Self::Health,
            0x15 => Self::Restarting,
            _ => Self::Unknown,
        }
    }

    /// True for frames small enough to hand back in one piece.
    fn is_control(self) -> bool {
        !matches!(
            self,
            Self::SendPacket | Self::RecvPacket | Self::ForwardPacket | Self::Unknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerpError {
    /// Frame length exceeds [`MAX_FRAME_LEN`].
    FrameTooLarge,
    /// The server's opening frame was not a well-formed `ServerKey`.
    BadServerKey,
    ShortBuffer,
}

/// A frame the reader produced.
#[derive(Debug)]
pub enum Frame<'a> {
    /// A small frame, captured whole.
    Control {
        kind: FrameType,
        payload: ControlPayload,
    },
    /// Part of a streamed payload.
    Body {
        kind: FrameType,
        total_len: u32,
        chunk: &'a [u8],
        end: bool,
    },
}

/// Owned storage for a captured control frame, so callers can hold one while
/// continuing to feed the reader.
#[derive(Clone, Copy)]
pub struct ControlPayload {
    buf: [u8; CONTROL_FRAME_MAX],
    len: usize,
}

impl ControlPayload {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Debug for ControlPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlPayload({} bytes)", self.len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Buffering,
    Streaming,
    Draining,
}

/// Incremental DERP frame reader.
pub struct FrameReader {
    state: State,
    header: [u8; HEADER_LEN],
    header_have: usize,
    kind: FrameType,
    total: u32,
    remaining: u32,
    control: [u8; CONTROL_FRAME_MAX],
    control_len: usize,
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
            header: [0; HEADER_LEN],
            header_have: 0,
            kind: FrameType::Unknown,
            total: 0,
            remaining: 0,
            control: [0; CONTROL_FRAME_MAX],
            control_len: 0,
        }
    }

    /// Consumes bytes, returning how many were used and at most one frame.
    /// `(0, None)` means more input is needed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> Result<(usize, Option<Frame<'a>>), DerpError> {
        let mut pos = 0;
        loop {
            match self.state {
                State::Header => {
                    let need = HEADER_LEN - self.header_have;
                    let take = need.min(input.len() - pos);
                    self.header[self.header_have..self.header_have + take]
                        .copy_from_slice(&input[pos..pos + take]);
                    self.header_have += take;
                    pos += take;
                    if self.header_have < HEADER_LEN {
                        return Ok((pos, None));
                    }
                    self.header_have = 0;
                    self.kind = FrameType::from_u8(self.header[0]);
                    self.total = u32::from_be_bytes([
                        self.header[1],
                        self.header[2],
                        self.header[3],
                        self.header[4],
                    ]);
                    // Refuse before reserving anything: the length is
                    // attacker-controlled.
                    if self.total > MAX_FRAME_LEN {
                        return Err(DerpError::FrameTooLarge);
                    }
                    self.remaining = self.total;
                    self.control_len = 0;

                    if self.total == 0 {
                        let kind = self.kind;
                        self.state = State::Header;
                        return Ok((pos, Some(self.control_frame(kind))));
                    }
                    self.state = if self.kind.is_control() {
                        State::Buffering
                    } else {
                        State::Streaming
                    };
                }

                State::Buffering => {
                    let avail = input.len() - pos;
                    if avail == 0 {
                        return Ok((pos, None));
                    }
                    let space = CONTROL_FRAME_MAX - self.control_len;
                    let take = (self.remaining as usize).min(avail).min(space);
                    self.control[self.control_len..self.control_len + take]
                        .copy_from_slice(&input[pos..pos + take]);
                    self.control_len += take;
                    self.remaining -= take as u32;
                    pos += take;

                    if self.remaining == 0 {
                        let kind = self.kind;
                        self.state = State::Header;
                        return Ok((pos, Some(self.control_frame(kind))));
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
                        return Ok((pos, None));
                    }
                    let kind = self.kind;
                    self.state = State::Header;
                    return Ok((pos, Some(self.control_frame(kind))));
                }

                State::Streaming => {
                    let avail = input.len() - pos;
                    if avail == 0 {
                        return Ok((pos, None));
                    }
                    let take = (self.remaining as usize).min(avail);
                    let chunk = &input[pos..pos + take];
                    self.remaining -= take as u32;
                    pos += take;
                    let end = self.remaining == 0;
                    let kind = self.kind;
                    let total_len = self.total;
                    if end {
                        self.state = State::Header;
                    }
                    return Ok((
                        pos,
                        Some(Frame::Body {
                            kind,
                            total_len,
                            chunk,
                            end,
                        }),
                    ));
                }
            }
        }
    }

    fn control_frame(&self, kind: FrameType) -> Frame<'static> {
        Frame::Control {
            kind,
            payload: ControlPayload {
                buf: self.control,
                len: self.control_len,
            },
        }
    }
}

/// Extracts the server's public key from a `ServerKey` payload.
///
/// The frame is the magic followed by the key. The magic is checked because a
/// mismatch means we are not talking to a DERP server at all — most likely a
/// captive portal or proxy that accepted the upgrade and returned something
/// else entirely.
pub fn parse_server_key(payload: &[u8]) -> Result<[u8; KEY_LEN], DerpError> {
    if payload.len() < MAGIC.len() + KEY_LEN || !payload.starts_with(MAGIC) {
        return Err(DerpError::BadServerKey);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&payload[MAGIC.len()..MAGIC.len() + KEY_LEN]);
    Ok(key)
}

/// Writes a frame header into `out`, returning bytes written.
pub fn write_header(out: &mut [u8], kind: FrameType, len: u32) -> Result<usize, DerpError> {
    if out.len() < HEADER_LEN {
        return Err(DerpError::ShortBuffer);
    }
    out[0] = kind as u8;
    out[1..5].copy_from_slice(&len.to_be_bytes());
    Ok(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u8, len: u32) -> [u8; 5] {
        let l = len.to_be_bytes();
        [kind, l[0], l[1], l[2], l[3]]
    }

    #[test]
    fn magic_is_eight_bytes() {
        // "DERP" plus a 4-byte emoji.
        assert_eq!(MAGIC.len(), 8);
        assert!(MAGIC.starts_with(b"DERP"));
    }

    #[test]
    fn reads_a_server_key_frame() {
        let mut r = FrameReader::new();
        let mut input = [0u8; 5 + 8 + 32];
        input[..5].copy_from_slice(&header(0x01, 40));
        input[5..13].copy_from_slice(MAGIC);
        input[13..].copy_from_slice(&[7u8; 32]);

        let (used, frame) = r.feed(&input).unwrap();
        assert_eq!(used, input.len());
        match frame {
            Some(Frame::Control { kind, payload }) => {
                assert_eq!(kind, FrameType::ServerKey);
                assert_eq!(parse_server_key(payload.as_slice()).unwrap(), [7u8; 32]);
            }
            other => panic!("expected server key, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_server_key_without_the_magic() {
        let mut payload = [0u8; 40];
        payload[..8].copy_from_slice(b"NOTDERP!");
        assert_eq!(
            parse_server_key(&payload).err(),
            Some(DerpError::BadServerKey)
        );
        assert_eq!(parse_server_key(&[]).err(), Some(DerpError::BadServerKey));
    }

    /// The length field is 32 bits and comes from the network; trusting it
    /// would hand a remote party control over our memory.
    #[test]
    fn refuses_an_oversized_frame() {
        let mut r = FrameReader::new();
        let input = header(0x05, u32::MAX);
        assert_eq!(r.feed(&input).err(), Some(DerpError::FrameTooLarge));
    }

    #[test]
    fn streams_a_relayed_packet_across_reads() {
        let mut r = FrameReader::new();
        let head = header(0x05, 10);
        let (used, frame) = r.feed(&head).unwrap();
        assert_eq!(used, 5);
        assert!(frame.is_none());

        let (_, frame) = r.feed(b"hello").unwrap();
        match frame {
            Some(Frame::Body { chunk, end, .. }) => {
                assert_eq!(chunk, b"hello");
                assert!(!end);
            }
            other => panic!("expected body, got {other:?}"),
        }
        let (_, frame) = r.feed(b"world").unwrap();
        match frame {
            Some(Frame::Body {
                chunk, end, kind, ..
            }) => {
                assert_eq!(chunk, b"world");
                assert!(end);
                assert_eq!(kind, FrameType::RecvPacket);
            }
            other => panic!("expected final body, got {other:?}"),
        }
    }

    #[test]
    fn empty_frames_are_delivered() {
        let mut r = FrameReader::new();
        let input = header(0x06, 0);
        let (used, frame) = r.feed(&input).unwrap();
        assert_eq!(used, 5);
        match frame {
            Some(Frame::Control { kind, payload }) => {
                assert_eq!(kind, FrameType::KeepAlive);
                assert!(payload.as_slice().is_empty());
            }
            other => panic!("expected keepalive, got {other:?}"),
        }
    }

    /// An unmodelled frame type must be consumed, not treated as an error —
    /// a server-side addition should never wedge the connection.
    #[test]
    fn unknown_frames_are_skipped() {
        let mut r = FrameReader::new();
        let mut input = [0u8; 5 + 4];
        input[..5].copy_from_slice(&header(0x7e, 4));
        let (used, frame) = r.feed(&input).unwrap();
        assert_eq!(used, input.len());
        match frame {
            Some(Frame::Body { kind, end, .. }) => {
                assert_eq!(kind, FrameType::Unknown);
                assert!(end);
            }
            other => panic!("expected skipped body, got {other:?}"),
        }
        // The reader is back on a frame boundary.
        let next = header(0x06, 0);
        assert!(matches!(
            r.feed(&next).unwrap().1,
            Some(Frame::Control {
                kind: FrameType::KeepAlive,
                ..
            })
        ));
    }

    #[test]
    fn oversized_control_frames_are_drained_not_buffered() {
        let mut r = FrameReader::new();
        let len = (CONTROL_FRAME_MAX + 100) as u32;
        let mut input = [0u8; HEADER_LEN + CONTROL_FRAME_MAX + 100];
        input[..5].copy_from_slice(&header(0x03, len));
        let (used, frame) = r.feed(&input).unwrap();
        assert_eq!(used, input.len(), "every byte consumed");
        match frame {
            Some(Frame::Control { payload, .. }) => {
                assert_eq!(payload.as_slice().len(), CONTROL_FRAME_MAX);
            }
            other => panic!("expected truncated control frame, got {other:?}"),
        }
    }

    #[test]
    fn writes_headers() {
        let mut out = [0u8; 5];
        write_header(&mut out, FrameType::SendPacket, 1234).unwrap();
        assert_eq!(out[0], 0x04);
        assert_eq!(u32::from_be_bytes([out[1], out[2], out[3], out[4]]), 1234);
        assert_eq!(
            write_header(&mut [0u8; 2], FrameType::Ping, 0).err(),
            Some(DerpError::ShortBuffer)
        );
    }
}
