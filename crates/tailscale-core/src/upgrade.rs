//! The HTTP/1.1 protocol switch that fronts the ts2021 Noise channel.
//!
//! Tailscale's control plane serves this on **plain port 80**. There is no TLS
//! on this path and none is needed: Noise supplies confidentiality and
//! authentication on top, so a middlebox intercepting port 80 sees only Noise.
//! Upstream treats port 80 as the happy path and reserves 443 for a
//! TLS-wrapped fallback whose certificate it deliberately does not verify.
//!
//! The Noise initiation rides in the request header rather than after the
//! switch, which saves a round trip — the server can begin its half of the
//! handshake before it has even answered `101`.

pub const UPGRADE_PATH: &str = "/ts2021";
pub const UPGRADE_HEADER_VALUE: &str = "tailscale-control-protocol";
pub const HANDSHAKE_HEADER_NAME: &str = "X-Tailscale-Handshake";

/// Base64 of a 101-byte initiation, plus generous room for the rest.
pub const MAX_REQUEST_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeError {
    /// Response headers are not complete yet; read more bytes and retry.
    Incomplete,
    /// Status line was not `101 Switching Protocols`.
    NotSwitching,
    /// Malformed status line.
    Malformed,
    /// Output buffer too small.
    ShortBuffer,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding. Written out rather than pulled from a crate so
/// the core stays dependency-light for the `no_std` build.
pub fn base64_encode(input: &[u8], out: &mut [u8]) -> Result<usize, UpgradeError> {
    let needed = input.len().div_ceil(3) * 4;
    if out.len() < needed {
        return Err(UpgradeError::ShortBuffer);
    }
    let mut o = 0;
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out[o] = B64[(n >> 18) as usize & 0x3f];
        out[o + 1] = B64[(n >> 12) as usize & 0x3f];
        out[o + 2] = if chunk.len() > 1 {
            B64[(n >> 6) as usize & 0x3f]
        } else {
            b'='
        };
        out[o + 3] = if chunk.len() > 2 {
            B64[n as usize & 0x3f]
        } else {
            b'='
        };
        o += 4;
    }
    Ok(needed)
}

/// Writes the upgrade request into `out`, returning its length.
pub fn build_request(
    host: &str,
    initiation: &[u8],
    out: &mut [u8],
) -> Result<usize, UpgradeError> {
    let mut b64 = [0u8; 200];
    let n = base64_encode(initiation, &mut b64)?;

    let mut w = Writer { buf: out, pos: 0 };
    w.str("POST ")?;
    w.str(UPGRADE_PATH)?;
    w.str(" HTTP/1.1\r\nHost: ")?;
    w.str(host)?;
    w.str("\r\nUpgrade: ")?;
    w.str(UPGRADE_HEADER_VALUE)?;
    w.str("\r\nConnection: upgrade\r\n")?;
    w.str(HANDSHAKE_HEADER_NAME)?;
    w.str(": ")?;
    w.bytes(&b64[..n])?;
    // Content-Length is required: without it the server may wait for a body on
    // a POST it will never receive, and the upgrade stalls.
    w.str("\r\nContent-Length: 0\r\n\r\n")?;
    Ok(w.pos)
}

/// Checks for `101 Switching Protocols` and locates the end of the headers.
///
/// Returns the offset just past the blank line, so the caller knows where the
/// Noise response begins — the server may have coalesced both into one read.
pub fn parse_response(buf: &[u8]) -> Result<usize, UpgradeError> {
    let end = find_headers_end(buf).ok_or(UpgradeError::Incomplete)?;
    let line_end = buf.iter().position(|&b| b == b'\r').ok_or(UpgradeError::Malformed)?;
    let status = &buf[..line_end];
    // "HTTP/1.1 101 Switching Protocols"
    let code_start = status
        .iter()
        .position(|&b| b == b' ')
        .ok_or(UpgradeError::Malformed)?
        + 1;
    if status.len() < code_start + 3 {
        return Err(UpgradeError::Malformed);
    }
    if &status[code_start..code_start + 3] != b"101" {
        return Err(UpgradeError::NotSwitching);
    }
    Ok(end)
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn str(&mut self, s: &str) -> Result<(), UpgradeError> {
        self.bytes(s.as_bytes())
    }
    fn bytes(&mut self, b: &[u8]) -> Result<(), UpgradeError> {
        if self.pos + b.len() > self.buf.len() {
            return Err(UpgradeError::ShortBuffer);
        }
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        let mut out = [0u8; 32];
        let n = base64_encode(b"f", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zg==");
        let n = base64_encode(b"fo", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm8=");
        let n = base64_encode(b"foo", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm9v");
        let n = base64_encode(b"foobar", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm9vYmFy");
    }

    #[test]
    fn request_has_the_headers_the_server_demands() {
        let mut out = [0u8; MAX_REQUEST_LEN];
        let n = build_request("controlplane.tailscale.com", &[0u8; 101], &mut out).unwrap();
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("POST /ts2021 HTTP/1.1\r\n"));
        assert!(s.contains("Host: controlplane.tailscale.com\r\n"));
        assert!(s.contains("Upgrade: tailscale-control-protocol\r\n"));
        assert!(s.contains("X-Tailscale-Handshake: "));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn accepts_101_and_rejects_others() {
        let ok = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
        assert_eq!(parse_response(ok), Ok(ok.len()));

        let bad = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 35\r\n\r\n";
        assert_eq!(parse_response(bad), Err(UpgradeError::NotSwitching));

        assert_eq!(
            parse_response(b"HTTP/1.1 101 Switching"),
            Err(UpgradeError::Incomplete)
        );
    }

    /// The server is free to coalesce the 101 and the Noise response into one
    /// TCP segment, so the caller must be told where the headers stop.
    #[test]
    fn reports_offset_past_headers() {
        const HEADERS: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\r\n";
        let mut buf = [0u8; HEADERS.len() + 3];
        buf[..HEADERS.len()].copy_from_slice(HEADERS);
        // A Noise response frame header, coalesced into the same segment.
        buf[HEADERS.len()..].copy_from_slice(&[0x02, 0x00, 0x30]);
        assert_eq!(parse_response(&buf), Ok(HEADERS.len()));
    }
}
