//! TSMP — Tailscale's in-tunnel message protocol, IP protocol 99.
//!
//! `tailscale ping` uses this rather than ICMP, so answering it is what makes
//! a node visibly reachable to the standard tooling. It rides inside the
//! WireGuard tunnel as an ordinary IPv4 packet, which means a reply has to be
//! a well-formed IPv4 packet too — header checksum included.
//!
//! Only the ping/pong pair is implemented. The other message types report
//! rejected connections and advertise disco keys, neither of which this client
//! has anything to say about yet.

pub const IP_PROTO_TSMP: u8 = 99;
pub const TYPE_PING: u8 = b'p';
pub const TYPE_PONG: u8 = b'o';

const IPV4_HEADER_LEN: usize = 20;
/// `'o'` + 8 echoed bytes + a 2-byte PeerAPI port.
const PONG_PAYLOAD_LEN: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    /// Opaque bytes the sender wants echoed back untouched.
    pub data: [u8; 8],
    pub src: [u8; 4],
    /// The address the request was sent to — our own, and therefore the source
    /// address the reply must carry.
    pub dst: [u8; 4],
}

/// Recognises a TSMP ping inside a decrypted tunnel packet.
///
/// Returns `None` for anything else, including IPv6 and other IP protocols,
/// so callers can pass every inbound packet through without pre-filtering.
pub fn parse_ping(packet: &[u8]) -> Option<Ping> {
    if packet.len() < IPV4_HEADER_LEN {
        return None;
    }
    // Version 4 only. The IHL may exceed 5 when options are present, so the
    // payload offset is computed rather than assumed.
    if packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl + 9 {
        return None;
    }
    if packet[9] != IP_PROTO_TSMP {
        return None;
    }
    let payload = &packet[ihl..];
    if payload[0] != TYPE_PING {
        return None;
    }

    let mut data = [0u8; 8];
    data.copy_from_slice(&payload[1..9]);
    let mut src = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&packet[16..20]);
    Some(Ping { data, src, dst })
}

/// Builds the IPv4 TSMP pong answering `ping`, returning its length.
///
/// Source and destination are taken from the request and swapped: the address
/// the peer used to reach us is the one it expects to hear back from.
pub fn write_pong(ping: &Ping, out: &mut [u8]) -> Option<usize> {
    let total = IPV4_HEADER_LEN + PONG_PAYLOAD_LEN;
    if out.len() < total {
        return None;
    }
    out[..total].fill(0);
    out[0] = 0x45; // IPv4, 5-word header
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[8] = 64; // TTL
    out[9] = IP_PROTO_TSMP;
    out[12..16].copy_from_slice(&ping.dst);
    out[16..20].copy_from_slice(&ping.src);
    // Checksum is computed over the header with the field itself zeroed,
    // which the fill above already guarantees.
    let sum = checksum(&out[..IPV4_HEADER_LEN]);
    out[10..12].copy_from_slice(&sum.to_be_bytes());

    out[IPV4_HEADER_LEN] = TYPE_PONG;
    out[IPV4_HEADER_LEN + 1..IPV4_HEADER_LEN + 9].copy_from_slice(&ping.data);
    // PeerAPIPort: we serve no peer API, so zero.
    Some(total)
}

/// Standard IPv4 header checksum: ones' complement of the ones' complement
/// sum of the 16-bit words.
fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping_packet(data: [u8; 8]) -> [u8; 29] {
        let mut p = [0u8; 29];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&29u16.to_be_bytes());
        p[8] = 64;
        p[9] = IP_PROTO_TSMP;
        p[12..16].copy_from_slice(&[100, 64, 0, 2]);
        p[16..20].copy_from_slice(&[100, 64, 0, 1]);
        p[20] = TYPE_PING;
        p[21..29].copy_from_slice(&data);
        p
    }

    #[test]
    fn parses_a_ping() {
        let p = ping_packet([1, 2, 3, 4, 5, 6, 7, 8]);
        let ping = parse_ping(&p).unwrap();
        assert_eq!(ping.data, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(ping.src, [100, 64, 0, 2]);
        assert_eq!(ping.dst, [100, 64, 0, 1]);
    }

    #[test]
    fn ignores_everything_that_is_not_a_tsmp_ping() {
        let mut p = ping_packet([0; 8]);
        p[9] = 6; // TCP
        assert_eq!(parse_ping(&p), None);

        let mut p = ping_packet([0; 8]);
        p[20] = TYPE_PONG;
        assert_eq!(parse_ping(&p), None, "a pong is not a ping");

        let mut p = ping_packet([0; 8]);
        p[0] = 0x60; // IPv6
        assert_eq!(parse_ping(&p), None);

        assert_eq!(parse_ping(&[]), None);
        assert_eq!(parse_ping(&[0x45; 10]), None, "truncated");
    }

    /// Addresses must be swapped, or the reply goes back to ourselves.
    #[test]
    fn pong_swaps_addresses_and_echoes_data() {
        let ping = parse_ping(&ping_packet([9; 8])).unwrap();
        let mut out = [0u8; 64];
        let n = write_pong(&ping, &mut out).unwrap();
        assert_eq!(n, 31);

        assert_eq!(&out[12..16], &[100, 64, 0, 1], "src is who they pinged");
        assert_eq!(&out[16..20], &[100, 64, 0, 2], "dst is the requester");
        assert_eq!(out[9], IP_PROTO_TSMP);
        assert_eq!(out[20], TYPE_PONG);
        assert_eq!(&out[21..29], &[9u8; 8], "opaque bytes echoed verbatim");
    }

    /// A wrong header checksum makes the peer drop the reply silently, so this
    /// is verified the way a receiver does it: summing the whole header,
    /// checksum field included, must yield zero.
    #[test]
    fn pong_header_checksum_validates() {
        let ping = parse_ping(&ping_packet([0; 8])).unwrap();
        let mut out = [0u8; 64];
        write_pong(&ping, &mut out).unwrap();
        assert_ne!(&out[10..12], &[0, 0], "checksum was actually written");
        assert_eq!(checksum(&out[..IPV4_HEADER_LEN]), 0);
    }

    #[test]
    fn refuses_a_short_buffer() {
        let ping = parse_ping(&ping_packet([0; 8])).unwrap();
        assert_eq!(write_pong(&ping, &mut [0u8; 8]), None);
    }
}
