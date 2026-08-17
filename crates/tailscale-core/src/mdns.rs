//! Just enough mDNS to relay a query onto a LAN and the answers back.
//!
//! This is not a Tailscale protocol, but it lives here for the same reason
//! everything else does: it is `no_std` and sans-IO, so it can be tested on a
//! laptop instead of by flashing a board.
//!
//! Discovery is the one thing a tailnet cannot carry. mDNS is UDP multicast to
//! `224.0.0.251:5353`, and multicast is not routed between a tailnet and a LAN
//! — a client's browse never leaves its own link, so nothing on the far side
//! can answer it. A device that is meant to make a LAN reachable therefore has
//! to answer discovery *on behalf of* that LAN, and be addressed directly to do
//! it.
//!
//! The relay needs almost no parsing. A query arriving from a client is already
//! a well-formed DNS message, and the answers coming back are too, so both can
//! be forwarded verbatim. Exactly one bit has to change: the **QU bit**, the
//! top bit of a question's class, which asks responders to reply by unicast to
//! the sender rather than to the multicast group. Setting it is what lets a
//! device collect answers on an ordinary UDP socket without joining a multicast
//! group at all.

/// The multicast address and port mDNS is spoken on.
pub const GROUP: [u8; 4] = [224, 0, 0, 251];
pub const PORT: u16 = 5353;

/// Smallest message that can carry a header and one question.
const HEADER_LEN: usize = 12;

/// Top bit of a question's class: "answer me by unicast".
const QU_BIT: u8 = 0x80;

#[derive(Debug, PartialEq, Eq)]
pub enum MdnsError {
    /// Too short to be a DNS message, or a name that never terminates.
    Malformed,
}

/// Rewrites every question in `msg` to request a unicast reply.
///
/// Returns the number of questions touched. The message is modified in place
/// because it is forwarded onward unchanged otherwise — the point is to relay
/// the client's own query, not to compose a new one that might ask something
/// subtly different.
pub fn request_unicast_replies(msg: &mut [u8]) -> Result<u16, MdnsError> {
    rewrite_question_class(msg, true)
}

/// Clears the QU bit from every question, undoing [`request_unicast_replies`].
///
/// Responders echo the question back in their answer, QU bit and all. A client
/// that never set that bit compares the echo against what it sent, finds
/// `CLASS32769` where it asked for `CLASS1`, and rejects the answer as a
/// mismatched question — so a relay has to put the question back the way the
/// client wrote it before handing the answer over.
pub fn restore_multicast_questions(msg: &mut [u8]) -> Result<u16, MdnsError> {
    rewrite_question_class(msg, false)
}

fn rewrite_question_class(msg: &mut [u8], set: bool) -> Result<u16, MdnsError> {
    if msg.len() < HEADER_LEN {
        return Err(MdnsError::Malformed);
    }
    let questions = u16::from_be_bytes([msg[4], msg[5]]);
    let mut pos = HEADER_LEN;
    for _ in 0..questions {
        pos = skip_name(msg, pos)?;
        // QTYPE(2) then QCLASS(2); the QU bit is the top bit of QCLASS.
        let class_at = pos + 2;
        if class_at + 2 > msg.len() {
            return Err(MdnsError::Malformed);
        }
        if set {
            msg[class_at] |= QU_BIT;
        } else {
            msg[class_at] &= !QU_BIT;
        }
        pos = class_at + 2;
    }
    Ok(questions)
}

/// True if this looks like a response rather than a query.
///
/// Used to decide whether a datagram arriving on the LAN socket is an answer
/// worth relaying back, or somebody else's question that happens to have been
/// addressed to us.
pub fn is_response(msg: &[u8]) -> bool {
    // QR is the top bit of the flags word.
    msg.len() >= HEADER_LEN && msg[2] & 0x80 != 0
}

/// The message's transaction ID, used to match answers to the query.
///
/// mDNS responders are permitted to answer with an ID of zero, so this is a
/// hint for pairing rather than something to filter on strictly — discarding
/// everything that does not match would throw away most real answers.
pub fn transaction_id(msg: &[u8]) -> Option<u16> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    Some(u16::from_be_bytes([msg[0], msg[1]]))
}

/// Overwrites the transaction ID, so a relayed answer carries the ID the
/// client used rather than whatever the responder chose.
pub fn set_transaction_id(msg: &mut [u8], id: u16) {
    if msg.len() >= HEADER_LEN {
        let be = id.to_be_bytes();
        msg[0] = be[0];
        msg[1] = be[1];
    }
}

/// Advances past a DNS name, returning the offset just after it.
///
/// Compression pointers are rejected rather than followed. A question in a
/// query has nothing earlier to point at, so a pointer here means either a
/// malformed message or one crafted to make a parser loop.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, MdnsError> {
    loop {
        let len = *msg.get(pos).ok_or(MdnsError::Malformed)? as usize;
        if len & 0xc0 != 0 {
            return Err(MdnsError::Malformed);
        }
        pos += 1;
        if len == 0 {
            return Ok(pos);
        }
        pos = pos.checked_add(len).ok_or(MdnsError::Malformed)?;
        if pos > msg.len() {
            return Err(MdnsError::Malformed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_services._dns-sd._udp.local` PTR — what a client sends to enumerate
    /// every service type on a link.
    fn browse_query() -> [u8; 46] {
        // 12 header + 29 label bytes + 1 terminator + 4 type/class.
        let mut q = [0u8; 46];
        q[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // id
        q[4..6].copy_from_slice(&1u16.to_be_bytes()); // one question
        let name: &[&[u8]] = &[b"_services", b"_dns-sd", b"_udp", b"local"];
        let mut pos = 12;
        for label in name {
            q[pos] = label.len() as u8;
            q[pos + 1..pos + 1 + label.len()].copy_from_slice(label);
            pos += 1 + label.len();
        }
        q[pos] = 0;
        pos += 1;
        q[pos..pos + 2].copy_from_slice(&12u16.to_be_bytes()); // PTR
        q[pos + 2..pos + 4].copy_from_slice(&1u16.to_be_bytes()); // IN
        assert_eq!(pos + 4, q.len(), "fixture must have no trailing padding");
        q
    }

    #[test]
    fn qu_bit_is_set_on_every_question() {
        let mut q = browse_query();
        // The class sits at the end: type(2) + class(2).
        let class_at = q.len() - 2;
        assert_eq!(q[class_at] & QU_BIT, 0, "starts as a multicast question");
        assert_eq!(request_unicast_replies(&mut q).unwrap(), 1);
        assert_eq!(q[class_at] & QU_BIT, QU_BIT);
        // The class's low bits still say IN — the bit is added, not assigned.
        assert_eq!(u16::from_be_bytes([q[class_at], q[class_at + 1]]) & 0x7fff, 1);
    }

    #[test]
    fn the_rest_of_the_message_is_untouched() {
        let original = browse_query();
        let mut q = original;
        request_unicast_replies(&mut q).unwrap();
        let class_at = q.len() - 2;
        assert_eq!(q[..class_at], original[..class_at], "name and type intact");
        assert_eq!(q[class_at + 1], original[class_at + 1]);
    }

    /// A responder echoes the question back with the bit still set, and a
    /// client that never asked for unicast rejects the answer over it.
    #[test]
    fn the_qu_bit_can_be_put_back_the_way_the_client_wrote_it() {
        let original = browse_query();
        let mut q = original;
        request_unicast_replies(&mut q).unwrap();
        assert_ne!(q, original);
        assert_eq!(restore_multicast_questions(&mut q).unwrap(), 1);
        assert_eq!(q, original, "byte-identical to what the client sent");
    }

    #[test]
    fn a_truncated_message_is_rejected_rather_than_indexed() {
        for len in 0..12 {
            let mut short = [0u8; 12];
            assert_eq!(
                request_unicast_replies(&mut short[..len]),
                Err(MdnsError::Malformed)
            );
        }
        // Claims a question but has no room for one.
        let mut q = [0u8; 12];
        q[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(request_unicast_replies(&mut q), Err(MdnsError::Malformed));
    }

    /// A pointer in a question would have nothing earlier to point at, so it is
    /// either malformed or an attempt to make the parser chase its own tail.
    #[test]
    fn compression_pointers_are_refused() {
        let mut q = [0u8; 20];
        q[4..6].copy_from_slice(&1u16.to_be_bytes());
        q[12] = 0xc0;
        q[13] = 0x0c;
        assert_eq!(request_unicast_replies(&mut q), Err(MdnsError::Malformed));
    }

    #[test]
    fn responses_are_told_from_queries() {
        let q = browse_query();
        assert!(!is_response(&q));
        let mut r = q;
        r[2] |= 0x80;
        assert!(is_response(&r));
        assert!(!is_response(&[0u8; 4]));
    }

    #[test]
    fn transaction_id_round_trips() {
        let mut q = browse_query();
        assert_eq!(transaction_id(&q), Some(0x1234));
        set_transaction_id(&mut q, 0xbeef);
        assert_eq!(transaction_id(&q), Some(0xbeef));
        assert_eq!(transaction_id(&[0u8; 2]), None);
    }
}
