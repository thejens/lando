//! The WireGuard handshake, both roles.
//!
//! Both are implemented because a peer is as likely to initiate to us as the
//! other way round; a device that can only initiate is unreachable until it
//! happens to speak first.
//!
//! Sans-IO throughout: ephemeral keys, indices and timestamps are parameters
//! rather than generated internally, which keeps the whole handshake
//! deterministic and testable without a clock or an RNG.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

use super::{init, mac1, resp, Tai64n, WgError};
use super::{CONSTRUCTION, IDENTIFIER, INITIATION_LEN, MSG_INITIATION, MSG_RESPONSE, RESPONSE_LEN};
use crate::crypto;
use crate::key::{NodePrivate, NodePublic, KEY_LEN};

/// Every handshake AEAD uses a freshly derived key, so the nonce is always 0.
const ZERO_NONCE: [u8; 12] = [0u8; 12];
const TAG_LEN: usize = 16;

/// An all-zero pre-shared key, i.e. no PSK. Tailscale does not use one, but
/// the pattern is `IKpsk2`, so the mix still happens with zeros.
const NO_PSK: [u8; KEY_LEN] = [0u8; KEY_LEN];

/// The running `(chaining_key, hash)` pair.
struct State {
    c: [u8; KEY_LEN],
    h: [u8; KEY_LEN],
}

impl State {
    /// `h = HASH(HASH(c || IDENTIFIER) || peer_static)`, binding the handshake
    /// to the responder's identity from the very first byte.
    fn new(responder_static: &NodePublic) -> Self {
        let c = crypto::hash(CONSTRUCTION);
        let h = crypto::hash_parts(&[&c, IDENTIFIER]);
        let h = crypto::hash_parts(&[&h, responder_static.as_bytes()]);
        Self { c, h }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = crypto::hash_parts(&[&self.h, data]);
    }

    fn mix_key(&mut self, input: &[u8]) {
        let [c] = crypto::kdf::<1>(&self.c, input);
        self.c = c;
    }

    /// `KDF_2`: advances the chaining key and yields a single-use cipher.
    fn mix_key_and_cipher(&mut self, input: &[u8]) -> ChaCha20Poly1305 {
        let [c, k] = crypto::kdf::<2>(&self.c, input);
        self.c = c;
        ChaCha20Poly1305::new_from_slice(&k).expect("32-byte key")
    }

    /// `KDF_3` over the pre-shared key, mixing the middle output into the hash.
    fn mix_psk(&mut self) -> ChaCha20Poly1305 {
        let [c, tau, k] = crypto::kdf::<3>(&self.c, &NO_PSK);
        self.c = c;
        self.mix_hash(&tau);
        ChaCha20Poly1305::new_from_slice(&k).expect("32-byte key")
    }

    fn seal(
        &mut self,
        cipher: &ChaCha20Poly1305,
        out: &mut [u8],
        plaintext: &[u8],
    ) -> Result<(), WgError> {
        if out.len() != plaintext.len() + TAG_LEN {
            return Err(WgError::ShortBuffer);
        }
        let (body, tag_slot) = out.split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&ZERO_NONCE), &self.h, body)
            .map_err(|_| WgError::Decrypt)?;
        tag_slot.copy_from_slice(&tag);
        self.mix_hash(out);
        Ok(())
    }

    fn open(
        &mut self,
        cipher: &ChaCha20Poly1305,
        out: &mut [u8],
        ciphertext: &[u8],
    ) -> Result<(), WgError> {
        if ciphertext.len() != out.len() + TAG_LEN {
            return Err(WgError::Malformed);
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        out.copy_from_slice(body);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&ZERO_NONCE),
                &self.h,
                out,
                Tag::from_slice(tag),
            )
            .map_err(|_| WgError::Decrypt)?;
        self.mix_hash(ciphertext);
        Ok(())
    }

    /// Derives the transport keys. Returned in initiator order
    /// `(send, receive)`; the responder swaps them.
    fn split(self) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        let [a, b] = crypto::kdf::<2>(&self.c, &[]);
        (a, b)
    }
}

/// Keys and indices for an established WireGuard session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    pub send: [u8; KEY_LEN],
    pub receive: [u8; KEY_LEN],
    /// Index we chose; peers put this in the `receiver` field of packets to us.
    pub local_index: u32,
    /// Index the peer chose; goes in the `receiver` field of packets we send.
    pub peer_index: u32,
}

/// Our half of a handshake we started.
pub struct Initiator {
    state: State,
    ephemeral: NodePrivate,
    static_private: NodePrivate,
    local_index: u32,
}

impl Initiator {
    /// Builds a handshake initiation.
    ///
    /// `timestamp` must be strictly greater than any previously sent to this
    /// peer, or the peer discards the message without replying. See
    /// [`Tai64n`] — on a device with no clock this comes from a flash counter.
    pub fn new(
        static_private: &NodePrivate,
        peer_static: &NodePublic,
        ephemeral: NodePrivate,
        local_index: u32,
        timestamp: Tai64n,
    ) -> Result<(Self, [u8; INITIATION_LEN]), WgError> {
        let mut state = State::new(peer_static);
        let mut msg = [0u8; INITIATION_LEN];
        msg[0] = MSG_INITIATION;
        msg[init::SENDER..init::SENDER + 4].copy_from_slice(&local_index.to_le_bytes());

        let ephemeral_pub = ephemeral.public();
        // Chaining key first, then the hash — the reverse order still produces
        // a self-consistent implementation that no real peer will talk to.
        state.mix_key(ephemeral_pub.as_bytes());
        msg[init::EPHEMERAL..init::EPHEMERAL + KEY_LEN].copy_from_slice(ephemeral_pub.as_bytes());
        state.mix_hash(ephemeral_pub.as_bytes());

        let cipher = state.mix_key_and_cipher(&ephemeral.dh(peer_static));
        let static_public = static_private.public();
        let (head, rest) = msg.split_at_mut(init::STATIC);
        let _ = head;
        state.seal(
            &cipher,
            &mut rest[..KEY_LEN + TAG_LEN],
            static_public.as_bytes(),
        )?;

        let cipher = state.mix_key_and_cipher(&static_private.dh(peer_static));
        let (head, rest) = msg.split_at_mut(init::TIMESTAMP);
        let _ = head;
        state.seal(&cipher, &mut rest[..12 + TAG_LEN], timestamp.as_bytes())?;

        let m = mac1(peer_static, &msg[..init::MAC1]);
        msg[init::MAC1..init::MAC1 + m.len()].copy_from_slice(&m);
        // mac2 stays zero until a cookie reply has been received.

        Ok((
            Self {
                state,
                ephemeral,
                static_private: static_private.clone(),
                local_index,
            },
            msg,
        ))
    }

    /// Consumes the peer's response, yielding transport keys.
    pub fn consume_response(mut self, msg: &[u8]) -> Result<SessionKeys, WgError> {
        if msg.len() != RESPONSE_LEN || msg[0] != MSG_RESPONSE {
            return Err(WgError::Malformed);
        }
        let peer_index = u32::from_le_bytes(
            msg[resp::SENDER..resp::SENDER + 4]
                .try_into()
                .map_err(|_| WgError::Malformed)?,
        );

        let mut peer_ephemeral = [0u8; KEY_LEN];
        peer_ephemeral.copy_from_slice(&msg[resp::EPHEMERAL..resp::EPHEMERAL + KEY_LEN]);
        let peer_ephemeral = NodePublic(peer_ephemeral);

        self.state.mix_key(peer_ephemeral.as_bytes());
        self.state.mix_hash(peer_ephemeral.as_bytes());
        self.state.mix_key(&self.ephemeral.dh(&peer_ephemeral));
        self.state.mix_key(&self.static_private.dh(&peer_ephemeral));

        let cipher = self.state.mix_psk();
        self.state
            .open(&cipher, &mut [], &msg[resp::EMPTY..resp::EMPTY + TAG_LEN])?;

        let (send, receive) = self.state.split();
        Ok(SessionKeys {
            send,
            receive,
            local_index: self.local_index,
            peer_index,
        })
    }
}

/// Our half of a handshake a peer started.
pub struct Responder {
    state: State,
    static_private: NodePrivate,
    peer_static: NodePublic,
    peer_ephemeral: NodePublic,
    peer_index: u32,
}

/// What was learned from a peer's initiation before replying.
#[derive(Debug, Clone, Copy)]
pub struct Initiation {
    pub peer_static: NodePublic,
    /// Must be checked against the greatest timestamp previously seen from
    /// this peer; anything not strictly greater is a replay.
    pub timestamp: Tai64n,
    pub peer_index: u32,
}

impl Responder {
    /// Validates and decrypts a peer's initiation.
    ///
    /// `mac1` is checked before any Curve25519 work, which is the whole point
    /// of that field: messages not addressed to our static key are rejected
    /// cheaply, so an attacker cannot force expensive operations.
    pub fn consume_initiation(
        static_private: &NodePrivate,
        msg: &[u8],
    ) -> Result<(Self, Initiation), WgError> {
        if msg.len() != INITIATION_LEN || msg[0] != MSG_INITIATION {
            return Err(WgError::Malformed);
        }
        let static_public = static_private.public();
        let expected = mac1(&static_public, &msg[..init::MAC1]);
        if msg[init::MAC1..init::MAC1 + expected.len()] != expected {
            return Err(WgError::BadMac);
        }

        let peer_index = u32::from_le_bytes(
            msg[init::SENDER..init::SENDER + 4]
                .try_into()
                .map_err(|_| WgError::Malformed)?,
        );

        let mut state = State::new(&static_public);
        let mut peer_ephemeral = [0u8; KEY_LEN];
        peer_ephemeral.copy_from_slice(&msg[init::EPHEMERAL..init::EPHEMERAL + KEY_LEN]);
        let peer_ephemeral = NodePublic(peer_ephemeral);

        state.mix_key(peer_ephemeral.as_bytes());
        state.mix_hash(peer_ephemeral.as_bytes());

        let cipher = state.mix_key_and_cipher(&static_private.dh(&peer_ephemeral));
        let mut peer_static = [0u8; KEY_LEN];
        state.open(
            &cipher,
            &mut peer_static,
            &msg[init::STATIC..init::STATIC + KEY_LEN + TAG_LEN],
        )?;
        let peer_static = NodePublic(peer_static);

        let cipher = state.mix_key_and_cipher(&static_private.dh(&peer_static));
        let mut timestamp = [0u8; 12];
        state.open(
            &cipher,
            &mut timestamp,
            &msg[init::TIMESTAMP..init::TIMESTAMP + 12 + TAG_LEN],
        )?;

        Ok((
            Self {
                state,
                static_private: static_private.clone(),
                peer_static,
                peer_ephemeral,
                peer_index,
            },
            Initiation {
                peer_static,
                timestamp: Tai64n::from_bytes(timestamp),
                peer_index,
            },
        ))
    }

    pub fn peer_static(&self) -> &NodePublic {
        &self.peer_static
    }

    /// Builds the response and derives transport keys.
    pub fn respond(
        mut self,
        ephemeral: NodePrivate,
        local_index: u32,
    ) -> Result<([u8; RESPONSE_LEN], SessionKeys), WgError> {
        let mut msg = [0u8; RESPONSE_LEN];
        msg[0] = MSG_RESPONSE;
        msg[resp::SENDER..resp::SENDER + 4].copy_from_slice(&local_index.to_le_bytes());
        msg[resp::RECEIVER..resp::RECEIVER + 4].copy_from_slice(&self.peer_index.to_le_bytes());

        let ephemeral_pub = ephemeral.public();
        self.state.mix_key(ephemeral_pub.as_bytes());
        msg[resp::EPHEMERAL..resp::EPHEMERAL + KEY_LEN].copy_from_slice(ephemeral_pub.as_bytes());
        self.state.mix_hash(ephemeral_pub.as_bytes());

        self.state.mix_key(&ephemeral.dh(&self.peer_ephemeral));
        self.state.mix_key(&ephemeral.dh(&self.peer_static));

        let cipher = self.state.mix_psk();
        let (head, rest) = msg.split_at_mut(resp::EMPTY);
        let _ = head;
        self.state.seal(&cipher, &mut rest[..TAG_LEN], &[])?;

        let m = mac1(&self.peer_static, &msg[..resp::MAC1]);
        msg[resp::MAC1..resp::MAC1 + m.len()].copy_from_slice(&m);

        // The responder's send/receive are the reverse of the initiator's.
        let (receive, send) = self.state.split();
        let _ = &self.static_private;
        Ok((
            msg,
            SessionKeys {
                send,
                receive,
                local_index,
                peer_index: self.peer_index,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (NodePrivate, NodePrivate, NodePrivate, NodePrivate) {
        (
            NodePrivate::from_bytes([1; 32]),
            NodePrivate::from_bytes([2; 32]),
            NodePrivate::from_bytes([3; 32]),
            NodePrivate::from_bytes([4; 32]),
        )
    }

    /// The decisive test: two independent halves must agree on keys. Getting
    /// any KDF, DH, or ordering detail wrong breaks this.
    #[test]
    fn handshake_round_trips_and_agrees_on_keys() {
        let (i_static, r_static, i_eph, r_eph) = keys();

        let (initiator, init_msg) = Initiator::new(
            &i_static,
            &r_static.public(),
            i_eph,
            0xAABB_CCDD,
            Tai64n::from_counter(7),
        )
        .unwrap();
        assert_eq!(init_msg[0], MSG_INITIATION);
        assert_eq!(init_msg.len(), INITIATION_LEN);

        let (responder, learned) = Responder::consume_initiation(&r_static, &init_msg).unwrap();
        // The responder recovers the initiator's identity and timestamp.
        assert_eq!(learned.peer_static, i_static.public());
        assert_eq!(learned.timestamp, Tai64n::from_counter(7));
        assert_eq!(learned.peer_index, 0xAABB_CCDD);

        let (resp_msg, r_keys) = responder.respond(r_eph, 0x1122_3344).unwrap();
        assert_eq!(resp_msg.len(), RESPONSE_LEN);

        let i_keys = initiator.consume_response(&resp_msg).unwrap();

        // Each side sends with what the other receives with.
        assert_eq!(i_keys.send, r_keys.receive);
        assert_eq!(i_keys.receive, r_keys.send);
        assert_ne!(i_keys.send, i_keys.receive);
        assert_eq!(i_keys.peer_index, 0x1122_3344);
        assert_eq!(r_keys.peer_index, 0xAABB_CCDD);
    }

    /// An initiation addressed to a different static key must be rejected
    /// before any Curve25519 work happens.
    #[test]
    fn rejects_initiation_for_another_key() {
        let (i_static, r_static, i_eph, _) = keys();
        let stranger = NodePrivate::from_bytes([9; 32]);

        let (_, msg) = Initiator::new(
            &i_static,
            &r_static.public(),
            i_eph,
            1,
            Tai64n::from_counter(1),
        )
        .unwrap();
        assert_eq!(
            Responder::consume_initiation(&stranger, &msg).err(),
            Some(WgError::BadMac)
        );
    }

    #[test]
    fn rejects_tampered_initiation() {
        let (i_static, r_static, i_eph, _) = keys();
        let (_, mut msg) = Initiator::new(
            &i_static,
            &r_static.public(),
            i_eph,
            1,
            Tai64n::from_counter(1),
        )
        .unwrap();
        // Flip a bit in the encrypted static and re-mac so mac1 still passes.
        msg[init::STATIC] ^= 0x01;
        let m = mac1(&r_static.public(), &msg[..init::MAC1]);
        msg[init::MAC1..init::MAC1 + m.len()].copy_from_slice(&m);
        assert_eq!(
            Responder::consume_initiation(&r_static, &msg).err(),
            Some(WgError::Decrypt)
        );
    }

    #[test]
    fn rejects_malformed_lengths() {
        let (_, r_static, _, _) = keys();
        assert_eq!(
            Responder::consume_initiation(&r_static, &[1u8; 10]).err(),
            Some(WgError::Malformed)
        );
    }

    /// Distinct ephemerals must produce distinct session keys, or forward
    /// secrecy is not actually being provided.
    #[test]
    fn distinct_ephemerals_give_distinct_keys() {
        let (i_static, r_static, i_eph, r_eph) = keys();
        let run = |ie: NodePrivate, re: NodePrivate| {
            let (initiator, m) = Initiator::new(
                &i_static,
                &r_static.public(),
                ie,
                1,
                Tai64n::from_counter(1),
            )
            .unwrap();
            let (responder, _) = Responder::consume_initiation(&r_static, &m).unwrap();
            let (rm, _) = responder.respond(re, 2).unwrap();
            initiator.consume_response(&rm).unwrap().send
        };
        let a = run(i_eph, r_eph);
        let b = run(
            NodePrivate::from_bytes([5; 32]),
            NodePrivate::from_bytes([6; 32]),
        );
        assert_ne!(a, b);
    }
}
