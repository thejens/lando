//! WireGuard transport packets: the encrypted data path.
//!
//! Layout is `type | reserved[3] | receiver u32 | counter u64 | ciphertext`,
//! all little-endian — including the AEAD nonce, which is the opposite of the
//! ts2021 record layer's big-endian counter despite using the same cipher.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

use super::handshake::SessionKeys;
use super::{WgError, MSG_TRANSPORT, TAG_LEN, TRANSPORT_HEADER_LEN};

/// Counter at which a key must no longer be used. WireGuard reserves the top
/// of the space so a rekey always has room to complete.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;

/// Replay window in bits. WireGuard specifies 2048; at 32 bytes of state per
/// peer this is cheap even on a microcontroller, and a smaller window drops
/// legitimately reordered packets under load.
const WINDOW_BITS: u64 = 2048;
const WINDOW_WORDS: usize = (WINDOW_BITS / 64) as usize;

/// Sliding-window replay filter.
///
/// Accepts any counter above the highest seen, and any counter within the
/// window below it that has not already been used. Anything older is rejected:
/// without this, a captured packet can be replayed indefinitely.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: u64,
    bits: [u64; WINDOW_WORDS],
    /// Distinguishes "counter 0 not yet seen" from "counter 0 seen".
    started: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bits: [0; WINDOW_WORDS],
            started: false,
        }
    }

    /// Records `counter` as seen, returning false if it is a replay or too old.
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.set(counter);
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift >= WINDOW_BITS {
                self.bits = [0; WINDOW_WORDS];
            } else {
                self.shift_left(shift);
            }
            self.highest = counter;
            self.set(counter);
            return true;
        }
        let behind = self.highest - counter;
        if behind >= WINDOW_BITS {
            return false;
        }
        if self.get(counter) {
            return false;
        }
        self.set(counter);
        true
    }

    fn index(&self, counter: u64) -> (usize, u32) {
        let bit = (counter % WINDOW_BITS) as usize;
        (bit / 64, (bit % 64) as u32)
    }

    fn get(&self, counter: u64) -> bool {
        let (w, b) = self.index(counter);
        self.bits[w] & (1u64 << b) != 0
    }

    fn set(&mut self, counter: u64) {
        let (w, b) = self.index(counter);
        self.bits[w] |= 1u64 << b;
    }

    /// Clears the bits vacated by advancing the window by `shift` positions.
    fn shift_left(&mut self, shift: u64) {
        for i in 1..=shift {
            let (w, b) = self.index(self.highest + i);
            self.bits[w] &= !(1u64 << b);
        }
    }
}

/// An established WireGuard session.
pub struct Session {
    send_cipher: ChaCha20Poly1305,
    receive_cipher: ChaCha20Poly1305,
    send_counter: u64,
    replay: ReplayWindow,
    local_index: u32,
    peer_index: u32,
}

/// `4 zero bytes || counter` little-endian — note ts2021 uses big-endian here.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

impl Session {
    pub fn new(keys: &SessionKeys) -> Self {
        Self {
            send_cipher: ChaCha20Poly1305::new_from_slice(&keys.send).expect("32-byte key"),
            receive_cipher: ChaCha20Poly1305::new_from_slice(&keys.receive).expect("32-byte key"),
            send_counter: 0,
            replay: ReplayWindow::new(),
            local_index: keys.local_index,
            peer_index: keys.peer_index,
        }
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Messages sent on this key so far. Drives the message-count half of the
    /// rekey policy, which matters on a fast link long before the time limit.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// True once this session has sent enough messages to require a rekey.
    pub fn needs_rekey(&self) -> bool {
        self.send_counter >= REJECT_AFTER_MESSAGES
    }

    /// Encrypts `payload` into `out`, returning the packet length.
    ///
    /// Plaintext is zero-padded to a multiple of 16 before encryption, as the
    /// protocol requires — it blunts traffic analysis by quantising lengths.
    /// The padding is inside the AEAD, so the receiver recovers it and must
    /// rely on the inner IP header for the true length.
    pub fn encrypt(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, WgError> {
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(WgError::NonceExhausted);
        }
        let padded_len = payload.len().div_ceil(16) * 16;
        let total = TRANSPORT_HEADER_LEN + padded_len + TAG_LEN;
        if out.len() < total {
            return Err(WgError::ShortBuffer);
        }

        let counter = self.send_counter;
        out[0] = MSG_TRANSPORT;
        out[1..4].fill(0);
        out[4..8].copy_from_slice(&self.peer_index.to_le_bytes());
        out[8..16].copy_from_slice(&counter.to_le_bytes());

        let body = &mut out[TRANSPORT_HEADER_LEN..TRANSPORT_HEADER_LEN + padded_len];
        body[..payload.len()].copy_from_slice(payload);
        body[payload.len()..].fill(0);
        let tag = self
            .send_cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce(counter)), &[], body)
            .map_err(|_| WgError::Decrypt)?;
        out[TRANSPORT_HEADER_LEN + padded_len..total].copy_from_slice(&tag);

        self.send_counter += 1;
        Ok(total)
    }

    /// Decrypts a transport packet in place, returning the plaintext length.
    ///
    /// The returned slice includes any padding the sender added; callers read
    /// the inner IP header to find the real length.
    pub fn decrypt<'a>(&mut self, packet: &'a mut [u8]) -> Result<&'a [u8], WgError> {
        if packet.len() < TRANSPORT_HEADER_LEN + TAG_LEN || packet[0] != MSG_TRANSPORT {
            return Err(WgError::Malformed);
        }
        let receiver = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        if receiver != self.local_index {
            return Err(WgError::Malformed);
        }
        let counter = u64::from_le_bytes(packet[8..16].try_into().unwrap());

        let body_len = packet.len() - TRANSPORT_HEADER_LEN - TAG_LEN;
        let (header, rest) = packet.split_at_mut(TRANSPORT_HEADER_LEN);
        let _ = header;
        let (body, tag) = rest.split_at_mut(body_len);
        let tag = Tag::clone_from_slice(tag);

        // Authenticate before touching the replay window: an attacker must not
        // be able to advance it with forged counters.
        self.receive_cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce(counter)), &[], body, &tag)
            .map_err(|_| WgError::Decrypt)?;
        if !self.replay.accept(counter) {
            return Err(WgError::ReplayedTransport);
        }
        Ok(&packet[TRANSPORT_HEADER_LEN..TRANSPORT_HEADER_LEN + body_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KEY_LEN;

    fn pair() -> (Session, Session) {
        let a = SessionKeys {
            send: [1; KEY_LEN],
            receive: [2; KEY_LEN],
            local_index: 10,
            peer_index: 20,
        };
        let b = SessionKeys {
            send: [2; KEY_LEN],
            receive: [1; KEY_LEN],
            local_index: 20,
            peer_index: 10,
        };
        (Session::new(&a), Session::new(&b))
    }

    #[test]
    fn nonce_is_little_endian() {
        assert_eq!(nonce(1), [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            nonce(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
    }

    #[test]
    fn packets_round_trip() {
        let (mut a, mut b) = pair();
        let mut buf = [0u8; 256];
        for i in 0..5u8 {
            let payload = [i; 40];
            let n = a.encrypt(&payload, &mut buf).unwrap();
            assert_eq!(buf[0], MSG_TRANSPORT);
            let plain = b.decrypt(&mut buf[..n]).unwrap();
            assert_eq!(&plain[..40], &payload[..]);
        }
    }

    #[test]
    fn payload_is_padded_to_16_bytes() {
        let (mut a, _) = pair();
        let mut buf = [0u8; 256];
        let n = a.encrypt(&[7u8; 1], &mut buf).unwrap();
        assert_eq!(n, TRANSPORT_HEADER_LEN + 16 + TAG_LEN);
        let n = a.encrypt(&[7u8; 16], &mut buf).unwrap();
        assert_eq!(n, TRANSPORT_HEADER_LEN + 16 + TAG_LEN);
        let n = a.encrypt(&[7u8; 17], &mut buf).unwrap();
        assert_eq!(n, TRANSPORT_HEADER_LEN + 32 + TAG_LEN);
    }

    #[test]
    fn replayed_packet_is_rejected() {
        let (mut a, mut b) = pair();
        let mut buf = [0u8; 256];
        let n = a.encrypt(b"hello", &mut buf).unwrap();
        let copy = buf;
        assert!(b.decrypt(&mut buf[..n]).is_ok());

        let mut again = copy;
        assert_eq!(
            b.decrypt(&mut again[..n]).err(),
            Some(WgError::ReplayedTransport)
        );
    }

    #[test]
    fn packet_for_another_session_is_rejected() {
        let (mut a, mut b) = pair();
        let mut buf = [0u8; 256];
        let n = a.encrypt(b"hello", &mut buf).unwrap();
        buf[4..8].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(b.decrypt(&mut buf[..n]).err(), Some(WgError::Malformed));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b) = pair();
        let mut buf = [0u8; 256];
        let n = a.encrypt(b"hello", &mut buf).unwrap();
        buf[TRANSPORT_HEADER_LEN] ^= 0x01;
        assert_eq!(b.decrypt(&mut buf[..n]).err(), Some(WgError::Decrypt));
    }

    #[test]
    fn window_accepts_reordering_but_not_replays() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(3), "an earlier packet within the window is fine");
        assert!(!w.accept(3), "but only once");
        assert!(!w.accept(0));
        assert!(w.accept(4));
        assert!(w.accept(1));
    }

    #[test]
    fn window_rejects_ancient_counters() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(10_000));
        assert!(!w.accept(1), "far below the window");
        assert!(w.accept(10_000 - WINDOW_BITS + 1), "just inside");
        assert!(!w.accept(10_000 - WINDOW_BITS), "just outside");
    }

    /// A large jump forward must clear the whole window, not leave stale bits
    /// that would reject fresh counters.
    #[test]
    fn large_jump_clears_the_window() {
        let mut w = ReplayWindow::new();
        for c in 0..100 {
            assert!(w.accept(c));
        }
        assert!(w.accept(1_000_000));
        assert!(w.accept(1_000_001));
        assert!(w.accept(1_000_000 - 50));
    }

    /// Advancing by less than the window width must clear exactly the vacated
    /// bits — an off-by-one here silently drops or admits packets.
    #[test]
    fn small_advance_clears_only_vacated_bits() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(WINDOW_BITS));
        // Counter 0 and WINDOW_BITS share a slot; 0 is now outside the window.
        assert!(!w.accept(0));
        assert!(w.accept(1));
    }
}
