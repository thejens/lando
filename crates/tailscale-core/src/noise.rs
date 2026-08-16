//! The ts2021 control channel: Noise IK handshake plus its record layer.
//!
//! This is `Noise_IK_25519_ChaChaPoly_BLAKE2s` with Tailscale-specific framing.
//! Three details differ from a textbook Noise implementation and each one fails
//! silently if you get it wrong, so they are called out where they occur:
//!
//!   1. The record-layer nonce counter is **big-endian**. Noise specifies
//!      little-endian; Tailscale does not follow it here.
//!   2. Record-layer AEAD uses **no associated data**. During the handshake AD
//!      is the running hash `h`, but transport records pass nil.
//!   3. Frame headers are **not** mixed into `h`. Only the prologue, the
//!      control static, the ephemeral public key, and ciphertexts are.
//!
//! Crucially for a microcontroller, a frame is capped at 4096 bytes, so this
//! layer needs one fixed 4 KB buffer no matter how large the logical message
//! is — everything above it (HTTP/2, JSON) has to stream.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

use crate::key::{MachinePrivate, MachinePublic, KEY_LEN};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &[u8] = b"Tailscale Control Protocol v";

pub const MSG_TYPE_INITIATION: u8 = 1;
pub const MSG_TYPE_RESPONSE: u8 = 2;
/// Unauthenticated, human-readable server error. Tamperable by definition —
/// useful for diagnostics, never for control flow.
pub const MSG_TYPE_ERROR: u8 = 3;
pub const MSG_TYPE_RECORD: u8 = 4;

pub const INITIATION_LEN: usize = 101;
pub const RESPONSE_LEN: usize = 51;
/// Header on every frame except the initiation, which carries 2 extra version bytes.
pub const HEADER_LEN: usize = 3;
pub const INITIATION_HEADER_LEN: usize = 5;
pub const TAG_LEN: usize = 16;

pub const MAX_MESSAGE_SIZE: usize = 4096;
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE - HEADER_LEN;
pub const MAX_PLAINTEXT_SIZE: usize = MAX_CIPHERTEXT_SIZE - TAG_LEN;

/// Every handshake AEAD operation uses a fresh key with a zero nonce, because
/// `MixDH` derives a new cipher for each one. Only the record layer counts up.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    /// Frame type was not the one expected at this point in the protocol.
    UnexpectedType(u8),
    /// Server sent a `msgTypeError` frame; payload is a plaintext hint.
    ServerError,
    /// Declared frame length disagrees with the protocol or the buffer.
    BadLength,
    /// AEAD authentication failed.
    Decrypt,
    /// Caller-supplied buffer is too small for the result.
    ShortBuffer,
    /// The 2^64 record limit for a key was reached. Practically unreachable.
    NonceExhausted,
}

fn blake2s(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

/// BLAKE2s block size, needed for the HMAC pad construction.
const BLAKE2S_BLOCK: usize = 64;

/// HMAC-BLAKE2s (RFC 2104 over BLAKE2s).
///
/// Hand-rolled rather than taken from the `hmac` crate: RustCrypto's BLAKE2 has
/// a `Lazy` buffer kind (it supports a native keyed mode) which `hmac::Hmac`
/// cannot wrap. Note this is *not* BLAKE2s's own keyed mode — Noise and Go's
/// `hkdf.New(newBLAKE2s, …)` both specify plain HMAC, and the two are not
/// interchangeable.
fn hmac_blake2s(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut padded = [0u8; BLAKE2S_BLOCK];
    if key.len() > BLAKE2S_BLOCK {
        padded[..32].copy_from_slice(&blake2s(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLAKE2S_BLOCK];
    let mut opad = [0x5cu8; BLAKE2S_BLOCK];
    for i in 0..BLAKE2S_BLOCK {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }

    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner: [u8; 32] = inner.finalize().into();

    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// HKDF (RFC 5869) with BLAKE2s and an empty `info`, producing `N` 32-byte
/// outputs — the exact shape Noise's `HKDF()` needs.
fn hkdf<const N: usize>(salt: &[u8; 32], ikm: &[u8]) -> [[u8; 32]; N] {
    let prk = hmac_blake2s(salt, &[ikm]);
    let mut out = [[0u8; 32]; N];
    for i in 0..N {
        let counter = [(i + 1) as u8];
        out[i] = if i == 0 {
            hmac_blake2s(&prk, &[&counter])
        } else {
            hmac_blake2s(&prk, &[&out[i - 1], &counter])
        };
    }
    out
}

/// Renders a `u16` as decimal without allocating. Returns the used prefix.
fn decimal(v: u16, buf: &mut [u8; 5]) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut n = v;
    let mut i = 5;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    buf.copy_within(i..5, 0);
    &buf[..5 - i]
}

struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
}

impl SymmetricState {
    fn initialize() -> Self {
        // PROTOCOL_NAME is 33 bytes, longer than BLAKE2s's 32-byte digest, so
        // the spec's "hash it" branch applies rather than the zero-pad branch.
        let h = blake2s(PROTOCOL_NAME);
        Self { h, ck: h }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// `MixKey(X25519(priv, pub))`, returning the single-use cipher it derives.
    ///
    /// Bundled into one operation, as upstream does, so it is impossible to
    /// call the DH with two private or two public keys.
    fn mix_dh(&mut self, private: &MachinePrivate, public: &MachinePublic) -> ChaCha20Poly1305 {
        let dh = private.dh(public);
        let [ck, k] = hkdf::<2>(&self.ck, &dh);
        self.ck = ck;
        ChaCha20Poly1305::new_from_slice(&k).expect("32-byte key")
    }

    /// Encrypts `plaintext` into `out` (which must be `plaintext.len() + 16`),
    /// with the running hash as associated data, then mixes the ciphertext in.
    fn encrypt_and_hash(
        &mut self,
        cipher: &ChaCha20Poly1305,
        out: &mut [u8],
        plaintext: &[u8],
    ) -> Result<(), NoiseError> {
        if out.len() != plaintext.len() + TAG_LEN {
            return Err(NoiseError::ShortBuffer);
        }
        let (body, tag_slot) = out.split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&ZERO_NONCE), &self.h, body)
            .map_err(|_| NoiseError::Decrypt)?;
        tag_slot.copy_from_slice(&tag);
        self.mix_hash(out);
        Ok(())
    }

    /// Inverse of [`Self::encrypt_and_hash`]. `out` must be
    /// `ciphertext.len() - 16`; pass an empty slice for an empty payload.
    fn decrypt_and_hash(
        &mut self,
        cipher: &ChaCha20Poly1305,
        out: &mut [u8],
        ciphertext: &[u8],
    ) -> Result<(), NoiseError> {
        if ciphertext.len() < TAG_LEN || out.len() != ciphertext.len() - TAG_LEN {
            return Err(NoiseError::BadLength);
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
            .map_err(|_| NoiseError::Decrypt)?;
        self.mix_hash(ciphertext);
        Ok(())
    }

    fn split(self) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
        // Empty IKM, chaining key as salt — note this differs from mix_dh,
        // which passes the DH output as IKM.
        let [k1, k2] = hkdf::<2>(&self.ck, &[]);
        (
            ChaCha20Poly1305::new_from_slice(&k1).expect("32-byte key"),
            ChaCha20Poly1305::new_from_slice(&k2).expect("32-byte key"),
        )
    }
}

/// Client half of the Noise IK handshake, mid-flight.
///
/// Split into start/finish because the initiation rides inside the HTTP upgrade
/// request's `X-Tailscale-Handshake` header, saving a round trip. The response
/// only arrives after the server answers `101`.
pub struct Handshake {
    state: SymmetricState,
    machine_key: MachinePrivate,
    ephemeral: MachinePrivate,
}

impl Handshake {
    /// Builds the 101-byte initiation. `ephemeral` must be freshly generated
    /// and never reused — reuse breaks forward secrecy for the whole session.
    pub fn start(
        machine_key: MachinePrivate,
        control_key: &MachinePublic,
        version: u16,
        ephemeral: MachinePrivate,
    ) -> (Self, [u8; INITIATION_LEN]) {
        let mut state = SymmetricState::initialize();

        let mut digits = [0u8; 5];
        let mut prologue = [0u8; PROLOGUE_PREFIX.len() + 5];
        let digits = decimal(version, &mut digits);
        prologue[..PROLOGUE_PREFIX.len()].copy_from_slice(PROLOGUE_PREFIX);
        prologue[PROLOGUE_PREFIX.len()..PROLOGUE_PREFIX.len() + digits.len()]
            .copy_from_slice(digits);
        state.mix_hash(&prologue[..PROLOGUE_PREFIX.len() + digits.len()]);

        // <- s : the responder's static is known in advance in pattern IK.
        state.mix_hash(control_key.as_bytes());

        let mut msg = [0u8; INITIATION_LEN];
        msg[0..2].copy_from_slice(&version.to_be_bytes());
        msg[2] = MSG_TYPE_INITIATION;
        msg[3..5].copy_from_slice(&((INITIATION_LEN - INITIATION_HEADER_LEN) as u16).to_be_bytes());

        // -> e
        let ephemeral_pub = ephemeral.public();
        msg[5..37].copy_from_slice(ephemeral_pub.as_bytes());
        // Note the header is deliberately not hashed — only the key itself.
        state.mix_hash(ephemeral_pub.as_bytes());

        // -> es, s
        let cipher = state.mix_dh(&ephemeral, control_key);
        let machine_pub = machine_key.public();
        state
            .encrypt_and_hash(&cipher, &mut msg[37..85], machine_pub.as_bytes())
            .expect("48 == 32 + 16");

        // -> ss, and an empty payload whose tag authenticates the whole message
        let cipher = state.mix_dh(&machine_key, control_key);
        state
            .encrypt_and_hash(&cipher, &mut msg[85..101], &[])
            .expect("16 == 0 + 16");

        (
            Self {
                state,
                machine_key,
                ephemeral,
            },
            msg,
        )
    }

    /// Consumes the 51-byte server response and produces the transport session.
    pub fn finish(mut self, resp: &[u8]) -> Result<Session, NoiseError> {
        if resp.len() < HEADER_LEN {
            return Err(NoiseError::BadLength);
        }
        match resp[0] {
            MSG_TYPE_RESPONSE => {}
            MSG_TYPE_ERROR => return Err(NoiseError::ServerError),
            other => return Err(NoiseError::UnexpectedType(other)),
        }
        let declared = u16::from_be_bytes([resp[1], resp[2]]) as usize;
        if declared != RESPONSE_LEN - HEADER_LEN || resp.len() != RESPONSE_LEN {
            return Err(NoiseError::BadLength);
        }

        // <- e, ee, se
        let mut control_ephemeral = [0u8; KEY_LEN];
        control_ephemeral.copy_from_slice(&resp[3..35]);
        let control_ephemeral = MachinePublic(control_ephemeral);
        self.state.mix_hash(control_ephemeral.as_bytes());
        let _ = self.state.mix_dh(&self.ephemeral, &control_ephemeral);
        let cipher = self.state.mix_dh(&self.machine_key, &control_ephemeral);
        self.state
            .decrypt_and_hash(&cipher, &mut [], &resp[35..51])?;

        let handshake_hash = self.state.h;
        let (tx, rx) = self.state.split();
        Ok(Session {
            tx,
            rx,
            tx_nonce: 0,
            rx_nonce: 0,
            handshake_hash,
        })
    }
}

/// An established ts2021 transport. Frames are `1b type | 2b len BE | ciphertext`.
pub struct Session {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_nonce: u64,
    rx_nonce: u64,
    handshake_hash: [u8; 32],
}

/// Builds the 12-byte record nonce: four zero bytes then a **big-endian**
/// counter. Noise specifies little-endian here; Tailscale does not.
fn record_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

impl Session {
    /// Channel binding value, for anything that needs to prove this session.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Frames and encrypts one record into `out`, returning the bytes written.
    /// `plaintext` must not exceed [`MAX_PLAINTEXT_SIZE`]; callers with more
    /// data are responsible for splitting it across records.
    pub fn write_record(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(NoiseError::BadLength);
        }
        let total = HEADER_LEN + plaintext.len() + TAG_LEN;
        if out.len() < total {
            return Err(NoiseError::ShortBuffer);
        }
        if self.tx_nonce == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }

        out[0] = MSG_TYPE_RECORD;
        out[1..3].copy_from_slice(&((plaintext.len() + TAG_LEN) as u16).to_be_bytes());
        let (body, tag_slot) = out[HEADER_LEN..total].split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        // Associated data is empty for transport records, unlike the handshake.
        let tag = self
            .tx
            .encrypt_in_place_detached(
                Nonce::from_slice(&record_nonce(self.tx_nonce)),
                &[],
                body,
            )
            .map_err(|_| NoiseError::Decrypt)?;
        tag_slot.copy_from_slice(&tag);
        self.tx_nonce += 1;
        Ok(total)
    }

    /// Decrypts a record body in place, returning the plaintext length.
    ///
    /// `body` is the ciphertext *after* the 3-byte header, which the caller has
    /// already parsed to know how many bytes to read. Splitting it this way
    /// keeps the transport free of any read-more-bytes callback.
    pub fn read_record(&mut self, body: &mut [u8]) -> Result<usize, NoiseError> {
        if body.len() < TAG_LEN {
            return Err(NoiseError::BadLength);
        }
        if self.rx_nonce == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let plaintext_len = body.len() - TAG_LEN;
        let (ct, tag) = body.split_at_mut(plaintext_len);
        let tag = Tag::clone_from_slice(tag);
        self.rx
            .decrypt_in_place_detached(
                Nonce::from_slice(&record_nonce(self.rx_nonce)),
                &[],
                ct,
                &tag,
            )
            .map_err(|_| NoiseError::Decrypt)?;
        self.rx_nonce += 1;
        Ok(plaintext_len)
    }
}

/// Parses a frame header into `(type, payload_len)`.
pub fn parse_header(hdr: &[u8; HEADER_LEN]) -> (u8, usize) {
    (hdr[0], u16::from_be_bytes([hdr[1], hdr[2]]) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a 32-byte hex literal, reusing the key parser so the tests do
    /// not need their own.
    fn h32(s: &str) -> [u8; 32] {
        MachinePublic::parse_hex(s).unwrap().0
    }

    /// The KDF is the piece most likely to be subtly wrong and it fails
    /// opaquely — a bad chaining key just produces an undecryptable handshake
    /// with no hint as to why. These vectors come from Python's `hmac` +
    /// `hashlib.blake2s`, an independent implementation, so they catch a
    /// self-consistent-but-wrong construction that a round-trip test cannot.
    #[test]
    fn hmac_blake2s_matches_reference() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hmac_blake2s(&key, &[b"tailscale"]),
            h32("26dc379e5a2c2143f17cc1eec53fc7e1d5d2ec2a3f7470a8f261fb5271bbfcc4")
        );

        // Keys longer than the 64-byte block must be hashed down first.
        let long: [u8; 100] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hmac_blake2s(&long, &[b"x"]),
            h32("7c5a4a1c1150b1eadcba56974986fd860c4aca9cd69fa0c65c9f67dadad9883a")
        );
    }

    #[test]
    fn hkdf_matches_reference() {
        // The MixDH case: chaining key as salt, DH output as IKM.
        let out = hkdf::<2>(&[0xAA; 32], &[0xBB; 32]);
        assert_eq!(
            out[0],
            h32("fe332fdec9cd425f88cdabe009f2d78aff433e89c9d38673f5158bc3f15cff34")
        );
        assert_eq!(
            out[1],
            h32("3e81c8bf9aaa02a751a3e2b6312cbf0900289ff68c6db75e3548eca281b0a75c")
        );

        // The Split case: empty IKM, which is easy to get wrong by passing the
        // chaining key as IKM instead of as salt.
        let out = hkdf::<2>(&[0xCC; 32], &[]);
        assert_eq!(
            out[0],
            h32("9e0ffdb8cdbc6c9b346c6ff26db6c19274dbd993b1f83db3950be8b6b3948f3a")
        );
        assert_eq!(
            out[1],
            h32("e86d3d5ab526d67a864f80d225d2ee0b4bf8e9494edb9c00fbda33f33b0ae970")
        );
    }

    #[test]
    fn initial_state_hashes_the_protocol_name() {
        let s = SymmetricState::initialize();
        assert_eq!(
            s.h,
            h32("bbea022b948cf3bc5857d70804229179e1116bc40cb8cc074835349c464bca36")
        );
        assert_eq!(s.ck, s.h);
    }

    #[test]
    fn decimal_renders_versions() {
        let mut b = [0u8; 5];
        assert_eq!(decimal(0, &mut b), b"0");
        assert_eq!(decimal(1, &mut b), b"1");
        assert_eq!(decimal(145, &mut b), b"145");
        assert_eq!(decimal(65535, &mut b), b"65535");
    }

    #[test]
    fn initiation_is_well_formed() {
        let machine = MachinePrivate::from_bytes([7u8; 32]);
        let ephemeral = MachinePrivate::from_bytes([9u8; 32]);
        let control = MachinePrivate::from_bytes([3u8; 32]).public();
        let (_, msg) = Handshake::start(machine, &control, 145, ephemeral.clone());

        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), 145);
        assert_eq!(msg[2], MSG_TYPE_INITIATION);
        assert_eq!(u16::from_be_bytes([msg[3], msg[4]]), 96);
        // The ephemeral public key travels in the clear.
        assert_eq!(&msg[5..37], ephemeral.public().as_bytes());
    }

    #[test]
    fn record_nonce_is_big_endian() {
        assert_eq!(record_nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            record_nonce(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// Round-trips the record layer by wiring one session's tx to another's rx,
    /// which is exactly how the two ends of a real session are related.
    #[test]
    fn records_round_trip() {
        let state = SymmetricState::initialize();
        let (c1, c2) = state.split();
        let mut client = Session {
            tx: c1.clone(),
            rx: c2.clone(),
            tx_nonce: 0,
            rx_nonce: 0,
            handshake_hash: [0u8; 32],
        };
        let mut server = Session {
            tx: c2,
            rx: c1,
            tx_nonce: 0,
            rx_nonce: 0,
            handshake_hash: [0u8; 32],
        };

        for i in 0..4u8 {
            let payload = [i; 100];
            let mut frame = [0u8; 256];
            let n = client.write_record(&payload, &mut frame).unwrap();
            assert_eq!(n, HEADER_LEN + 100 + TAG_LEN);

            let (ty, len) = parse_header(&frame[..3].try_into().unwrap());
            assert_eq!(ty, MSG_TYPE_RECORD);
            let plain = server
                .read_record(&mut frame[HEADER_LEN..HEADER_LEN + len])
                .unwrap();
            assert_eq!(&frame[HEADER_LEN..HEADER_LEN + plain], &payload[..]);
        }
    }

    #[test]
    fn oversized_record_is_rejected() {
        let state = SymmetricState::initialize();
        let (c1, c2) = state.split();
        let mut s = Session {
            tx: c1,
            rx: c2,
            tx_nonce: 0,
            rx_nonce: 0,
            handshake_hash: [0u8; 32],
        };
        let big = [0u8; MAX_PLAINTEXT_SIZE + 1];
        let mut out = [0u8; MAX_MESSAGE_SIZE + 64];
        assert_eq!(s.write_record(&big, &mut out), Err(NoiseError::BadLength));
    }
}
