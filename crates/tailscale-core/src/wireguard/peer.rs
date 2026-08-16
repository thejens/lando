//! Per-peer session lifecycle and WireGuard's timers.
//!
//! Sessions are not durable: WireGuard requires a rekey after 120 seconds and
//! forbids using a key at all after 180. Something has to own that, track the
//! previous session while a rekey is in flight, and decide when to initiate or
//! send a keepalive.
//!
//! Time enters as a monotonic millisecond count supplied by the caller rather
//! than read from a clock, so the whole policy is deterministic and testable —
//! and so the firmware can drive it from a hardware timer without a notion of
//! wall-clock time, which the Pico does not have.

use super::handshake::SessionKeys;
use super::transport::{Session, REJECT_AFTER_MESSAGES};
use super::{Tai64n, WgError};
use crate::key::NodePublic;

/// Monotonic milliseconds. The epoch is arbitrary; only differences matter.
pub type Instant = u64;

/// WireGuard's timer constants, in milliseconds.
pub mod timers {
    /// After this long, the initiator should begin a rekey.
    pub const REKEY_AFTER_TIME: u64 = 120_000;
    /// After this long a key must not be used at all, in either direction.
    pub const REJECT_AFTER_TIME: u64 = 180_000;
    /// Wait this long for a handshake response before retrying.
    pub const REKEY_TIMEOUT: u64 = 5_000;
    /// Give up retrying a handshake after this long.
    pub const REKEY_ATTEMPT_TIME: u64 = 90_000;
    /// If we received data and have sent nothing since, send a keepalive.
    pub const KEEPALIVE_TIMEOUT: u64 = 10_000;
    /// Rekey once this many messages have been sent on a key.
    pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
}

/// What the caller should do for this peer right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do.
    Idle,
    /// Send a handshake initiation — no usable session, or one due for rekey.
    Initiate,
    /// Send an empty transport packet, holding the NAT mapping open.
    Keepalive,
}

struct Active {
    session: Session,
    established: Instant,
    last_sent: Option<Instant>,
    last_received: Option<Instant>,
    /// Only the initiator starts a rekey, so both sides do not do it at once.
    initiator: bool,
}

impl Active {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_sub(self.established) >= timers::REJECT_AFTER_TIME
    }

    fn due_for_rekey(&self, now: Instant) -> bool {
        self.initiator
            && (now.saturating_sub(self.established) >= timers::REKEY_AFTER_TIME
                || self.session.send_counter() >= timers::REKEY_AFTER_MESSAGES)
    }

    /// True when data arrived more recently than anything we sent, and long
    /// enough ago that the peer deserves an answer.
    fn owes_keepalive(&self, now: Instant) -> bool {
        let Some(received) = self.last_received else {
            return false;
        };
        if self.last_sent.is_some_and(|s| s >= received) {
            return false;
        }
        now.saturating_sub(received) >= timers::KEEPALIVE_TIMEOUT
    }
}

/// A single WireGuard peer and everything that expires.
pub struct Peer {
    pub static_public: NodePublic,
    current: Option<Active>,
    /// Kept briefly during a rekey: packets encrypted under the old key are
    /// still in flight, and dropping them causes a visible stall.
    previous: Option<Active>,
    /// Greatest handshake timestamp accepted from this peer. Anything not
    /// strictly greater is a replay of a captured initiation.
    last_handshake_timestamp: Option<Tai64n>,
    /// When the in-flight handshake initiation was sent, if any.
    handshake_sent: Option<Instant>,
    /// When the current run of handshake attempts began.
    handshake_started: Option<Instant>,
}

impl Peer {
    pub fn new(static_public: NodePublic) -> Self {
        Self {
            static_public,
            current: None,
            previous: None,
            last_handshake_timestamp: None,
            handshake_sent: None,
            handshake_started: None,
        }
    }

    /// Validates a peer's handshake timestamp against the greatest seen.
    ///
    /// This is the receiving half of the TAI64N rule. Without it a captured
    /// initiation can be replayed forever; with it, a peer whose clock goes
    /// backwards — a rebooted device with no RTC — is locked out until we
    /// forget, which is exactly why our own timestamps come from a counter
    /// persisted to flash.
    pub fn accept_handshake_timestamp(&mut self, ts: Tai64n) -> Result<(), WgError> {
        match self.last_handshake_timestamp {
            Some(prev) if !ts.is_newer_than(&prev) => Err(WgError::ReplayedHandshake),
            _ => {
                self.last_handshake_timestamp = Some(ts);
                Ok(())
            }
        }
    }

    /// Records that a handshake initiation was just sent.
    pub fn handshake_sent(&mut self, now: Instant) {
        self.handshake_sent = Some(now);
        self.handshake_started.get_or_insert(now);
    }

    /// Installs freshly negotiated keys, retiring the previous session.
    pub fn install_session(&mut self, keys: &SessionKeys, now: Instant, initiator: bool) {
        self.previous = self.current.take();
        self.current = Some(Active {
            session: Session::new(keys),
            established: now,
            last_sent: None,
            last_received: None,
            initiator,
        });
        self.handshake_sent = None;
        self.handshake_started = None;
    }

    /// The session to encrypt outbound data with, if one is usable.
    ///
    /// Only the current session ever sends: the previous one exists solely to
    /// decrypt packets still in flight.
    pub fn send_session(&mut self, now: Instant) -> Option<&mut Session> {
        let active = self.current.as_mut()?;
        if active.expired(now) || active.session.send_counter() >= REJECT_AFTER_MESSAGES {
            return None;
        }
        active.last_sent = Some(now);
        Some(&mut active.session)
    }

    /// Finds the session a packet is addressed to, by its receiver index.
    ///
    /// Demultiplexing by index is what lets the previous session keep working
    /// through a rekey — both are live, distinguished only by this field.
    pub fn session_for_index(&mut self, index: u32, now: Instant) -> Option<&mut Session> {
        for slot in [self.current.as_mut(), self.previous.as_mut()] {
            if let Some(active) = slot {
                if active.session.local_index() == index && !active.expired(now) {
                    active.last_received = Some(now);
                    return Some(&mut active.session);
                }
            }
        }
        None
    }

    /// Drops sessions that may no longer be used.
    pub fn expire(&mut self, now: Instant) {
        if self.current.as_ref().is_some_and(|a| a.expired(now)) {
            self.current = None;
        }
        if self.previous.as_ref().is_some_and(|a| a.expired(now)) {
            self.previous = None;
        }
    }

    pub fn has_session(&self, now: Instant) -> bool {
        self.current.as_ref().is_some_and(|a| !a.expired(now))
    }

    /// Decides what this peer needs right now.
    pub fn poll(&self, now: Instant) -> Action {
        // A handshake already in flight: retry only after REKEY_TIMEOUT, and
        // stop entirely once the attempt window closes, so an unreachable peer
        // does not generate traffic forever.
        if let Some(sent) = self.handshake_sent {
            let giving_up = self
                .handshake_started
                .is_some_and(|s| now.saturating_sub(s) >= timers::REKEY_ATTEMPT_TIME);
            if giving_up {
                return Action::Idle;
            }
            return if now.saturating_sub(sent) >= timers::REKEY_TIMEOUT {
                Action::Initiate
            } else {
                Action::Idle
            };
        }

        match &self.current {
            None => Action::Initiate,
            Some(active) if active.expired(now) => Action::Initiate,
            Some(active) if active.due_for_rekey(now) => Action::Initiate,
            Some(active) if active.owes_keepalive(now) => Action::Keepalive,
            _ => Action::Idle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::NodePrivate;

    fn peer() -> Peer {
        Peer::new(NodePrivate::from_bytes([1; 32]).public())
    }

    fn keys(local: u32, peer_index: u32) -> SessionKeys {
        SessionKeys {
            send: [1; 32],
            receive: [2; 32],
            local_index: local,
            peer_index,
        }
    }

    #[test]
    fn with_no_session_it_wants_to_handshake() {
        assert_eq!(peer().poll(0), Action::Initiate);
    }

    #[test]
    fn handshake_retries_are_rate_limited_then_abandoned() {
        let mut p = peer();
        p.handshake_sent(1_000);
        assert_eq!(p.poll(2_000), Action::Idle, "too soon to retry");
        assert_eq!(
            p.poll(1_000 + timers::REKEY_TIMEOUT),
            Action::Initiate,
            "retry once the timeout elapses"
        );
        // An unreachable peer must stop generating traffic eventually.
        assert_eq!(
            p.poll(1_000 + timers::REKEY_ATTEMPT_TIME),
            Action::Idle,
            "give up after the attempt window"
        );
    }

    #[test]
    fn established_session_is_idle_then_rekeys() {
        let mut p = peer();
        p.install_session(&keys(1, 2), 0, true);
        assert_eq!(p.poll(1_000), Action::Idle);
        assert_eq!(p.poll(timers::REKEY_AFTER_TIME), Action::Initiate);
    }

    /// Only the initiator rekeys, so both ends do not start at once.
    #[test]
    fn responder_does_not_initiate_rekey() {
        let mut p = peer();
        p.install_session(&keys(1, 2), 0, false);
        assert_eq!(p.poll(timers::REKEY_AFTER_TIME), Action::Idle);
        // But it still stops using the key at the hard limit.
        assert_eq!(p.poll(timers::REJECT_AFTER_TIME), Action::Initiate);
    }

    #[test]
    fn expired_session_cannot_send_and_is_dropped() {
        let mut p = peer();
        p.install_session(&keys(1, 2), 0, true);
        assert!(p.send_session(1_000).is_some());
        assert!(p.send_session(timers::REJECT_AFTER_TIME).is_none());
        assert!(!p.has_session(timers::REJECT_AFTER_TIME));
        p.expire(timers::REJECT_AFTER_TIME);
        assert_eq!(p.poll(timers::REJECT_AFTER_TIME), Action::Initiate);
    }

    /// During a rekey both sessions must decrypt, or packets already in flight
    /// under the old key are lost and the transfer visibly stalls.
    #[test]
    fn previous_session_still_receives_during_rekey() {
        let mut p = peer();
        p.install_session(&keys(10, 20), 0, true);
        p.install_session(&keys(11, 21), 1_000, true);

        assert!(p.session_for_index(11, 1_000).is_some(), "current");
        assert!(p.session_for_index(10, 1_000).is_some(), "previous");
        assert!(p.session_for_index(99, 1_000).is_none(), "unknown index");
    }

    #[test]
    fn keepalive_is_owed_only_after_receiving() {
        let mut p = peer();
        p.install_session(&keys(1, 2), 0, true);
        assert_eq!(p.poll(timers::KEEPALIVE_TIMEOUT), Action::Idle);

        p.session_for_index(1, 1_000).unwrap();
        assert_eq!(p.poll(1_000 + 1), Action::Idle, "not yet due");
        assert_eq!(
            p.poll(1_000 + timers::KEEPALIVE_TIMEOUT),
            Action::Keepalive
        );

        // Sending anything discharges the obligation.
        p.send_session(1_000 + timers::KEEPALIVE_TIMEOUT).unwrap();
        assert_eq!(p.poll(1_000 + timers::KEEPALIVE_TIMEOUT + 1), Action::Idle);
    }

    /// The receiving half of the TAI64N rule: a captured initiation must not
    /// be replayable.
    #[test]
    fn handshake_timestamps_must_strictly_increase() {
        let mut p = peer();
        assert!(p.accept_handshake_timestamp(Tai64n::from_counter(5)).is_ok());
        assert_eq!(
            p.accept_handshake_timestamp(Tai64n::from_counter(5)).err(),
            Some(WgError::ReplayedHandshake),
            "equal is a replay"
        );
        assert_eq!(
            p.accept_handshake_timestamp(Tai64n::from_counter(4)).err(),
            Some(WgError::ReplayedHandshake),
            "older is a replay"
        );
        assert!(p.accept_handshake_timestamp(Tai64n::from_counter(6)).is_ok());
    }
}
