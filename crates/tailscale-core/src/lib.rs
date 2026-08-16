//! Sans-IO core of a minimal Tailscale client.
//!
//! Nothing in this crate touches a socket, a clock, or an allocator. Every
//! protocol is a state machine that consumes and produces byte slices, so the
//! *same compiled logic* runs in `lando-host` on a development machine, under a
//! real debugger, and in `lando-fw` on the Pico 2 W where there is no debugger
//! at all.
//!
//! That property is the whole reason for the split. Protocol code that can only
//! be exercised by flashing a board does not get exercised, and bare-metal
//! debugging is a bad place to discover that a length prefix is little-endian.
//! Every bug found so far was found on the host.
//!
//! Kept deliberately `no_std` even under `cargo test`, so that a dependency on
//! `std` fails the normal test run rather than surfacing at cross-compile time.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod control;
pub mod crypto;
pub mod derp;
pub mod disco;
pub mod h2;
pub mod json;
pub mod key;
pub mod noise;
pub mod tsmp;
pub mod upgrade;
pub mod wireguard;

/// Capability version advertised to the control plane.
///
/// This travels three places that must agree: the cleartext frame header, the
/// Noise prologue, and later the `MapRequest`. The control plane gates
/// behaviour on it and eventually refuses versions it considers too old, so
/// this is the single value to bump when chasing upstream.
pub const CAPABILITY_VERSION: u16 = 145;

/// Hostname of Tailscale's hosted control plane.
pub const DEFAULT_CONTROL_HOST: &str = "controlplane.tailscale.com";
