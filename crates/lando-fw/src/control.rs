//! The ts2021 control channel, on embassy.
//!
//! Every protocol decision lives in `tailscale-core`; this file owns sockets
//! and buffers only, exactly as `lando-host`'s transport does on a laptop. The
//! two are deliberately the same shape, because when they disagree it is
//! always this layer that is wrong — the protocol code is shared and tested.
//!
//! The control channel needs no TLS: it is plain TCP on port 80 with Noise
//! applied on top, which is the single fact that makes a client on a
//! microcontroller tractable at all.

use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_time::Duration;
use embedded_io_async::{Read, Write};

use tailscale_core::key::{MachinePrivate, MachinePublic};
use tailscale_core::noise::{Handshake, Session, HEADER_LEN, MSG_TYPE_ERROR, RESPONSE_LEN};
use tailscale_core::upgrade::{build_request, parse_response, UpgradeError, MAX_REQUEST_LEN};

use crate::logln;

/// Big enough for the upgrade response plus whatever the server coalesces
/// behind it. Noise frames are capped at 4096 by the protocol, so this also
/// bounds a single record.
const RX: usize = 4096;
const TX: usize = 2048;

#[derive(Debug)]
pub enum ControlError {
    Dns,
    Connect,
    Io,
    Refused,
    Handshake,
}

/// Opens a ts2021 session: DNS, TCP, HTTP upgrade, Noise IK.
///
/// Takes the socket buffers from the caller so their lifetime — and their
/// cost in SRAM — is visible at the call site rather than hidden here.
pub async fn connect<'a>(
    stack: Stack<'static>,
    host: &str,
    control_key: &MachinePublic,
    machine_key: MachinePrivate,
    ephemeral: MachinePrivate,
    capability_version: u16,
    rx_buf: &'a mut [u8; RX],
    tx_buf: &'a mut [u8; TX],
) -> Result<(TcpSocket<'a>, Session), ControlError> {
    let addrs = stack
        .dns_query(host, DnsQueryType::A)
        .await
        .map_err(|_| ControlError::Dns)?;
    let addr = *addrs.first().ok_or(ControlError::Dns)?;
    logln!("control: {} resolves to {}", host, addr);

    let mut socket = TcpSocket::new(stack, rx_buf, tx_buf);
    socket.set_timeout(Some(Duration::from_secs(20)));
    socket
        .connect((addr, 80))
        .await
        .map_err(|_| ControlError::Connect)?;

    let (handshake, initiation) =
        Handshake::start(machine_key, control_key, capability_version, ephemeral);

    let mut request = [0u8; MAX_REQUEST_LEN];
    let n = build_request(host, &initiation, &mut request).map_err(|_| ControlError::Handshake)?;
    socket
        .write_all(&request[..n])
        .await
        .map_err(|_| ControlError::Io)?;

    // The server may coalesce the 101, the Noise response and its opening
    // HTTP/2 SETTINGS into one segment, so nothing read here may be discarded.
    let mut buf = [0u8; 512];
    let mut have = 0usize;
    let body_start = loop {
        if have == buf.len() {
            return Err(ControlError::Handshake);
        }
        let n = socket
            .read(&mut buf[have..])
            .await
            .map_err(|_| ControlError::Io)?;
        if n == 0 {
            return Err(ControlError::Io);
        }
        have += n;
        match parse_response(&buf[..have]) {
            Ok(end) => break end,
            Err(UpgradeError::Incomplete) => continue,
            Err(_) => return Err(ControlError::Refused),
        }
    };

    while have - body_start < RESPONSE_LEN {
        // A type-3 frame is an unauthenticated plaintext error. Surface it
        // rather than failing to decrypt something that was never a response.
        if have - body_start >= HEADER_LEN && buf[body_start] == MSG_TYPE_ERROR {
            logln!("control: server rejected the handshake");
            return Err(ControlError::Refused);
        }
        let n = socket
            .read(&mut buf[have..])
            .await
            .map_err(|_| ControlError::Io)?;
        if n == 0 {
            return Err(ControlError::Io);
        }
        have += n;
    }

    let session = handshake
        .finish(&buf[body_start..body_start + RESPONSE_LEN])
        .map_err(|_| ControlError::Handshake)?;
    Ok((socket, session))
}
