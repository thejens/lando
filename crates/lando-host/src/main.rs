//! Drives `tailscale-core` against the real control plane from a dev machine.
//!
//! This exists so every protocol stage can be finished and proven before any
//! firmware is flashed. The Pico has no debugger — logging is over USB CDC and
//! nothing else — so a bug that reproduces here should never be chased there.

mod state;
mod transport;

use std::time::Duration;

use tailscale_core::control::{
    self, parse_register_response, write_register_request, Hostinfo, Register, REGISTER_PATH,
};
use tailscale_core::key::MachinePublic;
use tailscale_core::{CAPABILITY_VERSION, DEFAULT_CONTROL_HOST};

use state::{hex, State};
use transport::{H2Conn, NoiseTransport};

/// The control plane's Noise static, from `GET /key?v=2` (the `publicKey`
/// field, not `legacyPublicKey`). That endpoint is HTTPS-only, so the device
/// never fetches it — it is provisioned over USB, and pinned here.
///
/// Unchanged since at least January 2023, but Tailscale publishes no rotation
/// guarantee. A handshake that fails to decrypt is the symptom of rotation.
const PINNED_CONTROL_KEY: &str =
    "mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b";

/// How long to wait for a browser to complete an interactive login.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

fn main() {
    if let Err(e) = run() {
        eprintln!("\nerror: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let host = std::env::var("LANDO_CONTROL_HOST").unwrap_or_else(|_| DEFAULT_CONTROL_HOST.into());
    let key_str = std::env::var("LANDO_CONTROL_KEY").unwrap_or_else(|_| PINNED_CONTROL_KEY.into());
    let hostname = std::env::var("LANDO_HOSTNAME").unwrap_or_else(|_| "lando".into());
    let control_key =
        MachinePublic::parse(&key_str).map_err(|e| format!("parsing control key: {e:?}"))?;

    let state_path = State::path();
    let (state, fresh) = State::load_or_create(&state_path)?;

    println!("control host : {host}:80  (cleartext — Noise supplies the crypto)");
    println!("capver       : {CAPABILITY_VERSION}");
    println!(
        "identity     : {} ({})",
        state_path.display(),
        if fresh { "newly generated" } else { "loaded" }
    );
    println!("node pub     : {}", hex(state.node_key.public().as_bytes()));

    let transport = NoiseTransport::connect(
        &host,
        &control_key,
        state.machine_key.clone(),
        CAPABILITY_VERSION,
    )?;
    let mut conn = H2Conn::start(transport)?;
    println!("noise        : established");
    println!("channel bind : {}", hex(&conn.handshake_hash()));

    let auth_key = load_auth_key()?;
    let hostinfo = Hostinfo {
        hostname: &hostname,
        ..Default::default()
    };
    let node_key = state.node_key.public();
    let base = Register {
        capability_version: CAPABILITY_VERSION,
        node_key: &node_key,
        auth_key: auth_key.as_deref().map(str::trim),
        followup: None,
        hostinfo: &hostinfo,
        ephemeral: false,
    };

    let interactive = base.auth_key.is_none();
    println!(
        "register     : POST {REGISTER_PATH} ({})",
        if interactive {
            "interactive"
        } else {
            "pre-auth key"
        }
    );

    let first = register(&mut conn, &host, &base)?;
    let parsed = parse_register_response(&first)
        .map_err(|e| format!("parsing RegisterResponse: {e:?} in {first:?}"))?;
    if !parsed.error.is_empty() {
        return Err(format!(
            "control plane refused registration: {}",
            parsed.error
        ));
    }

    // Interactive path: the server returns a URL, and a second request with
    // `Followup` set is held open until a browser completes the login.
    // The URL is copied out because `parsed` borrows the buffer we replace.
    let body = if parsed.auth_url.is_empty() {
        first
    } else if !interactive {
        return Err(format!(
            "pre-auth key was not accepted; server wants interactive login at {}",
            parsed.auth_url
        ));
    } else {
        let url = parsed.auth_url.to_string();
        println!();
        println!("Open this in the browser signed in to your personal tailnet:");
        println!();
        println!("    {url}");
        println!();
        println!("Waiting for approval (up to {}s)...", LOGIN_TIMEOUT.as_secs());
        conn.set_read_timeout(LOGIN_TIMEOUT)?;
        register(
            &mut conn,
            &host,
            &Register {
                followup: Some(&url),
                ..base
            },
        )?
    };

    let parsed = parse_register_response(&body).map_err(|e| {
        if body.is_empty() {
            "the follow-up registration returned an empty body — the auth URL was \
             most likely never opened, so the server gave up waiting. Re-run and \
             open the printed URL to complete the login."
                .to_string()
        } else {
            format!(
                "parsing follow-up RegisterResponse: {e:?} in {:?}",
                String::from_utf8_lossy(&body)
            )
        }
    })?;
    if !parsed.error.is_empty() {
        return Err(format!("login failed: {}", parsed.error));
    }
    if !parsed.auth_url.is_empty() {
        return Err("server still wants interactive login after follow-up".into());
    }

    let login = tailscale_core::json::field(&body, "Login")
        .ok()
        .flatten()
        .and_then(|v| control::nested_str(v, "LoginName"))
        .unwrap_or("(unknown)");

    println!();
    println!("registered as     : {login}");
    println!("machine authorized: {}", parsed.machine_authorized);
    println!("node key expired  : {}", parsed.node_key_expired);
    if !parsed.machine_authorized {
        println!();
        println!("This tailnet requires manual device approval — approve it in the");
        println!("admin console before the node becomes reachable.");
    }
    println!();
    println!("Next: POST /machine/map to stream the netmap.");
    Ok(())
}

/// Issues one `RegisterRequest` and collects the response body.
fn register(conn: &mut H2Conn, host: &str, req: &Register) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; 4096];
    let n = write_register_request(&mut buf, req)
        .map_err(|e| format!("building RegisterRequest: {e:?}"))?;
    let mut body = Vec::new();
    conn.post(host, REGISTER_PATH, &buf[..n], |chunk| {
        body.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(body)
}

/// Finds the pre-auth key, preferring sources that keep it off the command
/// line and out of shell history. The key is a tailnet-joining credential —
/// treat it like an SSH private key until it has been used or revoked.
fn load_auth_key() -> Result<Option<String>, String> {
    if let Ok(v) = std::env::var("LANDO_AUTHKEY") {
        return Ok(Some(v));
    }
    let path = std::env::var("LANDO_AUTHKEY_FILE").unwrap_or_else(|_| ".lando-authkey".into());
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading {path}: {e}")),
    }
}
