//! Drives `tailscale-core` against the real control plane from a dev machine.
//!
//! This exists so every protocol stage can be finished and proven before any
//! firmware is flashed. The Pico has no debugger — logging is over USB CDC and
//! nothing else — so a bug that reproduces here should never be chased there.

mod derp;
mod node;
mod state;
mod transport;
mod tunnel;

use std::time::Duration;

use tailscale_core::control::{
    self, parse_register_response, write_map_request, write_register_request, Hostinfo, MapFrames,
    MapRequest, Register, MAP_PATH, REGISTER_PATH,
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

/// Relay region we advertise as our home. Region 1 is NYC, which is where the
/// default `derp1.tailscale.com` lives; the two must agree or peers will send
/// to a relay we are not connected to.
const DERP_HOME_REGION: u32 = 1;

/// Read timeout while streaming the netmap. Generous because a quiet tailnet
/// legitimately sends nothing between keep-alives.
const MAP_POLL_TIMEOUT: Duration = Duration::from_secs(180);

fn main() {
    if let Err(e) = run() {
        eprintln!("\nerror: {e}");
        std::process::exit(1);
    }
}

/// Connects to a DERP relay and completes its handshake.
///
/// Separate from the control-plane flow because it exercises a different
/// stack: TLS rather than Noise, and the node key rather than the machine key.
fn derp_check(state: &State) -> Result<(), String> {
    let relay = std::env::var("LANDO_DERP").unwrap_or_else(|_| "derp1.tailscale.com".into());
    println!("relay        : {relay}:443 (TLS, certificate verified)");
    println!("node pub     : {}", hex(state.node_key.public().as_bytes()));

    let started = std::time::Instant::now();
    let mut client = derp::DerpClient::connect(
        &relay,
        state.node_key.as_bytes(),
        state.node_key.public().as_bytes(),
    )?;
    println!("handshake    : OK ({:?})", started.elapsed());
    println!("server key   : {}", hex(client.server_key()));
    println!();
    println!("Listening for relay events (Ctrl-C to stop)...");
    loop {
        match client.next_event()? {
            None => {}
            Some(derp::Event::Packet { src, data }) => {
                println!("  packet from {} ({} bytes)", hex(&src[..8]), data.len());
            }
            Some(derp::Event::PeerPresent(k)) => println!("  peer present: {}", hex(&k[..8])),
            Some(derp::Event::PeerGone(k)) => println!("  peer gone:    {}", hex(&k[..8])),
            Some(derp::Event::KeepAlive) => println!("  keep-alive"),
            Some(derp::Event::Other(kind)) => println!("  {kind:?}"),
        }
    }
}

/// Runs as a full node: control plane in a background thread to stay online,
/// datapath in the foreground.
///
/// Two threads rather than one because both halves block indefinitely by
/// design — the map long-poll is what keeps the node online, and the relay
/// read is what makes it reachable. Neither may starve the other.
fn node_mode() -> Result<(), String> {
    let relay = std::env::var("LANDO_DERP").unwrap_or_else(|_| "derp1.tailscale.com".into());
    let (state, _) = State::load_or_create(&State::path())?;
    let known_peers: node::PeerSet = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let peers_for_control = known_peers.clone();
    std::thread::spawn(move || {
        if let Err(e) = control_plane(Some(peers_for_control), DERP_HOME_REGION) {
            eprintln!("control plane stopped: {e}");
        }
    });

    // Let registration and the first netmap land before answering handshakes,
    // so the authorisation check has something to check against.
    std::thread::sleep(Duration::from_secs(6));
    node::run(&relay, &state.node_key, known_peers)
}

fn run() -> Result<(), String> {
    if std::env::args().nth(1).as_deref() == Some("node") {
        return node_mode();
    }
    if std::env::args().nth(1).as_deref() == Some("derp") {
        let (state, _) = State::load_or_create(&State::path())?;
        return derp_check(&state);
    }
    control_plane(None, 0)
}

/// Registers and holds the netmap long-poll open, optionally publishing the
/// peer list for the datapath.
fn control_plane(peers_out: Option<node::PeerSet>, home_derp: u32) -> Result<(), String> {
    let host = std::env::var("LANDO_CONTROL_HOST").unwrap_or_else(|_| DEFAULT_CONTROL_HOST.into());
    let key_str = std::env::var("LANDO_CONTROL_KEY").unwrap_or_else(|_| PINNED_CONTROL_KEY.into());
    let hostname = std::env::var("LANDO_HOSTNAME").unwrap_or_else(|_| "lando".into());
    // Configurable so the client can be pointed at a self-hosted control
    // server, which is the only way to see both ends of an exchange.
    let port: u16 = std::env::var("LANDO_CONTROL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let control_key =
        MachinePublic::parse(&key_str).map_err(|e| format!("parsing control key: {e:?}"))?;

    let state_path = State::path();
    let (state, fresh) = State::load_or_create(&state_path)?;

    println!("control host : {host}:{port}  (cleartext — Noise supplies the crypto)");
    println!("capver       : {CAPABILITY_VERSION}");
    println!(
        "identity     : {} ({})",
        state_path.display(),
        if fresh { "newly generated" } else { "loaded" }
    );
    println!("node pub     : {}", hex(state.node_key.public().as_bytes()));

    let transport = NoiseTransport::connect(
        &host,
        port,
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
        preferred_derp: home_derp,
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
    // The long-poll is what makes the node report online, so it runs until
    // interrupted rather than returning.
    println!();
    println!("map          : POST {MAP_PATH} (streaming, uncompressed)");
    conn.set_read_timeout(MAP_POLL_TIMEOUT)?;
    poll_netmap(&mut conn, &host, &node_key, &state.disco_key.public(), &hostinfo, peers_out)
}

/// Streams the netmap until the connection drops or the process is killed.
fn poll_netmap(
    conn: &mut H2Conn,
    host: &str,
    node_key: &tailscale_core::key::NodePublic,
    disco_key: &tailscale_core::key::DiscoPublic,
    hostinfo: &Hostinfo,
    peers_out: Option<node::PeerSet>,
) -> Result<(), String> {
    let mut buf = vec![0u8; 4096];
    let n = write_map_request(
        &mut buf,
        &MapRequest {
            capability_version: CAPABILITY_VERSION,
            node_key,
            disco_key,
            hostinfo,
            stream: true,
            keep_alive: true,
            omit_peers: false,
            // Empty because a streaming request cannot advertise anything:
            // the server treats it as read-only and discards Hostinfo and
            // Endpoints alike. Describing ourselves needs a separate one-shot
            // request.
            endpoints: &[],
            endpoint_types: &[],
        },
    )
    .map_err(|e| format!("building MapRequest: {e:?}"))?;
    if std::env::var("LANDO_TRACE").is_ok() {
        eprintln!("MapRequest: {}", String::from_utf8_lossy(&buf[..n]));
    }

    let mut frames = MapFrames::new();
    // The host can afford to assemble a frame before parsing it. The firmware
    // cannot: a netmap can exceed the Pico's entire SRAM, so it will have to
    // extract fields while streaming. The frame layer above is already
    // streaming so that only this buffer has to change.
    let mut current: Vec<u8> = Vec::new();
    let mut count = 0usize;

    conn.post(host, MAP_PATH, &buf[..n], move |mut data| {
        while !data.is_empty() {
            let (used, frame) = frames.feed(data);
            if used == 0 && frame.is_none() {
                break;
            }
            data = &data[used..];
            let Some(frame) = frame else { continue };

            if frame.total_len == 0 {
                println!("  keep-alive");
                continue;
            }
            current.extend_from_slice(frame.chunk);
            if !frame.end {
                continue;
            }
            count += 1;
            println!("  netmap frame #{count}: {} bytes", current.len());
            report_netmap(&current, count == 1);
            if let Ok(path) = std::env::var("LANDO_DUMP_NETMAP") {
                let _ = std::fs::write(&path, &current);
            }
            // Publish the peer list for the datapath. A delta frame that omits
            // Peers leaves the previous list in place rather than clearing it.
            if let Some(out) = &peers_out {
                let found: Vec<_> = control::peers(&current).map(|p| p.node_key).collect();
                if !found.is_empty() {
                    println!("    peers     : {} known", found.len());
                    *out.lock().unwrap() = found;
                }
            }
            current.clear();
        }
        Ok(())
    })
}

/// Prints the few netmap fields that matter at this stage.
fn report_netmap(body: &[u8], verbose: bool) {
    let get = |k: &str| tailscale_core::json::field(body, k).ok().flatten();
    if let Some(node) = get("Node") {
        if let Some(addrs) = control::nested_raw(node, "Addresses") {
            println!("    addresses : {}", String::from_utf8_lossy(addrs));
        }
        if verbose {
            if let Some(name) = control::nested_str(node, "Name") {
                println!("    name      : {name}");
            }
        }
    }
    if let Some(tailscale_core::json::Value::Raw(peers)) = get("Peers") {
        // Cheap element count: peer objects are the only top-level braces.
        let n = peers.iter().filter(|&&b| b == b'{').count();
        println!("    peers     : ~{n}");
    }
    if let Some(err) = get("Error").and_then(|v| v.as_str()) {
        if !err.is_empty() {
            println!("    error     : {err}");
        }
    }
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
