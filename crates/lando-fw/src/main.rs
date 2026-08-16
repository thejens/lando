//! Firmware for the Raspberry Pi Pico 2 W.
//!
//! The protocol work all lives in `tailscale-core`, which is `no_std` and
//! sans-IO precisely so it can arrive here unchanged. What this crate owns is
//! the parts that cannot be tested on a laptop: the radio, flash, USB, and the
//! scheduling that ties them together.
//!
//! USB CDC is the board's only channel — there is no debug probe — so it is
//! built here rather than taken from a logging crate, for two reasons. It has
//! to carry commands as well as output, and the first command that matters is
//! `b`: reboot into the bootloader. Without it every firmware change needs
//! someone physically holding BOOTSEL while replugging the board, which makes
//! the edit-flash-observe loop depend on a human being in the room.
//!
//! Note that macOS may silently refuse to bind a driver to a new USB device
//! until the accessory is approved. The symptom is a device that enumerates
//! and then sits at `!registered, !matched` in `ioreg` with no `/dev` node,
//! which looks exactly like firmware that hangs during enumeration.

#![no_std]
#![no_main]

mod config;
mod control;
mod h2conn;
mod wg;

use core::fmt::Write as _;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0, USB};
use embassy_rp::pio::{InterruptHandler as PioInterruptHandler, Pio};
use embassy_rp::trng::{InterruptHandler as TrngInterruptHandler, Trng};
use embassy_rp::usb::{Driver, InterruptHandler};
use cyw43::{Aligned, A4};
use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config as UsbConfig};
use heapless::String;

use crate::config::{Config, Store};
use static_cell::StaticCell;

use panic_halt as _;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<DMA_CH0>;
    TRNG_IRQ => TrngInterruptHandler<embassy_rp::peripherals::TRNG>;
});

/// RP2350 requires a signed image block in flash; without it the bootloader
/// refuses to run the binary at all.
#[link_section = ".start_block"]
#[used]
static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

/// The control plane's Noise static, from `GET /key?v=2`. That endpoint is
/// HTTPS-only, so the device never fetches it — it is pinned here and can be
/// re-provisioned if it ever rotates.
const CONTROL_KEY: &str =
    "mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b";

const LINE_LEN: usize = 128;
/// Log lines waiting to go out. Bounded, and full means drop: a device whose
/// network stack stalls because its logging backed up is worse than one that
/// loses a line.
static LOGS: Channel<CriticalSectionRawMutex, String<LINE_LEN>, 16> = Channel::new();

/// Queues a line for the USB console, dropping it if the queue is full.
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => {{
        // Scoped inside the macro so callers need not import it, and so a
        // module that imports a different `Write` still compiles.
        use core::fmt::Write as _;
        let mut line: heapless::String<128> = heapless::String::new();
        let _ = core::write!(&mut line, $($arg)*);
        let _ = $crate::LOGS.try_send(line);
    }};
}

#[embassy_executor::task]
async fn cyw43_task(runner: cyw43::Runner<'static, RadioBus>) -> ! {
    runner.run().await
}

/// The bus cyw43 talks to the radio over: PIO-driven SPI plus the power pin.
type RadioBus = cyw43::SpiBus<Output<'static>, PioSpi<'static, PIO0, 0>>;

#[embassy_executor::task]
async fn net_task(
    mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn usb_task(mut device: embassy_usb::UsbDevice<'static, Driver<'static, USB>>) {
    device.run().await;
}

#[embassy_executor::task]
async fn console_task(class: CdcAcmClass<'static, Driver<'static, USB>>, mut store: Store) {
    // Split once and let each half manage its own connection state, so output
    // and command handling are independent: a host that only reads must not
    // block the path that could reboot the board.
    let (mut tx, mut rx) = class.split();

    let out = async {
        loop {
            tx.wait_connection().await;
            loop {
                let line = LOGS.receive().await;
                // CDC packets are 64 bytes; longer lines are split rather than
                // truncated so nothing is silently lost.
                let mut failed = false;
                for chunk in line.as_bytes().chunks(62) {
                    if tx.write_packet(chunk).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed || tx.write_packet(b"\r\n").await.is_err() {
                    break;
                }
            }
        }
    };

    let inp = async {
        let mut packet = [0u8; 64];
        let mut line: String<160> = String::new();
        let mut pending = store.load().unwrap_or_default();
        loop {
            rx.wait_connection().await;
            loop {
                let Ok(n) = rx.read_packet(&mut packet).await else {
                    break;
                };
                for &b in &packet[..n] {
                    match b {
                        b'\r' | b'\n' => {
                            handle_command(line.as_str(), &mut pending, &mut store);
                            line.clear();
                        }
                        // Bare `b` stays a single-keystroke escape: it is the
                        // only command that must work when everything else is
                        // broken, including whatever is echoing our newlines.
                        b'b' if line.is_empty() => {
                            embassy_rp::rom_data::reset_to_usb_boot(0, 0);
                        }
                        _ => {
                            let _ = line.push(b as char);
                        }
                    }
                }
            }
        }
    };

    join(out, inp).await;
}

/// Runs one console command against the pending config.
///
/// Values are staged in memory and only reach flash on `save`, so a mistyped
/// field can be corrected without leaving the sector half-written.
fn handle_command(line: &str, pending: &mut Config, store: &mut Store) {
    let line = line.trim();
    let (cmd, value) = line.split_once(' ').unwrap_or((line, ""));
    match cmd {
        "" => {}
        "ssid" => match String::try_from(value) {
            Ok(v) => {
                pending.ssid = v;
                logln!("ssid staged ({} chars)", value.len());
            }
            Err(_) => logln!("ssid too long"),
        },
        "pass" => match String::try_from(value) {
            Ok(v) => {
                pending.password = v;
                // Never echo the value, only that it landed.
                logln!("password staged ({} chars)", value.len());
            }
            Err(_) => logln!("password too long"),
        },
        "host" => match String::try_from(value) {
            Ok(v) => {
                pending.control_host = v;
                logln!("control host staged: {}", value);
            }
            Err(_) => logln!("host too long"),
        },
        "ckey" => match String::try_from(value) {
            Ok(v) => {
                pending.control_key = v;
                logln!("control key staged ({} chars)", value.len());
            }
            Err(_) => logln!("control key too long"),
        },
        "key" => match String::try_from(value) {
            Ok(v) => {
                pending.auth_key = v;
                logln!("auth key staged ({} chars)", value.len());
            }
            Err(_) => logln!("auth key too long"),
        },
        "save" => match store.save(pending) {
            Ok(()) => logln!("saved to flash; reboot to apply"),
            Err(()) => logln!("flash write failed"),
        },
        "clear" => match store.clear() {
            Ok(()) => logln!("flash config erased"),
            Err(()) => logln!("flash erase failed"),
        },
        "show" => {
            let stored = store.load();
            logln!(
                "stored: {}  staged: ssid={} pass={} key={}",
                if stored.is_some() { "yes" } else { "none" },
                pending.ssid.len(),
                pending.password.len(),
                pending.auth_key.len()
            );
        }
        "help" | "?" => {
            logln!("ssid|pass|key|host|ckey <v> | save | clear | show | b=bootloader");
        }
        other => logln!("unknown command {:?} (try ?)", other),
    }
}

/// Registers this node, returning a short status line.
async fn register(
    conn: &mut h2conn::H2Conn,
    socket: &mut embassy_net::tcp::TcpSocket<'_>,
    host: &str,
    cfg: &Config,
    node_key: &tailscale_core::key::NodePublic,
) -> Result<String<64>, h2conn::H2Error> {
    let hostinfo = tailscale_core::control::Hostinfo {
        hostname: "lando-pico",
        ..Default::default()
    };
    let auth = if cfg.auth_key.is_empty() {
        None
    } else {
        Some(cfg.auth_key.as_str())
    };

    let mut body = [0u8; 640];
    let n = tailscale_core::control::write_register_request(
        &mut body,
        &tailscale_core::control::Register {
            capability_version: tailscale_core::CAPABILITY_VERSION,
            node_key,
            auth_key: auth,
            followup: None,
            hostinfo: &hostinfo,
            ephemeral: false,
        },
    )
    .map_err(|_| h2conn::H2Error::Frame)?;

    let mut out = [0u8; 1024];
    let len = conn
        .post(
            socket,
            host,
            tailscale_core::control::REGISTER_PATH,
            &body[..n],
            &mut out,
        )
        .await?;

    let mut status: String<64> = String::new();
    match tailscale_core::control::parse_register_response(&out[..len]) {
        Ok(r) if !r.error.is_empty() => {
            let _ = core::write!(&mut status, "refused: {}", r.error);
        }
        Ok(r) if !r.auth_url.is_empty() => {
            let _ = core::write!(&mut status, "needs interactive login");
        }
        Ok(r) => {
            let _ = core::write!(&mut status, "registered, authorized={}", r.machine_authorized);
        }
        Err(_) => {
            let _ = core::write!(&mut status, "bad response ({} bytes)", len);
        }
    }
    Ok(status)
}

/// Holds the netmap long-poll open, which is what makes the node report
/// online — that status is driven by this poll, not by registration.
async fn map_poll(
    conn: &mut h2conn::H2Conn,
    socket: &mut embassy_net::tcp::TcpSocket<'_>,
    host: &str,
    node_key: &tailscale_core::key::NodePublic,
    disco_key: &tailscale_core::key::DiscoPublic,
    endpoint: &str,
) -> Result<(), h2conn::H2Error> {
    let hostinfo = tailscale_core::control::Hostinfo {
        hostname: "lando-pico",
        preferred_derp: 1,
        ..Default::default()
    };
    let mut body = [0u8; 640];
    let n = tailscale_core::control::write_map_request(
        &mut body,
        &tailscale_core::control::MapRequest {
            capability_version: tailscale_core::CAPABILITY_VERSION,
            node_key,
            disco_key,
            hostinfo: &hostinfo,
            stream: true,
            keep_alive: true,
            // Peers are dropped for now: the netmap is the largest thing that
            // arrives here, and nothing on the device consumes peers yet.
            omit_peers: true,
            endpoints: &[endpoint],
            home_derp: 0,
        },
    )
    .map_err(|_| h2conn::H2Error::Frame)?;

    logln!("map: streaming (peers omitted)");
    let mut frames = tailscale_core::control::MapFrames::new();
    let mut count = 0u32;
    let mut current = 0usize;
    conn.post_stream(
        socket,
        host,
        tailscale_core::control::MAP_PATH,
        &body[..n],
        |mut data| {
            while !data.is_empty() {
                let (used, frame) = frames.feed(data);
                if used == 0 && frame.is_none() {
                    break;
                }
                data = &data[used..];
                let Some(frame) = frame else { continue };
                if frame.total_len == 0 {
                    logln!("map: keep-alive");
                    continue;
                }
                current += frame.chunk.len();
                if frame.end {
                    count += 1;
                    logln!("map: frame {} ({} bytes) — node is online", count, current);
                    current = 0;
                }
            }
        },
    )
    .await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    let driver = Driver::new(p.USB, Irqs);

    let mut store = Store::new(p.FLASH);
    let mut stored = store.load();

    // Keys are generated once and kept. This has to happen before the console
    // task takes the store, and before anything tries to register.
    let mut trng = Trng::new(p.TRNG, Irqs, Default::default());
    if let Some(cfg) = stored.as_mut() {
        if cfg.machine_key.is_none() || cfg.node_key.is_none() {
            let mut k = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut trng, &mut k);
            cfg.machine_key = Some(k);
            rand_core::RngCore::fill_bytes(&mut trng, &mut k);
            cfg.node_key = Some(k);
            let _ = store.save(cfg);
        }
    }

    let mut config = UsbConfig::new(0xc0de, 0xcafe);
    config.manufacturer = Some("lando");
    config.product = Some("lando-fw");
    config.serial_number = Some("lando-0001");
    // Composite device with an interface association descriptor, which is what
    // hosts expect of a CDC device that may grow more interfaces later.
    config.device_class = 0xEF;
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.composite_with_iads = true;

    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static CDC_STATE: StaticCell<State> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        &mut [],
        CONTROL_BUF.init([0; 64]),
    );
    let class = CdcAcmClass::new(&mut builder, CDC_STATE.init(State::new()), 64);
    let usb = builder.build();

    spawner.spawn(usb_task(usb)).unwrap();
    spawner.spawn(console_task(class, store)).unwrap();

    // Enumeration has to finish before anything else is attempted, and the
    // host needs a moment after that before it will read what we write.
    Timer::after(Duration::from_secs(2)).await;

    logln!("lando-fw on RP2350, capver {}", tailscale_core::CAPABILITY_VERSION);
    logln!("send 'b' on this port to reboot into the bootloader");

    // Proves the protocol core runs on the target rather than merely linking:
    // this is the same code path the host uses to open a control connection.
    let machine = tailscale_core::key::MachinePrivate::from_bytes([7u8; 32]);
    let ephemeral = tailscale_core::key::MachinePrivate::from_bytes([9u8; 32]);
    match tailscale_core::key::MachinePublic::parse(
        "mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b",
    ) {
        Ok(control) => {
            let started = embassy_time::Instant::now();
            let (_, initiation) = tailscale_core::noise::Handshake::start(
                machine,
                &control,
                tailscale_core::CAPABILITY_VERSION,
                ephemeral,
            );
            logln!(
                "noise initiation: {} bytes, type {}, built in {} ms",
                initiation.len(),
                initiation[2],
                started.elapsed().as_millis()
            );
        }
        Err(e) => logln!("control key parse failed: {:?}", e),
    }

    // ---- radio ----
    // The radio DMAs straight out of these, so they must be 4-byte aligned;
    // a plain `include_bytes!` has no alignment guarantee at all.
    static FW: Aligned<A4, [u8; 231077]> =
        Aligned(*include_bytes!("../cyw43-firmware/43439A0.bin"));
    static NVRAM: Aligned<A4, [u8; 742]> =
        Aligned(*include_bytes!("../cyw43-firmware/nvram_rp2040.bin"));
    let clm = include_bytes!("../cyw43-firmware/43439A0_clm.bin");

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        RM2_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        embassy_rp::dma::Channel::new(p.DMA_CH0, Irqs),
    );

    static CYW43_STATE: StaticCell<cyw43::State> = StaticCell::new();
    let (net_device, mut control, runner) =
        cyw43::new(CYW43_STATE.init(cyw43::State::new()), pwr, spi, &FW, &NVRAM).await;
    spawner.spawn(cyw43_task(runner)).unwrap();

    logln!("radio: loading country/regulatory blob");
    control.init(clm).await;
    // Power save adds seconds of latency to inbound packets, which matters for
    // a device whose whole job is answering them.
    control
        .set_power_management(cyw43::PowerManagementMode::None)
        .await;

    let Some(cfg) = stored.clone().filter(Config::is_complete) else {
        logln!("unprovisioned — set credentials over this console, then reboot");
        logln!("  ssid <name>");
        logln!("  pass <passphrase>");
        logln!("  save");
        loop {
            logln!("waiting for provisioning (type ? for help)");
            Timer::after(Duration::from_secs(10)).await;
        }
    };

    logln!("radio: joining {:?} ({} char key)", cfg.ssid.as_str(), cfg.password.len());
    let started = embassy_time::Instant::now();
    let joined = control
        .join(
            cfg.ssid.as_str(),
            cyw43::JoinOptions::new(cfg.password.as_bytes()),
        )
        .await;
    let status: String<64> = match &joined {
        Ok(_) => {
            let mut s: String<64> = String::new();
            let _ = core::write!(&mut s, "joined in {} ms", started.elapsed().as_millis());
            s
        }
        Err(e) => {
            let mut s: String<64> = String::new();
            let _ = core::write!(&mut s, "join failed: {:?}", e);
            s
        }
    };
    logln!("radio: {}", status);

    // ---- network stack ----
    // Seeded from the hardware TRNG initialised at boot: this seeds TCP
    // initial sequence numbers, and a device that boots with the same seed
    // every time is trivially predictable.
    let seed = rand_core::RngCore::next_u64(&mut trng);

    static RESOURCES: StaticCell<embassy_net::StackResources<4>> = StaticCell::new();
    let (stack, net_runner) = embassy_net::new(
        net_device,
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(embassy_net::StackResources::new()),
        seed,
    );
    spawner.spawn(net_task(net_runner)).unwrap();

    logln!("net: waiting for DHCP");
    let dhcp_started = embassy_time::Instant::now();
    stack.wait_config_up().await;
    let mut addr: String<64> = String::new();
    let mut endpoint: String<32> = String::new();
    if let Some(v4) = stack.config_v4() {
        let _ = core::write!(&mut addr, "{}", v4.address);
        // Advertised so peers can reach us directly. On a LAN this removes
        // the relay from the path entirely.
        let _ = core::write!(&mut endpoint, "{}:{}", v4.address.address(), wg::PORT);
    }
    logln!(
        "net: DHCP up in {} ms, address {}",
        dhcp_started.elapsed().as_millis(),
        addr.as_str()
    );

    // ---- control plane ----
    let cfg = cfg.clone();
    let host_spec = if cfg.control_host.is_empty() {
        tailscale_core::DEFAULT_CONTROL_HOST
    } else {
        cfg.control_host.as_str()
    };
    let (host, port) = match host_spec.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
        None => (host_spec, 80),
    };
    let key_str = if cfg.control_key.is_empty() {
        CONTROL_KEY
    } else {
        cfg.control_key.as_str()
    };

    let mut control_status: String<64> = String::new();
    let machine_key = cfg.machine_key.map(tailscale_core::key::MachinePrivate::from_bytes);
    let node_key = cfg.node_key.map(tailscale_core::key::NodePrivate::from_bytes);

    match (
        tailscale_core::key::MachinePublic::parse(key_str),
        machine_key,
        node_key,
    ) {
        (Ok(control_key), Some(machine_key), Some(node_key)) => {
            let mut seed = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut trng, &mut seed);
            let ephemeral = tailscale_core::key::MachinePrivate::from_bytes(seed);

            static RX: StaticCell<[u8; 4096]> = StaticCell::new();
            static TX: StaticCell<[u8; 2048]> = StaticCell::new();
            let started = embassy_time::Instant::now();
            match control::connect(
                stack,
                host,
                port,
                &control_key,
                machine_key,
                ephemeral,
                tailscale_core::CAPABILITY_VERSION,
                RX.init([0; 4096]),
                TX.init([0; 2048]),
            )
            .await
            {
                Err(e) => {
                    let _ = core::write!(&mut control_status, "ts2021 failed: {:?}", e);
                }
                Ok((mut socket, session, leftover, leftover_len)) => {
                    logln!("control: ts2021 up in {} ms", started.elapsed().as_millis());
                    match h2conn::H2Conn::start(&mut socket, session, &leftover[..leftover_len])
                        .await
                    {
                        Err(e) => {
                            let _ = core::write!(&mut control_status, "h2 failed: {:?}", e);
                        }
                        Ok(mut conn) => {
                            match register(&mut conn, &mut socket, host, &cfg, &node_key.public())
                                .await
                            {
                                Err(e) => {
                                    let _ =
                                        core::write!(&mut control_status, "register: {:?}", e);
                                }
                                Ok(text) => {
                                    logln!("control: {}", text.as_str());
                                    // One disco key: the netmap advertises it
                                    // and the UDP responder opens pings with
                                    // it, so they must be the same key.
                                    let mut disco = [0u8; 32];
                                    rand_core::RngCore::fill_bytes(&mut trng, &mut disco);
                                    let disco =
                                        tailscale_core::key::DiscoPrivate::from_bytes(disco);
                                    // A long-poll is quiet by design: the
                                    // server holds the response open and sends
                                    // nothing until the tailnet changes. The
                                    // 20 s idle timeout used for the handshake
                                    // would abort it during normal operation.
                                    socket.set_timeout(Some(
                                        embassy_time::Duration::from_secs(300),
                                    ));
                                    // Runs until the connection drops; the node
                                    // is online for exactly as long as it does.
                                    let mut wg_seed = [0u8; 4];
                                    rand_core::RngCore::fill_bytes(&mut trng, &mut wg_seed);
                                    let wg_index = u32::from_le_bytes(wg_seed);
                                    // Both halves block forever by design: the
                                    // poll is what keeps the node online, the
                                    // UDP socket is what makes it reachable.
                                    let polled = embassy_futures::select::select(
                                        map_poll(
                                            &mut conn,
                                            &mut socket,
                                            host,
                                            &node_key.public(),
                                            &disco.public(),
                                            endpoint.as_str(),
                                        ),
                                        wg::serve(stack, &node_key, &disco, wg_index),
                                    )
                                    .await;
                                    let polled = match polled {
                                        embassy_futures::select::Either::First(r) => r,
                                        embassy_futures::select::Either::Second(_) => Ok(()),
                                    };
                                    match polled {
                                        Ok(()) => {
                                            let _ = core::write!(
                                                &mut control_status,
                                                "map stream ended"
                                            );
                                        }
                                        Err(e) => {
                                            let _ = core::write!(
                                                &mut control_status,
                                                "map failed: {:?}",
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        (Err(_), _, _) => {
            let _ = core::write!(&mut control_status, "bad control key");
        }
        _ => {
            let _ = core::write!(&mut control_status, "no device keys");
        }
    }
    logln!("control: {}", control_status.as_str());

    // The status rides on every tick rather than being logged once at boot:
    // the host opens the CDC port during enumeration, so anything written
    // before an actual reader attaches is drained into a connection nobody is
    // listening to, and boot-time output is effectively unobservable.
    let mut ticks = 0u32;
    loop {
        logln!("tick {} — {}, addr {}", ticks, control_status.as_str(), addr.as_str());
        ticks = ticks.wrapping_add(1);
        Timer::after(Duration::from_secs(5)).await;
    }
}
