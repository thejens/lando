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

use core::fmt::Write as _;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0, USB};
use embassy_rp::pio::{InterruptHandler as PioInterruptHandler, Pio};
use embassy_rp::usb::{Driver, InterruptHandler};
use cyw43::{Aligned, A4};
use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use heapless::String;
use static_cell::StaticCell;

use panic_halt as _;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<DMA_CH0>;
});

/// WiFi credentials, baked into the image for now.
///
/// A stopgap: the device is meant to be provisioned over USB into a flash
/// sector, so credentials never sit in a build artifact. Until that exists,
/// this file is gitignored and the image is treated as sensitive.
const WIFI_CONFIG: &str = include_str!("../../../.lando-wifi");

fn wifi_credentials() -> (&'static str, &'static str) {
    let mut lines = WIFI_CONFIG.lines();
    (
        lines.next().unwrap_or("").trim(),
        lines.next().unwrap_or("").trim(),
    )
}

/// RP2350 requires a signed image block in flash; without it the bootloader
/// refuses to run the binary at all.
#[link_section = ".start_block"]
#[used]
static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

const LINE_LEN: usize = 128;
/// Log lines waiting to go out. Bounded, and full means drop: a device whose
/// network stack stalls because its logging backed up is worse than one that
/// loses a line.
static LOGS: Channel<CriticalSectionRawMutex, String<LINE_LEN>, 16> = Channel::new();

/// Queues a line for the USB console, dropping it if the queue is full.
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => {{
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
async fn usb_task(mut device: embassy_usb::UsbDevice<'static, Driver<'static, USB>>) {
    device.run().await;
}

#[embassy_executor::task]
async fn console_task(class: CdcAcmClass<'static, Driver<'static, USB>>) {
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
        let mut buf = [0u8; 64];
        loop {
            rx.wait_connection().await;
            loop {
                let Ok(n) = rx.read_packet(&mut buf).await else {
                    break;
                };
                for &b in &buf[..n] {
                    if b == b'b' {
                        // Hand the board back to the bootloader so the next
                        // image can be flashed without anyone touching it.
                        embassy_rp::rom_data::reset_to_usb_boot(0, 0);
                    }
                }
            }
        }
    };

    join(out, inp).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    let driver = Driver::new(p.USB, Irqs);

    let mut config = Config::new(0xc0de, 0xcafe);
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
    spawner.spawn(console_task(class)).unwrap();

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
    let (_net_device, mut control, runner) =
        cyw43::new(CYW43_STATE.init(cyw43::State::new()), pwr, spi, &FW, &NVRAM).await;
    spawner.spawn(cyw43_task(runner)).unwrap();

    logln!("radio: loading country/regulatory blob");
    control.init(clm).await;
    // Power save adds seconds of latency to inbound packets, which matters for
    // a device whose whole job is answering them.
    control
        .set_power_management(cyw43::PowerManagementMode::None)
        .await;

    let (ssid, pass) = wifi_credentials();
    logln!("radio: joining {:?} ({} char key)", ssid, pass.len());
    let started = embassy_time::Instant::now();
    let joined = control
        .join(ssid, cyw43::JoinOptions::new(pass.as_bytes()))
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

    // The status rides on every tick rather than being logged once at boot:
    // the host opens the CDC port during enumeration, so anything written
    // before an actual reader attaches is drained into a connection nobody is
    // listening to, and boot-time output is effectively unobservable.
    let mut ticks = 0u32;
    loop {
        logln!("tick {} — radio: {}", ticks, status);
        ticks = ticks.wrapping_add(1);
        Timer::after(Duration::from_secs(5)).await;
    }
}
