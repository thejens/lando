//! Firmware for the Raspberry Pi Pico 2 W.
//!
//! The protocol work all lives in `tailscale-core`, which is `no_std` and
//! sans-IO precisely so it can arrive here unchanged. What this crate owns is
//! the parts that cannot be tested on a laptop: the radio, flash, USB, and the
//! scheduling that ties them together.
//!
//! There is no debug probe on this board, so USB CDC is the only way anything
//! gets out. The logger runs as its own task, independent of the network
//! tasks, so a wedged network stack still talks.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_time::{Duration, Timer};

use panic_halt as _;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

/// RP2350 requires a signed image block in flash; without it the bootloader
/// refuses to run the binary at all.
#[link_section = ".start_block"]
#[used]
static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

#[embassy_executor::task]
async fn logger_task(driver: Driver<'static, USB>) {
    embassy_usb_logger::run!(1024, log::LevelFilter::Info, driver);
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    let driver = Driver::new(p.USB, Irqs);
    spawner.spawn(logger_task(driver)).unwrap();

    // The host takes a moment to enumerate the CDC device; anything logged
    // before that is written into the void.
    Timer::after(Duration::from_secs(2)).await;

    log::info!("lando-fw starting on RP2350");
    log::info!("capability version {}", tailscale_core::CAPABILITY_VERSION);
    log::info!("control host {}", tailscale_core::DEFAULT_CONTROL_HOST);

    // Proves the protocol core links and runs on the target, not just that the
    // firmware boots: this is the same code the host binary uses to talk to
    // the control plane.
    let machine = tailscale_core::key::MachinePrivate::from_bytes([7u8; 32]);
    let control = tailscale_core::key::MachinePublic::parse(
        "mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b",
    )
    .unwrap();
    let ephemeral = tailscale_core::key::MachinePrivate::from_bytes([9u8; 32]);
    let (_, initiation) = tailscale_core::noise::Handshake::start(
        machine,
        &control,
        tailscale_core::CAPABILITY_VERSION,
        ephemeral,
    );
    log::info!(
        "noise initiation built: {} bytes, type {}",
        initiation.len(),
        initiation[2]
    );

    let mut ticks = 0u32;
    loop {
        log::info!("alive, tick {ticks}");
        ticks = ticks.wrapping_add(1);
        Timer::after(Duration::from_secs(5)).await;
    }
}
