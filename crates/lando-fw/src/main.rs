//! Firmware for the Raspberry Pi Pico 2 W.
//!
//! The protocol work all lives in `tailscale-core`, which is `no_std` and
//! sans-IO precisely so it can arrive here unchanged. What this crate owns is
//! the parts that cannot be tested on a laptop: the radio, flash, USB, and the
//! scheduling that ties them together.
//!
//! There is no debug probe on this board, so USB CDC is the only way anything
//! gets out — which makes the order of operations at boot matter more than it
//! looks. `panic_halt` turns any panic or stack overflow into a silent spin
//! that stops the executor, USB task included, leaving the device stuck
//! half-enumerated with no way to say why. So nothing heavy runs before USB is
//! up and has had a chance to say something.

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
    embassy_usb_logger::run!(4096, log::LevelFilter::Info, driver);
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    let driver = Driver::new(p.USB, Irqs);
    spawner.spawn(logger_task(driver)).unwrap();

    // Enumeration has to finish before anything else is attempted, and the
    // host needs a moment after that before it will read what we write.
    Timer::after(Duration::from_secs(3)).await;

    let mut ticks = 0u32;
    loop {
        log::info!(
            "lando-fw alive on RP2350 — tick {ticks}, capver {}",
            tailscale_core::CAPABILITY_VERSION
        );
        ticks = ticks.wrapping_add(1);
        Timer::after(Duration::from_secs(2)).await;
    }
}
