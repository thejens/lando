//! Device configuration, stored in flash rather than compiled in.
//!
//! Baking credentials into the image with `include_str!` puts a WiFi
//! passphrase — and later a tailnet auth key — into every build artifact,
//! where it survives in `target/`, in any copy of the binary, and in anything
//! that ever reads the flash back out. Keeping them in a dedicated sector
//! written over USB means the firmware is the same bytes for every device and
//! carries no secrets at all.
//!
//! The layout is deliberately dull: a magic, a version, and length-prefixed
//! strings. A sector that fails to validate is treated as unprovisioned rather
//! than as an error, so a corrupt or erased sector is recoverable by writing a
//! new one instead of by reflashing.

use embassy_rp::flash::{Blocking, Flash, ERASE_SIZE};
use embassy_rp::peripherals::FLASH;
use heapless::String;

/// Total flash on the Pico 2 W.
pub const FLASH_SIZE: usize = 4 * 1024 * 1024;

/// Config lives in the last sector, as far from the program image as possible
/// so that growing the firmware never collides with it.
pub const CONFIG_OFFSET: u32 = (FLASH_SIZE - ERASE_SIZE) as u32;

const MAGIC: &[u8; 8] = b"LANDOCFG";
const VERSION: u8 = 1;
pub const MAX_FIELD: usize = 96;

/// What the device needs to reach the tailnet, none of which belongs in the
/// firmware image.
#[derive(Default, Clone)]
pub struct Config {
    pub ssid: String<MAX_FIELD>,
    pub password: String<MAX_FIELD>,
    /// Tailnet pre-auth key. Only needed for the first registration; after
    /// that the node key in this sector is what identifies the device.
    pub auth_key: String<MAX_FIELD>,
}

impl Config {
    pub fn is_complete(&self) -> bool {
        !self.ssid.is_empty() && !self.password.is_empty()
    }
}

pub struct Store {
    flash: Flash<'static, FLASH, Blocking, FLASH_SIZE>,
}

impl Store {
    pub fn new(flash: embassy_rp::Peri<'static, FLASH>) -> Self {
        Self {
            flash: Flash::new_blocking(flash),
        }
    }

    /// Reads the stored config, or `None` if the sector holds nothing valid.
    pub fn load(&mut self) -> Option<Config> {
        let mut buf = [0u8; 512];
        self.flash.blocking_read(CONFIG_OFFSET, &mut buf).ok()?;
        if &buf[..8] != MAGIC || buf[8] != VERSION {
            return None;
        }

        let mut pos = 9;
        let mut read_field = || -> Option<String<MAX_FIELD>> {
            let len = *buf.get(pos)? as usize;
            if len > MAX_FIELD || pos + 1 + len > buf.len() {
                return None;
            }
            let text = core::str::from_utf8(&buf[pos + 1..pos + 1 + len]).ok()?;
            pos += 1 + len;
            String::try_from(text).ok()
        };

        Some(Config {
            ssid: read_field()?,
            password: read_field()?,
            auth_key: read_field().unwrap_or_default(),
        })
    }

    /// Erases the sector and writes `config` into it.
    ///
    /// Erase granularity is a whole sector, so there is a window where the
    /// config is gone. That is acceptable here because the device is being
    /// provisioned over USB at the time, with a human watching.
    pub fn save(&mut self, config: &Config) -> Result<(), ()> {
        let mut buf = [0u8; 512];
        buf[..8].copy_from_slice(MAGIC);
        buf[8] = VERSION;
        let mut pos = 9;
        for field in [&config.ssid, &config.password, &config.auth_key] {
            let bytes = field.as_bytes();
            buf[pos] = bytes.len() as u8;
            buf[pos + 1..pos + 1 + bytes.len()].copy_from_slice(bytes);
            pos += 1 + bytes.len();
        }

        self.flash
            .blocking_erase(CONFIG_OFFSET, CONFIG_OFFSET + ERASE_SIZE as u32)
            .map_err(|_| ())?;
        self.flash.blocking_write(CONFIG_OFFSET, &buf).map_err(|_| ())
    }

    /// Erases the sector, returning the device to unprovisioned.
    pub fn clear(&mut self) -> Result<(), ()> {
        self.flash
            .blocking_erase(CONFIG_OFFSET, CONFIG_OFFSET + ERASE_SIZE as u32)
            .map_err(|_| ())
    }
}
