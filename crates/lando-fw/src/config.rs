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
const VERSION: u8 = 3;
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
    /// Control server hostname. Empty means Tailscale's hosted plane.
    pub control_host: String<MAX_FIELD>,
    /// The control server's Noise static, `mkey:...`. Empty means the pinned
    /// default, which is only correct for the hosted plane -- a self-hosted
    /// server has its own key and will fail to decrypt without it.
    pub control_key: String<MAX_FIELD>,
    /// Noise static identifying this device to the control plane.
    pub machine_key: Option<[u8; 32]>,
    /// WireGuard static identifying this node within the tailnet.
    ///
    /// Persisting both is what makes a reboot a *refresh* rather than a new
    /// registration. Regenerating them would create a second node and consume
    /// another auth-key use every time the device restarts.
    pub node_key: Option<[u8; 32]>,
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

        let ssid = read_field()?;
        let password = read_field()?;
        let auth_key = read_field().unwrap_or_default();
        let control_host = read_field().unwrap_or_default();
        let control_key = read_field().unwrap_or_default();

        // Keys are optional so a config written before the device had any
        // still loads; they are generated and saved on first registration.
        let mut read_key = || -> Option<[u8; 32]> {
            let present = *buf.get(pos)?;
            pos += 1;
            if present != 1 {
                return None;
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(buf.get(pos..pos + 32)?);
            pos += 32;
            Some(k)
        };

        Some(Config {
            ssid,
            password,
            auth_key,
            control_host,
            control_key,
            machine_key: read_key(),
            node_key: read_key(),
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
        for field in [
            &config.ssid,
            &config.password,
            &config.auth_key,
            &config.control_host,
            &config.control_key,
        ] {
            let bytes = field.as_bytes();
            buf[pos] = bytes.len() as u8;
            buf[pos + 1..pos + 1 + bytes.len()].copy_from_slice(bytes);
            pos += 1 + bytes.len();
        }

        for key in [&config.machine_key, &config.node_key] {
            match key {
                Some(k) => {
                    buf[pos] = 1;
                    buf[pos + 1..pos + 33].copy_from_slice(k);
                    pos += 33;
                }
                None => {
                    buf[pos] = 0;
                    pos += 1;
                }
            }
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
