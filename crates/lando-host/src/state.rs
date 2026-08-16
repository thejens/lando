//! Persistent node identity.
//!
//! The machine key and node key must outlive a restart. Re-registering with
//! the *same* node key is treated by the control plane as a refresh, whereas
//! generating fresh keys creates a new node and burns an auth-key use — and
//! auth keys are single-use or expire within 90 days, so a device that
//! re-registers from scratch on every boot stops working the first time it
//! reboots unattended.
//!
//! On the Pico this lands in a flash sector instead of a file, but the shape
//! is the same, which is why the format is trivially parseable.

use std::path::{Path, PathBuf};

use tailscale_core::key::{MachinePrivate, NodePrivate};

pub struct State {
    pub machine_key: MachinePrivate,
    pub node_key: NodePrivate,
    path: PathBuf,
}

impl State {
    pub fn path() -> PathBuf {
        std::env::var("LANDO_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".lando-state"))
    }

    /// Loads existing keys, or generates and persists a fresh identity.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), String> {
        if let Ok(text) = std::fs::read_to_string(path) {
            let machine = field(&text, "machine")?;
            let node = field(&text, "node")?;
            return Ok((
                Self {
                    machine_key: MachinePrivate::from_bytes(machine),
                    node_key: NodePrivate::from_bytes(node),
                    path: path.to_path_buf(),
                },
                false,
            ));
        }
        let state = Self {
            machine_key: MachinePrivate::generate(&mut rand_core::OsRng),
            node_key: NodePrivate::generate(&mut rand_core::OsRng),
            path: path.to_path_buf(),
        };
        state.save()?;
        Ok((state, true))
    }

    pub fn save(&self) -> Result<(), String> {
        let body = format!(
            "machine {}\nnode {}\n",
            hex(self.machine_key.as_bytes()),
            hex(self.node_key.as_bytes())
        );
        std::fs::write(&self.path, body).map_err(|e| format!("writing {:?}: {e}", self.path))?;
        restrict(&self.path);
        Ok(())
    }
}

/// Private keys must not be world-readable.
#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

fn field(text: &str, name: &str) -> Result<[u8; 32], String> {
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix(name).map(str::trim))
        .ok_or_else(|| format!("state file missing {name:?} line"))?;
    let bytes = line.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("{name} key is not 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (i, c) in bytes.chunks_exact(2).enumerate() {
        let hi = digit(c[0]).ok_or_else(|| format!("bad hex in {name}"))?;
        let lo = digit(c[1]).ok_or_else(|| format!("bad hex in {name}"))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
