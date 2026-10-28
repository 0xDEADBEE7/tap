//! Where TAP keeps its state, and helpers that create it privately (0700 dirs, 0600 files).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `$XDG_CONFIG_HOME/tap`, else `$HOME/.config/tap`, else `./.tap`.
pub fn tap_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).join("tap"))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/tap")))
        .unwrap_or_else(|| PathBuf::from(".tap"))
}

pub fn sessions_dir() -> PathBuf {
    tap_home().join("sessions")
}

pub fn session_dir(id: &str) -> PathBuf {
    sessions_dir().join(id)
}

/// The local interception CA lives here (`ca.pem`, `ca.key`, `bundle.pem`).
pub fn ca_dir() -> PathBuf {
    tap_home().join("ca")
}

/// `mkdir -p` with mode 0700 on every directory it creates, and 0700 on `path` itself.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Atomically replaces `path` with `contents` (temp file + rename), mode 0600.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    fs::rename(&temp, path)
}

/// Opens `path` for appending, creating it with mode 0600.
pub fn open_private_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}
