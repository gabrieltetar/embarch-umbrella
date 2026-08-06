//! What `setup` remembers between runs.
//!
//! Deliberately tiny, and deliberately *not* an address. The topology class
//! is stable; the address behind it isn't (design.md §3 decision 6), so
//! persisting a URL would recreate the staleness this suite just finished
//! removing. What's worth writing down is only what re-detection can't cheaply
//! rediscover: which class we concluded, the remote host if the operator named
//! one, and where a Windows-side `embarch-core.exe` was found from WSL2.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Bumped if the shape below ever changes incompatibly. Present from the
/// start so a future version can tell "old file" from "corrupt file."
pub const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    #[serde(default)]
    pub schema_version: u32,
    /// `local` / `wsl-host` / `remote`, as concluded by `setup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<String>,
    /// Only meaningful for `remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Where a Windows-side `embarch-core.exe` was found, when running under
    /// WSL2 — the one location worth caching, since finding it means walking
    /// `/mnt/c` (locate.rs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_exe: Option<PathBuf>,
}

/// Resolve the config directory from environment values.
///
/// Pure so the platform branches are testable without setting real env vars
/// or having the directories exist. Follows XDG on Unix and `%APPDATA%` on
/// Windows rather than pulling in a crate for fifteen lines.
pub fn config_dir_from(
    windows: bool,
    appdata: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    let base = if windows {
        PathBuf::from(appdata.filter(|s| !s.is_empty())?)
    } else if let Some(xdg) = xdg_config_home.filter(|s| !s.is_empty()) {
        PathBuf::from(xdg)
    } else {
        PathBuf::from(home.filter(|s| !s.is_empty())?).join(".config")
    };
    Some(base.join("embarch"))
}

fn config_dir() -> Result<PathBuf> {
    config_dir_from(
        cfg!(windows),
        std::env::var("APPDATA").ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
    .context("could not determine a config directory (no APPDATA, XDG_CONFIG_HOME, or HOME set)")
}

pub fn state_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("umbrella.toml"))
}

/// Read the saved state. A missing file is not an error — it just means
/// `setup` hasn't run, which every command has to cope with anyway.
pub fn load() -> State {
    let Ok(path) = state_path() else {
        return State::default();
    };
    load_from(&path).unwrap_or_default()
}

fn load_from(path: &Path) -> Option<State> {
    let text = std::fs::read_to_string(path).ok()?;
    match toml::from_str::<State>(&text) {
        Ok(state) => Some(state),
        Err(e) => {
            // Warn rather than fail: a corrupt state file should not stop
            // someone diagnosing a machine, and re-running `setup` fixes it.
            tracing::warn!("ignoring unreadable state file {}: {e}", path.display());
            None
        }
    }
}

pub fn save(state: &State) -> Result<()> {
    let path = state_path()?;
    let dir = path
        .parent()
        .context("state path has no parent directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("could not create {}", dir.display()))?;
    let mut state = state.clone();
    state.schema_version = STATE_SCHEMA_VERSION;
    let text = toml::to_string_pretty(&state).context("could not serialize state")?;
    std::fs::write(&path, text).with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_uses_appdata() {
        let d = config_dir_from(true, Some("C:\\Users\\me\\AppData\\Roaming"), None, None);
        assert_eq!(
            d,
            Some(PathBuf::from("C:\\Users\\me\\AppData\\Roaming").join("embarch"))
        );
    }

    #[test]
    fn unix_prefers_xdg_over_home() {
        let d = config_dir_from(false, None, Some("/home/me/.cfg"), Some("/home/me"));
        assert_eq!(d, Some(PathBuf::from("/home/me/.cfg/embarch")));
    }

    #[test]
    fn unix_falls_back_to_home_dot_config() {
        let d = config_dir_from(false, None, None, Some("/home/me"));
        assert_eq!(d, Some(PathBuf::from("/home/me/.config/embarch")));
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        assert_eq!(config_dir_from(false, None, Some(""), Some("/home/me")), Some(PathBuf::from("/home/me/.config/embarch")));
        assert_eq!(config_dir_from(false, None, None, Some("")), None);
        assert_eq!(config_dir_from(true, Some(""), None, Some("/home/me")), None);
    }

    #[test]
    fn state_round_trips_and_omits_empty_fields() {
        let state = State {
            schema_version: STATE_SCHEMA_VERSION,
            topology: Some("wsl-host".into()),
            host: None,
            core_exe: Some(PathBuf::from("/mnt/c/embarch/embarch-core.exe")),
        };
        let text = toml::to_string_pretty(&state).unwrap();
        // Match the key, not the substring — `topology = "wsl-host"` contains
        // "host" and made an earlier version of this assertion fail against
        // perfectly correct output.
        assert!(
            !text.lines().any(|l| l.trim_start().starts_with("host")),
            "None fields must not be written: {text}"
        );
        assert_eq!(toml::from_str::<State>(&text).unwrap(), state);
    }

    #[test]
    fn an_empty_file_loads_as_default() {
        assert_eq!(toml::from_str::<State>("").unwrap(), State::default());
    }
}
