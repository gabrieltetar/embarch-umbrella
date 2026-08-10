//! Reading `embarch/embarch.toml` for `doctor` (design.md §5 checks 6-9).
//!
//! The same shape `embarch-api/src/config.rs` deserializes — `doctor` has to
//! see exactly what `embarch-api` would see, not a reinterpretation of it —
//! minus the fields none of checks 6-9 read (`flash_format`, `env`; TOML
//! tolerates the extra keys since neither struct denies unknown fields), and
//! without `embarch-api`'s own validation, since `doctor`'s whole job is to
//! report what's wrong rather than fail fast on the first bad field. Another
//! liftable copy (design.md §3 decision 15's pattern), scoped to the checks
//! that need it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

fn default_core_port() -> u16 {
    crate::topology::DEFAULT_CORE_PORT
}

#[derive(Debug, Deserialize)]
pub struct CoreConfig {
    pub base_url: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default = "default_core_port")]
    pub port: u16,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_env: Option<String>,
}

impl CoreConfig {
    /// Doctor's checks call `crate::token::resolve_token` directly with
    /// `token`/`token_env` pulled out first, since check 4 needs to report
    /// resolution failures as its own check rather than bubbling an
    /// `anyhow::Error` — so this type carries no resolution method of its own.
    pub fn is_auto(&self) -> bool {
        self.base_url.trim().eq_ignore_ascii_case("auto")
    }
}

#[derive(Debug, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub source_path: PathBuf,
    #[serde(default)]
    pub build_cwd: Option<PathBuf>,
    pub build_command: Vec<String>,
    pub artifact_path: PathBuf,
    pub chip: String,
    #[serde(default)]
    pub artifact_path_for_core: Option<String>,
}

impl ProjectConfig {
    pub fn build_dir(&self) -> PathBuf {
        match &self.build_cwd {
            Some(cwd) => self.source_path.join(cwd),
            None => self.source_path.clone(),
        }
    }

    pub fn resolved_artifact_path(&self) -> PathBuf {
        self.build_dir().join(&self.artifact_path)
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub core: CoreConfig,
    #[serde(default, rename = "projects")]
    pub projects: Vec<ProjectConfig>,
}

impl Config {
    pub fn load_from_path(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("failed to parse config file at {}", path.display()))
    }
}

/// Walk up from the current directory looking for `embarch/embarch.toml`,
/// the same layout `init` writes (`init.rs::find_repo_root` plus the fixed
/// `embarch/embarch.toml` suffix).
pub fn find_config_path() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let repo = crate::init::find_repo_root(&cwd)?;
    let path = repo.join("embarch").join("embarch.toml");
    path.exists().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "[core]\nbase_url = \"auto\"\n\n[[projects]]\nname = \"fw\"\nsource_path = \"/repo\"\nbuild_command = [\"west\", \"build\"]\nartifact_path = \"build/zephyr/zephyr.hex\"\nchip = \"CHANGE-ME\"\nflash_format = \"hex\"\n";

    #[test]
    fn parses_a_scaffolded_config() {
        let dir = std::env::temp_dir().join(format!(
            "embarch-umbrella-config-test-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embarch.toml");
        std::fs::write(&path, SAMPLE).unwrap();

        let config = Config::load_from_path(&path).unwrap();
        assert!(config.core.is_auto());
        assert_eq!(config.projects.len(), 1);
        assert_eq!(config.projects[0].chip, "CHANGE-ME");
        assert_eq!(
            config.projects[0].resolved_artifact_path(),
            PathBuf::from("/repo/build/zephyr/zephyr.hex")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_cwd_is_joined_under_source_path() {
        let mut raw = SAMPLE.replace(
            "source_path = \"/repo\"",
            "source_path = \"/repo\"\nbuild_cwd = \"app/fw\"",
        );
        raw.push('\n');
        let dir = std::env::temp_dir().join(format!(
            "embarch-umbrella-config-test-cwd-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embarch.toml");
        std::fs::write(&path, &raw).unwrap();

        let config = Config::load_from_path(&path).unwrap();
        assert_eq!(config.projects[0].build_dir(), PathBuf::from("/repo/app/fw"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
