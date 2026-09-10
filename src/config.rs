//! Reading `embarch/embarch.toml` for `doctor` (embarch-umbrella spec.md §5).
//!
//! `ProjectConfig` below mirrors the same shape `embarch-api/src/config.rs`
//! deserializes — `doctor` has to see exactly what `embarch-api` would see,
//! not a reinterpretation of it — minus the fields none of checks 6-9 read
//! (`flash_format`, `env`; TOML tolerates the extra keys since neither struct
//! denies unknown fields), and without `embarch-api`'s own validation, since
//! `doctor`'s whole job is to report what's wrong rather than fail fast on
//! the first bad field. Another liftable copy (decision 15's
//! pattern), scoped to the checks that need it.
//!
//! `CoreConfig` below is *not* mirrored from `embarch-api/src/config.rs` —
//! that struct moved out to the shared `embarch-api/crates/embarch-core-client`
//! crate on 2026-08-24 (`../embarch-doc/embarch-umbrella/decisions/mirrors.md`
//! 20's amendment). This file still hand-keeps its own `CoreConfig` shape
//! rather than depending on the shared one for it; see decision 20's
//! amendment for why that half stays a mirror for now.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

fn default_core_port() -> u16 {
    embarch_topology::software::DEFAULT_CORE_PORT
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
    /// Doctor's checks call `embarch_core_client::token_discovery::resolve_token`
    /// directly with `token`/`token_env` pulled out first, since check 4
    /// needs to report resolution failures as its own check rather than
    /// bubbling an `anyhow::Error` — so this type carries no resolution
    /// method of its own.
    pub fn is_auto(&self) -> bool {
        self.base_url.trim().eq_ignore_ascii_case("auto")
    }
}

/// Mirrors `embarch-api/src/config.rs`'s `Discovery` (`embarch-api` decision
/// 12) — another liftable copy, per this file's own header note.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum Discovery {
    #[default]
    Static,
    ZephyrWest,
}

#[derive(Debug, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub source_path: PathBuf,
    #[serde(default)]
    pub discovery: Discovery,
    #[serde(default)]
    pub build_cwd: Option<PathBuf>,
    /// Present for `discovery = "static"`; absent for `discovery =
    /// "zephyr-west"`, where it's assembled per call by `embarch-api`
    /// instead (`embarch-api` decision 12).
    #[serde(default)]
    pub build_command: Option<Vec<String>>,
    #[serde(default)]
    pub artifact_path: Option<PathBuf>,
    #[serde(default)]
    pub chip: Option<String>,
    #[serde(default)]
    pub artifact_path_for_core: Option<String>,
    /// Only meaningful for `discovery = "zephyr-west"`.
    #[serde(default)]
    pub west_binary: Option<PathBuf>,
    /// Only meaningful for `discovery = "zephyr-west"`: the parent under
    /// which `embarch-api` gives each distinct target its own build
    /// subdirectory (`embarch-api/src/resolve.rs`, named by that crate's
    /// `zephyr::Target::build_dir_name`). Mirrored here for `doctor`'s
    /// check 16, which counts those subdirectories.
    #[serde(default)]
    pub build_dir_root: Option<PathBuf>,
}

impl ProjectConfig {
    pub fn is_zephyr_west(&self) -> bool {
        self.discovery == Discovery::ZephyrWest
    }

    pub fn build_dir(&self) -> PathBuf {
        match &self.build_cwd {
            Some(cwd) => self.source_path.join(cwd),
            None => self.source_path.clone(),
        }
    }

    /// Only meaningful for `discovery = "static"` — a `zephyr-west`
    /// project's artifact path is resolved per call, not stored.
    pub fn resolved_artifact_path(&self) -> Option<PathBuf> {
        self.artifact_path.as_ref().map(|p| self.build_dir().join(p))
    }

    /// `build_dir_root` as *this* machine reaches it.
    ///
    /// `embarch-api` uses the configured value verbatim and runs a
    /// `zephyr-west` build with `cwd = source_path`, so a **relative** root —
    /// which is exactly what `init` writes (`embarch/build`) — really lands
    /// under `source_path`. Resolving it the same way here is what makes
    /// check 16 count the directories a build would actually create, rather
    /// than a path relative to wherever `doctor` happened to be run.
    pub fn resolved_build_dir_root(&self) -> Option<PathBuf> {
        let root = self.build_dir_root.as_ref()?;
        Some(if root.is_absolute() {
            root.clone()
        } else {
            self.source_path.join(root)
        })
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
        assert_eq!(config.projects[0].chip.as_deref(), Some("CHANGE-ME"));
        assert_eq!(
            config.projects[0].resolved_artifact_path(),
            Some(PathBuf::from("/repo/build/zephyr/zephyr.hex"))
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

    #[test]
    fn zephyr_west_project_parses_without_static_fields() {
        let raw = "[core]\nbase_url = \"auto\"\n\n[[projects]]\nname = \"fw\"\nsource_path = \"/repo\"\ndiscovery = \"zephyr-west\"\nwest_binary = \"west\"\n";
        let dir = std::env::temp_dir().join(format!(
            "embarch-umbrella-config-test-zw-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embarch.toml");
        std::fs::write(&path, raw).unwrap();

        let config = Config::load_from_path(&path).unwrap();
        assert!(config.projects[0].is_zephyr_west());
        assert_eq!(config.projects[0].chip, None);
        assert_eq!(config.projects[0].resolved_artifact_path(), None);

        std::fs::remove_dir_all(&dir).ok();
    }
}
