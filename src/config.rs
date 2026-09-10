//! Reading `embarch/embarch.toml` for `doctor` (embarch-umbrella spec.md §5).
//!
//! `ProjectConfig` below mirrors the same shape `embarch-api/src/config.rs`
//! deserializes — `doctor` has to see exactly what `embarch-api` would see,
//! not a reinterpretation of it — minus the fields none of checks 6-9 read
//! (`env`; TOML tolerates the extra keys since neither struct denies unknown
//! fields). `flash_format` **is** carried here, required with no
//! `serde(default)` exactly as upstream declares it, even though no check
//! reads its value: the point is that a config missing it fails to parse
//! under this mirror too, the same way it fails upstream. Another liftable
//! copy (decision 15's pattern), scoped to the checks that need it.
//!
//! This mirror does **not** reproduce `embarch-api`'s own `.validate()` in
//! full — `doctor`'s whole job is to report what's wrong rather than fail
//! fast on the first bad field, so `source_path` existence stays a per-project
//! report (see `check_config` in `doctor.rs`), not a hard refusal, and token
//! resolution is check 4's job via the real `embarch_core_client` crate, not
//! this file's. It does reproduce the two structural refusals that are
//! **binary facts about the file**, not per-project reports: a duplicate
//! project name, and the two config keys retired-by-refusal upstream
//! (decisions 51/53) — [`Config::load_from_path`]'s `validate` below.
//!
//! As of the check-6 rewrite (`doctor.rs`), this mirror is no longer the
//! *only* thing standing between `doctor` and a config the real
//! `embarch-api` would refuse: check 6 shells out to the located
//! `embarch-api` for its actual verdict, the same way check 8 already does
//! for target discovery, so a config this mirror is too permissive about is
//! still correctly reported by check 6 whenever `embarch-api` is located.
//! The mirror's own strictness above only matters when it isn't (check 6's
//! `LoaderVerdict::Unanswerable` fallback) — which is why it's still worth
//! keeping in sync rather than left maximally permissive.
//!
//! `CoreConfig` below is *not* mirrored from `embarch-api/src/config.rs` —
//! that struct moved out to the shared `embarch-api/crates/embarch-core-client`
//! crate on 2026-08-24 (`../embarch-doc/embarch-umbrella/decisions/mirrors.md`
//! 20's amendment). This file still hand-keeps its own `CoreConfig` shape
//! rather than depending on the shared one for it; see decision 20's
//! amendment for why that half stays a mirror for now. It now also mirrors
//! the five `*_timeout_secs` fields the shared crate's `CoreConfig` carries
//! (`status`/`reset`/`flash`/`serial`/`study`) — absent here since 2026-08-24 and
//! nothing consulted them, since umbrella's own doctor checks use their own
//! fixed budgets, not the configured ones. Declared for shape-fidelity with
//! the mirrored struct, not because anything here reads them yet.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

fn default_core_port() -> u16 {
    embarch_topology::software::DEFAULT_CORE_PORT
}

fn default_status_timeout_secs() -> u64 {
    10
}
fn default_reset_timeout_secs() -> u64 {
    10
}
fn default_flash_timeout_secs() -> u64 {
    120
}
fn default_serial_timeout_secs() -> u64 {
    15
}
fn default_study_timeout_secs() -> u64 {
    30
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
    // Shape-fidelity only — nothing here reads these yet (see this file's
    // header): doctor's own checks use fixed budgets, not the configured
    // ones. `#[allow(dead_code)]` rather than dropping the fields, the same
    // posture `zephyr.rs`'s `BoardYml::board` already takes for a field kept
    // only so the shape parses.
    #[allow(dead_code)]
    #[serde(default = "default_status_timeout_secs")]
    pub status_timeout_secs: u64,
    #[allow(dead_code)]
    #[serde(default = "default_reset_timeout_secs")]
    pub reset_timeout_secs: u64,
    #[allow(dead_code)]
    #[serde(default = "default_flash_timeout_secs")]
    pub flash_timeout_secs: u64,
    #[allow(dead_code)]
    #[serde(default = "default_serial_timeout_secs")]
    pub serial_timeout_secs: u64,
    #[allow(dead_code)]
    #[serde(default = "default_study_timeout_secs")]
    pub study_timeout_secs: u64,
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
    /// Required, no `serde(default)`, matching `embarch-api/src/config.rs`
    /// exactly (both discovery kinds) — declared even though no check 6-9
    /// reads its value, so that a config omitting it fails to parse under
    /// this mirror too, the same way it fails upstream.
    #[allow(dead_code)]
    pub flash_format: String,
    /// **Not upstream** — `embarch-api` retired this field (its own
    /// decision 15's UNC-guessing retrospective) but still tolerates it by
    /// name, on the record, *because* `embarch-umbrella` still scaffolds and
    /// reads it (`embarch-api` decision 64, `decisions/shape.md`): `init.rs`
    /// writes it for a `discovery = "static"` project on a WSL2 split
    /// (this repo's decision 16), and `doctor` check 9 is the WSL2
    /// UNC-vs-real-path comparison decision 16 describes. This is
    /// deliberately kept, not a fourth strand of drift to close — removing
    /// it would need `init.rs`'s write removed in the same change *and*
    /// `embarch-api` decision 64's toleration retired in step, which is a
    /// change to another sub-project's repo and out of this task's scope.
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
    /// `[[projects.targets]]`, retired upstream (`embarch-api` decision
    /// 53) — kept here **only** so a config still declaring it is refused
    /// by name at load (see `Config::validate` below) instead of parsing
    /// silently into a field nothing reads, the same posture upstream
    /// gives it.
    #[serde(default, rename = "targets")]
    pub retired_targets: Vec<toml::Value>,
    /// `soc_chip_overrides`, retired unbuilt upstream (`embarch-api`
    /// decision 13) — kept here for the same by-name refusal `retired_targets`
    /// gets.
    #[serde(default, rename = "soc_chip_overrides")]
    pub retired_soc_chip_overrides: Option<toml::Value>,
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
        let config: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file at {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// The two structural refusals this mirror reproduces from
    /// `embarch-api`'s own `validate()` — binary facts about the file
    /// (a duplicate name, a retired key still declared) rather than a
    /// per-project report, which is why they belong here and not in
    /// `doctor.rs`'s check 6/7/8/9 (see this file's header). Deliberately
    /// **not** a full mirror of upstream's `validate()`: `source_path`
    /// existence and token resolution stay check 6's and check 4's own
    /// per-project/per-run reports, matching `doctor`'s "report everything
    /// wrong" posture rather than upstream's fail-on-first-bad-field one.
    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for project in &self.projects {
            if !seen.insert(project.name.as_str()) {
                anyhow::bail!("duplicate project name '{}' in config", project.name);
            }
            if !project.retired_targets.is_empty() {
                anyhow::bail!(
                    "project '{}' declares [[projects.targets]], which is retired \
                     (`embarch-api` decision 53) — nothing ever selected a row. Declare one \
                     [[projects]] entry per target instead",
                    project.name
                );
            }
            if project.retired_soc_chip_overrides.is_some() {
                anyhow::bail!(
                    "project '{}' declares soc_chip_overrides, which is retired and was never \
                     built (`embarch-api` decision 13) — remove the key",
                    project.name
                );
            }
        }
        Ok(())
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
        let raw = "[core]\nbase_url = \"auto\"\n\n[[projects]]\nname = \"fw\"\nsource_path = \"/repo\"\ndiscovery = \"zephyr-west\"\nwest_binary = \"west\"\nflash_format = \"hex\"\n";
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
