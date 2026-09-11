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
//! `CoreConfig` is no longer mirrored here at all (`../embarch-doc/embarch-umbrella/decisions/mirrors.md`
//! 20's second amendment, closing the config half's `CoreConfig` strand):
//! this file re-exports `embarch_core_client::CoreConfig` directly rather
//! than hand-keeping a parallel struct, the same move decision 20's first
//! amendment already made for token resolution. The shared type already
//! carries both `is_auto()` and `resolve_token()`; doctor's check 4 still
//! calls `embarch_core_client::token_discovery::resolve_token` directly
//! (with `token`/`token_env` pulled out first) rather than the latter, so
//! it can report resolution failures as its own check.
//!
//! `ProjectConfig` below is still a hand-kept mirror — see decisions/mirrors.md
//! 20's second amendment for why that half could not follow `CoreConfig`
//! out (the type lives inside `embarch-api`'s own binary, not in the shared
//! crate) and what replaces the diff job for it instead:
//! `tests/project_config_fixture.rs`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub use embarch_core_client::CoreConfig;

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

    /// Drift guard for `ProjectConfig` — the one mirror `049` could not
    /// close by depending on a shared crate, since the real type lives
    /// inside `embarch-api`'s own binary rather than in
    /// `embarch-api/crates/embarch-core-client`
    /// (`../embarch-doc/embarch-umbrella/decisions/mirrors.md` 20's second
    /// amendment). This is the cheaper half instead: a real
    /// `embarch-api` config fixture (`embarch-api/config.example.toml`,
    /// read from that repo directly, not copied here — a path-dep sibling
    /// symlinked beside this worktree) is parsed two ways. First through a
    /// shadow struct listing **every** field the real upstream
    /// `ProjectConfig`/`Config` declare today with
    /// `#[serde(deny_unknown_fields)]`, so a field `embarch-api` adds and
    /// starts using in its own example config — one this file's mirror
    /// does not yet know about — fails this test the moment the fixture
    /// picks it up. Then through *this* file's real `Config`, confirming
    /// this mirror still parses what upstream now ships.
    ///
    /// What this does **not** catch: a field added upstream that never
    /// makes it into `config.example.toml`'s *uncommented* lines — most of
    /// that file's optional fields are commented out, so this fixture
    /// alone under-covers those. Narrower than a full diff job, but a real
    /// improvement on "nothing fails when they drift" (see this file's own
    /// header and `open.md`). Widening the fixture is `embarch-api`'s call,
    /// not this repo's to make by editing that file.
    ///
    /// Keep `UpstreamProjectConfig`'s field list in step with
    /// `embarch-api/src/config.rs`'s real `ProjectConfig` by hand — that's
    /// the drift this test exists to catch, so there is no shortcut to
    /// keeping the list itself current.
    #[test]
    fn embarch_api_example_config_has_no_field_this_mirror_does_not_know_about() {
        use std::collections::HashMap;

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct UpstreamDefaultTarget {
            #[serde(default)]
            board: Option<String>,
            #[serde(default)]
            variant: Option<String>,
            #[serde(default)]
            revision: Option<String>,
            #[serde(default)]
            app: Option<String>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct UpstreamProjectConfig {
            name: String,
            source_path: PathBuf,
            #[serde(default)]
            discovery: Discovery,
            #[serde(default)]
            build_cwd: Option<PathBuf>,
            #[serde(default)]
            build_command: Option<Vec<String>>,
            #[serde(default)]
            artifact_path: Option<PathBuf>,
            #[serde(default)]
            chip: Option<String>,
            flash_format: String,
            #[serde(default)]
            base_address: Option<u64>,
            #[serde(default)]
            build_timeout_secs: Option<u64>,
            #[serde(default)]
            env: HashMap<String, String>,
            #[serde(default)]
            serial_port: Option<String>,
            #[serde(default)]
            serial_baud: Option<u32>,
            #[serde(default)]
            probe_serial: Option<String>,
            #[serde(default)]
            west_binary: Option<PathBuf>,
            #[serde(default)]
            build_dir_root: Option<PathBuf>,
            #[serde(default, rename = "targets")]
            retired_targets: Vec<toml::Value>,
            #[serde(default, rename = "soc_chip_overrides")]
            retired_soc_chip_overrides: Option<toml::Value>,
            #[serde(default)]
            default_snippets: Vec<String>,
            #[serde(default)]
            default_target: Option<UpstreamDefaultTarget>,
            #[serde(default)]
            default_extra_args: Vec<String>,
            #[serde(default)]
            version_command: Option<Vec<String>>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct UpstreamConfig {
            core: toml::Value,
            #[serde(default, rename = "projects")]
            projects: Vec<UpstreamProjectConfig>,
            #[serde(default)]
            dev_bench: Option<toml::Value>,
        }

        let fixture_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../embarch-api/config.example.toml");
        let raw = std::fs::read_to_string(&fixture_path).unwrap_or_else(|e| {
            panic!(
                "could not read {} (path-dep sibling missing beside this worktree?): {e}",
                fixture_path.display()
            )
        });

        let upstream: UpstreamConfig = toml::from_str(&raw).unwrap_or_else(|e| {
            panic!(
                "{} declares a field `UpstreamProjectConfig`/`UpstreamConfig` in this test \
                 does not know about (or is missing one this test requires) — \
                 `embarch-api`'s `ProjectConfig`/`Config` shape moved. Update this test's \
                 shadow struct to match `embarch-api/src/config.rs`, then check whether this \
                 file's own `ProjectConfig` needs the same field: {e}",
                fixture_path.display()
            )
        });
        assert!(
            !upstream.projects.is_empty(),
            "{} declared no [[projects]] — nothing was actually exercised",
            fixture_path.display()
        );

        // Confirm this repo's own mirror still parses the same fixture —
        // catches this mirror rejecting a config upstream now ships (e.g. a
        // newly-required field this file doesn't declare).
        let mirrored = Config::load_from_path(&fixture_path).unwrap_or_else(|e| {
            panic!(
                "this file's own ProjectConfig rejected {}, which the real embarch-api accepts: \
                 {e}",
                fixture_path.display()
            )
        });
        assert_eq!(mirrored.projects.len(), upstream.projects.len());
    }
}
