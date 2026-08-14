//! Zephyr/west detection and live target validation — the `embarch-umbrella`
//! half of `design.md` §3 decision 17 (`embarch-api/design.md` §3 decision
//! 12 is the full design, including the parts umbrella doesn't need).
//!
//! Two callers, both read-only, neither building or flashing anything:
//! `init` (does this repo look Zephyr/west-shaped, so a `discovery =
//! "zephyr-west"` project should be scaffolded instead of a guessed static
//! one) and `doctor` check 8 (is at least one live-discovered target actually
//! file-backing-valid, i.e. is `boards/`/`app/` non-empty and not broken).
//!
//! This is a liftable copy of `embarch-api/src/zephyr.rs`'s scanning half
//! (`design.md` §3 decision 15's pattern, applied again — the same reasoning
//! that already justified copying topology detection and token/config
//! reading rather than extracting a shared crate): the two copies are
//! expected to drift if Zephyr's board-revision file-naming convention ever
//! changes, and that's an accepted, documented risk, not an oversight.
//! `embarch-api`'s copy is the one that actually assembles build commands and
//! selects a target for a real build — this one only counts and detects.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct BoardYml {
    board: BoardSection,
    #[serde(default)]
    revision: Option<RevisionSection>,
}

#[derive(Debug, Deserialize)]
struct BoardSection {
    #[serde(default)]
    socs: Vec<SocSection>,
}

#[derive(Debug, Deserialize)]
struct SocSection {
    #[serde(default)]
    cpuclusters: Vec<CpuClusterSection>,
    #[serde(default)]
    variants: Vec<VariantSection>,
}

#[derive(Debug, Deserialize)]
struct CpuClusterSection {
    #[serde(default)]
    variants: Vec<VariantSection>,
}

// Only the count of variants matters here (unlike embarch-api's zephyr.rs,
// which needs each one's name to assemble a real board qualifier) — an
// empty struct still deserializes a `{name: ...}` YAML mapping fine, serde
// just ignores the field it doesn't ask for.
#[derive(Debug, Deserialize)]
struct VariantSection {}

#[derive(Debug, Deserialize)]
struct RevisionSection {
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    revisions: Vec<RevisionEntry>,
}

#[derive(Debug, Deserialize)]
struct RevisionEntry {
    name: String,
}

struct BoardDef {
    dir: PathBuf,
    yml: BoardYml,
}

/// Whether `source_path` looks like a Zephyr/west project at all: at least
/// one parseable `board.yml`/`.yaml` somewhere under `boards/`, and at least
/// one `app/*/CMakeLists.txt`. Used by `init` to decide whether to scaffold
/// `discovery = "zephyr-west"` instead of guessing a single board.
pub fn looks_zephyr_west_shaped(source_path: &Path) -> bool {
    !scan_boards(source_path).is_empty() && !scan_apps(source_path).is_empty()
}

/// How many distinct, file-backing-validated (board, soc, cpucluster,
/// variant, revision, app) targets this repo actually has — `doctor` check
/// 8's pass/fail signal for a `discovery = "zephyr-west"` project. Zero
/// means `boards/`/`app/` are empty or nothing in them validated (e.g. every
/// declared revision is missing its overlay/defconfig file), which is worth
/// a fail even though the repo is structurally Zephyr/west-shaped.
pub fn count_valid_targets(source_path: &Path) -> usize {
    let boards = scan_boards(source_path);
    let apps = scan_apps(source_path);
    if apps.is_empty() {
        return 0;
    }

    let mut count = 0;
    for board in &boards {
        for soc in &board.yml.board.socs {
            if soc.cpuclusters.is_empty() {
                count += count_for_variants(board, &soc.variants, &apps);
            } else {
                for cluster in &soc.cpuclusters {
                    count += count_for_variants(board, &cluster.variants, &apps);
                }
            }
        }
    }
    count
}

fn count_for_variants(board: &BoardDef, variants: &[VariantSection], apps: &[String]) -> usize {
    let variant_count = variants.len().max(1);
    let revisions = candidate_revisions(&board.yml.revision);

    let revision_count = if revisions.is_empty() {
        // No revision section at all -> one implicit revision, always backed
        // by the board's plain base files.
        1
    } else {
        // A revision-suffixed file check needs the full (board, soc,
        // cpucluster, variant) tuple in a real repo; here we only need a
        // count, and this check's job is "is there at least one real
        // target," not "list every one precisely" (`embarch-api
        // list-targets` is the precise answer) — so a revision counts as
        // backed if it's the declared default (always true) or *any*
        // revision-suffixed file anywhere in the board directory names it.
        // This can overcount relative to embarch-api's per-tuple check (a
        // real repo might have the overlay for one variant but not
        // another, at the same revision), which is an accepted
        // approximation for a doctor pass/fail signal.
        let default_revision = board.yml.revision.as_ref().and_then(|r| r.default.as_deref());
        revisions
            .iter()
            .filter(|r| Some(r.as_str()) == default_revision || revision_file_exists(&board.dir, r))
            .count()
    };

    variant_count * revision_count * apps.len()
}

fn candidate_revisions(revision: &Option<RevisionSection>) -> Vec<String> {
    match revision {
        None => Vec::new(),
        Some(r) => {
            let mut names: Vec<String> = r.revisions.iter().map(|e| e.name.clone()).collect();
            if let Some(default) = &r.default {
                if !names.contains(default) {
                    names.push(default.clone());
                }
            }
            names
        }
    }
}

fn revision_file_exists(board_dir: &Path, revision: &str) -> bool {
    let rev_token = format!("_{}", revision.replace('.', "_"));
    let Ok(entries) = std::fs::read_dir(board_dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        (name.ends_with(".overlay") || name.ends_with(".defconfig"))
            && name.contains(&rev_token)
    })
}

fn scan_boards(source_path: &Path) -> Vec<BoardDef> {
    let boards_dir = source_path.join("boards");
    let mut out = Vec::new();
    let mut stack = vec![boards_dir];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yml" || e == "yaml");
            if !is_yaml {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Ok(yml) = serde_yaml::from_str::<BoardYml>(&raw) {
                out.push(BoardDef {
                    dir: path.parent().map(Path::to_path_buf).unwrap_or(dir.clone()),
                    yml,
                });
            }
        }
    }
    out
}

fn scan_apps(source_path: &Path) -> Vec<String> {
    let app_dir = source_path.join("app");
    let Ok(entries) = std::fs::read_dir(&app_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().is_dir() && e.path().join("CMakeLists.txt").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut base = std::env::temp_dir();
        base.push(format!(
            "embarch-umbrella-zephyr-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }

    #[test]
    fn not_zephyr_west_when_no_boards_dir() {
        let dir = tempdir();
        fs::create_dir_all(dir.path().join("app/foo")).unwrap();
        assert!(!looks_zephyr_west_shaped(dir.path()));
        assert_eq!(count_valid_targets(dir.path()), 0);
    }

    #[test]
    fn not_zephyr_west_when_no_app_dir() {
        let dir = tempdir();
        let board_dir = dir.path().join("boards/acme/single");
        fs::create_dir_all(&board_dir).unwrap();
        fs::write(
            board_dir.join("single.yml"),
            "board:\n  name: single\n  socs:\n    - name: nrf54l15\n",
        )
        .unwrap();
        assert!(!looks_zephyr_west_shaped(dir.path()));
    }

    #[test]
    fn zephyr_west_shaped_with_boards_and_app() {
        let dir = tempdir();
        let board_dir = dir.path().join("boards/acme/single");
        fs::create_dir_all(&board_dir).unwrap();
        fs::write(
            board_dir.join("single.yml"),
            "board:\n  name: single\n  socs:\n    - name: nrf54l15\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("app/foo")).unwrap();
        fs::write(dir.path().join("app/foo/CMakeLists.txt"), "").unwrap();

        assert!(looks_zephyr_west_shaped(dir.path()));
        assert_eq!(count_valid_targets(dir.path()), 1);
    }

    #[test]
    fn counts_every_variant_and_app_combination() {
        let dir = tempdir();
        let board_dir = dir.path().join("boards/acme/roadrunner");
        fs::create_dir_all(&board_dir).unwrap();
        fs::write(
            board_dir.join("roadrunner.yml"),
            r#"
board:
  name: roadrunner
  socs:
    - name: nrf54l15
      cpuclusters:
        - name: cpuapp
          variants:
            - name: os_5led
            - name: os_3led
"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("app/healthband")).unwrap();
        fs::write(dir.path().join("app/healthband/CMakeLists.txt"), "").unwrap();

        // No revision section at all -> treated as one implicit revision;
        // 2 variants * 1 revision * 1 app = 2.
        assert_eq!(count_valid_targets(dir.path()), 2);
    }
}
