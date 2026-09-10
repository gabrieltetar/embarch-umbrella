//! Zephyr/west **shape** detection — the `embarch-umbrella` half of
//! decision 17 (`embarch-api` decision 12 is the
//! full design, including the parts umbrella doesn't need).
//!
//! One caller, read-only, building and flashing nothing: `init`, answering
//! "does this repo look Zephyr/west-shaped, so a `discovery = "zephyr-west"`
//! project should be scaffolded instead of a guessed static one".
//!
//! **This is deliberately not a target scanner, as of 2026-09-05.** It used
//! to carry a trimmed copy of `embarch-api/src/zephyr.rs`'s scanning half
//! that counted (board, soc, cpucluster, variant, revision, app) tuples for
//! `doctor` check 8, with a documented overcount: a revision counted as
//! backed if *any* revision-suffixed file in the board directory named it.
//! Check 8 now asks `embarch-api list-targets` instead (decision 17's
//! amendment, and `doctor::check_chip`'s comment for why the bootstrapping
//! objection does not apply there), so the copy is gone and with it the
//! drift risk this header used to accept as a known cost.
//!
//! Shape detection stays local because it genuinely does run before a
//! config exists — `init` is deciding what to *write* — so there is nothing
//! to shell out with. It asks strictly less than a scan: is there a
//! parseable `board.yml` under `boards/`, and an `app/*/CMakeLists.txt`.

use serde::Deserialize;
use std::path::Path;

/// Only the `board:` key's presence and parseability matter here — no field
/// under it is read. `embarch-api`'s copy is the one that models socs,
/// variants, cpuclusters and revisions, because it assembles real board
/// qualifiers; this one is answering a yes/no question about a directory.
#[derive(Debug, Deserialize)]
struct BoardYml {
    #[allow(dead_code)]
    board: serde_yaml::Value,
}

/// Whether `source_path` looks like a Zephyr/west project at all: at least
/// one parseable `board.yml`/`.yaml` somewhere under `boards/`, and at least
/// one `app/*/CMakeLists.txt`. Used by `init` to decide whether to scaffold
/// `discovery = "zephyr-west"` instead of guessing a single board.
pub fn looks_zephyr_west_shaped(source_path: &Path) -> bool {
    has_parseable_board_yml(source_path) && has_app_with_cmakelists(source_path)
}

fn has_parseable_board_yml(source_path: &Path) -> bool {
    let mut stack = vec![source_path.join("boards")];
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
            if serde_yaml::from_str::<BoardYml>(&raw).is_ok() {
                return true;
            }
        }
    }
    false
}

fn has_app_with_cmakelists(source_path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(source_path.join("app")) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.path().is_dir() && e.path().join("CMakeLists.txt").is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

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

    fn write_board(dir: &TempDir, body: &str) {
        let board_dir = dir.path().join("boards/acme/single");
        fs::create_dir_all(&board_dir).unwrap();
        fs::write(board_dir.join("single.yml"), body).unwrap();
    }

    fn write_app(dir: &TempDir) {
        fs::create_dir_all(dir.path().join("app/foo")).unwrap();
        fs::write(dir.path().join("app/foo/CMakeLists.txt"), "").unwrap();
    }

    #[test]
    fn not_zephyr_west_when_no_boards_dir() {
        let dir = tempdir();
        write_app(&dir);
        assert!(!looks_zephyr_west_shaped(dir.path()));
    }

    #[test]
    fn not_zephyr_west_when_no_app_dir() {
        let dir = tempdir();
        write_board(&dir, "board:\n  name: single\n  socs:\n    - name: nrf54l15\n");
        assert!(!looks_zephyr_west_shaped(dir.path()));
    }

    #[test]
    fn not_zephyr_west_when_the_app_dir_has_no_cmakelists() {
        let dir = tempdir();
        write_board(&dir, "board:\n  name: single\n  socs:\n    - name: nrf54l15\n");
        fs::create_dir_all(dir.path().join("app/foo")).unwrap();
        assert!(!looks_zephyr_west_shaped(dir.path()));
    }

    #[test]
    fn zephyr_west_shaped_with_boards_and_app() {
        let dir = tempdir();
        write_board(&dir, "board:\n  name: single\n  socs:\n    - name: nrf54l15\n");
        write_app(&dir);
        assert!(looks_zephyr_west_shaped(dir.path()));
    }

    /// A `board.yml` with nothing but the top-level key is still a shape
    /// signal — how many real targets it declares is `embarch-api
    /// list-targets`' question, not this module's (decision 17's amendment).
    #[test]
    fn a_board_yml_with_no_socs_still_counts_as_shape() {
        let dir = tempdir();
        write_board(&dir, "board:\n  name: single\n");
        write_app(&dir);
        assert!(looks_zephyr_west_shaped(dir.path()));
    }

    /// A file that is YAML but has no `board:` key is not a board
    /// definition, so it must not by itself make a repo look Zephyr-shaped.
    #[test]
    fn a_yaml_file_without_a_board_key_is_not_a_board() {
        let dir = tempdir();
        write_board(&dir, "twister:\n  platform: single\n");
        write_app(&dir);
        assert!(!looks_zephyr_west_shaped(dir.path()));
    }
}
