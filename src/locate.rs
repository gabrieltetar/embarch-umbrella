//! Finding the other two binaries.
//!
//! Umbrella never does hardware or build work itself — it shells out
//! (design.md §1) — so "where is `embarch-core`" is a question it has to
//! answer before it can do almost anything.
//!
//! **`setup` deliberately does not modify `PATH`.** The suite release ships
//! all three binaries in one archive (design.md §3 decision 14), so the
//! sibling-of-myself lookup below finds them with no environment surgery at
//! all — and editing someone's shell rc or the Windows registry to add a
//! directory is invasive, easy to get wrong per shell, and awkward to undo.
//! `setup` prints the one line to add instead, and leaves the choice to the
//! operator. (Refinement of design.md §3 decision 3's "put both binaries on
//! PATH", recorded 2026-08-05.)

use std::path::{Path, PathBuf};

/// How a binary was found — worth reporting, because "the one next to me" and
/// "some other copy on your PATH" produce very different debugging stories
/// when versions disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundBy {
    EnvVar,
    SavedState,
    NextToMe,
    Path,
    WindowsConventionalDir,
}

impl FoundBy {
    pub fn as_str(self) -> &'static str {
        match self {
            FoundBy::EnvVar => "EMBARCH_CORE_EXE",
            FoundBy::SavedState => "recorded by setup",
            FoundBy::NextToMe => "next to the embarch binary",
            FoundBy::Path => "PATH",
            FoundBy::WindowsConventionalDir => "conventional Windows install directory",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub path: PathBuf,
    pub found_by: FoundBy,
    /// A Windows `.exe` being invoked from a WSL2 guest. Relevant because
    /// controlling a Windows service from here needs an elevated *Windows*
    /// shell, which umbrella will never try to obtain itself (design.md §3
    /// decision 7).
    pub windows_exe_from_wsl2: bool,
}

/// Executable name for a native binary on this platform.
pub fn native_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

/// Where a Windows-side install would conventionally put `embarch-core.exe`,
/// as seen from a WSL2 guest.
///
/// Pure and separate so the list is reviewable and testable without a
/// Windows filesystem mounted. Deliberately short: guessing at a developer's
/// source checkout would find a stale debug build as often as the real thing.
pub fn windows_conventional_core_paths() -> Vec<PathBuf> {
    [
        "/mnt/c/Program Files/embarch/embarch-core.exe",
        "/mnt/c/Program Files (x86)/embarch/embarch-core.exe",
        "/mnt/c/ProgramData/embarch/embarch-core.exe",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// Split a `PATH` value into directories, honoring the platform separator.
pub fn path_dirs(path_var: &str, windows: bool) -> Vec<PathBuf> {
    let sep = if windows { ';' } else { ':' };
    path_var
        .split(sep)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn is_file(p: &Path) -> bool {
    p.is_file()
}

/// Locate `embarch-core`, in the precedence order design.md §3 decision 7
/// specifies: an explicit override, then what `setup` recorded, then the copy
/// shipped alongside this binary, then `PATH`, then — under WSL2 only — the
/// conventional Windows install directories.
pub fn locate_core(saved: Option<&Path>, under_wsl2: bool) -> Option<Located> {
    if let Some(raw) = std::env::var_os("EMBARCH_CORE_EXE") {
        let path = PathBuf::from(raw);
        // Honored even if it doesn't exist: the operator said which binary it
        // is, so a wrong path should surface as *that* error rather than being
        // silently replaced by a different copy. Same explicit-wins shape as
        // embarch-core's EMBARCH_DEV_BENCH_PORT.
        return Some(Located {
            windows_exe_from_wsl2: under_wsl2 && is_windows_path(&path),
            path,
            found_by: FoundBy::EnvVar,
        });
    }

    if let Some(path) = saved.filter(|p| is_file(p)) {
        return Some(Located {
            path: path.to_path_buf(),
            found_by: FoundBy::SavedState,
            windows_exe_from_wsl2: under_wsl2 && is_windows_path(path),
        });
    }

    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        let sibling = dir.join(native_name("embarch-core"));
        if is_file(&sibling) {
            return Some(Located {
                path: sibling,
                found_by: FoundBy::NextToMe,
                windows_exe_from_wsl2: false,
            });
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        let name = native_name("embarch-core");
        for dir in path_dirs(&path_var, cfg!(windows)) {
            let candidate = dir.join(&name);
            if is_file(&candidate) {
                return Some(Located {
                    path: candidate,
                    found_by: FoundBy::Path,
                    windows_exe_from_wsl2: false,
                });
            }
        }
    }

    if under_wsl2 {
        for candidate in windows_conventional_core_paths() {
            if is_file(&candidate) {
                return Some(Located {
                    path: candidate,
                    found_by: FoundBy::WindowsConventionalDir,
                    windows_exe_from_wsl2: true,
                });
            }
        }
    }

    None
}

/// Is this a path into a Windows filesystem as mounted by WSL2?
pub fn is_windows_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/mnt/") || s.contains(":\\") || s.ends_with(".exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_splitting_honors_the_platform_separator() {
        assert_eq!(
            path_dirs("/usr/bin:/usr/local/bin", false),
            vec![PathBuf::from("/usr/bin"), PathBuf::from("/usr/local/bin")]
        );
        assert_eq!(
            path_dirs("C:\\bin;C:\\tools", true),
            vec![PathBuf::from("C:\\bin"), PathBuf::from("C:\\tools")]
        );
    }

    #[test]
    fn empty_path_entries_are_skipped() {
        // A trailing or doubled separator is common and must not produce a
        // lookup against the current directory.
        assert_eq!(path_dirs("/usr/bin::", false), vec![PathBuf::from("/usr/bin")]);
        assert!(path_dirs("", false).is_empty());
    }

    #[test]
    fn windows_paths_are_recognized() {
        assert!(is_windows_path(Path::new("/mnt/c/embarch/embarch-core.exe")));
        assert!(is_windows_path(Path::new("C:\\embarch\\embarch-core.exe")));
        assert!(!is_windows_path(Path::new("/usr/local/bin/embarch-core")));
    }

    #[test]
    fn conventional_windows_paths_are_all_exe_paths_under_mnt() {
        let paths = windows_conventional_core_paths();
        assert!(!paths.is_empty());
        assert!(paths.iter().all(|p| is_windows_path(p)));
    }

    #[test]
    fn native_name_matches_the_platform() {
        let n = native_name("embarch-core");
        if cfg!(windows) {
            assert_eq!(n, "embarch-core.exe");
        } else {
            assert_eq!(n, "embarch-core");
        }
    }
}
