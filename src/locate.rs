//! Finding the other two binaries.
//!
//! Umbrella never does hardware or build work itself — it shells out
//! (design.md §1) — so "where is `embarch-core`" is a question it has to
//! answer before it can do almost anything.
//!
//! **`setup` now installs for real (design.md §3 decision 28).** It copies
//! the suite's binaries to a canonical per-user location and mutates `PATH`
//! for real (`install.rs`) — reversing the 2026-08-05 refinement that used
//! to live here (never edit `PATH`, find `embarch-core` as a sibling of
//! `embarch` instead). That sibling-lookup mechanism (`next_to_me`) is gone
//! from the resolution chain below entirely: it was found misreporting which
//! binary was actually in play for a `wsl-host` topology (design.md §10,
//! 2026-08-17), and `install.rs`'s copy step is now the only place "look at
//! my own directory" logic remains — a one-time install source, not an
//! ongoing lookup.

use std::path::{Path, PathBuf};

/// How a binary was found — worth reporting, because different sources
/// produce very different debugging stories when versions disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundBy {
    EnvVar,
    SavedState,
    Path,
    WindowsConventionalDir,
    /// The canonical copy `setup` just installed, this same run (`install.rs`,
    /// decision 28) — used only as a same-process fallback, since a `PATH`
    /// change this run just made isn't visible to this run's own environment
    /// until a new shell starts.
    JustInstalled,
}

impl FoundBy {
    pub fn as_str(self) -> &'static str {
        match self {
            FoundBy::EnvVar => "EMBARCH_CORE_EXE",
            FoundBy::SavedState => "recorded by setup",
            FoundBy::Path => "PATH",
            FoundBy::WindowsConventionalDir => "Windows install directory",
            FoundBy::JustInstalled => "just installed here",
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

/// Fixed, conventional Windows install locations for `embarch-core.exe`, as
/// seen from a WSL2 guest — a fallback for a copy installed some other way
/// than decision 28's canonical per-user location (see
/// `windows_localappdata_core_path`, tried first).
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

/// Decision 28's real canonical Windows install location
/// (`%LOCALAPPDATA%\embarch\bin\embarch-core.exe`), resolved from a WSL2
/// guest. `%LOCALAPPDATA%` is per-user, and WSL2 has no direct view of the
/// Windows username to derive this path by hand — so, same technique
/// `token.rs` already uses for the machine-wide `%ProgramData%` case, shell
/// out to Windows for the real value and translate it to its `/mnt/c` form.
/// `None` on any failure (no `cmd.exe`/`wslpath`, unexpected output) — the
/// caller falls through to `windows_conventional_core_paths` either way.
#[cfg(unix)]
pub fn windows_localappdata_core_path() -> Option<PathBuf> {
    let local_appdata = windows_env_var_via_shellout("LOCALAPPDATA")?;
    let mnt_root = translate_windows_path_to_wsl(&local_appdata)?;
    Some(mnt_root.join("embarch").join("bin").join("embarch-core.exe"))
}

#[cfg(unix)]
fn windows_env_var_via_shellout(name: &str) -> Option<String> {
    let output = std::process::Command::new("cmd.exe").args(["/C", "echo", &format!("%{name}%")]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty() && !trimmed.contains('%')).then(|| trimmed.to_string())
}

#[cfg(unix)]
fn translate_windows_path_to_wsl(win_path: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("wslpath").args(["-u", win_path]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    trimmed.starts_with('/').then(|| PathBuf::from(trimmed))
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

/// Locate `embarch-api`: the same order as `locate_core` minus the
/// Windows-side cases, since the API always runs where the *source* is —
/// which, on the WSL2 split, is this side of the boundary. `PATH` is enough
/// once `setup` (decision 28) has run; before that, `EMBARCH_API_BIN` is the
/// escape hatch.
pub fn locate_api() -> Option<Located> {
    if let Some(raw) = std::env::var_os("EMBARCH_API_BIN") {
        return Some(Located {
            path: PathBuf::from(raw),
            found_by: FoundBy::EnvVar,
            windows_exe_from_wsl2: false,
        });
    }
    on_path("embarch-api")
}

fn on_path(stem: &str) -> Option<Located> {
    let path_var = std::env::var("PATH").ok()?;
    let name = native_name(stem);
    path_dirs(&path_var, cfg!(windows))
        .into_iter()
        .map(|dir| dir.join(&name))
        .find(|c| is_file(c))
        .map(|path| Located {
            path,
            found_by: FoundBy::Path,
            windows_exe_from_wsl2: false,
        })
}

/// Locate `embarch-core`, in the precedence order design.md §3 decisions 7
/// and 28 specify: an explicit override, then what `setup` recorded, then
/// `PATH` (populated for real by `setup`'s install step once decision 28 has
/// run), then — under WSL2 only — the real canonical Windows location, then
/// the older fixed conventional directories as a last resort.
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

    if let Some(found) = on_path("embarch-core") {
        return Some(found);
    }

    if under_wsl2 {
        #[cfg(unix)]
        if let Some(path) = windows_localappdata_core_path() {
            if is_file(&path) {
                return Some(Located { path, found_by: FoundBy::WindowsConventionalDir, windows_exe_from_wsl2: true });
            }
        }
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
