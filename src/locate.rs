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
    /// The Windows service's own `BINARY_PATH_NAME` — the only authoritative
    /// answer to "which `embarch-core.exe` does this machine run" on a
    /// `wsl-host` (decision 38). Ranked ahead of the two guesses below it
    /// because it is a reading rather than a guess, and behind `PATH` because
    /// a binary this side of the boundary is one `doctor` can run cheaply.
    WindowsServiceRegistration,
    /// The canonical copy `setup` just installed, this same run (`install.rs`,
    /// decision 28) — used only as a same-process fallback, since a `PATH`
    /// change this run just made isn't visible to this run's own environment
    /// until a new shell starts.
    JustInstalled,
    /// The canonical copy `setup` *would* install — reported by
    /// `setup --dry-run` (decision 21) where a real run would report
    /// `JustInstalled`. A separate variant rather than reusing that one,
    /// because "just installed here" is the one thing a dry run must never
    /// claim.
    PendingInstall,
}

impl FoundBy {
    pub fn as_str(self) -> &'static str {
        match self {
            FoundBy::EnvVar => "EMBARCH_CORE_EXE",
            FoundBy::SavedState => "recorded by setup",
            FoundBy::Path => "PATH",
            FoundBy::WindowsConventionalDir => "Windows install directory",
            FoundBy::WindowsServiceRegistration => "the Windows service's own registration",
            FoundBy::JustInstalled => "just installed here",
            FoundBy::PendingInstall => "would be installed by this run",
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
        // Decision 38: the service's own registration, before either guess.
        // `deploy-core` has read it since decision 32 for the same reason —
        // on this bench the live service runs out of a directory that appears
        // on no conventional list — and a `doctor` that cannot find the Core
        // the machine actually runs reports a healthy install as broken.
        if let Some(path) = windows_core_service_binary_path() {
            if is_file(&path) {
                return Some(Located {
                    path,
                    found_by: FoundBy::WindowsServiceRegistration,
                    windows_exe_from_wsl2: true,
                });
            }
        }

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

/// `embarch-core`'s own Windows service label (its `service.rs`'s
/// `SERVICE_LABEL`). Duplicated rather than imported: umbrella depends on
/// none of the three binaries it orchestrates, by design (design.md §1) —
/// it shells out. Verified against the real installed service on this
/// bench, not read off the source: `sc.exe query com.embarch.core` returns
/// `SERVICE_NAME: com.embarch.core`.
pub const WINDOWS_CORE_SERVICE_LABEL: &str = "com.embarch.core";

/// What a read-only probe found on the Windows side (design.md §3 decision
/// 30). Absence — no service at all — is `None` from the probe, not a
/// variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsServiceState {
    Running,
    /// Installed, but not currently running — still the Core this machine
    /// means, just stopped. `up`'s job is to say how to start *it*, not to
    /// start a different one.
    Installed,
}

/// Is `embarch-core` installed as a Windows service, as seen from a WSL2
/// guest (design.md §3 decision 30)?
///
/// **Read-only, and that is the safety argument.** `sc.exe query` changes
/// nothing, so a wrong answer here costs a check rather than a botched
/// start — which is why this is allowed to be a probe at all instead of a
/// prompt or a required flag.
///
/// `None` for every failure mode alike — no `sc.exe` (not under WSL2, or no
/// Windows interop), a service that does not exist (`sc.exe` exits 1060), or
/// output this cannot parse. All three mean the same thing to the caller:
/// no Windows service to defer to, carry on with the existing behaviour.
#[cfg(unix)]
pub fn windows_core_service_state() -> Option<WindowsServiceState> {
    let output = std::process::Command::new("sc.exe")
        .args(["query", WINDOWS_CORE_SERVICE_LABEL])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_sc_query(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(unix))]
pub fn windows_core_service_state() -> Option<WindowsServiceState> {
    // This probe exists to resolve a WSL2-guest ambiguity (design.md §3
    // decision 30). A native Windows `embarch` can control the service
    // directly and has no ambiguity to resolve.
    None
}

/// The **service's own** `BINARY_PATH_NAME`, as seen from a WSL2 guest —
/// which is the only authoritative answer to "which `embarch-core.exe` does
/// this machine actually run".
///
/// `locate_core` deliberately guesses (decision 28's canonical location, then
/// a short conventional list) because its job is to find *an* exe to invoke.
/// Deploying is the opposite problem: replacing the wrong copy is worse than
/// finding none, and on this bench the live service runs out of a
/// release-archive directory that appears on no conventional list at all
/// (`embarch-dev-workflow.md` §4a). `sc.exe qc` is read-only, so a wrong
/// answer costs a check rather than a botched deploy.
///
/// `None` for every failure alike — no `sc.exe`, no such service, or output
/// this cannot parse.
#[cfg(unix)]
pub fn windows_core_service_binary_path() -> Option<PathBuf> {
    let output = std::process::Command::new("sc.exe")
        .args(["qc", WINDOWS_CORE_SERVICE_LABEL])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let win_path = parse_sc_qc_binary_path(&String::from_utf8_lossy(&output.stdout))?;
    translate_windows_path_to_wsl(&win_path)
}

#[cfg(not(unix))]
pub fn windows_core_service_binary_path() -> Option<PathBuf> {
    None
}

/// Pulls the executable out of `sc.exe qc`'s `BINARY_PATH_NAME` line.
///
/// Two things make this less trivial than a `split(':')`. The value is a
/// *command line*, not a path — this bench's is
/// `C:\...\embarch-core.exe run --bind 0.0.0.0` — and it contains a drive
/// letter's own colon, so the field is split off by name rather than at the
/// first colon in the line. The path is then cut at `.exe` rather than at
/// whitespace, because on any machine where Core lives under `Program Files`
/// a whitespace split truncates it mid-path and names a directory instead of
/// a binary. Quotes are stripped, since `sc.exe` quotes when the installer
/// did.
fn parse_sc_qc_binary_path(stdout: &str) -> Option<String> {
    const FIELD: &str = "BINARY_PATH_NAME";
    let line = stdout.lines().find(|l| l.contains(FIELD))?;
    let after_field = &line[line.find(FIELD)? + FIELD.len()..];
    let value = after_field.trim_start().trim_start_matches(':').trim().trim_start_matches('"');
    let end = value.to_ascii_lowercase().find(".exe")? + ".exe".len();
    Some(value[..end].to_string())
}

/// Parses `sc.exe query`'s output. Split out from the shell-out so the
/// parsing is testable without Windows interop — the same split
/// `token.rs`/`zephyr.rs` already make for their own shell-outs.
///
/// Anchored on `SERVICE_NAME:` being present, because `sc.exe` prints its
/// "does not exist" message on *stdout* while still sometimes exiting
/// non-zero; requiring the header means a failure message can never be read
/// as a running service.
fn parse_sc_query(stdout: &str) -> Option<WindowsServiceState> {
    if !stdout.contains("SERVICE_NAME:") {
        return None;
    }
    let state_line = stdout.lines().find(|l| l.trim_start().starts_with("STATE"))?;
    // `STATE : 4  RUNNING` / `STATE : 1  STOPPED` — matched on the word,
    // not the numeric code, since the words are what `sc.exe` guarantees to
    // print and the spacing varies.
    Some(if state_line.contains("RUNNING") {
        WindowsServiceState::Running
    } else {
        WindowsServiceState::Installed
    })
}

/// Is this a path into a Windows filesystem as mounted by WSL2?
pub fn is_windows_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/mnt/") || s.contains(":\\") || s.ends_with(".exe")
}

#[cfg(test)]
mod tests {

    /// Verbatim from the real `sc.exe qc com.embarch.core` on this bench —
    /// not hand-typed from the docs, which is the whole reason
    /// `parse_sc_query`'s own fixture is a real capture too.
    ///
    /// Three things this pins at once: the value is a *command line* (`run
    /// --bind 0.0.0.0` follows the exe), it contains a drive letter's colon
    /// after the field's own colon, and the exe path here appears on no
    /// conventional install list — which is exactly why `deploy-core` reads
    /// the service's registration instead of guessing (decision 32), and why
    /// `locate_core` now reads it too (decision 38).
    #[test]
    fn the_services_own_binary_path_is_parsed_out_of_a_command_line() {
        let real = "[SC] QueryServiceConfig SUCCESS\n\n\
             SERVICE_NAME: com.embarch.core\n        \
             TYPE               : 10  WIN32_OWN_PROCESS \n        \
             START_TYPE         : 2   AUTO_START\n        \
             BINARY_PATH_NAME   : C:\\Users\\tmp12\\embarch-setup\\embarch-0.1.0-x86_64-pc-windows-msvc\\embarch-core.exe run --bind 0.0.0.0\n        \
             DISPLAY_NAME       : com.embarch.core\n";
        assert_eq!(
            parse_sc_qc_binary_path(real).as_deref(),
            Some(
                r"C:\Users\tmp12\embarch-setup\embarch-0.1.0-x86_64-pc-windows-msvc\embarch-core.exe"
            )
        );
    }

    /// A path with a space in it — the case a whitespace split would
    /// truncate mid-path, naming `C:\Program` instead of a binary.
    #[test]
    fn a_quoted_path_with_spaces_survives() {
        let line = "        BINARY_PATH_NAME   : \"C:\\Program Files\\embarch\\embarch-core.exe\" run\n";
        assert_eq!(
            parse_sc_qc_binary_path(line).as_deref(),
            Some(r"C:\Program Files\embarch\embarch-core.exe")
        );
    }

    #[test]
    fn a_config_dump_without_the_field_is_none() {
        assert_eq!(parse_sc_qc_binary_path("SERVICE_NAME: x\n"), None);
    }
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
    fn sc_query_output_for_a_running_service_is_read_as_running() {
        // Verbatim from the real `sc.exe query com.embarch.core` on this
        // bench, so the parser is pinned to output that actually occurred
        // rather than output imagined for it.
        let stdout = "\nSERVICE_NAME: com.embarch.core \n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 4  RUNNING \n                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n";
        assert_eq!(parse_sc_query(stdout), Some(WindowsServiceState::Running));
    }

    #[test]
    fn a_stopped_service_is_installed_not_absent() {
        let stdout = "\nSERVICE_NAME: com.embarch.core \n        TYPE               : 10  WIN32_OWN_PROCESS  \n        STATE              : 1  STOPPED \n";
        assert_eq!(parse_sc_query(stdout), Some(WindowsServiceState::Installed));
    }

    #[test]
    fn the_service_does_not_exist_message_is_never_read_as_a_service() {
        // `sc.exe` prints this on stdout; without the SERVICE_NAME anchor a
        // looser parse could find no STATE line and still have to decide.
        let stdout = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.\n";
        assert_eq!(parse_sc_query(stdout), None);
    }

    #[test]
    fn output_with_no_state_line_at_all_is_none_rather_than_a_guess() {
        assert_eq!(parse_sc_query("SERVICE_NAME: com.embarch.core\n"), None);
    }

    /// The provenance string is user-facing: `doctor`'s check 1 prints it, and
    /// "found by guessing at a conventional directory" versus "read off the
    /// service registration" is the difference between a claim about *a*
    /// binary and a claim about *the* one this machine runs (decision 38).
    #[test]
    fn the_service_registration_is_a_distinct_provenance() {
        assert_ne!(
            FoundBy::WindowsServiceRegistration.as_str(),
            FoundBy::WindowsConventionalDir.as_str()
        );
        assert!(FoundBy::WindowsServiceRegistration.as_str().contains("service"));
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
