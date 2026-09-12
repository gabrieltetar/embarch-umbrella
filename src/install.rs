//! Installing the suite for real: copying the release binaries to a
//! canonical per-user location and making sure `PATH` actually includes it.
//!
//! Replaces `locate.rs`'s old sibling-lookup-plus-printed-hint approach
//! (decision 3's 2026-08-05 refinement) — reversed by decision
//! 28, at the user's explicit request, after a real `wsl-host` onboarding
//! run the same day showed the sibling lookup misreporting which
//! `embarch-core` binary was actually in play (decision 28).
//!
//! Every write here is per-user — no elevation needed, distinct from the
//! Core-service install decision 7 already requires elevation for — and
//! idempotent: re-running `setup` is always safe, and `setup --uninstall`
//! reverses all of it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::locate;

/// Where the suite's binaries live once installed — not wherever the
/// release archive happened to be unpacked. A per-user location needs no
/// elevation to write to, unlike a system-wide one (`/usr/local/bin`,
/// `C:\Program Files\...`), keeping `setup`'s "elevation is rare, only for
/// the Core service" property intact for this step too.
pub fn canonical_bin_dir_from(
    windows: bool,
    local_appdata: Option<&str>,
    xdg_data_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    let base = if windows {
        PathBuf::from(local_appdata.filter(|s| !s.is_empty())?)
    } else if let Some(xdg) = xdg_data_home.filter(|s| !s.is_empty()) {
        PathBuf::from(xdg)
    } else {
        PathBuf::from(home.filter(|s| !s.is_empty())?)
            .join(".local")
            .join("share")
    };
    Some(base.join("embarch").join("bin"))
}

pub fn canonical_bin_dir() -> Result<PathBuf> {
    canonical_bin_dir_from(
        cfg!(windows),
        std::env::var("LOCALAPPDATA").ok().as_deref(),
        std::env::var("XDG_DATA_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
    .context("could not determine an install directory (no LOCALAPPDATA, XDG_DATA_HOME, or HOME set)")
}

/// The three binaries the suite release archive carries, in the order a
/// person reads them: the one they just ran, the one it sets up, and the one
/// everything afterwards goes through. Named once so `install_binaries` and
/// [`plan_install`] can never disagree about the set.
pub const SUITE_BINARIES: [&str; 3] = ["embarch", "embarch-core", "embarch-api"];

/// Copy `embarch`, `embarch-core`, `embarch-api` from `source_dir` (the
/// currently-running `embarch` binary's own directory — the unpacked release
/// archive) into `dest_dir`, creating it if needed. This is the *only* place
/// "look at my own directory" logic remains: a one-time install source at
/// `setup` time, not the ongoing resolution mechanism decision 3's sibling
/// lookup used to be. Skips a binary that isn't present at the source (a dev
/// build missing `embarch-api`, say) rather than failing the whole install
/// over one, and is a safe no-op for a binary already at its destination
/// (re-running `setup` from an already-installed copy).
pub fn install_binaries(source_dir: &Path, dest_dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("could not create {}", dest_dir.display()))?;

    let mut written = Vec::new();
    for stem in SUITE_BINARIES {
        let name = locate::native_name(stem);
        let src = source_dir.join(&name);
        let dst = dest_dir.join(&name);

        if !src.is_file() {
            continue;
        }
        if paths_refer_to_the_same_file(&src, &dst) {
            written.push(dst);
            continue;
        }
        // std::fs::copy preserves the source's permission bits (including
        // the executable bit on Unix), so nothing further is needed there.
        std::fs::copy(&src, &dst)
            .with_context(|| format!("could not copy {} to {}", src.display(), dst.display()))?;
        written.push(dst);
    }
    Ok(written)
}

fn paths_refer_to_the_same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Remove the canonical install directory entirely — the install-copy half
/// of `setup --uninstall`. Not an error if it was never there.
pub fn remove_binaries(dest_dir: &Path) -> Result<bool> {
    if !dest_dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(dest_dir).with_context(|| format!("could not remove {}", dest_dir.display()))?;
    Ok(true)
}

// ---------- PATH, Unix (Linux, macOS, and WSL2's own shell) ----------

/// The dedicated, sourced env file `setup` writes — resolves decision 3's
/// original "which shell, which of several startup files?" objection: only
/// ever one idempotent line needs adding to any given rc file, sourcing this
/// file, rather than guessing shell-specific syntax inline in each rc file.
pub fn env_file_path(bin_dir: &Path) -> PathBuf {
    bin_dir.parent().map(|install_dir| install_dir.join("env")).unwrap_or_else(|| bin_dir.join("env"))
}

fn env_file_contents(bin_dir: &Path) -> String {
    format!("export PATH=\"{}:$PATH\"\n", bin_dir.display())
}

/// Write (or overwrite) the dedicated env file. Always rewritten — cheap,
/// and keeps it correct if the install location ever changes.
pub fn write_env_file(bin_dir: &Path) -> Result<PathBuf> {
    let env_path = env_file_path(bin_dir);
    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
    }
    std::fs::write(&env_path, env_file_contents(bin_dir))
        .with_context(|| format!("could not write {}", env_path.display()))?;
    Ok(env_path)
}

fn sourcing_line(env_path: &Path) -> String {
    format!(". \"{}\"", env_path.display())
}

const MARKER: &str = "# added by `embarch setup` (embarch-umbrella decision 28, decisions/install.md)";

/// The exact text this file wrote before the four-file split moved the doc
/// `LEGACY_MARKER` names out from under it — that doc no longer exists, but
/// a machine set up before this change still carries this exact line in its
/// rc file, and `ensure_not_sourced` (the uninstall half) must keep
/// recognising it or an old install is left with a dangling comment nothing
/// will ever remove.
const LEGACY_MARKER: &str = "# added by `embarch setup` (embarch-umbrella/design.md decision 28)";

/// Which rc files to consider. Only ones that already exist are ever
/// touched — matching decision 28's "one idempotent line, never a new file"
/// scope; a shell whose rc doesn't exist yet gets nothing written for it.
pub fn candidate_rc_files(home: &Path) -> Vec<PathBuf> {
    [".bashrc", ".zshrc"].iter().map(|f| home.join(f)).collect()
}

/// Whether `content` already carries the sourcing line for `env_path`. The
/// one predicate `ensure_sourced`, `ensure_not_sourced` and [`plan_install`]
/// all share, so a dry run can never report a change the real run would not
/// make.
fn contains_sourcing_line(content: &str, env_path: &Path) -> bool {
    let line = sourcing_line(env_path);
    content.lines().any(|l| l.trim() == line)
}

/// Read-only form of the above, for [`plan_install`]. An unreadable rc file
/// reads as "not sourced yet" — the same thing the real run would then fail
/// to change, and reporting the intent is more useful than staying silent.
fn already_sourced(rc_path: &Path, env_path: &Path) -> bool {
    std::fs::read_to_string(rc_path).is_ok_and(|c| contains_sourcing_line(&c, env_path))
}

/// Idempotently append a line sourcing `env_path` to `rc_path`, if `rc_path`
/// exists and doesn't already source it. Returns whether a change was made.
pub fn ensure_sourced(rc_path: &Path, env_path: &Path) -> Result<bool> {
    if !rc_path.is_file() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(rc_path).with_context(|| format!("could not read {}", rc_path.display()))?;
    let line = sourcing_line(env_path);
    if contains_sourcing_line(&existing, env_path) {
        return Ok(false);
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("\n{MARKER}\n{line}\n"));
    std::fs::write(rc_path, updated).with_context(|| format!("could not write {}", rc_path.display()))?;
    Ok(true)
}

/// Remove the sourcing line (and its marker comment) this decision added to
/// `rc_path` — the uninstall half. A no-op, not an error, if either the file
/// or the line isn't there.
pub fn ensure_not_sourced(rc_path: &Path, env_path: &Path) -> Result<bool> {
    if !rc_path.is_file() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(rc_path).with_context(|| format!("could not read {}", rc_path.display()))?;
    let line = sourcing_line(env_path);
    if !contains_sourcing_line(&existing, env_path) {
        return Ok(false);
    }

    let mut out_lines: Vec<&str> = Vec::new();
    let mut skip_marker_pending = false;
    for l in existing.lines() {
        if l.trim() == line {
            skip_marker_pending = false;
            continue;
        }
        if l.trim() == MARKER || l.trim() == LEGACY_MARKER {
            skip_marker_pending = true;
            continue;
        }
        if skip_marker_pending {
            // The marker is always immediately followed by the line itself
            // in what ensure_sourced wrote, so reaching here means some
            // other content already broke that up — keep it rather than
            // guess.
            skip_marker_pending = false;
        }
        out_lines.push(l);
    }
    let mut updated = out_lines.join("\n");
    if existing.ends_with('\n') {
        updated.push('\n');
    }
    std::fs::write(rc_path, updated).with_context(|| format!("could not write {}", rc_path.display()))?;
    Ok(true)
}

/// `$HOME` passed in rather than read here, so `setup` resolves every
/// location it may write to in one place and the whole flow can be pointed
/// at a sandbox in a test.
pub fn ensure_path_unix_in(bin_dir: &Path, home: &Path) -> Result<Vec<PathBuf>> {
    let env_path = write_env_file(bin_dir)?;
    let mut changed = Vec::new();
    for rc in candidate_rc_files(home) {
        if ensure_sourced(&rc, &env_path)? {
            changed.push(rc);
        }
    }
    Ok(changed)
}

pub fn remove_path_unix(bin_dir: &Path) -> Result<Vec<PathBuf>> {
    let env_path = env_file_path(bin_dir);
    let home = std::env::var("HOME").context("HOME is not set")?;
    let mut changed = Vec::new();
    for rc in candidate_rc_files(Path::new(&home)) {
        if ensure_not_sourced(&rc, &env_path)? {
            changed.push(rc);
        }
    }
    if env_path.is_file() {
        std::fs::remove_file(&env_path).with_context(|| format!("could not remove {}", env_path.display()))?;
    }
    Ok(changed)
}

// ---------- PATH, Windows ----------

#[cfg(windows)]
pub mod windows_path {
    use super::*;
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::{RegKey, RegValue};

    /// Read `HKCU\Environment\Path`, preserving whether it was stored as
    /// `REG_SZ` or `REG_EXPAND_SZ` (a `%VAR%`-expanding value) — silently
    /// downgrading an `REG_EXPAND_SZ` value to plain `REG_SZ` on write would
    /// break any `%USERPROFILE%`-style entry already in there, exactly the
    /// kind of corruption decision 28 exists to avoid. A missing value
    /// (fresh user profile) is treated as empty, matching what Windows
    /// itself would create it as: `REG_EXPAND_SZ`.
    fn read_path(env_key: &RegKey) -> (String, RegType) {
        match env_key.get_raw_value("Path") {
            Ok(v) => (decode_reg_string(&v), v.vtype),
            Err(_) => (String::new(), RegType::REG_EXPAND_SZ),
        }
    }

    fn decode_reg_string(v: &RegValue) -> String {
        let units: Vec<u16> = v.bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        String::from_utf16_lossy(&units).trim_end_matches('\u{0}').to_string()
    }

    fn encode_reg_string(s: &str, vtype: RegType) -> RegValue {
        let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        bytes.push(0);
        bytes.push(0);
        RegValue { bytes, vtype }
    }

    fn dirs_equal(a: &str, b: &str) -> bool {
        a.trim().trim_end_matches('\\').eq_ignore_ascii_case(b.trim().trim_end_matches('\\'))
    }

    fn open_env_key() -> Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            .context("could not open HKCU\\Environment")
    }

    /// Read-only: is `bin_dir` already on the per-user `PATH`? Opened
    /// `KEY_READ` only, so `setup --dry-run` cannot even hold a writable
    /// handle to the key decision 28 edits.
    pub fn is_on_path(bin_dir: &Path) -> Result<bool> {
        let env_key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ)
            .context("could not read HKCU\\Environment")?;
        let (current, _) = read_path(&env_key);
        let bin_dir_str = bin_dir.to_string_lossy();
        Ok(current.split(';').any(|d| dirs_equal(d, &bin_dir_str)))
    }

    /// Add `bin_dir` to the per-user `PATH`, idempotently. Returns whether a
    /// change was made. No elevation needed — `HKCU`, not `HKLM`. Note:
    /// already-open shells (and Explorer, until it next re-reads the
    /// environment) won't see this until a new session starts — an OS
    /// constraint, not something a registry write can work around.
    pub fn ensure_path(bin_dir: &Path) -> Result<bool> {
        let env_key = open_env_key()?;
        let (current, vtype) = read_path(&env_key);
        let bin_dir_str = bin_dir.to_string_lossy();

        if current.split(';').any(|d| dirs_equal(d, &bin_dir_str)) {
            return Ok(false);
        }

        let updated = if current.trim().is_empty() {
            bin_dir_str.to_string()
        } else if current.trim_end().ends_with(';') {
            format!("{current}{bin_dir_str}")
        } else {
            format!("{current};{bin_dir_str}")
        };

        env_key
            .set_raw_value("Path", &encode_reg_string(&updated, vtype))
            .context("could not write HKCU\\Environment\\Path")?;
        Ok(true)
    }

    /// Remove `bin_dir` from the per-user `PATH` — the uninstall half.
    pub fn remove_path(bin_dir: &Path) -> Result<bool> {
        let env_key = open_env_key()?;
        let (current, vtype) = read_path(&env_key);
        let bin_dir_str = bin_dir.to_string_lossy();

        let before: Vec<&str> = current.split(';').collect();
        let remaining: Vec<&str> = before.iter().copied().filter(|d| !dirs_equal(d, &bin_dir_str)).collect();

        if remaining.len() == before.len() {
            return Ok(false);
        }

        env_key
            .set_raw_value("Path", &encode_reg_string(&remaining.join(";"), vtype))
            .context("could not write HKCU\\Environment\\Path")?;
        Ok(true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn dirs_equal_ignores_case_and_trailing_backslash() {
            assert!(dirs_equal(r"C:\Users\me\bin\", r"c:\users\me\bin"));
            assert!(!dirs_equal(r"C:\Users\me\bin", r"C:\Users\me\other"));
        }

        #[test]
        fn reg_string_round_trips_preserving_vtype() {
            let v = encode_reg_string("C:\\a;C:\\b", RegType::REG_EXPAND_SZ);
            assert_eq!(v.vtype, RegType::REG_EXPAND_SZ);
            assert_eq!(decode_reg_string(&v), "C:\\a;C:\\b");
        }
    }
}

// ---------- top-level install / uninstall ----------

/// What a real install actually did, for `setup` to report.
pub struct InstallReport {
    pub bin_dir: PathBuf,
    pub copied: Vec<PathBuf>,
    pub path_changed: bool,
}

/// Copy this platform's binaries to the canonical location and make sure
/// `PATH` includes it — the real install step decision 28 introduces,
/// replacing decision 3's sibling-lookup-plus-printed-hint.
///
/// Every location it writes to is a parameter rather than an environment
/// read, because [`plan_install`] has to describe exactly these writes for
/// `setup --dry-run` (decision 21) and the two must not drift.
pub fn install_into(source_dir: &Path, bin_dir: &Path, home: Option<&Path>) -> Result<InstallReport> {
    let copied = install_binaries(source_dir, bin_dir)?;
    let path_changed = ensure_path(bin_dir, home)?;
    Ok(InstallReport { bin_dir: bin_dir.to_path_buf(), copied, path_changed })
}

#[cfg(unix)]
fn ensure_path(bin_dir: &Path, home: Option<&Path>) -> Result<bool> {
    let home = home.context("HOME is not set")?;
    Ok(!ensure_path_unix_in(bin_dir, home)?.is_empty())
}

#[cfg(windows)]
fn ensure_path(bin_dir: &Path, _home: Option<&Path>) -> Result<bool> {
    windows_path::ensure_path(bin_dir)
}

// ---------- the same install, described rather than done ----------

/// What [`install_into`] *would* do, computed by reading only — decision
/// 21's `setup --dry-run` half. Deliberately built from the same constants
/// and the same predicates the real install uses (`SUITE_BINARIES`,
/// `paths_refer_to_the_same_file`, `contains_sourcing_line`) rather than
/// from a second description of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub bin_dir: PathBuf,
    pub binaries: Vec<PlannedBinary>,
    pub path: PathPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedBinary {
    pub name: String,
    pub dest: PathBuf,
    pub action: BinaryAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryAction {
    Copy,
    AlreadyInPlace,
    /// Not next to the running `embarch` — a dev build, or an archive
    /// unpacked in pieces. `install_binaries` skips it rather than failing
    /// the whole install over one binary, so the plan says so too.
    MissingAtSource,
}

/// How `PATH` gets the canonical directory on this platform, or that it
/// already has it. The two arms are decision 28's two platform branches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPlan {
    AlreadyPresent,
    // Each platform constructs one of the two; both are matched in
    // `render` on every platform, and matching is not construction.
    #[cfg_attr(windows, allow(dead_code))]
    Unix { env_file: PathBuf, rc_files: Vec<PathBuf> },
    #[cfg_attr(not(windows), allow(dead_code))]
    WindowsRegistry,
    /// Could not be established without writing something — reported rather
    /// than guessed at.
    Undetermined(String),
}

pub fn plan_install(source_dir: &Path, bin_dir: &Path, home: Option<&Path>) -> InstallPlan {
    let binaries = SUITE_BINARIES
        .iter()
        .map(|stem| {
            let name = locate::native_name(stem);
            let src = source_dir.join(&name);
            let dest = bin_dir.join(&name);
            let action = if !src.is_file() {
                BinaryAction::MissingAtSource
            } else if paths_refer_to_the_same_file(&src, &dest) {
                BinaryAction::AlreadyInPlace
            } else {
                BinaryAction::Copy
            };
            PlannedBinary { name, dest, action }
        })
        .collect();
    InstallPlan { bin_dir: bin_dir.to_path_buf(), binaries, path: plan_path(bin_dir, home) }
}

#[cfg(unix)]
fn plan_path(bin_dir: &Path, home: Option<&Path>) -> PathPlan {
    let env_file = env_file_path(bin_dir);
    let Some(home) = home else {
        return PathPlan::Undetermined("HOME is not set".to_string());
    };
    // `write_env_file` always rewrites, so "no change" means the file is
    // already byte-identical to what this run would write.
    let env_file_current =
        std::fs::read_to_string(&env_file).is_ok_and(|c| c == env_file_contents(bin_dir));
    let rc_files: Vec<PathBuf> = candidate_rc_files(home)
        .into_iter()
        .filter(|rc| rc.is_file() && !already_sourced(rc, &env_file))
        .collect();
    if env_file_current && rc_files.is_empty() {
        PathPlan::AlreadyPresent
    } else {
        PathPlan::Unix { env_file, rc_files }
    }
}

#[cfg(windows)]
fn plan_path(bin_dir: &Path, _home: Option<&Path>) -> PathPlan {
    match windows_path::is_on_path(bin_dir) {
        Ok(true) => PathPlan::AlreadyPresent,
        Ok(false) => PathPlan::WindowsRegistry,
        Err(e) => PathPlan::Undetermined(format!("{e:#}")),
    }
}

impl InstallPlan {
    /// Destinations that will hold a suite binary once this plan has run —
    /// what `setup` needs to know whether the `embarch-core` it is about to
    /// register would be the copy this same run puts there.
    pub fn destinations(&self) -> Vec<PathBuf> {
        self.binaries
            .iter()
            .filter(|b| b.action != BinaryAction::MissingAtSource)
            .map(|b| b.dest.clone())
            .collect()
    }

    pub fn render(&self) -> String {
        let mut out = format!("Would install to {}:\n", self.bin_dir.display());
        for b in &self.binaries {
            let what = match b.action {
                BinaryAction::Copy => "copy",
                BinaryAction::AlreadyInPlace => "already there, no copy",
                BinaryAction::MissingAtSource => "not next to this binary, skipped",
            };
            out.push_str(&format!("  {:<13} {what}\n", b.name));
        }
        out.push_str(&match &self.path {
            PathPlan::AlreadyPresent => {
                format!("PATH: already includes {}, no change.", self.bin_dir.display())
            }
            PathPlan::Unix { env_file, rc_files } => {
                let rc = if rc_files.is_empty() {
                    "no shell rc file needs a line added".to_string()
                } else {
                    format!(
                        "add one sourcing line to {}",
                        rc_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                    )
                };
                format!("PATH: would write {} and {rc}. Per-user, no elevation.", env_file.display())
            }
            PathPlan::WindowsRegistry => {
                "PATH: would append it to HKCU\\Environment\\Path. Per-user, no elevation.".to_string()
            }
            PathPlan::Undetermined(why) => {
                format!("PATH: could not tell whether a change is needed ({why}).")
            }
        });
        out
    }
}

/// Reverse `install`: remove the canonical binaries and undo the `PATH`
/// additions. The Core-service and token-file halves of `setup --uninstall`
/// are handled separately in `setup.rs` — this is only the decision-28 part.
pub fn uninstall() -> Result<()> {
    let bin_dir = canonical_bin_dir()?;

    #[cfg(windows)]
    windows_path::remove_path(&bin_dir)?;
    #[cfg(unix)]
    remove_path_unix(&bin_dir)?;

    remove_binaries(&bin_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_uses_local_appdata() {
        let d = canonical_bin_dir_from(true, Some(r"C:\Users\me\AppData\Local"), None, None);
        assert_eq!(d, Some(PathBuf::from(r"C:\Users\me\AppData\Local").join("embarch").join("bin")));
    }

    #[test]
    fn unix_prefers_xdg_data_home_over_home() {
        let d = canonical_bin_dir_from(false, None, Some("/home/me/.data"), Some("/home/me"));
        assert_eq!(d, Some(PathBuf::from("/home/me/.data/embarch/bin")));
    }

    #[test]
    fn unix_falls_back_to_home_dot_local_share() {
        let d = canonical_bin_dir_from(false, None, None, Some("/home/me"));
        assert_eq!(d, Some(PathBuf::from("/home/me/.local/share/embarch/bin")));
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        assert_eq!(canonical_bin_dir_from(false, None, Some(""), Some("/home/me")), Some(PathBuf::from("/home/me/.local/share/embarch/bin")));
        assert_eq!(canonical_bin_dir_from(false, None, None, Some("")), None);
        assert_eq!(canonical_bin_dir_from(true, Some(""), None, None), None);
    }

    #[test]
    fn env_file_lives_beside_bin_dir() {
        let bin_dir = PathBuf::from("/home/me/.local/share/embarch/bin");
        assert_eq!(env_file_path(&bin_dir), PathBuf::from("/home/me/.local/share/embarch/env"));
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("embarch-umbrella-install-test-{name}-{:?}", std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn install_binaries_copies_present_files_and_skips_missing_ones() {
        let src = tmp_dir("src-a");
        let dst = tmp_dir("dst-a");
        std::fs::write(src.join(locate::native_name("embarch")), b"embarch").unwrap();
        std::fs::write(src.join(locate::native_name("embarch-core")), b"core").unwrap();
        // embarch-api deliberately absent from source.

        let written = install_binaries(&src, &dst).unwrap();
        assert_eq!(written.len(), 2);
        assert!(dst.join(locate::native_name("embarch")).is_file());
        assert!(dst.join(locate::native_name("embarch-core")).is_file());
        assert!(!dst.join(locate::native_name("embarch-api")).exists());

        std::fs::remove_dir_all(&src).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }

    #[test]
    fn install_binaries_is_a_no_op_when_source_is_already_the_destination() {
        let dir = tmp_dir("same");
        std::fs::write(dir.join(locate::native_name("embarch")), b"embarch").unwrap();

        let written = install_binaries(&dir, &dir).unwrap();
        assert_eq!(written.len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_binaries_is_not_an_error_when_nothing_is_there() {
        let dir = tmp_dir("never-existed");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!remove_binaries(&dir).unwrap());
    }

    #[test]
    fn ensure_sourced_is_idempotent() {
        let dir = tmp_dir("rc");
        let rc = dir.join(".bashrc");
        std::fs::write(&rc, "# existing content\n").unwrap();
        let env_path = dir.join("env");

        assert!(ensure_sourced(&rc, &env_path).unwrap());
        let after_first = std::fs::read_to_string(&rc).unwrap();
        assert!(after_first.contains(&sourcing_line(&env_path)));

        assert!(!ensure_sourced(&rc, &env_path).unwrap());
        let after_second = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(after_first, after_second, "a second run must not duplicate the line");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_sourced_skips_an_rc_file_that_does_not_exist() {
        let dir = tmp_dir("no-rc");
        let rc = dir.join(".zshrc"); // never created
        let env_path = dir.join("env");
        assert!(!ensure_sourced(&rc, &env_path).unwrap());
        assert!(!rc.exists(), "must never create an rc file that wasn't already there");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_not_sourced_removes_what_ensure_sourced_added() {
        let dir = tmp_dir("rc-remove");
        let rc = dir.join(".bashrc");
        std::fs::write(&rc, "# existing content\nalias ll='ls -la'\n").unwrap();
        let env_path = dir.join("env");

        assert!(ensure_sourced(&rc, &env_path).unwrap());
        assert!(ensure_not_sourced(&rc, &env_path).unwrap());

        let final_content = std::fs::read_to_string(&rc).unwrap();
        assert!(!final_content.contains(&sourcing_line(&env_path)));
        assert!(!final_content.contains(MARKER));
        assert!(final_content.contains("alias ll='ls -la'"), "unrelated content must survive");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_not_sourced_removes_the_legacy_pre_four_file_split_marker() {
        // A machine set up by `embarch setup` before the four-file split still
        // has this exact marker text (naming a `design.md` that no longer
        // exists) sitting in its rc file. `ensure_not_sourced` must still
        // remove it and the sourcing line beside it, or an old install is
        // left with a dangling comment nothing will ever clean up.
        let dir = tmp_dir("rc-legacy-marker");
        let rc = dir.join(".bashrc");
        let env_path = dir.join("env");
        let legacy_content = format!(
            "# existing content\nalias ll='ls -la'\n\n{LEGACY_MARKER}\n{}\n",
            sourcing_line(&env_path)
        );
        std::fs::write(&rc, &legacy_content).unwrap();

        assert!(ensure_not_sourced(&rc, &env_path).unwrap());

        let final_content = std::fs::read_to_string(&rc).unwrap();
        assert!(!final_content.contains(&sourcing_line(&env_path)));
        assert!(!final_content.contains(LEGACY_MARKER));
        assert!(!final_content.contains(MARKER));
        assert!(final_content.contains("alias ll='ls -la'"), "unrelated content must survive");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_not_sourced_is_a_no_op_when_never_added() {
        let dir = tmp_dir("rc-noop");
        let rc = dir.join(".bashrc");
        std::fs::write(&rc, "# just some rc file\n").unwrap();
        let env_path = dir.join("env");
        assert!(!ensure_not_sourced(&rc, &env_path).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
