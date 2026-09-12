//! `embarch deploy-core` — get a local `embarch-core` change onto the live
//! Windows service (decision 32).
//!
//! **Why this is a command and not a document.**
//! [`embarch-dev-workflow.md`][wf] §4a calls its own subject "the single
//! most-repeated undocumented step in the suite" and says two handoffs in a
//! row pointed at a section that did not exist yet. Writing it down fixed
//! the *forgetting*. It did not fix the re-typing: every deploy since has
//! been a hand-assembled rsync loop, a hand-typed absolute `cargo.exe` path,
//! and a from-scratch PowerShell script — re-derived, un-reviewed, and
//! different each time. A documented five-step manual procedure with a
//! silent failure mode in the middle of it is a command waiting to be
//! written.
//!
//! [wf]: https://github.com/gabrieltetar/embarch-doc/blob/main/embarch-dev-workflow.md
//!
//! **What it does, and the one thing it refuses to trust.** Sync the shared
//! crates and Core to the Windows-side source copies (shared first, Core
//! last — same ordering §6 requires for commits, and for the same reason: a
//! Core built against stale siblings compiles and is wrong), build natively
//! with Windows `cargo.exe`, then stop/copy/start the service from inside a
//! single elevation, and **verify the binary on disk actually changed**.
//!
//! That last step is the whole point. `embarch-core.exe update`'s own
//! self-elevation, when the consent dialog never renders, **exits `0`,
//! prints nothing, and does nothing** — §4a records this happening and
//! leaving the live Core down for several minutes. It happened again on
//! 2026-08-27, in the session that wrote this module, which is what prompted
//! it. A deploy that cannot tell success from that is not a deploy; so this
//! hashes the installed binary against the freshly built one and fails
//! loudly when they disagree. (A length check shipped first and missed a
//! same-size rebuild twice in a row — decision 32's amendment — which is why
//! this compares content instead.)
//!
//! **Elevation, and decision 7.** Umbrella's standing posture is that it
//! never obtains elevation itself — it prints the elevated command and lets
//! a human run it (`setup.rs`). This is a deliberate, narrow exception, and
//! the distinction that makes it one: umbrella still never elevates
//! *silently*. `--print-script` is the decision-7 behaviour verbatim (write
//! the script, print the one command, do nothing), and it is what runs
//! whenever this is not under WSL2. The default merely saves the human the
//! copy-paste, through one UAC prompt they see and can decline. What it will
//! not do is guess: every path it uses is either explicitly given, read from
//! the service's own registration, or refused with the flag that supplies
//! it.

use std::path::{Path, PathBuf};

use crate::locate;
use crate::state;

/// Sync order: shared crates first, `embarch-core` last.
///
/// Not alphabetical and not arbitrary. `embarch-core`'s `Cargo.toml` carries
/// `path` dependencies on both of the others, so a run that copied Core
/// first and was interrupted would leave a Windows tree whose Core is newer
/// than the crates it is built against — which compiles cleanly and is
/// wrong. Same ordering, same reason, as the commit ordering
/// `embarch-dev-workflow.md` §6 requires.
pub const SYNC_CRATES: [&str; 3] = ["embarch-study-designer", "embarch-topology", "embarch-core"];

const EXIT_FAILURE: i32 = 1;

/// Everything a deploy needs, resolved before anything is touched.
///
/// Built and printed as a unit so an operator sees all five paths *before*
/// the first `rsync`, rather than discovering a wrong one halfway through a
/// two-minute build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Linux-side checkouts' parent — the canonical git clones.
    pub source_root: PathBuf,
    /// Windows-side source copies' parent, as a `/mnt/...` path. **Not git
    /// clones**, by design: build inputs only.
    pub windows_root: PathBuf,
    /// Windows `cargo.exe`, as a `/mnt/...` path. Never on the WSL `PATH`.
    pub cargo_exe: PathBuf,
    /// The exe the service actually runs, as a `/mnt/...` path — read from
    /// the service's own `BINARY_PATH_NAME`, never guessed.
    pub install_target: PathBuf,
    pub service: String,
}

impl Plan {
    /// The build output this plan will produce.
    pub fn built_exe(&self) -> PathBuf {
        self.windows_root
            .join("embarch-core")
            .join("target")
            .join("release")
            .join("embarch-core.exe")
    }

    pub fn render(&self) -> String {
        format!(
            "  source (Linux)   {}\n  \
               source (Windows) {}\n  \
               cargo.exe        {}\n  \
               builds           {}\n  \
               installs to      {}\n  \
               service          {}",
            self.source_root.display(),
            self.windows_root.display(),
            self.cargo_exe.display(),
            self.built_exe().display(),
            self.install_target.display(),
            self.service,
        )
    }
}

/// Where each path came from, so a resolution that surprises an operator can
/// be argued with rather than only observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub plan: Plan,
    pub notes: Vec<String>,
}

/// Resolves a [`Plan`] from flags, saved state, and probes — in that order,
/// which is the order of decreasing confidence.
///
/// Pure with respect to the probes: they arrive as arguments so this is
/// testable without a Windows filesystem, `sc.exe`, or a real checkout. That
/// is the same split `locate.rs` already makes for its own shell-outs, and
/// `embarch_core_client::token_discovery` makes upstream for the token
/// fallback chain this crate now depends on rather than mirrors.
#[allow(clippy::too_many_arguments)]
pub fn resolve_plan(
    source_root: Option<&Path>,
    windows_root: Option<&Path>,
    cargo_exe: Option<&Path>,
    install_target: Option<&Path>,
    service: Option<&str>,
    saved: &state::State,
    probed_service_binary: Option<PathBuf>,
    probed_cargo_exe: Option<PathBuf>,
    cwd_repo_parent: Option<PathBuf>,
) -> Result<Resolution, String> {
    let mut notes = Vec::new();

    let source_root = pick(
        "--source-root",
        source_root,
        saved.deploy_source_root.as_deref(),
        cwd_repo_parent,
        "the parent of the checkout you are standing in",
        &mut notes,
        "source (Linux)",
    )?;

    // No probe for this one on purpose. There is no way to tell a Windows
    // directory that holds this suite's source copies from any other
    // directory, and picking wrong means building the wrong tree and
    // deploying it — so an unset value is an error naming the flag, not a
    // guess. Once given, it is remembered.
    let windows_root = pick(
        "--windows-root",
        windows_root,
        saved.deploy_windows_root.as_deref(),
        None,
        "",
        &mut notes,
        "source (Windows)",
    )?;

    let cargo_exe = pick(
        "--cargo",
        cargo_exe,
        saved.deploy_cargo_exe.as_deref(),
        probed_cargo_exe,
        "%USERPROFILE%\\.cargo\\bin\\cargo.exe",
        &mut notes,
        "cargo.exe",
    )?;

    let install_target = pick(
        "--install-target",
        install_target,
        None,
        probed_service_binary,
        "the service's own BINARY_PATH_NAME",
        &mut notes,
        "installs to",
    )?;

    Ok(Resolution {
        plan: Plan {
            source_root,
            windows_root,
            cargo_exe,
            install_target,
            service: service.unwrap_or(locate::WINDOWS_CORE_SERVICE_LABEL).to_string(),
        },
        notes,
    })
}

/// Flag, then saved state, then probe — and an error naming the flag if none
/// of the three answered. `install_target` deliberately passes `None` for
/// saved state: the service's registration is authoritative and free to
/// read, so caching it could only ever go stale against the thing it
/// describes.
fn pick(
    flag: &str,
    explicit: Option<&Path>,
    saved: Option<&Path>,
    probed: Option<PathBuf>,
    probe_description: &str,
    notes: &mut Vec<String>,
    label: &str,
) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = saved {
        notes.push(format!("{label}: from saved state ({flag} to change it)"));
        return Ok(p.to_path_buf());
    }
    if let Some(p) = probed {
        notes.push(format!("{label}: {probe_description}"));
        return Ok(p);
    }
    Err(format!("could not determine {label} — pass {flag}"))
}

/// The elevated half, as a PowerShell script.
///
/// **It logs from inside the elevated context, and that is the only reason
/// it is a script at all.** `ShellExecuteExW`'s relaunch gives the elevated
/// child its own console, so wrapping the *unelevated* launcher in a
/// redirect captures nothing — §4a records exactly this. A script that
/// `Tee-Object`s each step to a file the unelevated side can read afterwards
/// is what turns "it exited 0" into a transcript.
///
/// Pure, so what gets run is reviewable in a test rather than only in a
/// temp file.
pub fn elevated_script(win_install: &str, win_built: &str, win_log: &str, service: &str) -> String {
    format!(
        "# Generated by `embarch deploy-core` (embarch-umbrella\n\
         # decision 32). Runs elevated; logs each step from *inside* the\n\
         # elevated context, because the elevated child gets its own console\n\
         # and a redirect around the unelevated launcher captures nothing.\n\
         $ErrorActionPreference = 'Stop'\n\
         $log = '{win_log}'\n\
         function Say($m) {{ $m | Tee-Object -FilePath $log -Append }}\n\
         Set-Content -Path $log -Value '=== embarch deploy-core ==='\n\
         try {{\n\
         \x20 Say 'stopping {service}'\n\
         \x20 & sc.exe stop {service} 2>&1 | Tee-Object -FilePath $log -Append\n\
         \x20 # The SCM reports the stop *request*, not its completion.\n\
         \x20 for ($i = 0; $i -lt 30; $i++) {{\n\
         \x20   $s = (& sc.exe query {service}) -join ' '\n\
         \x20   if ($s -match 'STOPPED') {{ break }}\n\
         \x20   Start-Sleep -Milliseconds 500\n\
         \x20 }}\n\
         \x20 Say 'backing up the installed binary'\n\
         \x20 Copy-Item '{win_install}' '{win_install}.bak-deploy' -Force\n\
         \x20 Say 'copying the fresh build in'\n\
         \x20 Copy-Item '{win_built}' '{win_install}' -Force\n\
         \x20 Say (\"installed length: \" + (Get-Item '{win_install}').Length)\n\
         \x20 Say 'starting {service}'\n\
         \x20 & sc.exe start {service} 2>&1 | Tee-Object -FilePath $log -Append\n\
         \x20 Start-Sleep -Seconds 2\n\
         \x20 & sc.exe query {service} 2>&1 | Tee-Object -FilePath $log -Append\n\
         }} catch {{\n\
         \x20 Say \"FAILED: $_\"\n\
         \x20 # Roll the old binary back rather than leaving the service\n\
         \x20 # pointed at a half-copied file — the same posture\n\
         \x20 # `embarch-core.exe update` takes on a failed start.\n\
         \x20 if (Test-Path '{win_install}.bak-deploy') {{\n\
         \x20   Copy-Item '{win_install}.bak-deploy' '{win_install}' -Force\n\
         \x20   & sc.exe start {service} 2>&1 | Tee-Object -FilePath $log -Append\n\
         \x20 }}\n\
         \x20 exit 1\n\
         }}\n\
         Say '=== done ==='\n"
    )
}

/// Did the deploy actually land? Content, not length — decision 32's
/// amendment: a release rebuild of one constant, or a rename-only change,
/// produces two builds the same size, and a length check reported "landed"
/// on both a real cancelled deploy and (once) a genuine no-op it couldn't
/// tell apart from success.
///
/// Pure, and separate, because "exited 0 having done nothing" is the failure
/// this whole module exists to catch and it deserves a test rather than a
/// comment. Parameters are named for what they hold, not what they measure,
/// so a caller can no longer pass a byte count here by mistake.
pub fn landed(built_digest: [u8; 32], installed_digest_after: [u8; 32]) -> bool {
    built_digest == installed_digest_after
}

/// SHA-256 of a file's contents, for [`landed`]. Not a length and not a
/// timestamp — a copy preserves neither reliably across the `/mnt` boundary,
/// and length is exactly the check decision 32's amendment retired.
fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let bytes = std::fs::read(path)?;
    Ok(hash_bytes(&bytes))
}

/// The digest [`hash_file`] takes off disk, split out so tests can hash a
/// literal without writing a file.
fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Runs the whole deploy. Returns a process exit code.
pub async fn deploy_core(
    source_root: Option<PathBuf>,
    windows_root: Option<PathBuf>,
    cargo_exe: Option<PathBuf>,
    install_target: Option<PathBuf>,
    service: Option<String>,
    dry_run: bool,
    print_script: bool,
) -> i32 {
    if !crate::env::under_wsl2() {
        println!(
            "deploy-core is a WSL2 -> Windows-service operation: it syncs Linux checkouts to \
             Windows source copies, builds with Windows `cargo.exe`, and replaces the binary a \
             Windows service runs. On a machine where Core is native, `embarch-core install` / \
             `embarch-core update` already do this directly."
        );
        return EXIT_FAILURE;
    }

    let saved = state::load();
    let resolution = match resolve_plan(
        source_root.as_deref(),
        windows_root.as_deref(),
        cargo_exe.as_deref(),
        install_target.as_deref(),
        service.as_deref(),
        &saved,
        locate::windows_core_service_binary_path(),
        probe_windows_cargo_exe(),
        cwd_repo_parent(),
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("deploy-core: {e}");
            return EXIT_FAILURE;
        }
    };
    let plan = &resolution.plan;
    println!("deploy-core plan:\n{}", plan.render());
    for note in &resolution.notes {
        println!("  ({note})");
    }

    // Checked before the build rather than after the handshake fails: a
    // redeploy that moves `DEV_BENCH_WIRE_SCHEMA_VERSION` makes every bench
    // on the old number answer `compatible: false`, and there is no
    // partial-upgrade mode (`embarch-dev-workflow.md` §4a, coupling 1).
    if let Some(wire) = read_wire_schema_version(&plan.source_root) {
        println!(
            "  (dev-bench wire schema in this source: v{wire} — if that moved, reflash the bench \
             in this same sitting and `reset_dev_bench` afterwards)"
        );
    }

    for crate_name in SYNC_CRATES {
        let from = plan.source_root.join(crate_name);
        if !from.is_dir() {
            println!("deploy-core: {} isn't a directory", from.display());
            return EXIT_FAILURE;
        }
    }

    if dry_run {
        println!("deploy-core: --dry-run, nothing done");
        return 0;
    }

    // --- unelevated: sync, then build ------------------------------------
    for crate_name in SYNC_CRATES {
        let from = format!("{}/", plan.source_root.join(crate_name).display());
        let to = format!("{}/", plan.windows_root.join(crate_name).display());
        println!("syncing {crate_name}");
        // `--delete` is deliberately absent, matching §4a: a file deleted on
        // the Linux side lingers on the Windows side as an orphan, which
        // cargo ignores. The trade is that a grep of the Windows copy can
        // turn up source that no longer exists — which is why §4a says to
        // treat the Windows copy as a build input, never as a reference.
        let status = std::process::Command::new("rsync")
            .args(["-a", "--exclude", "/target/", "--exclude", "/.git/", &from, &to])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                println!("deploy-core: rsync of {crate_name} failed ({s})");
                return EXIT_FAILURE;
            }
            Err(e) => {
                println!("deploy-core: couldn't run rsync: {e}");
                return EXIT_FAILURE;
            }
        }
    }

    println!("building natively (this is the slow part)");
    let core_dir = plan.windows_root.join("embarch-core");
    let status = std::process::Command::new(&plan.cargo_exe)
        .args(["build", "--release"])
        .current_dir(&core_dir)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            println!("deploy-core: cargo build failed ({s})");
            return EXIT_FAILURE;
        }
        Err(e) => {
            println!("deploy-core: couldn't run {}: {e}", plan.cargo_exe.display());
            return EXIT_FAILURE;
        }
    }

    let built = plan.built_exe();
    let built_digest = match hash_file(&built) {
        Ok(d) => d,
        Err(e) => {
            println!("deploy-core: no build output at {}: {e}", built.display());
            return EXIT_FAILURE;
        }
    };
    // A same-length note used to gate on length here too, but length is
    // exactly the signal decision 32's amendment retired — a same-size
    // rebuild is the common case, not a corner case, so it is not worth
    // printing on its own. The digest comparison below is the real check.

    // --- the elevated half ------------------------------------------------
    let Some(script_dir) = windows_temp_dir() else {
        println!(
            "deploy-core: couldn't find a Windows-visible temp directory to write the elevated \
             script into (needs `cmd.exe` + `wslpath`)"
        );
        return EXIT_FAILURE;
    };
    let script_path = script_dir.join("embarch-deploy-core.ps1");
    let log_path = script_dir.join("embarch-deploy-core.log");

    let (Some(win_install), Some(win_built), Some(win_script), Some(win_log)) = (
        to_windows_path(&plan.install_target),
        to_windows_path(&built),
        to_windows_path(&script_path),
        to_windows_path(&log_path),
    ) else {
        println!("deploy-core: couldn't translate one of the paths back to Windows form");
        return EXIT_FAILURE;
    };

    let script = elevated_script(&win_install, &win_built, &win_log, &plan.service);
    if let Err(e) = std::fs::write(&script_path, &script) {
        println!("deploy-core: couldn't write {}: {e}", script_path.display());
        return EXIT_FAILURE;
    }
    let _ = std::fs::remove_file(&log_path);

    if print_script {
        // Decision 7's posture, verbatim: umbrella did everything it can
        // without elevation and hands the elevated step to a human.
        println!(
            "deploy-core: wrote {}\n\nRun this in a Windows shell (it will prompt for \
             elevation):\n  powershell -NoProfile -Command \"Start-Process powershell -Verb \
             RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{}'\"\n\n\
             This mode does not verify the result itself — there is no separate --verify-only \
             flag. Check {} against the build at {} yourself (a hash, not a size — same-size \
             rebuilds are common) or run `deploy-core` again without --print-script for the full, \
             self-verifying path.",
            script_path.display(),
            win_script,
            win_install,
            win_built
        );
        return 0;
    }

    println!("elevating (one UAC prompt — decline it and nothing changes)");
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Start-Process powershell -Verb RunAs -Wait -ArgumentList \
                 '-NoProfile','-ExecutionPolicy','Bypass','-File','{win_script}'"
            ),
        ])
        .status();
    if let Err(e) = status {
        println!("deploy-core: couldn't launch powershell.exe: {e}");
        return EXIT_FAILURE;
    }

    // The transcript is the only account of what the elevated child did —
    // its console is gone by now (§4a). A missing transcript is a hard
    // failure in its own right, checked before the content comparison below:
    // decision 32's amendment is explicit that the success line must not
    // depend on the service merely being `RUNNING`, which is true of a
    // deploy that did nothing at all — and a missing transcript is exactly
    // "the elevated child never started", the clearest case of that.
    match std::fs::read_to_string(&log_path) {
        Ok(text) => {
            println!("--- elevated transcript ---");
            // UTF-16LE from `Tee-Object` on Windows PowerShell reads as
            // interleaved NULs through `read_to_string`; strip them rather
            // than print a spaced-out mess.
            for line in text.replace('\u{0}', "").lines() {
                let line = line.trim_end();
                if !line.is_empty() {
                    println!("  {line}");
                }
            }
            println!("---------------------------");
        }
        Err(_) => {
            println!(
                "deploy-core: FAILED. No transcript at {} — the elevated child never started, \
                 which is what a UAC prompt that never rendered looks like. Re-run, or use \
                 --print-script and run the elevated step yourself.",
                log_path.display()
            );
            return EXIT_FAILURE;
        }
    }

    // --- verify, because exit code 0 is not evidence ----------------------
    let installed_digest_after = match hash_file(&plan.install_target) {
        Ok(d) => d,
        Err(e) => {
            println!("deploy-core: can't read {} afterwards: {e}", plan.install_target.display());
            return EXIT_FAILURE;
        }
    };
    if !landed(built_digest, installed_digest_after) {
        println!(
            "deploy-core: FAILED to land. {} does not match the build's content. The commonest \
             cause is a UAC consent dialog that never rendered — that exits 0 and does nothing \
             (`embarch-dev-workflow.md` §4a). Re-run, or use --print-script and run the elevated \
             step yourself.",
            plan.install_target.display()
        );
        return EXIT_FAILURE;
    }
    match locate::windows_core_service_state() {
        Some(locate::WindowsServiceState::Running) => {
            println!("deploy-core: landed, and {} is running", plan.service)
        }
        Some(locate::WindowsServiceState::Installed) => {
            println!(
                "deploy-core: the binary landed but {} is NOT running — the script's own \
                 transcript above says how far it got. `embarch up` starts it.",
                plan.service
            );
            return EXIT_FAILURE;
        }
        None => println!(
            "deploy-core: the binary landed; couldn't read the service state to confirm it \
             restarted"
        ),
    }

    // Remembered only after a deploy that actually worked, so a wrong
    // `--windows-root` isn't persisted for the next run to inherit.
    let mut saved = saved;
    saved.deploy_source_root = Some(plan.source_root.clone());
    saved.deploy_windows_root = Some(plan.windows_root.clone());
    saved.deploy_cargo_exe = Some(plan.cargo_exe.clone());
    if let Err(e) = state::save(&saved) {
        println!("  (couldn't save these paths for next time: {e})");
    }

    println!(
        "  next: if the wire schema moved, `flash_dev_bench` + `reset_dev_bench`, then check \
         GET /dev-bench/hello reports compatible: true"
    );
    0
}

/// `DEV_BENCH_WIRE_SCHEMA_VERSION`, read out of the crate's own source.
///
/// The same trick `embarch-dev-bench`'s `app/CMakeLists.txt` uses, and for
/// the same reason it was made to: that number was hand-mirrored in C and
/// went stale twice. Umbrella has no dependency on the crate (embarch-umbrella
/// spec.md §1 — it orchestrates, it does not link), so reading the source is the honest
/// way to say the number here at all.
fn read_wire_schema_version(source_root: &Path) -> Option<u32> {
    let path = source_root.join("embarch-study-designer").join("src").join("schema_version.rs");
    let text = std::fs::read_to_string(path).ok()?;
    parse_wire_schema_version(&text)
}

fn parse_wire_schema_version(source: &str) -> Option<u32> {
    const DECL: &str = "pub const DEV_BENCH_WIRE_SCHEMA_VERSION: u32 = ";
    let rest = &source[source.find(DECL)? + DECL.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// `%USERPROFILE%\.cargo\bin\cargo.exe`, translated. Never on the WSL
/// `PATH`, which is why every manual deploy has typed it out by hand.
#[cfg(unix)]
fn probe_windows_cargo_exe() -> Option<PathBuf> {
    let profile = windows_env_var("USERPROFILE")?;
    let root = wsl_path(&profile)?;
    let candidate = root.join(".cargo").join("bin").join("cargo.exe");
    candidate.is_file().then_some(candidate)
}

#[cfg(not(unix))]
fn probe_windows_cargo_exe() -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn windows_temp_dir() -> Option<PathBuf> {
    let temp = windows_env_var("TEMP")?;
    let dir = wsl_path(&temp)?;
    dir.is_dir().then_some(dir)
}

#[cfg(not(unix))]
fn windows_temp_dir() -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn windows_env_var(name: &str) -> Option<String> {
    let out = std::process::Command::new("cmd.exe")
        .args(["/C", "echo", &format!("%{name}%")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty() && !trimmed.contains('%')).then(|| trimmed.to_string())
}

#[cfg(unix)]
fn wsl_path(win: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("wslpath").args(["-u", win]).output().ok()?;
    out.status.success().then_some(())?;
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim();
    trimmed.starts_with('/').then(|| PathBuf::from(trimmed))
}

#[cfg(unix)]
fn to_windows_path(p: &Path) -> Option<String> {
    let out =
        std::process::Command::new("wslpath").args(["-w", &p.to_string_lossy()]).output().ok()?;
    out.status.success().then_some(())?;
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(not(unix))]
fn to_windows_path(p: &Path) -> Option<String> {
    Some(p.to_string_lossy().into_owned())
}

/// The parent of the git checkout the operator is standing in — this suite's
/// standard layout puts every sub-project as a sibling
/// ([DOC-PROTOCOL.md][dp] §2), so the parent of any one of them is the source
/// root.
///
/// A convenience with a real failure mode, which is why it is the *last*
/// fallback and is reported as a guess when it fires: running this from
/// somewhere else entirely would name the wrong root, and the plan is
/// printed before anything is copied precisely so that is visible.
///
/// [dp]: https://github.com/gabrieltetar/embarch-doc/blob/main/DOC-PROTOCOL.md
fn cwd_repo_parent() -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let top = PathBuf::from(text.trim());
    let parent = top.parent()?.to_path_buf();
    // Only if it actually looks like this suite's layout. Otherwise the
    // "guess" would be an arbitrary directory that happens to be above a git
    // repo.
    SYNC_CRATES.iter().all(|c| parent.join(c).is_dir()).then_some(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(windows_root: Option<&str>) -> state::State {
        state::State {
            deploy_windows_root: windows_root.map(PathBuf::from),
            ..Default::default()
        }
    }

    /// The ordering invariant, asserted rather than left to a comment:
    /// `embarch-core` depends on both of the others by `path`, so a run that
    /// copied it first and died would leave a tree that builds cleanly and
    /// is wrong.
    #[test]
    fn core_is_synced_last() {
        assert_eq!(*SYNC_CRATES.last().unwrap(), "embarch-core");
        assert!(SYNC_CRATES.contains(&"embarch-study-designer"));
        assert!(SYNC_CRATES.contains(&"embarch-topology"));
    }

    #[test]
    fn an_unresolvable_windows_root_names_its_flag_rather_than_guessing() {
        let err = resolve_plan(
            Some(Path::new("/src")),
            None,
            Some(Path::new("/mnt/c/cargo.exe")),
            Some(Path::new("/mnt/c/core.exe")),
            None,
            &state_with(None),
            None,
            None,
            None,
        )
        .expect_err("must refuse");
        assert!(err.contains("--windows-root"), "{err}");
    }

    #[test]
    fn saved_state_answers_on_a_second_run_and_says_so() {
        let resolution = resolve_plan(
            Some(Path::new("/src")),
            None,
            Some(Path::new("/mnt/c/cargo.exe")),
            Some(Path::new("/mnt/c/core.exe")),
            None,
            &state_with(Some("/mnt/c/win")),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resolution.plan.windows_root, PathBuf::from("/mnt/c/win"));
        assert!(
            resolution.notes.iter().any(|n| n.contains("saved state")),
            "the operator should be told which paths they did not supply: {:?}",
            resolution.notes
        );
    }

    /// A flag beats saved state. Otherwise a wrong path, once remembered,
    /// could never be corrected without editing the state file by hand.
    #[test]
    fn an_explicit_flag_wins_over_saved_state() {
        let resolution = resolve_plan(
            Some(Path::new("/src")),
            Some(Path::new("/mnt/c/other")),
            Some(Path::new("/mnt/c/cargo.exe")),
            Some(Path::new("/mnt/c/core.exe")),
            None,
            &state_with(Some("/mnt/c/win")),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resolution.plan.windows_root, PathBuf::from("/mnt/c/other"));
    }

    /// The install target is never taken from saved state — the service's
    /// own registration is authoritative and free to read, so a cache could
    /// only go stale against the thing it describes.
    #[test]
    fn the_install_target_comes_from_the_service_probe() {
        let resolution = resolve_plan(
            Some(Path::new("/src")),
            Some(Path::new("/mnt/c/win")),
            Some(Path::new("/mnt/c/cargo.exe")),
            None,
            None,
            &state_with(Some("/mnt/c/win")),
            Some(PathBuf::from("/mnt/c/Users/x/embarch-setup/embarch-core.exe")),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            resolution.plan.install_target,
            PathBuf::from("/mnt/c/Users/x/embarch-setup/embarch-core.exe")
        );
        assert_eq!(resolution.plan.service, locate::WINDOWS_CORE_SERVICE_LABEL);
    }

    #[test]
    fn the_build_output_is_where_cargo_puts_it() {
        let plan = Plan {
            source_root: PathBuf::from("/src"),
            windows_root: PathBuf::from("/mnt/c/win"),
            cargo_exe: PathBuf::from("/mnt/c/cargo.exe"),
            install_target: PathBuf::from("/mnt/c/core.exe"),
            service: "com.embarch.core".to_string(),
        };
        assert_eq!(
            plan.built_exe(),
            PathBuf::from("/mnt/c/win/embarch-core/target/release/embarch-core.exe")
        );
        assert!(plan.render().contains("com.embarch.core"));
    }

    /// The failure this module exists for: a clean exit that changed
    /// nothing.
    #[test]
    fn a_deploy_that_did_nothing_is_not_a_deploy() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert!(landed(a, a));
        assert!(!landed(a, b));
    }

    /// Decision 32's amendment, the exact case a byte count cannot catch: two
    /// builds the same length with different content — a rebuild of one
    /// constant, or a rename-only change.
    #[test]
    fn same_length_different_content_is_not_landed() {
        let built = hash_bytes(b"embarch-core build one, 4096 bytes padded......");
        let installed = hash_bytes(b"embarch-core build two, 4096 bytes padded.....!");
        assert_eq!(
            b"embarch-core build one, 4096 bytes padded......".len(),
            b"embarch-core build two, 4096 bytes padded.....!".len(),
            "the test fixture itself must be the same-length case"
        );
        assert!(!landed(built, installed));
    }

    #[test]
    fn the_elevated_script_stops_copies_and_starts_in_that_order() {
        let script = elevated_script(
            r"C:\install\embarch-core.exe",
            r"C:\build\embarch-core.exe",
            r"C:\temp\deploy.log",
            "com.embarch.core",
        );
        let stop = script.find("sc.exe stop").expect("must stop");
        let copy = script.find(r"Copy-Item 'C:\build").expect("must copy the build in");
        let start = script.find("sc.exe start").expect("must start");
        assert!(stop < copy, "copying over a running binary is what the stop is for");
        assert!(copy < start);
        // Waits for STOPPED rather than trusting `sc.exe stop`'s own return,
        // which reports the request and not its completion.
        assert!(script.contains("STOPPED"));
        // Rolls back on failure rather than leaving the service pointed at a
        // half-copied file.
        assert!(script.contains(".bak-deploy"));
    }

    #[test]
    fn the_wire_schema_version_is_read_out_of_the_crate() {
        let source = "/// docs\npub const DEV_BENCH_WIRE_SCHEMA_VERSION: u32 = 12;\n";
        assert_eq!(parse_wire_schema_version(source), Some(12));
        assert_eq!(parse_wire_schema_version("nothing here"), None);
    }
}
