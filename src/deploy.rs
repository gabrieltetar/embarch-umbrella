//! `embarch deploy-core` — get a local `embarch-core` change running on the
//! Windows machine (decision 32, changed by decision 68).
//!
//! **Since decision 68 this installs a development Core beside the service,
//! not over it** (`deploy_dev.rs`): the service stays registered and stopped,
//! its binary is never written, and `--restore-service` starts it again. The
//! text below is decision 32's account of the original elevated
//! stop/copy/start; its hash-the-result rule survives, aimed at the copy and
//! the running development Core's `/status`.
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

use crate::deploy_dev;
use crate::locate;
use crate::state;

/// Sync order: shared crates first, `embarch-core` last.
///
/// Not alphabetical and not arbitrary. `embarch-core`'s `Cargo.toml` carries
/// `path` dependencies on all three others, so a run that copied Core
/// first and was interrupted would leave a Windows tree whose Core is newer
/// than the crates it is built against — which compiles cleanly and is
/// wrong. Same ordering, same reason, as the commit ordering
/// `embarch-dev-workflow.md` §6 requires.
pub const SYNC_CRATES: [&str; 4] = ["embarch-study-designer", "embarch-topology", "embarch-smp", "embarch-core"];

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
    /// The exe the service runs, read from its own `BINARY_PATH_NAME`. **Read
    /// only** (decision 68): it is named in the plan and never written.
    pub service_binary: Option<PathBuf>,
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
               service          {} (never written)",
            self.source_root.display(),
            self.windows_root.display(),
            self.cargo_exe.display(),
            self.built_exe().display(),
            "%LOCALAPPDATA%\\embarch\\dev\\core\\embarch-core.exe",
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

    Ok(Resolution {
        plan: Plan {
            source_root,
            windows_root,
            cargo_exe,
            service_binary: probed_service_binary,
            service: service.unwrap_or(locate::WINDOWS_CORE_SERVICE_LABEL).to_string(),
        },
        notes,
    })
}

/// Flag, then saved state, then probe — and an error naming the flag if none
/// of the three answered.
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
///
/// `pub(crate)`: check 15 (`doctor.rs`, `embarch-umbrella` decision 56) hashes
/// the located `embarch-core` binary the same way, to compare against
/// `/status`'s `binary_sha256` — one hashing routine, not two.
pub(crate) fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
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
#[allow(clippy::too_many_arguments)]
pub async fn deploy_core(
    source_root: Option<PathBuf>,
    windows_root: Option<PathBuf>,
    cargo_exe: Option<PathBuf>,
    service: Option<String>,
    dry_run: bool,
    print_script: bool,
    cancel_run: bool,
    restore_service: bool,
) -> i32 {
    if !crate::env::under_wsl2() {
        eprintln!(
            "deploy-core is a WSL2 -> Windows-service operation: it syncs Linux checkouts to \
             Windows source copies, builds with Windows `cargo.exe`, and replaces the binary a \
             Windows service runs. On a machine where Core is native, `embarch-core install` / \
             `embarch-core update` already do this directly."
        );
        return EXIT_FAILURE;
    }

    if restore_service {
        return restore_service_cmd(service).await;
    }

    let saved = state::load();
    let resolution = match resolve_plan(
        source_root.as_deref(),
        windows_root.as_deref(),
        cargo_exe.as_deref(),
        service.as_deref(),
        &saved,
        locate::windows_core_service_binary_path(),
        probe_windows_cargo_exe(),
        cwd_repo_parent(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("deploy-core: {e}");
            return EXIT_FAILURE;
        }
    };
    let plan = &resolution.plan;
    let bind = locate::windows_core_service_bind_address();
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
            eprintln!("deploy-core: {} isn't a directory", from.display());
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
                eprintln!("deploy-core: rsync of {crate_name} failed ({s})");
                return EXIT_FAILURE;
            }
            Err(e) => {
                eprintln!("deploy-core: couldn't run rsync: {e}");
                return EXIT_FAILURE;
            }
        }
    }

    println!("building natively (this is the slow part)");
    let core_dir = plan.windows_root.join("embarch-core");
    // Decision 57: the copy has no `.git`, so carry the Linux checkout's
    // commit across, or the service's `--version` says `(commit unknown)`.
    let stamp = checkout_stamp(&plan.source_root.join("embarch-core"));
    let status = std::process::Command::new(&plan.cargo_exe)
        .args(["build", "--release"])
        .current_dir(&core_dir)
        .envs(stamp_env(stamp.as_ref(), std::env::var("WSLENV").ok().as_deref()))
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("deploy-core: cargo build failed ({s})");
            return EXIT_FAILURE;
        }
        Err(e) => {
            eprintln!("deploy-core: couldn't run {}: {e}", plan.cargo_exe.display());
            return EXIT_FAILURE;
        }
    }

    let built = plan.built_exe();
    let built_digest = match hash_file(&built) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("deploy-core: no build output at {}: {e}", built.display());
            return EXIT_FAILURE;
        }
    };
    // A same-length note used to gate on length here too, but length is
    // exactly the signal decision 32's amendment retired — a same-size
    // rebuild is the common case, not a corner case, so it is not worth
    // printing on its own. The digest comparison below is the real check.

    // --- beside the service, never over it (decision 68) ------------------
    let Some(local_appdata) = windows_env_var_checked("LOCALAPPDATA") else {
        eprintln!("deploy-core: couldn't read %LOCALAPPDATA% from Windows (needs `cmd.exe`)");
        return EXIT_FAILURE;
    };
    let layout = deploy_dev::dev_layout(&local_appdata);
    let host = RealHost { built: built.clone(), layout: layout.clone() };
    if host.dest_wsl().is_none() {
        eprintln!("deploy-core: couldn't translate {} to a WSL path", layout.exe);
        return EXIT_FAILURE;
    }

    let service_state = locate::windows_core_service_state();
    let service_running = service_state == Some(locate::WindowsServiceState::Running);
    if let (Some(_), Some(false)) = (service_state, locate::windows_core_service_is_release_install()) {
        println!(
            "deploy-core: the registered service is a source install and is no longer updated by \
             this command; `embarch install-core` installs one from a signed release."
        );
    }

    if print_script && service_running {
        // Decision 7's posture: the only elevated step is stopping the service.
        let script = deploy_dev::stop_service_script(&plan.service, &host.win_log());
        match host.write_script("embarch-deploy-core-stop.ps1", &script) {
            Ok(win_script) => println!(
                "deploy-core: the service is running. Stop it with the one elevated step:\n  \
                 powershell -NoProfile -Command \"Start-Process powershell -Verb RunAs -Wait \
                 -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{win_script}'\"\n\
                 then re-run `deploy-core` (it will install the development Core and verify it)."
            ),
            Err(e) => {
                eprintln!("deploy-core: {e}");
                return EXIT_FAILURE;
            }
        }
        return 0;
    }

    if service_running {
        println!("elevating to stop {} (one UAC prompt — decline it and nothing changes)", plan.service);
    }
    let api = RealCore;
    let saved_pid = saved.deploy_dev_core_pid;
    let inputs = deploy_dev::InstallInputs {
        layout: &layout,
        service: &plan.service,
        service_running,
        bind: bind.as_deref(),
        built: built_digest,
        recorded_pid: saved_pid,
        cancel_run,
        waits: DEPLOY_WAITS,
        elevated_log: &host.win_log(),
    };
    let pid = match deploy_dev::install_development(&api, &host, &inputs).await {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("deploy-core: FAILED. {e}");
            return EXIT_FAILURE;
        }
    };
    println!(
        "deploy-core: landed. The development Core (PID {pid}) runs the build, and /status reports \
         `development` with its hash. `embarch deploy-core --restore-service` brings the service back."
    );

    // Remembered only after a deploy that actually worked, so a wrong
    // `--windows-root` isn't persisted for the next run to inherit.
    let mut saved = saved;
    saved.deploy_source_root = Some(plan.source_root.clone());
    saved.deploy_windows_root = Some(plan.windows_root.clone());
    saved.deploy_cargo_exe = Some(plan.cargo_exe.clone());
    saved.deploy_dev_core_pid = Some(pid);
    if let Err(e) = state::save(&saved) {
        println!("  (couldn't save these paths for next time: {e})");
    }

    println!(
        "  next: if the wire schema moved, `flash_dev_bench` + `reset_dev_bench`, then check \
         GET /dev-bench/hello reports compatible: true"
    );
    0
}

/// `deploy-core --restore-service`: stop the development Core by its recorded
/// PID, start the service, wait for `/status` to read `service` with a key
/// matching `core-fingerprint`.
async fn restore_service_cmd(service: Option<String>) -> i32 {
    let service = service.unwrap_or_else(|| locate::WINDOWS_CORE_SERVICE_LABEL.to_string());
    let Some(local_appdata) = windows_env_var_checked("LOCALAPPDATA") else {
        eprintln!("deploy-core: couldn't read %LOCALAPPDATA% from Windows (needs `cmd.exe`)");
        return EXIT_FAILURE;
    };
    let layout = deploy_dev::dev_layout(&local_appdata);
    let Some(data_dir) = crate::setup::data_dir_for(embarch_topology::software::TopologyClass::WslHost, false) else {
        return EXIT_FAILURE;
    };
    let fingerprint = match std::fs::read_to_string(data_dir.join(crate::agent_run::FINGERPRINT_FILE)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "deploy-core: no core-fingerprint in {} ({e}) — without it the restored service \
                 cannot be told from any other Core",
                data_dir.display()
            );
            return EXIT_FAILURE;
        }
    };
    let host = RealHost { built: PathBuf::new(), layout: layout.clone() };
    let mut saved = state::load();
    println!("elevating to start {service} (one UAC prompt)");
    match deploy_dev::restore_service(
        &RealCore,
        &host,
        &layout,
        &service,
        saved.deploy_dev_core_pid,
        &fingerprint,
        DEPLOY_WAITS,
        &host.win_log(),
    )
    .await
    {
        Ok(()) => {
            saved.deploy_dev_core_pid = None;
            let _ = state::save(&saved);
            println!("deploy-core: {service} is back; /status reads `service` with the recorded key");
            0
        }
        Err(e) => {
            eprintln!("deploy-core: FAILED to restore the service. {e}");
            EXIT_FAILURE
        }
    }
}

const DEPLOY_WAITS: deploy_dev::Waits = deploy_dev::Waits { attempts: 40, interval: std::time::Duration::from_millis(500) };

/// Core's HTTP face, resolved fresh each call: the process on the port changes
/// during a deploy, and so can its token.
struct RealCore;

impl RealCore {
    async fn target(&self) -> Result<(String, String), String> {
        let resolved =
            embarch_topology::software::resolve_software_topology(embarch_topology::software::DEFAULT_CORE_PORT, None, None).await;
        let base = resolved.base_url().ok_or("no Core answered on any candidate address")?.to_string();
        let token = embarch_core_client::token_discovery::resolve_token(None, None).map_err(|e| format!("{e:#}"))?;
        Ok((base, token))
    }
}

impl deploy_dev::CoreApi for RealCore {
    async fn status(&self) -> Result<deploy_dev::StatusView, String> {
        let (base, token) = self.target().await?;
        let (code, body) =
            crate::doctor::authed_get(&base, "/status", &token, crate::doctor::DEVICE_SCAN_GET_TIMEOUT).await?;
        if code != 200 {
            return Err(format!("/status answered {code}"));
        }
        deploy_dev::parse_status(&body)
    }

    async fn cancel_study(&self, id: &str) -> Result<(), String> {
        let (base, token) = self.target().await?;
        let url = format!("{}/study/{id}/cancel", base.trim_end_matches('/'));
        let r = reqwest::Client::new()
            .post(&url)
            .bearer_auth(token)
            .timeout(crate::doctor::DEVICE_SCAN_GET_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        // 202 cancelling; 409 means it already ended, which is what we wanted.
        match r.status().as_u16() {
            202 | 409 => Ok(()),
            c => Err(format!("POST {url} answered {c}")),
        }
    }
}

/// The Windows side, through `powershell.exe` and the `/mnt` mount.
struct RealHost {
    built: PathBuf,
    layout: deploy_dev::DevLayout,
}

impl RealHost {
    fn dest_wsl(&self) -> Option<PathBuf> {
        wsl_path(&self.layout.exe)
    }

    fn win_log(&self) -> String {
        windows_temp_dir()
            .and_then(|d| to_windows_path(&d.join("embarch-deploy-core.log")))
            .unwrap_or_default()
    }

    fn write_script(&self, name: &str, script: &str) -> Result<String, String> {
        let dir = windows_temp_dir().ok_or("couldn't find a Windows-visible temp directory (needs `cmd.exe` + `wslpath`)")?;
        let path = dir.join(name);
        std::fs::write(&path, script).map_err(|e| format!("couldn't write {}: {e}", path.display()))?;
        to_windows_path(&path).ok_or_else(|| "couldn't translate the script path to Windows form".to_string())
    }
}

impl deploy_dev::Host for RealHost {
    fn run_script(&self, script: &str, elevated: bool) -> Result<String, String> {
        let win_script = self.write_script(if elevated { "embarch-deploy-core-elevated.ps1" } else { "embarch-deploy-core-user.ps1" }, script)?;
        if !elevated {
            let out = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", &win_script])
                .output()
                .map_err(|e| format!("couldn't launch powershell.exe: {e}"))?;
            return if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            } else {
                Err(format!("script failed: {}", String::from_utf8_lossy(&out.stderr)))
            };
        }
        let log = windows_temp_dir().map(|d| d.join("embarch-deploy-core.log")).ok_or("no temp dir")?;
        let _ = std::fs::remove_file(&log);
        std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Start-Process powershell -Verb RunAs -Wait -ArgumentList \
                     '-NoProfile','-ExecutionPolicy','Bypass','-File','{win_script}'"
                ),
            ])
            .status()
            .map_err(|e| format!("couldn't launch powershell.exe: {e}"))?;
        // The transcript is the only account of what the elevated child did;
        // a missing one is the UAC prompt that never rendered (§4a).
        let text = std::fs::read_to_string(&log).map_err(|_| {
            format!(
                "no transcript at {} — the elevated child never started, which is what a UAC \
                 prompt that never rendered looks like. Re-run, or use --print-script",
                log.display()
            )
        })?;
        let text = text.replace('\u{0}', "");
        println!("--- elevated transcript ---\n{}\n---------------------------", text.trim_end());
        if text.contains("FAILED:") {
            return Err("the elevated step reported FAILED (see the transcript)".to_string());
        }
        Ok(text)
    }

    fn install_copy(&self) -> Result<[u8; 32], String> {
        let dest = self.dest_wsl().ok_or("couldn't translate the development exe path")?;
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("couldn't create {}: {e}", dir.display()))?;
        }
        std::fs::copy(&self.built, &dest).map_err(|e| format!("couldn't copy the build to {}: {e}", dest.display()))?;
        hash_file(&dest).map_err(|e| format!("couldn't read {} back: {e}", dest.display()))
    }
}

fn windows_env_var_checked(name: &str) -> Option<String> {
    windows_env_var(name)
}

#[cfg(not(unix))]
fn windows_env_var(_name: &str) -> Option<String> {
    None
}

#[cfg(not(unix))]
fn wsl_path(_win: &str) -> Option<PathBuf> {
    None
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

/// The Linux checkout's commit and dirty flag, for the Windows build
/// (decision 57). The rsync above excludes `.git`, so `cargo.exe` building
/// the copy would stamp `unknown`. `None` when git cannot say, and the build
/// then does exactly that.
fn checkout_stamp(dir: &Path) -> Option<(String, bool)> {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .arg("--no-optional-locks")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let commit = git(&["rev-parse", "HEAD"])?;
    let changes = git(&["status", "--porcelain", "--untracked-files=no"])?;
    Some((commit, !changes.is_empty()))
}

/// The environment `cargo.exe` gets so its `build.rs` stamps the Linux
/// commit. A Win32 process started from WSL sees only the variables `WSLENV`
/// names, so the two are appended to whatever `WSLENV` already lists.
fn stamp_env(stamp: Option<&(String, bool)>, wslenv: Option<&str>) -> Vec<(String, String)> {
    let Some((commit, dirty)) = stamp else {
        return Vec::new();
    };
    let shared = "EMBARCH_BUILD_COMMIT:EMBARCH_BUILD_DIRTY";
    let wslenv = match wslenv.map(str::trim).filter(|w| !w.is_empty()) {
        Some(existing) => format!("{existing}:{shared}"),
        None => shared.to_string(),
    };
    vec![
        ("EMBARCH_BUILD_COMMIT".to_string(), commit.clone()),
        ("EMBARCH_BUILD_DIRTY".to_string(), if *dirty { "1" } else { "0" }.to_string()),
        ("WSLENV".to_string(), wslenv),
    ]
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

    /// Decision 57: the Windows build gets the Linux commit, shared through
    /// `WSLENV` without dropping what it already lists.
    #[test]
    fn stamp_env_shares_the_commit_through_wslenv() {
        assert!(stamp_env(None, Some("FOO")).is_empty());
        let stamp = ("744b94be2b96".to_string(), true);
        let env = stamp_env(Some(&stamp), Some("FOO/p"));
        assert_eq!(
            env,
            vec![
                ("EMBARCH_BUILD_COMMIT".to_string(), "744b94be2b96".to_string()),
                ("EMBARCH_BUILD_DIRTY".to_string(), "1".to_string()),
                ("WSLENV".to_string(), "FOO/p:EMBARCH_BUILD_COMMIT:EMBARCH_BUILD_DIRTY".to_string()),
            ]
        );
        let clean = ("abc".to_string(), false);
        let env = stamp_env(Some(&clean), Some("  "));
        assert_eq!(env[1].1, "0");
        assert_eq!(env[2].1, "EMBARCH_BUILD_COMMIT:EMBARCH_BUILD_DIRTY");
    }

    fn state_with(windows_root: Option<&str>) -> state::State {
        state::State {
            deploy_windows_root: windows_root.map(PathBuf::from),
            ..Default::default()
        }
    }

    /// The ordering invariant, asserted rather than left to a comment:
    /// `embarch-core` depends on all three others by `path`, so a run that
    /// copied it first and died would leave a tree that builds cleanly and
    /// is wrong.
    #[test]
    fn core_is_synced_last() {
        assert_eq!(*SYNC_CRATES.last().unwrap(), "embarch-core");
        assert!(SYNC_CRATES.contains(&"embarch-study-designer"));
        assert!(SYNC_CRATES.contains(&"embarch-topology"));
        assert!(SYNC_CRATES.contains(&"embarch-smp"));
    }

    #[test]
    fn an_unresolvable_windows_root_names_its_flag_rather_than_guessing() {
        let err = resolve_plan(
            Some(Path::new("/src")),
            None,
            Some(Path::new("/mnt/c/cargo.exe")),
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
            None,
            &state_with(Some("/mnt/c/win")),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(resolution.plan.windows_root, PathBuf::from("/mnt/c/other"));
    }

    /// The service's binary is read from its registration, for the plan only
    /// (decision 68); it is never an input and nothing writes it.
    #[test]
    fn the_service_binary_comes_from_the_probe_and_is_read_only() {
        let resolution = resolve_plan(
            Some(Path::new("/src")),
            Some(Path::new("/mnt/c/win")),
            Some(Path::new("/mnt/c/cargo.exe")),
            None,
            &state_with(Some("/mnt/c/win")),
            Some(PathBuf::from("/mnt/c/Users/x/embarch-setup/embarch-core.exe")),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            resolution.plan.service_binary,
            Some(PathBuf::from("/mnt/c/Users/x/embarch-setup/embarch-core.exe"))
        );
        assert!(resolution.plan.render().contains("never written"));
        assert_eq!(resolution.plan.service, locate::WINDOWS_CORE_SERVICE_LABEL);
    }

    #[test]
    fn the_build_output_is_where_cargo_puts_it() {
        let plan = Plan {
            source_root: PathBuf::from("/src"),
            windows_root: PathBuf::from("/mnt/c/win"),
            cargo_exe: PathBuf::from("/mnt/c/cargo.exe"),
            service_binary: None,
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
    fn the_wire_schema_version_is_read_out_of_the_crate() {
        let source = "/// docs\npub const DEV_BENCH_WIRE_SCHEMA_VERSION: u32 = 12;\n";
        assert_eq!(parse_wire_schema_version(source), Some(12));
        assert_eq!(parse_wire_schema_version("nothing here"), None);
    }
}
