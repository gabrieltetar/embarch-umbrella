//! `setup`, `up`, and `down` — everything that acts on Core rather than just
//! looking at it.
//!
//! All three share one problem (where is `embarch-core`, and can I control it
//! from here?), which is why they live together. See decisions 3, 4, 7.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

use embarch_topology::software::TopologyClass;

use crate::desk;
use crate::env;
use crate::install;
use crate::locate::{self, FoundBy, Located};
use crate::state::{self, State};

/// Where `embarch-core` writes its machine-wide token file, as seen from
/// here (embarch-token.md §3.1). `None` for a `Remote` class, and also when
/// the data directory cannot be resolved (see [`data_dir_for`]).
///
/// This is an existence check only, not token discovery — reading and
/// validating the value is `doctor`'s job (embarch-umbrella spec.md §5), and needs
/// the discovery logic `embarch-api` already has.
pub fn token_path_for(class: TopologyClass) -> Option<PathBuf> {
    Some(data_dir_for(class)?.join("token"))
}

/// `embarch-core`'s machine-wide data directory, as seen from here — the one
/// path convention that holds every artefact Core owns: the token,
/// `study_results/`, `logs/` and `embarch-topology`'s `enrollment.toml`
/// ([embarch-core/interfaces/constants.md](../../embarch-doc/embarch-core/interfaces/constants.md)).
///
/// **Resolved by `embarch-topology`'s `machine_data_dir`**, the one resolver
/// for every class (its decision 52): `Local` is this machine's own
/// directory, `WslHost` is the Windows host's real `%ProgramData%` reached
/// through `/mnt`, and `Remote` has no path — no shared filesystem, so the
/// token has to be copied by hand (embarch-umbrella spec.md §6). A resolver
/// error reads as `None` here for the callers that can only act on a path;
/// `doctor`'s check 16 calls the resolver itself and reports the error.
///
/// **Class-aware rather than host-aware**, which is why check 16 uses this
/// and not `embarch_core_client::token_discovery`'s discovery: a `Remote`
/// Core's data directory is not on this filesystem at all.
pub fn data_dir_for(class: TopologyClass) -> Option<PathBuf> {
    embarch_topology::machine_data_dir(class).ok().flatten()
}

/// What `setup` concluded it should do, before doing any of it.
struct Plan {
    class: TopologyClass,
    host: Option<String>,
    core: Option<Located>,
    /// Core answered a probe before we changed anything.
    already_running: bool,
}

async fn make_plan(host: Option<&str>, port: u16) -> Plan {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();
    let core = locate::locate_core(saved.core_exe.as_deref(), under_wsl2);

    // If Core is already up, it has already answered the question
    // (`embarch-topology` decisions 2, 3: live, in-process, every
    // call — no local mirrored topology.rs/env.rs/probe.rs any more).
    let resolved = embarch_topology::software::resolve_software_topology(port, host, None).await;

    if let Some(found) = resolved.winner {
        return Plan {
            class: found.class,
            host: host.map(str::to_string).or(saved.host),
            core,
            already_running: true,
        };
    }

    // Nothing running yet, so infer where Core *should* live.
    let class = infer_class(host, core.as_ref());

    Plan {
        class,
        host: host.map(str::to_string).or(saved.host),
        core,
        already_running: false,
    }
}

/// Infer where Core belongs when nothing has answered a probe yet. Under
/// WSL2 the whole point of the split is that the probe is a Windows USB
/// device, so a locatable Windows-side binary means Core belongs there — not
/// in the guest. Shared with `doctor` (embarch-umbrella spec.md §5) so the two
/// commands never disagree about which class an unreachable Core "should" be.
pub fn infer_class(host: Option<&str>, core: Option<&Located>) -> TopologyClass {
    if host.is_some() {
        TopologyClass::Remote
    } else if core.is_some_and(|c| c.windows_exe_from_wsl2) {
        TopologyClass::WslHost
    } else {
        TopologyClass::Local
    }
}

/// What `setup` says on a `local` machine where Core is not running: it
/// registers nothing (decision 71), in a dry run and a real one alike.
fn local_registration_note(dry_run: bool) -> String {
    format!(
        "{}embarch-core is not registered as a service by `setup`; nothing was registered. \
         Register it with {}.",
        if dry_run { "Would not register: " } else { "" },
        registration_route(false)
    )
}

/// Where a first registration of Core's service comes from (decision 71):
/// `embarch install-core <release>`, elevated, on the machine that will run
/// Core. `core_on_windows` is that machine, not the one this binary runs on:
/// a `wsl-host` setup names the Windows-side command. macOS has no such half.
pub(crate) fn registration_route(core_on_windows: bool) -> String {
    if core_on_windows {
        "`embarch install-core <release>` in an elevated Windows shell".to_string()
    } else if cfg!(target_os = "linux") {
        "`sudo embarch install-core <release>`".to_string()
    } else {
        "not built on this platform: `embarch install-core` registers Core on Windows and Linux only"
            .to_string()
    }
}

/// How to change the address of a registration that exists (decision 71):
/// the *installed* binary, because `install --service` refuses any binary the
/// release record does not list by SHA-256 — the copy beside `embarch` is not.
pub(crate) fn rebind_route(addr: &str) -> String {
    format!(
        "`install --service --bind {addr}` from the installed binary (`%ProgramFiles%\\EmbArch\\core\\<version>\\embarch-core.exe` \
         on Windows, `/opt/embarch/core/<version>/embarch-core` on Linux), elevated"
    )
}

/// Run a command, inheriting stdio so the user sees whatever it prints.
fn run(program: &std::path::Path, args: &[&str]) -> Result<bool> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("could not run {}", program.display()))?;
    Ok(status.success())
}

/// Every location a run of `setup` may write to, resolved from the
/// environment in one place. Passed down rather than read at each write, so
/// `--dry-run`'s description and the real run's writes come from the same
/// four paths, and so the whole apply step can be pointed at a sandbox in a
/// test.
struct Locations {
    /// Directory holding the running `embarch` — the unpacked release
    /// archive, and decision 28's only install source.
    source_dir: Option<PathBuf>,
    /// Decision 28's canonical per-user install directory.
    bin_dir: Option<PathBuf>,
    /// `$HOME`, for the one sourcing line decision 28 adds to whichever
    /// shell rc files already exist. Unused on Windows, where `PATH` lives
    /// in the registry instead.
    home: Option<PathBuf>,
    /// Where the concluded topology is recorded (`state.rs`).
    state_path: Option<PathBuf>,
    /// The desk steps' inputs (decision 58), resolved here with everything
    /// else so a test hands in `None` and a mock rather than reaching the
    /// real `embarch-desk` and `claude` on the machine running it.
    desk: Option<Located>,
    claude: Option<PathBuf>,
    runner: Box<dyn desk::Runner>,
}

impl Locations {
    fn from_env() -> Self {
        Locations {
            source_dir: std::env::current_exe().ok().and_then(|e| e.parent().map(std::path::Path::to_path_buf)),
            bin_dir: install::canonical_bin_dir().ok(),
            home: std::env::var_os("HOME").map(PathBuf::from),
            state_path: state::state_path().ok(),
            desk: locate::locate_desk(),
            claude: locate::locate_claude(),
            runner: Box::new(desk::Real),
        }
    }
}

/// Decision 28's install — copy this platform's binaries to the canonical
/// location and make sure `PATH` includes it — or, under `--dry-run`, the
/// same plan printed and not taken (decision 21). Printed regardless of
/// outcome, since a failure here (e.g. no writable `HOME`/`LOCALAPPDATA`)
/// shouldn't silently abort the rest of `setup`.
///
/// Returns the destinations that hold (or, dry, would hold) a suite binary
/// afterwards — what the `local` fallback below needs.
fn install_this_platform(loc: &Locations, dry_run: bool) -> Vec<PathBuf> {
    let (Some(source_dir), Some(bin_dir)) = (&loc.source_dir, &loc.bin_dir) else {
        println!(
            "\nCould not work out where to install the suite binaries (no LOCALAPPDATA, \
             XDG_DATA_HOME, or HOME set) — skipping the install step."
        );
        return Vec::new();
    };

    if dry_run {
        let plan = install::plan_install(source_dir, bin_dir, loc.home.as_deref());
        println!("\n{}", plan.render());
        return plan.destinations();
    }

    match install::install_into(source_dir, bin_dir, loc.home.as_deref()) {
        Ok(report) => {
            if report.copied.is_empty() {
                println!("\nNothing to install: no suite binaries found next to this one.");
            } else {
                println!("\nInstalled to {}:", report.bin_dir.display());
                for path in &report.copied {
                    println!("  {}", path.display());
                }
                if report.path_changed {
                    println!("Added {} to your PATH (new shells will see it).", report.bin_dir.display());
                } else {
                    println!("PATH already includes {}.", report.bin_dir.display());
                }
            }
            report.copied
        }
        Err(e) => {
            println!("\nCould not install to the canonical location: {e:#}");
            Vec::new()
        }
    }
}

pub async fn setup(host: Option<&str>, port: u16, dev_bench_repo: Option<&std::path::Path>, dry_run: bool) -> i32 {
    let loc = Locations::from_env();
    let previously_saved = state::load();
    // Every detection step runs identically in both modes — that, not the
    // early return, is what decision 21 actually asks for: one detection
    // path, described or executed, never a second implementation of it.
    let plan = make_plan(host, port).await;
    apply_plan(plan, previously_saved, dev_bench_repo, &loc, dry_run)
}

/// Everything `setup` does once detection has concluded. The single place
/// any machine change happens, and the only argument that decides whether
/// one does is `dry_run`.
fn apply_plan(
    mut plan: Plan,
    previously_saved: State,
    dev_bench_repo: Option<&std::path::Path>,
    loc: &Locations,
    dry_run: bool,
) -> i32 {
    if dry_run {
        println!(
            "embarch setup --dry-run: every detection step below really ran; nothing below is done."
        );
    }

    let installed = install_this_platform(loc, dry_run);

    // locate_core's PATH lookup can't see a PATH change this same run just
    // made (a running process's own environment doesn't retroactively
    // update) — so for a same-machine Core, fall back to the copy this run
    // itself just installed rather than reporting "not found" on a machine
    // that's actually now fully set up. Not applicable to wsl-host/remote:
    // those need the real Windows-side or remote binary, not this local copy.
    if plan.core.is_none() && plan.class == TopologyClass::Local {
        let candidate = loc.bin_dir.as_ref().map(|d| d.join(locate::native_name("embarch-core")));
        if let Some(candidate) = candidate.filter(|c| installed.contains(c)) {
            let found_by = if dry_run { FoundBy::PendingInstall } else { FoundBy::JustInstalled };
            plan.core = Some(Located { path: candidate, found_by, windows_exe_from_wsl2: false });
        }
    }

    println!("\nTopology: {}", plan.class.as_str());
    match &plan.core {
        Some(c) => println!("embarch-core: {} ({})", c.path.display(), c.found_by.as_str()),
        None => println!("embarch-core: not found"),
    }

    // `embarch-core` decision 6's amendment: Core's own default
    // is loopback-only; widening it for the one topology that actually needs
    // a wider address is this call's job, not something a human has to
    // remember to type. Computed once and baked into every `install`
    // invocation below, whether run directly or printed for a human to paste
    // into an elevated shell — an installed service's `--bind` is part of
    // its registered start command (`embarch-core install`'s own doc
    // comment), so this only has to happen at install time, not on every
    // subsequent start.
    let bind_addr = embarch_topology::software::recommended_bind_address(plan.class);

    let mut install_failed = false;
    if plan.already_running {
        println!("embarch-core is already running — nothing to install.");
    } else {
        match (plan.class, &plan.core) {
            (TopologyClass::Remote, _) => {
                println!(
                    "\nCore is on another machine, and `setup` registers nothing there. On that \
                     machine, elevated: `embarch install-core <release>` (Windows and Linux; macOS \
                     has no such route yet). It binds loopback, so then widen it with\n  {}\n\
                     Then copy its token file's contents to this machine:\n  \
                     export EMBARCH_TOKEN=<contents of /var/lib/embarch/token on that machine>",
                    rebind_route(bind_addr)
                );
            }
            (TopologyClass::WslHost, Some(_)) => {
                // Cannot be done from here: controlling a Windows service
                // needs an elevated Windows shell, and umbrella never tries
                // to obtain one (decision 7). Identical in both
                // modes — it was already only ever a printed instruction.
                println!(
                    "\nCore belongs on the Windows side, and `setup` registers nothing there. \
                     Register it with {}. That binds loopback, which the WSL2 guest cannot \
                     reach, so then widen it with\n  {}",
                    registration_route(true),
                    rebind_route(bind_addr)
                );
            }
            // Decision 71: a plain `embarch-core install` registers nothing
            // (core decision 157), so `setup` neither runs it nor reports a
            // registration. The route that makes one needs a signed release,
            // which `setup` does not hold.
            (TopologyClass::Local, Some(_)) => {
                println!("\n{}", local_registration_note(dry_run));
                if !dry_run {
                    install_failed = true;
                }
            }
            (_, None) => {
                eprintln!(
                    "\nCan't continue without embarch-core. It ships in the same archive as this \
                     binary — unpack them into one directory, or point EMBARCH_CORE_EXE at it."
                );
                // Said even here: a dry run that stops early has still done
                // nothing, and leaving that unsaid is exactly the doubt
                // decision 21 exists to remove.
                if dry_run {
                    eprintln!("\n--dry-run: nothing above was done.");
                }
                return 1;
            }
        }
    }

    // The token file is Core's to create on first start; all we can usefully
    // say is whether it's there yet. A read either way, so `--dry-run`
    // reports exactly what a real run would.
    if let Some(token) = token_path_for(plan.class) {
        if token.exists() {
            println!("\nToken file: {} (present)", token.display());
        } else {
            println!(
                "\nToken file: {} (not yet — embarch-core creates it the first time it starts)",
                token.display()
            );
        }
    }

    // Decision 58: the desk is optional, so it comes after Core and never
    // stops the run; a failed step is reported and makes the exit non-zero.
    let desk_steps = desk::install(
        loc.desk.as_ref(),
        loc.claude.as_deref(),
        cfg!(target_os = "linux"),
        dry_run,
        loc.runner.as_ref(),
    );
    if desk::report("embarch-desk:", &desk_steps, dry_run) {
        install_failed = true;
    }

    let dev_bench_repo_path = dev_bench_repo
        .map(std::path::Path::to_path_buf)
        .or(previously_saved.dev_bench_repo_path);
    if let Some(p) = &dev_bench_repo_path {
        println!("\ndev-bench checkout for `doctor` check 13: {}", p.display());
    }

    let saved = State {
        schema_version: state::STATE_SCHEMA_VERSION,
        topology: Some(plan.class.as_str().to_string()),
        // Sticky only for `remote` (decision 51,
        // `embarch-umbrella/decisions/sticky-host.md`): a `local`/`wsl-host`
        // conclusion clears whatever `--host` a previous run recorded, so a
        // stale value can't outlive the run that gave it and steer a later
        // one into a wrong `Remote` inference.
        host: if plan.class == TopologyClass::Remote { plan.host } else { None },
        core_exe: plan
            .core
            .as_ref()
            .filter(|c| c.windows_exe_from_wsl2)
            .map(|c| c.path.clone()),
        dev_bench_repo_path,
        // `setup` is about the topology; `deploy-core`'s own paths are its
        // own (decision 32), and it saves them itself. Carried
        // through rather than defaulted so a `setup` re-run doesn't wipe
        // what a deploy remembered.
        deploy_source_root: previously_saved.deploy_source_root,
        deploy_windows_root: previously_saved.deploy_windows_root,
        deploy_cargo_exe: previously_saved.deploy_cargo_exe,
        deploy_dev_core_pid: previously_saved.deploy_dev_core_pid,
        // `init`'s registry is its own (decision 65); carried through for the
        // same reason.
        registered_repos: previously_saved.registered_repos,
    };
    match (&loc.state_path, dry_run) {
        (Some(p), true) => println!(
            "\nWould record topology `{}` in {}",
            saved.topology.as_deref().unwrap_or("?"),
            p.display()
        ),
        (Some(p), false) => match state::save_to(p, &saved) {
            Ok(()) => println!("Saved topology to {}", p.display()),
            Err(e) => println!("Could not save state: {e:#}"),
        },
        (None, _) => println!(
            "Could not save state: no config directory (no APPDATA, XDG_CONFIG_HOME, or HOME set)"
        ),
    }

    if dry_run {
        println!("\n--dry-run: nothing above was done. Re-run without --dry-run to do it.");
    } else {
        println!("\nNext: `embarch status` to confirm, then `embarch init` in a firmware repo.");
    }
    // Decision 7's fallback: the exact command was printed, and the install
    // did not happen, so a chained `&&` must stop.
    if install_failed { 1 } else { 0 }
}

/// Reverse `setup`: stop and unregister the Core service (best-effort — a
/// `wsl-host`/`remote` Core can't be controlled from here, same constraint
/// `up`/`down` already have), remove the machine-wide token file, and undo
/// decision 28's install (canonical binaries + `PATH` additions).
pub fn uninstall() -> i32 {
    let mut failed: Vec<&str> = Vec::new();
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();
    let core = locate::locate_core(saved.core_exe.as_deref(), under_wsl2);

    match &core {
        Some(c) if !c.windows_exe_from_wsl2 => {
            println!("Stopping and uninstalling the embarch-core service...");
            match run(&c.path, &["uninstall"]) {
                Ok(true) => println!("Service uninstalled."),
                Ok(false) | Err(_) => {
                    failed.push("service uninstall");
                    eprintln!("Could not uninstall the service — this may need elevation:\n  sudo \"{}\" uninstall", c.path.display());
                }
            }
        }
        Some(c) => {
            println!(
                "Core is on the Windows side. In an **elevated Windows** shell, run:\n  \"{}\" uninstall",
                windows_display_path(&c.path)
            );
        }
        None => println!("embarch-core not found — skipping service uninstall."),
    }

    let class = saved.topology.as_deref().and_then(topology_class_from_str).unwrap_or(TopologyClass::Local);
    if let Some(token) = token_path_for(class) {
        match std::fs::remove_file(&token) {
            Ok(()) => println!("Removed token file: {}", token.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                failed.push("token removal");
                eprintln!("Could not remove token file {}: {e}", token.display());
            }
        }
    }

    // Before the install undo: the desk's unit names a binary that undo deletes.
    let desk_steps = desk::uninstall(
        locate::locate_desk().as_ref(),
        locate::locate_claude().as_deref(),
        cfg!(target_os = "linux"),
        &desk::Real,
    );
    if desk::report("embarch-desk:", &desk_steps, false) {
        failed.push("desk");
    }

    match install::uninstall() {
        Ok(()) => println!("Removed the canonical install directory and PATH additions."),
        Err(e) => {
            failed.push("install undo");
            eprintln!("Could not fully undo the install: {e:#}");
        }
    }

    uninstall_exit(&failed)
}

/// Exit status for `setup --uninstall` over the steps that were attempted and
/// failed: 0 when none did, otherwise 1 with a final line naming each, so
/// `embarch setup --uninstall && …` stops with Core still installed.
fn uninstall_exit(failed: &[&str]) -> i32 {
    if failed.is_empty() {
        return 0;
    }
    eprintln!("Uninstall incomplete — failed: {}.", failed.join(", "));
    1
}

pub fn topology_class_from_str(s: &str) -> Option<TopologyClass> {
    match s {
        "local" => Some(TopologyClass::Local),
        "wsl-host" => Some(TopologyClass::WslHost),
        "remote" => Some(TopologyClass::Remote),
        _ => None,
    }
}

/// `/mnt/c/foo/bar.exe` back into `C:\foo\bar.exe`, for a command the user
/// will paste into a Windows shell rather than a WSL2 one.
pub fn windows_display_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("/mnt/") {
        let mut chars = rest.chars();
        if let Some(drive) = chars.next() {
            let tail: String = chars.as_str().trim_start_matches('/').replace('/', "\\");
            return format!("{}:\\{}", drive.to_ascii_uppercase(), tail);
        }
    }
    s.to_string()
}

/// Decision 30's probe, plus the message it produces. Under WSL2 with
/// mirrored networking, a Windows-hosted Core and a guest-hosted Core both
/// answer at loopback, so `local` does not say *where* Core is — and
/// `up`/`down` have to know before deciding whether they can act or must
/// hand over to an elevated Windows shell. The probe resolves it in favour
/// of the thing that is actually installed.
///
/// `Some(message)` means: defer to the Windows service, print this, do not
/// touch the guest-side path. `None` means no Windows service was found —
/// behave exactly as before this existed.
fn defer_to_windows_service(under_wsl2: bool, saved: &State, verb: &str) -> Option<Deferral> {
    if !under_wsl2 {
        return None;
    }
    let state = locate::windows_core_service_state()?;
    let label = locate::WINDOWS_CORE_SERVICE_LABEL;

    // Already in the state being asked for: say so and stop. Printing how to
    // start an already-running service is the kind of message that trains
    // people to stop reading them.
    let already = match (verb, state) {
        ("start", locate::WindowsServiceState::Running) => Some("running"),
        ("stop", locate::WindowsServiceState::Installed) => Some("stopped"),
        _ => None,
    };
    if let Some(already) = already {
        return Some(Deferral {
            message: format!(
                "embarch-core is installed as a Windows service ({label}) and already {already} \
                 — that is the Core this machine uses. Nothing to do."
            ),
            satisfied: true,
        });
    }

    // Name the real exe if it can be found, since that is what the operator
    // has to type; fall back to the service label, which is always true even
    // when the binary isn't locatable from here.
    let how = match locate::locate_core(saved.core_exe.as_deref(), under_wsl2) {
        Some(core) if core.windows_exe_from_wsl2 => {
            format!("  \"{}\" {verb}", windows_display_path(&core.path))
        }
        _ => format!("  sc.exe {verb} {label}"),
    };

    Some(Deferral {
        message: format!(
            "embarch-core is installed as a Windows service ({label}) — that is the Core this \
             machine uses, so nothing here touches a guest-side one.\nTo {verb} it, in an \
             **elevated Windows** shell:\n{how}"
        ),
        satisfied: false,
    })
}

/// What [`defer_to_windows_service`] found: a message to print, and whether
/// the request is already satisfied (so `up`/`down` exit `0` rather than
/// reporting a failure they didn't have).
struct Deferral {
    message: String,
    satisfied: bool,
}

/// A Core on another machine can't be controlled from here — umbrella does
/// no remote orchestration at all, by design (decision 8). Say
/// so plainly rather than shelling out to a local binary that would start a
/// *second*, wrong Core.
fn refuse_if_remote(saved: &State, verb: &str) -> Option<String> {
    if saved.topology.as_deref() != Some("remote") {
        return None;
    }
    let where_ = saved
        .host
        .as_deref()
        .map(|h| format!(" on {h}"))
        .unwrap_or_default();
    // Phrased to avoid conjugating the verb — an earlier version built the
    // past participle by appending "ped" and produced "startped".
    Some(format!(
        "Core runs on another machine{where_}, so this can't {verb} it from here. \
         Run `embarch-core {verb}` on that machine instead."
    ))
}

/// Start Core. Prefers the installed service; never silently spawns a
/// detached process (decision 4).
pub fn up(foreground: bool) -> i32 {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();

    if let Some(msg) = refuse_if_remote(&saved, "start") {
        eprintln!("{msg}");
        return 1;
    }

    // Decision 30, and it has to come before `locate_core`: on a machine
    // where `setup` also installed a guest-side `embarch-core` on `PATH`,
    // resolution would find *that* first and start the wrong Core.
    //
    // `--foreground` is deliberately exempt. The probe settles an ambiguity
    // about which Core `up` should drive; `--foreground` is not a request to
    // drive a service at all, it is "run Core in this terminal," which is a
    // third thing and an explicit one. It warns and proceeds — the same
    // explicit-wins posture `EMBARCH_CORE_EXE` already has.
    match defer_to_windows_service(under_wsl2, &saved, "start") {
        Some(deferral) if !foreground => {
            if deferral.satisfied {
                println!("{}", deferral.message);
                return 0;
            }
            eprintln!("{}", deferral.message);
            return 1;
        }
        Some(_) => eprintln!(
            "Warning: embarch-core is installed as a Windows service ({}) on this machine. \
             Running one in the foreground here starts a second, separate Core.",
            locate::WINDOWS_CORE_SERVICE_LABEL
        ),
        None => {}
    }

    let Some(core) = locate::locate_core(saved.core_exe.as_deref(), under_wsl2) else {
        eprintln!("embarch-core not found. Run `embarch setup`, or set EMBARCH_CORE_EXE.");
        return 1;
    };

    if core.windows_exe_from_wsl2 {
        eprintln!(
            "Core is on the Windows side and starting a Windows service needs elevation, which \
             this cannot obtain from WSL2. In an **elevated Windows** shell, run:\n  \"{}\" start",
            windows_display_path(&core.path)
        );
        return 1;
    }

    if foreground {
        println!("Running embarch-core in the foreground — Ctrl-C to stop it.");
        return match run(&core.path, &["run"]) {
            Ok(true) => 0,
            _ => 1,
        };
    }

    match run(&core.path, &["start"]) {
        Ok(true) => {
            println!("embarch-core service started.");
            0
        }
        _ => {
            // Deliberately not falling through to a detached `run`: a Core
            // that dies with the shell that started it is a worse outcome
            // than a clear message (decision 4).
            eprintln!(
                "Could not start the service. Either it isn't installed yet:\n  \
                 {}\n\
                 or start it with elevation:\n  sudo \"{}\" start\n\
                 or run Core in this terminal instead:\n  embarch up --foreground",
                registration_route(false),
                core.path.display()
            );
            1
        }
    }
}

/// `down` refuses while Core's `/status` shows a study in flight, unless
/// `cancel_run`, which cancels it first and waits for Core to say it is idle
/// (`deploy_dev::clear_study`, as `deploy-core --cancel-run` does). A Core
/// that does not answer has no study to protect: that is `Ok`, not a refusal
/// (decision 72).
pub async fn study_guard<A: crate::deploy_dev::CoreApi>(
    api: &A,
    cancel_run: bool,
    waits: crate::deploy_dev::Waits,
) -> Result<(), String> {
    let Ok(status) = api.status().await else {
        return Ok(());
    };
    if let Some(id) = &status.study_in_flight {
        if !cancel_run {
            return Err(format!(
                "study {id} is in flight; stopping Core now would end it. Cancel it, or re-run \
                 `embarch down --cancel-run`"
            ));
        }
    }
    crate::deploy_dev::clear_study(api, cancel_run, waits).await
}

pub async fn down(cancel_run: bool) -> i32 {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();

    if let Some(msg) = refuse_if_remote(&saved, "stop") {
        eprintln!("{msg}");
        return 1;
    }

    if let Err(e) = study_guard(&crate::deploy::RealCore, cancel_run, crate::deploy::DEPLOY_WAITS).await {
        eprintln!("{e}");
        return 1;
    }

    // Decision 30 names `up`; applying it to `down` too is an extension
    // beyond its text, taken deliberately. The ambiguity is identical, and
    // the asymmetry would be the dangerous half: `up` starting the wrong
    // Core fails on a port bind, `down` stopping the wrong one succeeds
    // quietly and leaves the real Core running.
    if let Some(deferral) = defer_to_windows_service(under_wsl2, &saved, "stop") {
        if deferral.satisfied {
            println!("{}", deferral.message);
            return 0;
        }
        eprintln!("{}", deferral.message);
        return 1;
    }

    let Some(core) = locate::locate_core(saved.core_exe.as_deref(), under_wsl2) else {
        eprintln!("embarch-core not found. Run `embarch setup`, or set EMBARCH_CORE_EXE.");
        return 1;
    };

    if core.windows_exe_from_wsl2 {
        eprintln!(
            "In an **elevated Windows** shell, run:\n  \"{}\" stop",
            windows_display_path(&core.path)
        );
        return 1;
    }

    match run(&core.path, &["stop"]) {
        Ok(true) => {
            println!("embarch-core service stopped.");
            0
        }
        _ => {
            eprintln!(
                "Could not stop the service — it may not be running, or this needs elevation:\n  \
                 sudo \"{}\" stop",
                core.path.display()
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deploy_dev::{CoreApi, StatusView, Waits};
    use std::cell::RefCell;
    use std::time::Duration;

    const WAITS: Waits = Waits { attempts: 3, interval: Duration::from_millis(1) };

    /// Answers `/status` from a queue (the last answer repeats); `None` is a
    /// Core that does not answer.
    struct FakeCore {
        statuses: RefCell<Vec<Option<StatusView>>>,
        cancelled: RefCell<Vec<String>>,
    }

    impl FakeCore {
        fn with(statuses: Vec<Option<StatusView>>) -> Self {
            Self { statuses: RefCell::new(statuses), cancelled: RefCell::default() }
        }
    }

    impl CoreApi for FakeCore {
        async fn status(&self) -> Result<StatusView, String> {
            let mut q = self.statuses.borrow_mut();
            let next = if q.len() > 1 { q.remove(0) } else { q.first().cloned().flatten() };
            next.ok_or_else(|| "no Core answered".to_string())
        }
        async fn cancel_study(&self, id: &str) -> Result<(), String> {
            self.cancelled.borrow_mut().push(id.to_string());
            Ok(())
        }
    }

    fn st(study: Option<&str>) -> Option<StatusView> {
        Some(StatusView { mode: Some("service".into()), study_in_flight: study.map(str::to_string), ..StatusView::default() })
    }

    #[tokio::test]
    async fn down_refuses_while_a_study_is_in_flight() {
        let core = FakeCore::with(vec![st(Some("run-7"))]);
        let e = super::study_guard(&core, false, WAITS).await.unwrap_err();
        assert!(e.contains("run-7") && e.contains("--cancel-run"), "{e}");
        assert!(core.cancelled.borrow().is_empty(), "a refusal cancels nothing");
    }

    #[tokio::test]
    async fn down_with_cancel_run_cancels_the_study_then_goes_ahead() {
        let core = FakeCore::with(vec![st(Some("run-7")), st(Some("run-7")), st(None)]);
        super::study_guard(&core, true, WAITS).await.unwrap();
        assert_eq!(core.cancelled.borrow().as_slice(), ["run-7".to_string()]);
    }

    #[tokio::test]
    async fn down_with_no_study_or_no_core_is_not_refused() {
        let idle = FakeCore::with(vec![st(None)]);
        super::study_guard(&idle, false, WAITS).await.unwrap();
        assert!(idle.cancelled.borrow().is_empty());
        let absent = FakeCore::with(vec![None]);
        super::study_guard(&absent, false, WAITS).await.unwrap();
    }

    #[tokio::test]
    async fn down_with_cancel_run_fails_if_the_study_will_not_end() {
        let core = FakeCore::with(vec![st(Some("run-7"))]);
        let e = super::study_guard(&core, true, WAITS).await.unwrap_err();
        assert!(e.contains("still in flight"), "{e}");
    }

    /// Decision 71: a plain `install` registers nothing, so `setup`'s `local`
    /// arm never says it installed or started anything, and never names
    /// `install --bind` as a step.
    #[test]
    fn local_setup_does_not_claim_or_name_a_registration_it_does_not_make() {
        for dry in [true, false] {
            let note = local_registration_note(dry);
            assert!(!note.contains("Installed and started"), "{note}");
            assert!(!note.contains("install --bind"), "{note}");
            assert!(note.contains("nothing was registered"), "{note}");
            assert!(note.contains("install-core"), "{note}");
        }
    }

    #[test]
    fn rebind_route_names_the_service_flag_and_the_installed_binary() {
        let r = rebind_route("0.0.0.0");
        assert!(r.contains("install --service --bind 0.0.0.0"), "{r}");
        assert!(r.contains("installed binary"), "{r}");
    }

    #[test]
    fn windows_registration_route_is_elevated_install_core() {
        assert!(registration_route(true).contains("install-core <release>"));
        assert!(registration_route(true).contains("elevated Windows"));
    }

    #[test]
    fn uninstall_exit_is_zero_with_nothing_failed_and_one_naming_each_failure() {
        assert_eq!(uninstall_exit(&[]), 0);
        assert_eq!(uninstall_exit(&["service uninstall"]), 1);
        assert_eq!(uninstall_exit(&["service uninstall", "token removal", "install undo"]), 1);
    }

    use super::*;

    #[test]
    fn token_path_translates_for_a_windows_core_seen_from_wsl2() {
        assert_eq!(
            token_path_for(TopologyClass::WslHost),
            Some(PathBuf::from("/mnt/c/ProgramData/embarch/token"))
        );
    }

    #[test]
    fn token_path_on_a_unix_local_core() {
        assert_eq!(
            token_path_for(TopologyClass::Local),
            Some(PathBuf::from("/var/lib/embarch/token"))
        );
    }

    #[test]
    fn a_remote_core_has_no_local_token_path() {
        // Not an oversight: there's no shared filesystem, so the token is
        // copied by hand (embarch-umbrella spec.md §6).
        assert_eq!(token_path_for(TopologyClass::Remote), None);
    }

    #[test]
    fn infer_class_prefers_an_explicit_host() {
        let windows_core = Located {
            path: PathBuf::from("/mnt/c/Program Files/embarch/embarch-core.exe"),
            found_by: crate::locate::FoundBy::WindowsConventionalDir,
            windows_exe_from_wsl2: true,
        };
        assert_eq!(infer_class(Some("bench.local"), Some(&windows_core)), TopologyClass::Remote);
    }

    #[test]
    fn infer_class_follows_a_locatable_windows_binary() {
        let windows_core = Located {
            path: PathBuf::from("/mnt/c/Program Files/embarch/embarch-core.exe"),
            found_by: crate::locate::FoundBy::WindowsConventionalDir,
            windows_exe_from_wsl2: true,
        };
        assert_eq!(infer_class(None, Some(&windows_core)), TopologyClass::WslHost);
    }

    #[test]
    fn infer_class_defaults_to_local() {
        assert_eq!(infer_class(None, None), TopologyClass::Local);
    }

    #[test]
    fn wsl_paths_render_as_windows_paths_for_pasting() {
        assert_eq!(
            windows_display_path(std::path::Path::new(
                "/mnt/c/Program Files/embarch/embarch-core.exe"
            )),
            "C:\\Program Files\\embarch\\embarch-core.exe"
        );
    }

    /// Decision 21's actual promise, and the only part of it a host test can
    /// establish: `--dry-run` walks the whole apply step and changes
    /// nothing. Every location `setup` can write to is pointed at a
    /// sandbox — the install directory, `$HOME`'s rc files, the env file,
    /// the state file — and `embarch-core` is a script that would leave a
    /// sentinel behind if it were ever executed. The plan deliberately has
    /// no located Core, so the `local` install-then-register path runs in
    /// full rather than short-circuiting.
    #[test]
    fn a_dry_run_reaches_no_side_effecting_call() {
        let sandbox = std::env::temp_dir().join(format!(
            "embarch-umbrella-dry-run-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&sandbox);
        let source = sandbox.join("archive");
        let home = sandbox.join("home");
        let bin_dir = sandbox.join("install").join("bin");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let sentinel = sandbox.join("EXECUTED");
        let core = source.join(locate::native_name("embarch-core"));
        std::fs::write(&core, format!("#!/bin/sh\ntouch \"{}\"\n", sentinel.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&core, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(source.join(locate::native_name("embarch")), b"embarch").unwrap();
        std::fs::write(home.join(".bashrc"), b"# rc\n").unwrap();

        let loc = Locations {
            source_dir: Some(source),
            bin_dir: Some(bin_dir.clone()),
            home: Some(home.clone()),
            state_path: Some(sandbox.join("config").join("umbrella.toml")),
            desk: None,
            claude: None,
            runner: Box::new(desk::Real),
        };
        let plan = Plan {
            class: TopologyClass::Local,
            host: None,
            core: None,
            already_running: false,
        };

        let code = apply_plan(plan, State::default(), None, &loc, true);
        assert_eq!(code, 0);

        assert!(!sentinel.exists(), "--dry-run must not run embarch-core");
        assert!(!bin_dir.exists(), "--dry-run must copy no binaries");
        assert!(!sandbox.join("install").join("env").exists(), "--dry-run must not write the env file");
        assert!(!sandbox.join("config").exists(), "--dry-run must not write the state file");
        assert_eq!(
            std::fs::read_to_string(home.join(".bashrc")).unwrap(),
            "# rc\n",
            "--dry-run must not touch a shell rc file"
        );

        std::fs::remove_dir_all(&sandbox).unwrap();
    }

    /// The counterpart: the dry run has to *describe* decision 28's install
    /// and `PATH` write, not quietly omit them because they are the steps
    /// that used to only print while acting.
    #[test]
    fn the_dry_run_plan_names_the_install_and_the_path_write() {
        let sandbox = std::env::temp_dir().join(format!(
            "embarch-umbrella-dry-plan-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&sandbox);
        let source = sandbox.join("archive");
        let home = sandbox.join("home");
        let bin_dir = sandbox.join("install").join("bin");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(source.join(locate::native_name("embarch")), b"embarch").unwrap();
        std::fs::write(source.join(locate::native_name("embarch-core")), b"core").unwrap();
        std::fs::write(home.join(".bashrc"), b"# rc\n").unwrap();

        let rendered = install::plan_install(&source, &bin_dir, Some(&home)).render();
        assert!(rendered.contains(&bin_dir.display().to_string()), "{rendered}");
        assert!(rendered.contains("embarch-core"), "{rendered}");
        // `embarch-api` isn't in this archive: named as skipped rather than
        // silently absent.
        assert!(rendered.contains("skipped"), "{rendered}");
        assert!(rendered.contains("PATH"), "{rendered}");
        #[cfg(unix)]
        assert!(rendered.contains(".bashrc"), "{rendered}");

        // And the destination the `local` fallback keys off is the one the
        // plan says a copy would land at.
        let plan = install::plan_install(&source, &bin_dir, Some(&home));
        assert!(plan.destinations().contains(&bin_dir.join(locate::native_name("embarch-core"))));

        std::fs::remove_dir_all(&sandbox).unwrap();
    }

    /// Decision 51: a `remote` conclusion writes `--host` forward.
    #[test]
    fn a_remote_conclusion_saves_the_host() {
        let sandbox = std::env::temp_dir().join(format!(
            "embarch-umbrella-host-save-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&sandbox);
        let state_path = sandbox.join("config").join("umbrella.toml");
        let loc = Locations {
            source_dir: None,
            bin_dir: None,
            home: None,
            state_path: Some(state_path.clone()),
            desk: None,
            claude: None,
            runner: Box::new(desk::Real),
        };
        let plan = Plan {
            class: TopologyClass::Remote,
            host: Some("bench.local".to_string()),
            core: None,
            already_running: true,
        };

        apply_plan(plan, State::default(), None, &loc, false);

        let saved = state::load_from(&state_path).unwrap();
        assert_eq!(saved.host.as_deref(), Some("bench.local"));

        std::fs::remove_dir_all(&sandbox).unwrap();
    }

    /// Decision 51: a later non-`remote` run clears whatever `--host` a
    /// previous `remote` run left behind, rather than carrying it forward as
    /// a leftover that could outlive the run that gave it.
    #[test]
    fn a_local_conclusion_clears_a_previously_saved_host() {
        let sandbox = std::env::temp_dir().join(format!(
            "embarch-umbrella-host-clear-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&sandbox);
        let state_path = sandbox.join("config").join("umbrella.toml");
        let loc = Locations {
            source_dir: None,
            bin_dir: None,
            home: None,
            state_path: Some(state_path.clone()),
            desk: None,
            claude: None,
            runner: Box::new(desk::Real),
        };
        let previously_saved = State {
            host: Some("bench.local".to_string()),
            ..State::default()
        };
        let plan = Plan {
            class: TopologyClass::Local,
            // `make_plan` would have carried the saved host forward here
            // (`host.map(...).or(saved.host)`) since no `--host` was given
            // this run either — the clearing has to happen after that, on
            // the concluded class, not by never inheriting it.
            host: previously_saved.host.clone(),
            core: None,
            already_running: true,
        };

        apply_plan(plan, previously_saved, None, &loc, false);

        let saved = state::load_from(&state_path).unwrap();
        assert_eq!(saved.host, None, "a local conclusion must not keep a stale saved host");

        std::fs::remove_dir_all(&sandbox).unwrap();
    }

    #[test]
    fn non_wsl_paths_are_left_alone() {
        assert_eq!(
            windows_display_path(std::path::Path::new("/usr/local/bin/embarch-core")),
            "/usr/local/bin/embarch-core"
        );
    }
}
