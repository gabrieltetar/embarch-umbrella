//! `setup`, `up`, and `down` — everything that acts on Core rather than just
//! looking at it.
//!
//! All three share one problem (where is `embarch-core`, and can I control it
//! from here?), which is why they live together. See design.md §3 decisions
//! 3, 4, 7 and milestone-6.md §3.3.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

use embarch_topology::software::TopologyClass;

use crate::env;
use crate::install;
use crate::locate::{self, FoundBy, Located};
use crate::state::{self, State};

/// Where `embarch-core` writes its machine-wide token file, as seen from
/// here (embarch-token.md §3.1). Pure so the WSL2 translation is testable.
///
/// This is an existence check only, not token discovery — reading and
/// validating the value is `doctor`'s job (design.md §5 check 4), and needs
/// the discovery logic `embarch-api` already has.
pub fn token_path_for(class: TopologyClass, windows: bool) -> Option<PathBuf> {
    match class {
        // A Windows-hosted Core from a WSL2 guest: same file, reached through
        // the /mnt mount. Assumes the standard %ProgramData% location, which
        // is the same assumption embarch-token.md §6 already records as an
        // unexercised edge case for relocated ProgramData.
        TopologyClass::WslHost => Some(PathBuf::from("/mnt/c/ProgramData/embarch/token")),
        TopologyClass::Local if windows => std::env::var_os("ProgramData")
            .map(|pd| PathBuf::from(pd).join("embarch").join("token")),
        TopologyClass::Local => Some(PathBuf::from("/var/lib/embarch/token")),
        // No shared filesystem — the token has to be copied by hand
        // (design.md §6), so there is no local path to check.
        TopologyClass::Remote => None,
    }
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
    // (embarch-topology/design.md decisions 2, 3: live, in-process, every
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
/// in the guest. Shared with `doctor` (design.md §5 check 2) so the two
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

/// Run a command, inheriting stdio so the user sees whatever it prints.
fn run(program: &std::path::Path, args: &[&str]) -> Result<bool> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("could not run {}", program.display()))?;
    Ok(status.success())
}

/// Copy this platform's binaries to the canonical location and make sure
/// `PATH` includes it (decision 28), from wherever the currently-running
/// `embarch` binary sits — the unpacked release archive. Printed regardless
/// of outcome, since a failure here (e.g. no writable `HOME`/`LOCALAPPDATA`)
/// shouldn't silently abort the rest of `setup`.
fn install_this_platform() -> Option<install::InstallReport> {
    let source_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    match install::install(&source_dir) {
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
            Some(report)
        }
        Err(e) => {
            println!("\nCould not install to the canonical location: {e:#}");
            None
        }
    }
}

pub async fn setup(host: Option<&str>, port: u16, dev_bench_repo: Option<&std::path::Path>) -> i32 {
    let install_report = install_this_platform();
    let previously_saved = state::load();
    let mut plan = make_plan(host, port).await;

    // locate_core's PATH lookup can't see a PATH change this same run just
    // made (a running process's own environment doesn't retroactively
    // update) — so for a same-machine Core, fall back to the copy this run
    // itself just installed rather than reporting "not found" on a machine
    // that's actually now fully set up. Not applicable to wsl-host/remote:
    // those need the real Windows-side or remote binary, not this local copy.
    if plan.core.is_none() && plan.class == TopologyClass::Local {
        if let Some(report) = &install_report {
            let candidate = report.bin_dir.join(locate::native_name("embarch-core"));
            if candidate.is_file() {
                plan.core = Some(Located { path: candidate, found_by: FoundBy::JustInstalled, windows_exe_from_wsl2: false });
            }
        }
    }

    println!("\nTopology: {}", plan.class.as_str());
    match &plan.core {
        Some(c) => println!("embarch-core: {} ({})", c.path.display(), c.found_by.as_str()),
        None => println!("embarch-core: not found"),
    }

    // embarch-core/design.md §3 decision 6's amendment: Core's own default
    // is loopback-only; widening it for the one topology that actually needs
    // a wider address is this call's job, not something a human has to
    // remember to type. Computed once and baked into every `install`
    // invocation below, whether run directly or printed for a human to paste
    // into an elevated shell — an installed service's `--bind` is part of
    // its registered start command (`embarch-core install`'s own doc
    // comment), so this only has to happen at install time, not on every
    // subsequent start.
    let bind_addr = embarch_topology::software::recommended_bind_address(plan.class);

    if plan.already_running {
        println!("embarch-core is already running — nothing to install.");
    } else {
        match (plan.class, &plan.core) {
            (TopologyClass::Remote, _) => {
                println!(
                    "\nCore is on another machine. Start it there yourself:\n  \
                     embarch-core install --bind {bind_addr}    (elevated, on that machine)\n\
                     Then copy its token file's contents to this machine:\n  \
                     export EMBARCH_TOKEN=<contents of /var/lib/embarch/token on that machine>"
                );
            }
            (TopologyClass::WslHost, Some(c)) => {
                // Cannot be done from here: controlling a Windows service
                // needs an elevated Windows shell, and umbrella never tries
                // to obtain one (design.md §3 decision 7).
                println!(
                    "\nCore belongs on the Windows side. In an **elevated Windows** shell, run:\n  \
                     \"{}\" install --bind {bind_addr}",
                    windows_display_path(&c.path)
                );
            }
            (TopologyClass::Local, Some(c)) => {
                println!("\nInstalling embarch-core as a service that starts at boot...");
                match run(&c.path, &["install", "--bind", bind_addr]) {
                    Ok(true) => println!("Installed and started."),
                    // Almost always a privilege failure. Trying first is
                    // still right: someone who ran `sudo embarch setup` gets
                    // it done in one step.
                    Ok(false) | Err(_) => println!(
                        "Could not install the service — this needs elevation. Run:\n  \
                         sudo \"{}\" install --bind {bind_addr}",
                        c.path.display()
                    ),
                }
            }
            (_, None) => {
                println!(
                    "\nCan't continue without embarch-core. It ships in the same archive as this \
                     binary — unpack them into one directory, or point EMBARCH_CORE_EXE at it."
                );
                return 1;
            }
        }
    }

    // The token file is Core's to create on first start; all we can usefully
    // say is whether it's there yet.
    if let Some(token) = token_path_for(plan.class, cfg!(windows)) {
        if token.exists() {
            println!("\nToken file: {} (present)", token.display());
        } else {
            println!(
                "\nToken file: {} (not yet — embarch-core creates it the first time it starts)",
                token.display()
            );
        }
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
        host: plan.host,
        core_exe: plan
            .core
            .as_ref()
            .filter(|c| c.windows_exe_from_wsl2)
            .map(|c| c.path.clone()),
        dev_bench_repo_path,
        // `setup` is about the topology; `deploy-core`'s own paths are its
        // own (design.md §3 decision 37), and it saves them itself. Carried
        // through rather than defaulted so a `setup` re-run doesn't wipe
        // what a deploy remembered.
        deploy_source_root: previously_saved.deploy_source_root,
        deploy_windows_root: previously_saved.deploy_windows_root,
        deploy_cargo_exe: previously_saved.deploy_cargo_exe,
    };
    match state::save(&saved) {
        Ok(()) => {
            if let Ok(p) = state::state_path() {
                println!("Saved topology to {}", p.display());
            }
        }
        Err(e) => println!("Could not save state: {e:#}"),
    }

    println!("\nNext: `embarch status` to confirm, then `embarch init` in a firmware repo.");
    0
}

/// Reverse `setup`: stop and unregister the Core service (best-effort — a
/// `wsl-host`/`remote` Core can't be controlled from here, same constraint
/// `up`/`down` already have), remove the machine-wide token file, and undo
/// decision 28's install (canonical binaries + `PATH` additions).
pub fn uninstall() -> i32 {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();
    let core = locate::locate_core(saved.core_exe.as_deref(), under_wsl2);

    match &core {
        Some(c) if !c.windows_exe_from_wsl2 => {
            println!("Stopping and uninstalling the embarch-core service...");
            match run(&c.path, &["uninstall"]) {
                Ok(true) => println!("Service uninstalled."),
                Ok(false) | Err(_) => {
                    println!("Could not uninstall the service — this may need elevation:\n  sudo \"{}\" uninstall", c.path.display());
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
    if let Some(token) = token_path_for(class, cfg!(windows)) {
        match std::fs::remove_file(&token) {
            Ok(()) => println!("Removed token file: {}", token.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => println!("Could not remove token file {}: {e}", token.display()),
        }
    }

    match install::uninstall() {
        Ok(()) => println!("Removed the canonical install directory and PATH additions."),
        Err(e) => println!("Could not fully undo the install: {e:#}"),
    }

    0
}

fn topology_class_from_str(s: &str) -> Option<TopologyClass> {
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
/// no remote orchestration at all, by design (design.md §3 decision 8). Say
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
/// detached process (design.md §3 decision 4).
pub fn up(foreground: bool) -> i32 {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();

    if let Some(msg) = refuse_if_remote(&saved, "start") {
        println!("{msg}");
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
            println!("{}", deferral.message);
            return if deferral.satisfied { 0 } else { 1 };
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
        println!(
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
            // than a clear message (design.md §3 decision 4).
            eprintln!(
                "Could not start the service. Either it isn't installed yet:\n  \
                 sudo \"{}\" install\n\
                 or start it with elevation:\n  sudo \"{}\" start\n\
                 or run Core in this terminal instead:\n  embarch up --foreground",
                core.path.display(),
                core.path.display()
            );
            1
        }
    }
}

pub fn down() -> i32 {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();

    if let Some(msg) = refuse_if_remote(&saved, "stop") {
        println!("{msg}");
        return 1;
    }

    // Decision 30 names `up`; applying it to `down` too is an extension
    // beyond its text, taken deliberately. The ambiguity is identical, and
    // the asymmetry would be the dangerous half: `up` starting the wrong
    // Core fails on a port bind, `down` stopping the wrong one succeeds
    // quietly and leaves the real Core running.
    if let Some(deferral) = defer_to_windows_service(under_wsl2, &saved, "stop") {
        println!("{}", deferral.message);
        return if deferral.satisfied { 0 } else { 1 };
    }

    let Some(core) = locate::locate_core(saved.core_exe.as_deref(), under_wsl2) else {
        eprintln!("embarch-core not found. Run `embarch setup`, or set EMBARCH_CORE_EXE.");
        return 1;
    };

    if core.windows_exe_from_wsl2 {
        println!(
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
    use super::*;

    #[test]
    fn token_path_translates_for_a_windows_core_seen_from_wsl2() {
        assert_eq!(
            token_path_for(TopologyClass::WslHost, false),
            Some(PathBuf::from("/mnt/c/ProgramData/embarch/token"))
        );
    }

    #[test]
    fn token_path_on_a_unix_local_core() {
        assert_eq!(
            token_path_for(TopologyClass::Local, false),
            Some(PathBuf::from("/var/lib/embarch/token"))
        );
    }

    #[test]
    fn a_remote_core_has_no_local_token_path() {
        // Not an oversight: there's no shared filesystem, so the token is
        // copied by hand (design.md §6).
        assert_eq!(token_path_for(TopologyClass::Remote, false), None);
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

    #[test]
    fn non_wsl_paths_are_left_alone() {
        assert_eq!(
            windows_display_path(std::path::Path::new("/usr/local/bin/embarch-core")),
            "/usr/local/bin/embarch-core"
        );
    }
}
