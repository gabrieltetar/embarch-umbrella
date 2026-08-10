//! `setup`, `up`, and `down` — everything that acts on Core rather than just
//! looking at it.
//!
//! All three share one problem (where is `embarch-core`, and can I control it
//! from here?), which is why they live together. See design.md §3 decisions
//! 3, 4, 7 and milestone-6.md §3.3.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

use crate::locate::{self, Located};
use crate::state::{self, State};
use crate::topology::{self, TopologyClass};
use crate::{env, probe};

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
    let gateway = if under_wsl2 {
        env::default_gateway()
    } else {
        None
    };
    let saved = state::load();
    let core = locate::locate_core(saved.core_exe.as_deref(), under_wsl2);

    // If Core is already up, it has already answered the question.
    let candidates = topology::candidates(under_wsl2, gateway.as_deref(), host, port);
    let client = reqwest::Client::new();
    let client = &client;
    let attempts = topology::resolve(&candidates, move |url| async move {
        probe::probe_core(client, &url).await
    })
    .await;

    if let Some(found) = topology::winner(&attempts) {
        return Plan {
            class: found.candidate.class,
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

pub async fn setup(host: Option<&str>, port: u16) -> i32 {
    let plan = make_plan(host, port).await;

    println!("Topology: {}", plan.class.as_str());
    match &plan.core {
        Some(c) => println!("embarch-core: {} ({})", c.path.display(), c.found_by.as_str()),
        None => println!("embarch-core: not found"),
    }

    if plan.already_running {
        println!("embarch-core is already running — nothing to install.");
    } else {
        match (plan.class, &plan.core) {
            (TopologyClass::Remote, _) => {
                println!(
                    "\nCore is on another machine. Start it there yourself:\n  \
                     embarch-core install    (elevated, on that machine)\n\
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
                     \"{}\" install",
                    windows_display_path(&c.path)
                );
            }
            (TopologyClass::Local, Some(c)) => {
                println!("\nInstalling embarch-core as a service that starts at boot...");
                match run(&c.path, &["install"]) {
                    Ok(true) => println!("Installed and started."),
                    // Almost always a privilege failure. Trying first is
                    // still right: someone who ran `sudo embarch setup` gets
                    // it done in one step.
                    Ok(false) | Err(_) => println!(
                        "Could not install the service — this needs elevation. Run:\n  \
                         sudo \"{}\" install",
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

    let saved = State {
        schema_version: state::STATE_SCHEMA_VERSION,
        topology: Some(plan.class.as_str().to_string()),
        host: plan.host,
        core_exe: plan
            .core
            .as_ref()
            .filter(|c| c.windows_exe_from_wsl2)
            .map(|c| c.path.clone()),
    };
    match state::save(&saved) {
        Ok(()) => {
            if let Ok(p) = state::state_path() {
                println!("Saved topology to {}", p.display());
            }
        }
        Err(e) => println!("Could not save state: {e:#}"),
    }

    // PATH is left alone on purpose (locate.rs's header). Say so, and give
    // the one line rather than editing someone's shell config for them.
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        println!(
            "\nTo run `embarch`, `embarch-core` and `embarch-api` from anywhere, add this to your \
             shell profile (setup does not edit it for you):\n  export PATH=\"{}:$PATH\"",
            dir.display()
        );
    }

    println!("\nNext: `embarch status` to confirm, then `embarch init` in a firmware repo.");
    0
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
