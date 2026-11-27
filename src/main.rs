//! `embarch` — setup and diagnostics for the EmbArch suite.
//!
//! Current truth is `embarch-doc/embarch-umbrella/spec.md`; why is
//! `decisions.md`; what's left is `open.md`. Implemented so far: topology
//! detection, `setup`, `init`, `up`/`down`, `doctor`, and `status`. Release CI
//! and dogfooding the guide are what remains.

mod agent;
mod agent_run;
mod config;
mod desk;
mod deploy;
mod deploy_dev;
mod doctor;
mod env;
mod agent_init;
mod init;
mod install;
mod install_core;
mod install_core_linux;
mod install_core_win;
mod locate;
mod manifest;
mod setup;
mod state;
mod verify_release;
mod zephyr;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// `schema_version` on every `--json` object `embarch` emits (`status`, `doctor`).
/// Hand-bumped when either object's shape changes; the umbrella's own counter,
/// not `embarch-api`'s (`embarch-umbrella` decision 11, after `embarch-api` 24).
pub const JSON_SCHEMA_VERSION: u32 = 1;

use embarch_topology::software::{winner, Attempt, ProbeOutcome, DEFAULT_CORE_PORT};

/// Exit codes follow embarch-api's CLI convention (`embarch-api` interfaces/tools.md):
/// 0 success, 1 any operation failure, 2 (clap's own) malformed invocation.
const EXIT_FAILURE: i32 = 1;

#[derive(Parser)]
#[command(
    name = "embarch",
    // Names the commit this binary was built from (decision 57).
    version = env!("EMBARCH_BUILD_VERSION"),
    about = "Setup and diagnostics for the EmbArch suite",
    long_about = "Sets up embarch-core and embarch-api on whatever topology this machine is, \
                  integrates a firmware repo, and diagnoses the whole chain.\n\n\
                  Deliberately not a supervisor and not in the runtime path: once setup is \
                  done, nothing routes through this binary."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check an unpacked suite release offline: the manifest's Sigstore
    /// signature under the exact release-workflow identity, then every
    /// listed file's SHA-256. Fetches nothing unless --refresh-trust-root.
    VerifyRelease {
        /// Folder holding embarch-manifest.json, its .sigstore.json bundle
        /// and the files it lists. Defaults to this binary's own folder.
        dir: Option<PathBuf>,

        /// Use this Sigstore trusted_root.json instead of the embedded one.
        #[arg(long, value_name = "FILE", conflicts_with = "refresh_trust_root")]
        trusted_root: Option<PathBuf>,

        /// Fetch the Sigstore trust root through TUF for this run only, and
        /// never cache it. For a release logged to a newer log shard than the
        /// embedded root knows. The only option that uses the network.
        #[arg(long)]
        refresh_trust_root: bool,
    },
    /// Verify a suite release in a staging folder only an administrator can
    /// write, refuse an older suite than the installed one, and record what
    /// was installed. Registering the service is a later step.
    InstallCore {
        /// The unpacked release folder, or its archive.
        source: PathBuf,

        /// Install a suite older than the installed one; the record says so.
        #[arg(long)]
        allow_downgrade: bool,

        /// Print the plan and change nothing.
        #[arg(long)]
        dry_run: bool,

        /// Core's data folder, where `release-staging/` and
        /// `installed-release.json` live. Defaults to this machine's.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,

        /// Use this Sigstore trusted_root.json instead of the embedded one.
        #[arg(long, value_name = "FILE", conflicts_with = "refresh_trust_root")]
        trusted_root: Option<PathBuf>,

        /// Fetch the Sigstore trust root through TUF for this run only.
        #[arg(long)]
        refresh_trust_root: bool,

        /// The agent runs in a container: the elevated install also lets
        /// your account start and stop the Core service, and nothing else
        /// about it (decision 72). Recorded with its date; only a later
        /// elevated install changes it.
        #[arg(long)]
        agent_in_container: bool,
    },
    /// One-time per-machine setup: detect the topology, install Core as a
    /// service that starts at boot, copy the suite's binaries to a
    /// canonical location, and add it to PATH.
    Setup {
        /// Core is on another machine at this host. Skips any local install.
        #[arg(long)]
        host: Option<String>,

        /// Core's port.
        #[arg(long, default_value_t = DEFAULT_CORE_PORT)]
        port: u16,

        /// Reverse a prior `setup`: uninstall the Core service, remove the
        /// token file, and undo the canonical install + PATH additions.
        #[arg(long)]
        uninstall: bool,

        /// Local `embarch-dev-bench` checkout, for `doctor` check 13's
        /// stale-firmware detection (decision 19). Saved to
        /// state; omit on a later `setup` run to leave a previously-saved
        /// path unchanged.
        #[arg(long)]
        dev_bench_repo: Option<PathBuf>,

        /// Run every detection step exactly as `setup` does, print the
        /// concrete actions — which service call, which files, whether
        /// elevation is needed — and change nothing (decision 21).
        #[arg(long, conflicts_with = "uninstall")]
        dry_run: bool,
    },

    /// Integrate the firmware repo in the current directory: scaffold
    /// `embarch/embarch.toml`, register the MCP server, exclude locally.
    Init {
        /// Reverse everything `init` did in this repo.
        #[arg(long)]
        uninstall: bool,
        /// Print what would be written (or, with `--uninstall`, removed) and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also set up the agent's container: its definition folder and
        /// exchange folder outside the repo (decision 65). Nothing is built.
        #[arg(long, conflicts_with = "uninstall")]
        container: bool,
        /// The container runtime the definition is rendered for.
        #[arg(long, requires = "container", value_parser = ["docker", "podman"], default_value = "docker")]
        runtime: String,
    },

    /// Start, stop, check and enter the agent's container (decision 67).
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Verify the whole chain, with a fix for every failed check.
    Doctor {
        /// Emit one JSON object instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Cheap liveness check: is Core up, and where.
    ///
    /// Exits 1 when Core isn't found, so a script can branch on the exit code
    /// alone. With --json the report still goes to stdout either way.
    Status {
        /// Emit one JSON object instead of human-readable output.
        #[arg(long)]
        json: bool,

        /// Core's host, for a Core on a genuinely separate machine. Probed
        /// last, after loopback and (under WSL2) the Windows host.
        #[arg(long)]
        host: Option<String>,

        /// Core's port.
        #[arg(long, default_value_t = DEFAULT_CORE_PORT)]
        port: u16,
    },

    /// Fallback: start Core when it isn't already a running service.
    Up {
        /// Run Core in this terminal instead of as a service. Blocks until
        /// Ctrl-C; useful for watching Core's own logs.
        #[arg(long)]
        foreground: bool,
    },

    /// Fallback: stop the running Core service, leaving it installed. Refuses
    /// while a study is in flight (decision 72).
    Down {
        /// Cancel the study in flight first, then stop.
        #[arg(long)]
        cancel_run: bool,
    },

    /// Get a local `embarch-core` change running beside the Windows service:
    /// sync, build natively, install a development Core in the engineer's
    /// profile (the service is stopped, never overwritten), verify by hash.
    /// `--restore-service` puts the service back.
    ///
    /// Replaces the hand-assembled procedure in
    /// `embarch-doc/embarch-dev-workflow.md` §4a — which that section itself
    /// calls "the single most-repeated undocumented step in the suite".
    DeployCore {
        /// Parent of the Linux-side checkouts. Defaults to saved state, then
        /// to the parent of the checkout you are standing in.
        #[arg(long)]
        source_root: Option<PathBuf>,

        /// Parent of the Windows-side source copies (a `/mnt/...` path).
        /// Never guessed — required on the first run, remembered after.
        #[arg(long)]
        windows_root: Option<PathBuf>,

        /// Windows `cargo.exe` (a `/mnt/...` path). Defaults to
        /// `%USERPROFILE%\.cargo\bin\cargo.exe`.
        #[arg(long)]
        cargo: Option<PathBuf>,

        /// Windows service to restart.
        #[arg(long)]
        service: Option<String>,

        /// Print the resolved plan and stop, touching nothing.
        #[arg(long)]
        dry_run: bool,

        /// Do everything unelevated, write the elevated script, and print
        /// the one command to run it — decision 7's posture,
        /// for when you would rather run the privileged half yourself.
        #[arg(long)]
        print_script: bool,

        /// Cancel a study in flight before the deploy stops the Core running
        /// it. Without this a study in flight refuses the deploy.
        #[arg(long)]
        cancel_run: bool,

        /// Stop the development Core and start the service again; waits for
        /// `/status` to read `service` with a key matching `core-fingerprint`.
        #[arg(long)]
        restore_service: bool,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Build the image when none carries the Containerfile's hash, then start
    /// the container with the vector `init --container` recorded.
    Up {
        /// The agent's name; omit inside its repo, or when only one exists.
        name: Option<String>,
    },
    /// Stop and remove the container. The work volume and the exchange folder stay.
    Down { name: Option<String> },
    /// Check the definition, the fingerprint copy, and from inside that Core
    /// answers and an address off the allowlist does not. Exits 1 on any finding.
    Status { name: Option<String> },
    /// A shell in the agent's clone, as the agent user.
    Shell {
        name: Option<String>,
        /// Run `claude` instead of `bash`.
        #[arg(long)]
        claude: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // stderr, so stdout stays reserved for command results and `--json`
    // output — same split embarch-api's CLI uses (`embarch-api` interfaces/tools.md).
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let cli = Cli::parse();

    let code = match cli.command {
        Command::Status { json, host, port } => status(json, host.as_deref(), port).await,
        Command::Setup { host, port, uninstall, dev_bench_repo, dry_run } => {
            if uninstall {
                setup::uninstall()
            } else {
                setup::setup(host.as_deref(), port, dev_bench_repo.as_deref(), dry_run).await
            }
        }
        Command::VerifyRelease { dir, trusted_root, refresh_trust_root } => {
            verify_release::run(dir, trusted_root, refresh_trust_root).await
        }
        Command::InstallCore {
            source,
            allow_downgrade,
            dry_run,
            data_dir,
            trusted_root,
            refresh_trust_root,
            agent_in_container,
        } => {
            install_core::run(
                source,
                data_dir,
                allow_downgrade,
                dry_run,
                trusted_root,
                refresh_trust_root,
                agent_in_container,
            )
            .await
        }
        Command::Init { uninstall, dry_run, container, runtime } => {
            let runtime = container.then(|| if runtime == "podman" { agent::Runtime::Podman } else { agent::Runtime::Docker });
            init::init(uninstall, dry_run, runtime)
        }
        Command::Agent { action } => {
            let ctx = agent_run::ctx_from_env();
            match action {
                AgentAction::Up { name } => agent_run::report(agent_run::up(&ctx, name.as_deref())),
                AgentAction::Down { name } => agent_run::report(agent_run::down(&ctx, name.as_deref())),
                AgentAction::Status { name } => agent_run::report_status(agent_run::status(&ctx, name.as_deref())),
                AgentAction::Shell { name, claude } => match agent_run::shell(&ctx, name.as_deref(), claude) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("{e:#}");
                        1
                    }
                },
            }
        }
        Command::Doctor { json } => doctor::doctor(json).await,
        Command::Up { foreground } => setup::up(foreground),
        Command::Down { cancel_run } => setup::down(cancel_run).await,
        Command::DeployCore {
            source_root,
            windows_root,
            cargo,
            service,
            dry_run,
            print_script,
            cancel_run,
            restore_service,
        } => {
            deploy::deploy_core(
                source_root,
                windows_root,
                cargo,
                service,
                dry_run,
                print_script,
                cancel_run,
                restore_service,
            )
            .await
        }
    };

    std::process::exit(code);
}

/// What `status` learned about Core's probe count, or why it couldn't.
///
/// A plain `Option<usize>` would make "zero probes plugged in" and "wasn't
/// allowed to look" both render as `0` / `null` — the exact collapse
/// `embarch-umbrella` decision 46 exists to rule out. Every non-`Count` state
/// is its own reported fact, never silently folded into a count.
enum ProbeReport {
    /// Core answered `GET /status` with `200` and this many entries in
    /// `probes` ([embarch-core/interfaces.md](../../embarch-doc/embarch-core/interfaces.md)'s `/status` row).
    Count(usize),
    /// No candidate answered as Core at all — nothing to authenticate to.
    Unreachable,
    /// A token could not be resolved. `String` is the display of the
    /// `anyhow::Error` `embarch_core_client::token_discovery::resolve_token`
    /// returned.
    NoToken(String),
    /// Core rejected the resolved token (`401`).
    Unauthorized,
    /// The authenticated request didn't come back with a count to read — a
    /// timeout, a connection drop, or a non-`200`/`401` status. `String` is
    /// `crate::doctor`'s own description of the failure, or ours.
    RequestFailed(String),
    /// Core answered `200` but its body carried no `probes` array. The
    /// request itself succeeded — Core is up and answering — so this is
    /// distinct from `RequestFailed`: a `--json` consumer that retries on
    /// `request-failed` would retry this forever, against a Core that
    /// isn't failing. `String` is our own description of what was wrong
    /// with the body.
    ///
    /// This used to be folded into `RequestFailed` under the same label
    /// (`embarch-umbrella` `5c92ea0`), which fixed the value collapse
    /// decision 46 rules out but left a wrong label — the state that
    /// determines whether a machine consumer retries — behind
    /// (`embarch-umbrella` task 039).
    BadResponse(String),
}

impl ProbeReport {
    fn state_str(&self) -> &'static str {
        match self {
            ProbeReport::Count(_) => "ok",
            ProbeReport::Unreachable => "unreachable",
            ProbeReport::NoToken(_) => "no-token",
            ProbeReport::Unauthorized => "unauthorized",
            ProbeReport::RequestFailed(_) => "request-failed",
            ProbeReport::BadResponse(_) => "bad-response",
        }
    }
}

/// Ask the winning candidate for its probe count, the same way `doctor`
/// check 5 does: resolve a token, one authenticated `GET /status`, read the
/// `probes` array's length (decision 46). `status` has no `--config`, so
/// unlike `doctor` this always resolves with no config override — the token
/// env var or file discovery `embarch_core_client::token_discovery::resolve_token`
/// falls back to on its own.
async fn probe_report(base_url: Option<&str>) -> ProbeReport {
    let Some(base_url) = base_url else {
        return ProbeReport::Unreachable;
    };

    let token = match embarch_core_client::token_discovery::resolve_token(None, None) {
        Ok(t) => t,
        Err(e) => return ProbeReport::NoToken(format!("{e:#}")),
    };

    match crate::doctor::authed_get(base_url, "/status", &token, crate::doctor::DEVICE_SCAN_GET_TIMEOUT).await {
        Ok((status, body)) => interpret_probe_response(status, &body),
        Err(reason) => ProbeReport::RequestFailed(reason),
    }
}

/// Turn a `/status` response's status code and body into a `ProbeReport`.
/// Split out of `probe_report` so the `200`-with-no-`probes`-array case
/// (`BadResponse`, `embarch-umbrella` task 039) can be tested without a
/// real socket or a resolved token.
fn interpret_probe_response(status: u16, body: &str) -> ProbeReport {
    match status {
        200 => match serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("probes").and_then(|p| p.as_array().map(Vec::len)))
        {
            Some(count) => ProbeReport::Count(count),
            None => ProbeReport::BadResponse(
                "Core answered HTTP 200 but its body carried no `probes` array".to_string(),
            ),
        },
        401 => ProbeReport::Unauthorized,
        status => ProbeReport::RequestFailed(format!("Core answered HTTP {status}")),
    }
}

/// Find Core and report where it is. Returns the process exit code.
async fn status(json: bool, host: Option<&str>, port: u16) -> i32 {
    // embarch-topology decisions 2, 3: live, in-process, every call — this
    // crate no longer owns any of the WSL2/gateway/probe I/O itself (formerly
    // this file's own use of `env.rs`/`probe.rs`/`topology.rs`).
    let resolved = embarch_topology::software::resolve_software_topology(port, host, None).await;
    let probes = probe_report(resolved.base_url()).await;

    if json {
        println!("{}", status_json(&resolved.attempts, &probes));
    } else {
        print_status(&resolved.attempts, &probes);
    }

    if resolved.winner.is_some() {
        0
    } else {
        EXIT_FAILURE
    }
}

fn outcome_str(outcome: ProbeOutcome) -> String {
    match outcome {
        ProbeOutcome::Core { authorized: true } => "core".to_string(),
        ProbeOutcome::Core { authorized: false } => "core-unauthorized".to_string(),
        ProbeOutcome::NotCore { status } => format!("not-core-http-{status}"),
        ProbeOutcome::Unreachable => "unreachable".to_string(),
    }
}

fn print_status(attempts: &[Attempt], probes: &ProbeReport) {
    match winner(attempts) {
        Some(found) => {
            println!(
                "Core: up at {} ({})",
                found.candidate.base_url,
                found.candidate.class.as_str()
            );
            match probes {
                ProbeReport::Count(n) => println!("  probes: {n}"),
                ProbeReport::NoToken(reason) => {
                    println!("  probes: unknown — no token ({reason})");
                }
                ProbeReport::Unauthorized => {
                    println!("  probes: unknown — Core rejected the token (401)");
                }
                ProbeReport::RequestFailed(reason) => {
                    println!("  probes: unknown — {reason}");
                }
                ProbeReport::BadResponse(reason) => {
                    println!("  probes: unknown — {reason}");
                }
                ProbeReport::Unreachable => unreachable!("a winner implies a base_url"),
            }
        }
        None => {
            println!("Core: not found");
            for attempt in attempts {
                let why = match attempt.outcome {
                    ProbeOutcome::Unreachable => "nothing listening".to_string(),
                    ProbeOutcome::NotCore { status } => {
                        format!("something answered HTTP {status}, but it isn't Core")
                    }
                    ProbeOutcome::Core { .. } => unreachable!("a hit would have won"),
                };
                println!(
                    "  tried {} ({}) — {why}",
                    attempt.candidate.base_url,
                    attempt.candidate.class.as_str()
                );
            }
            println!("  fix: start Core (`embarch up`), or pass --host if it's on another machine");
        }
    }
}

/// `probes` is always present and is `{"state": ..., "count": ...}` rather
/// than a bare nullable number, so "no probes" and "couldn't find out" don't
/// collapse into the same `0`/`null` a consumer would have to guess between
/// (decision 46). `count` is only non-null for `state: "ok"`.
fn probes_json(probes: &ProbeReport) -> serde_json::Value {
    let reason = match probes {
        ProbeReport::Count(_) | ProbeReport::Unreachable | ProbeReport::Unauthorized => None,
        ProbeReport::NoToken(reason)
        | ProbeReport::RequestFailed(reason)
        | ProbeReport::BadResponse(reason) => Some(reason.clone()),
    };
    serde_json::json!({
        "state": probes.state_str(),
        "count": match probes {
            ProbeReport::Count(n) => Some(*n),
            _ => None,
        },
        "reason": reason,
    })
}

fn status_json(attempts: &[Attempt], probes: &ProbeReport) -> String {
    let found = winner(attempts);
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "success": true,
        "reachable": found.is_some(),
        "base_url": found.map(|a| a.candidate.base_url.clone()),
        "topology": found.map(|a| a.candidate.class.as_str()),
        "authorized": found.and_then(|a| match a.outcome {
            ProbeOutcome::Core { authorized } => Some(authorized),
            _ => None,
        }),
        "probes": probes_json(probes),
        "attempts": attempts.iter().map(|a| serde_json::json!({
            "base_url": a.candidate.base_url,
            "topology": a.candidate.class.as_str(),
            "outcome": outcome_str(a.outcome),
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use embarch_topology::software::{Candidate, TopologyClass};

    fn core_attempt(authorized: bool) -> Attempt {
        Attempt {
            candidate: Candidate { class: TopologyClass::Local, base_url: "http://127.0.0.1:4884".to_string() },
            outcome: ProbeOutcome::Core { authorized },
        }
    }

    fn unreachable_attempt() -> Attempt {
        Attempt {
            candidate: Candidate { class: TopologyClass::Local, base_url: "http://127.0.0.1:4884".to_string() },
            outcome: ProbeOutcome::Unreachable,
        }
    }

    /// A found Core with a resolved token and probes attached reports the
    /// count, distinctly from either "unknown" state below — the shape
    /// `embarch-umbrella` decision 46 and the spec.md row it closes require.
    #[test]
    fn json_reports_the_probe_count_when_core_and_a_token_are_both_found() {
        let attempts = vec![core_attempt(true)];
        let json = status_json(&attempts, &ProbeReport::Count(3));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["reachable"], true);
        assert_eq!(v["probes"]["state"], "ok");
        assert_eq!(v["probes"]["count"], 3);
        assert!(v["probes"]["reason"].is_null());
    }

    /// Reachable but no token resolves is its own state — never a probe
    /// count of `0`, which is indistinguishable from "found Core, no probes
    /// plugged in" (the task's own "must be its own reported state" rule).
    #[test]
    fn json_reports_no_token_as_its_own_state_not_a_zero_count() {
        let attempts = vec![core_attempt(false)];
        let reason = "no EMBARCH_TOKEN, no token file".to_string();
        let json = status_json(&attempts, &ProbeReport::NoToken(reason.clone()));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["reachable"], true);
        assert_eq!(v["probes"]["state"], "no-token");
        assert!(v["probes"]["count"].is_null());
        assert_eq!(v["probes"]["reason"], reason);
    }

    /// Core rejecting the resolved token is distinct from not having one at
    /// all, and from a plain unreachable Core.
    #[test]
    fn json_reports_unauthorized_as_its_own_state() {
        let attempts = vec![core_attempt(false)];
        let json = status_json(&attempts, &ProbeReport::Unauthorized);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["probes"]["state"], "unauthorized");
        assert!(v["probes"]["count"].is_null());
    }

    /// No candidate answered as Core at all: `reachable: false`, and probes
    /// report `unreachable` rather than any of the found-Core states.
    #[test]
    fn json_reports_unreachable_when_no_candidate_is_core() {
        let attempts = vec![unreachable_attempt()];
        let json = status_json(&attempts, &ProbeReport::Unreachable);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["reachable"], false);
        assert_eq!(v["probes"]["state"], "unreachable");
        assert!(v["probes"]["count"].is_null());
    }

    /// `probe_report` on an unresolved base URL never touches the network —
    /// it must short-circuit to `Unreachable` before making a request.
    #[tokio::test]
    async fn probe_report_is_unreachable_with_no_base_url() {
        let report = probe_report(None).await;
        assert_eq!(report.state_str(), "unreachable");
    }

    /// The request succeeded — Core is up, authenticated, and answered
    /// `200` — but the body carries no `probes` array. This must not read
    /// as `request-failed`: that label is what a `--json` consumer switches
    /// on to decide whether to retry, and retrying this gets the same
    /// answer forever (`embarch-umbrella` task 039).
    #[test]
    fn a_200_with_no_probes_array_is_bad_response_not_request_failed() {
        let report = interpret_probe_response(200, "{}");
        assert_eq!(report.state_str(), "bad-response");
        assert_ne!(report.state_str(), "request-failed");

        let attempts = vec![core_attempt(true)];
        let json = status_json(&attempts, &report);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["probes"]["state"], "bad-response");
        assert!(v["probes"]["count"].is_null());
        assert!(v["probes"]["reason"].as_str().unwrap().contains("no `probes` array"));
    }

    /// A non-`200`/`401` status is still the transport-failure state:
    /// `interpret_probe_response`'s two outcomes stay distinct.
    #[test]
    fn a_non_200_status_is_still_request_failed() {
        let report = interpret_probe_response(500, "");
        assert_eq!(report.state_str(), "request-failed");
    }

    /// Pins `status --json`'s top-level keys and version: dropping a key, or
    /// changing the shape without moving `JSON_SCHEMA_VERSION`, fails here.
    #[test]
    fn status_json_top_level_keys_and_version_are_pinned() {
        let v: serde_json::Value =
            serde_json::from_str(&status_json(&[core_attempt(true)], &ProbeReport::Count(1))).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["attempts", "authorized", "base_url", "probes", "reachable", "schema_version", "success", "topology"]
        );
        assert_eq!(v["schema_version"], 1);
        assert_eq!(JSON_SCHEMA_VERSION, 1, "bump the pinned shape tests with the constant");
        assert_eq!(v["success"], true);
    }
}
