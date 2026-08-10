//! `embarch` — setup and diagnostics for the EmbArch suite.
//!
//! Design doc: ../embarch-doc/embarch-umbrella/design.md
//! Execution plan: ../embarch-doc/embarch-umbrella/milestone-6.md
//!
//! Implemented so far: topology detection (§3.2), `setup` (§3.3), `init`,
//! `up`/`down`, `doctor` (§3.4), and enough of `status` to be useful. §3.7
//! (release CI) and §3.8 (dogfooding the guide) are what remains.

mod config;
mod doctor;
mod env;
mod init;
mod locate;
mod probe;
mod setup;
mod state;
mod token;
mod topology;

use clap::{Parser, Subcommand};

use topology::{winner, Attempt, ProbeOutcome, DEFAULT_CORE_PORT};

/// Exit codes follow embarch-api's CLI convention (embarch-api/design.md §5a):
/// 0 success, 1 any operation failure, 2 (clap's own) malformed invocation.
const EXIT_FAILURE: i32 = 1;

#[derive(Parser)]
#[command(
    name = "embarch",
    version,
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
    /// One-time per-machine setup: detect the topology, install Core as a
    /// service that starts at boot, and record what it found.
    ///
    /// Does not edit your PATH — it prints the line to add instead.
    Setup {
        /// Core is on another machine at this host. Skips any local install.
        #[arg(long)]
        host: Option<String>,

        /// Core's port.
        #[arg(long, default_value_t = DEFAULT_CORE_PORT)]
        port: u16,
    },

    /// Integrate the firmware repo in the current directory: scaffold
    /// `embarch/embarch.toml`, register the MCP server, exclude locally.
    Init {
        /// Reverse everything `init` did in this repo.
        #[arg(long)]
        uninstall: bool,
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

    /// Fallback: stop the running Core service, leaving it installed.
    Down,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // stderr, so stdout stays reserved for command results and `--json`
    // output — same split embarch-api's CLI uses (embarch-api/design.md §10).
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let cli = Cli::parse();

    let code = match cli.command {
        Command::Status { json, host, port } => status(json, host.as_deref(), port).await,
        Command::Setup { host, port } => setup::setup(host.as_deref(), port).await,
        Command::Init { uninstall } => init::init(uninstall),
        Command::Doctor { json } => doctor::doctor(json).await,
        Command::Up { foreground } => setup::up(foreground),
        Command::Down => setup::down(),
    };

    std::process::exit(code);
}

/// Find Core and report where it is. Returns the process exit code.
async fn status(json: bool, host: Option<&str>, port: u16) -> i32 {
    let under_wsl2 = env::under_wsl2();
    let gateway = if under_wsl2 {
        env::default_gateway()
    } else {
        None
    };

    let candidates = topology::candidates(under_wsl2, gateway.as_deref(), host, port);
    let client = reqwest::Client::new();
    // The async block owns its `url` and borrows the client (a shared
    // reference is Copy, so the closure stays `Fn` across candidates).
    let client = &client;
    let attempts = topology::resolve(&candidates, move |url| async move {
        probe::probe_core(client, &url).await
    })
    .await;

    if json {
        println!("{}", status_json(&attempts));
    } else {
        print_status(&attempts);
    }

    if winner(&attempts).is_some() {
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

fn print_status(attempts: &[Attempt]) {
    match winner(attempts) {
        Some(found) => {
            println!(
                "Core: up at {} ({})",
                found.candidate.base_url,
                found.candidate.class.as_str()
            );
            // Not a warning about Core — a statement about how far this
            // command currently looks. Probe listing and a real token check
            // arrive with milestone-6.md §3.3/§3.4.
            println!("  auth: not checked (this probe is unauthenticated)");
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

fn status_json(attempts: &[Attempt]) -> String {
    let found = winner(attempts);
    serde_json::json!({
        "reachable": found.is_some(),
        "base_url": found.map(|a| a.candidate.base_url.clone()),
        "topology": found.map(|a| a.candidate.class.as_str()),
        "authorized": found.and_then(|a| match a.outcome {
            ProbeOutcome::Core { authorized } => Some(authorized),
            _ => None,
        }),
        "attempts": attempts.iter().map(|a| serde_json::json!({
            "base_url": a.candidate.base_url,
            "topology": a.candidate.class.as_str(),
            "outcome": outcome_str(a.outcome),
        })).collect::<Vec<_>>(),
    })
    .to_string()
}
