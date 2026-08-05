//! `embarch` — setup and diagnostics for the EmbArch suite.
//!
//! Design doc: ../embarch-doc/embarch-umbrella/design.md
//! Execution plan: ../embarch-doc/embarch-umbrella/milestone-6.md
//!
//! This is the milestone-6 §3.1 bootstrap: the command surface from design.md
//! §8 exists and parses, and every command reports itself unimplemented rather
//! than pretending to work. The behavior behind each one lands in §3.2–§3.4.

use clap::{Parser, Subcommand};

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
    /// service, ensure the token exists, put both binaries on PATH.
    Setup,

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

    /// Cheap liveness check: is Core up, which topology, how many probes.
    Status {
        /// Emit one JSON object instead of human-readable output.
        #[arg(long)]
        json: bool,
    },

    /// Fallback: start Core when it isn't already a running service.
    Up,

    /// Fallback: stop a Core started by `up`.
    Down,
}

fn main() {
    // stderr, so stdout stays reserved for command results and `--json`
    // output — same split embarch-api's CLI uses (embarch-api/design.md §10).
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let cli = Cli::parse();

    // Every arm is milestone-6 work that hasn't been done. Kept explicit
    // per-command rather than collapsed into one catch-all so each one turns
    // into a real implementation without restructuring dispatch.
    let (what, plan) = match cli.command {
        Command::Setup => ("setup", "milestone-6.md §3.3"),
        Command::Init { .. } => ("init", "milestone-6.md §3.4"),
        Command::Doctor { .. } => ("doctor", "milestone-6.md §3.4, design.md §5"),
        Command::Status { .. } => ("status", "milestone-6.md §3.4"),
        Command::Up => ("up", "milestone-6.md §3.4, design.md §3 decisions 4/7"),
        Command::Down => ("down", "milestone-6.md §3.4, design.md §3 decisions 4/7"),
    };

    eprintln!("embarch {what}: not implemented yet — see ../embarch-doc/embarch-umbrella/{plan}");
    std::process::exit(EXIT_FAILURE);
}
