//! `embarch init` — integrate the firmware repo in the current directory.
//!
//! Decisions 10, 12, 13. The whole point is that a firmware repo
//! you don't own ends up with **nothing tracked modified**: the config lives
//! in an `embarch/` folder excluded through `.git/info/exclude` (local to this
//! clone, unlike a committed `.gitignore`), and the MCP server is registered
//! at Claude Code's local scope rather than by writing a `.mcp.json`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use anyhow::{Context, Result};

use crate::locate;

const EXCLUDE_MARKER: &str = "# added by `embarch init`";
const EXCLUDE_ENTRY: &str = "embarch/";
const MCP_SERVER_NAME: &str = "embarch";

/// The one sentinel this file uses for "`init` could not know this — you do".
/// Deliberately the same string `chip` has always used: a scaffolded config
/// already ships in a state that cannot run until a human edits it, and the
/// board is now in that class too (decisions/projects.md 41).
const BOARD_PLACEHOLDER: &str = "CHANGE-ME";

/// Walk up from `start` looking for a `.git`, returning the repo root.
pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Pull `west.command` out of a `build_info.yml`.
///
/// A targeted extraction, **not** a YAML parser: it looks for the `west:`
/// block and the `command:` key one level under it. That's enough for the one
/// field that matters and avoids a YAML dependency for a single line, but it
/// will not survive an arbitrary reformatting of the file — west generates
/// this, so the shape is stable in practice.
///
/// Why this field at all: it is the only reliable answer to west's
/// build-directory trap (`embarch-api` interfaces/config.md). `west build -b <board>
/// app/foo` run from the repo root puts output in `<root>/build`, not
/// `<root>/app/foo/build`, and guessing wrong makes a stale artifact look
/// fresh — the worst failure mode during bring-up.
pub fn parse_west_command(yaml: &str) -> Option<String> {
    let mut in_west = false;
    for line in yaml.lines() {
        if !line.starts_with(char::is_whitespace) {
            in_west = line.trim_end() == "west:";
            continue;
        }
        if !in_west {
            continue;
        }
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("command:") {
            let value = value.trim().trim_matches('\'').trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Split a recorded command line into argv.
///
/// Handles single/double-quoted runs so a path with spaces survives; west
/// writes the command as one flat string, so some splitting is unavoidable.
pub fn split_argv(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;

    for c in command.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                any = true;
            }
            None if c.is_whitespace() => {
                if any || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                    any = false;
                }
            }
            None => current.push(c),
        }
    }
    if any || !current.is_empty() {
        out.push(current);
    }
    out
}

/// Point a `west build` argv at EmbArch's own build directory.
///
/// Replaces an existing `-d`/`--build-dir` rather than adding a second one.
/// A separate build directory isn't optional (decision 10):
/// sharing one with the engineer's interactive builds means the two clobber
/// each other's tree — different board revisions, different pristine state.
pub fn with_build_dir(argv: &[String], build_dir: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(argv.len() + 2);
    let mut skip_next = false;
    for arg in argv {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "-d" || arg == "--build-dir" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--build-dir=") {
            continue;
        }
        out.push(arg.clone());
    }
    // After the subcommand (`west build`), before any positional app path —
    // west accepts options anywhere, but this reads the way a human would
    // have written it.
    let insert_at = out.len().min(2);
    out.splice(
        insert_at..insert_at,
        ["-d".to_string(), build_dir.to_string()],
    );
    out
}

/// The Windows-visible UNC form of a WSL2 path, for `artifact_path_for_core`
/// (`embarch-api` spec.md §4) — what a Windows-hosted Core needs in
/// order to open a file the build wrote inside the WSL2 guest.
pub fn wsl_unc_path(distro: &str, absolute: &Path) -> String {
    let tail = absolute
        .to_string_lossy()
        .trim_start_matches('/')
        .replace('/', "\\");
    format!("\\\\wsl.localhost\\{distro}\\{tail}")
}

/// Find where a previous build actually put its artifact.
///
/// Looks rather than assumes, deliberately: sysbuild puts it at
/// `build/<app>/zephyr/zephyr.hex` while a plain build uses
/// `build/zephyr/zephyr.hex`, and which one applies depends on the SDK
/// (`embarch-dev-bench` decision 4's correction). Shortest match
/// wins, so a plain build's path beats a nested one when both exist.
pub fn find_artifact(build_dir: &Path, file_name: &str) -> Option<PathBuf> {
    let mut best: Option<PathBuf> = None;
    let mut stack = vec![(build_dir.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 4 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push((path, depth + 1));
            } else if path.file_name().is_some_and(|n| n == file_name) {
                let better = best
                    .as_ref()
                    .is_none_or(|b| path.components().count() < b.components().count());
                if better {
                    best = Some(path);
                }
            }
        }
    }
    best
}

/// The `-b`/`--board` value in a recorded build argv, if it named one.
pub fn board_in_argv(argv: &[String]) -> Option<String> {
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        if arg == "-b" || arg == "--board" {
            return it.next().filter(|v| !v.is_empty()).cloned();
        }
        if let Some(v) = arg.strip_prefix("--board=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Replace the board in a build argv with [`BOARD_PLACEHOLDER`], returning
/// whatever it displaced.
///
/// This is the whole of decision 41's mechanism. The recorded command is kept
/// otherwise verbatim — the west binary, the app path, the pristine flag are
/// all *this repo's* facts and `build_info.yml` is authoritative for them. The
/// board is the one field that is a claim about **hardware on a desk**, which
/// the file cannot know, so it is the one field redacted.
pub fn redact_board(argv: &[String]) -> (Vec<String>, Option<String>) {
    let mut out: Vec<String> = Vec::with_capacity(argv.len());
    let mut displaced = None;
    let mut take_next = false;
    for arg in argv {
        if take_next {
            take_next = false;
            if !arg.is_empty() {
                displaced = Some(arg.clone());
                out.push(BOARD_PLACEHOLDER.to_string());
                continue;
            }
        }
        if arg == "-b" || arg == "--board" {
            take_next = true;
            out.push(arg.clone());
            continue;
        }
        if let Some(v) = arg.strip_prefix("--board=") {
            if !v.is_empty() {
                displaced = Some(v.to_string());
                out.push(format!("--board={BOARD_PLACEHOLDER}"));
                continue;
            }
        }
        out.push(arg.clone());
    }
    (out, displaced)
}

/// How stale a recorded build is, phrased the way the question is actually
/// asked: "is this still the board on the desk?"
///
/// **An age, deliberately, and not a calendar date.** `init` runs today
/// whichever way, so a date stamped at write time dates the *scaffolding*, not
/// the build it inferred from — the number that matters. Turning an mtime into
/// a civil date also needs calendar arithmetic this crate has no dependency
/// for, and would not be worth adding one. `None` for a clock that makes the
/// answer nonsense (a file from the future, a reset RTC).
pub fn recorded_age(recorded: SystemTime, now: SystemTime) -> Option<String> {
    let days = now.duration_since(recorded).ok()?.as_secs() / 86_400;
    Some(match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        n => format!("{n} days ago"),
    })
}

/// Every recorded build in the repo, not only `build/build_info.yml`.
///
/// Bounded like [`find_artifact`] and for the same reason — a firmware repo's
/// tree is not something to walk unbounded. Sorted, so the report `init`
/// prints is stable between runs.
pub fn find_build_infos(repo: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![(repo.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // `.git` holds no builds, and a dotted directory is somebody
                // else's cache far more often than it is a build tree.
                if depth < 4 && !name.starts_with('.') {
                    stack.push((path, depth + 1));
                }
            } else if name == "build_info.yml" {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// One recorded build, as `init` will describe it to the user.
///
/// Holds the *contents* rather than a path so that [`scaffold_build_command`]
/// — where the whole of decision 41 lives — is pure and testable without a
/// repo on disk.
pub struct RecordedBuild {
    /// How to name this file to the user; repo-relative where possible.
    pub label: String,
    /// `west.command` from the file, if it had one.
    pub command: Option<String>,
    /// [`recorded_age`] of the file, if the filesystem would say.
    pub age: Option<String>,
}

/// What `init` writes for `build_command`, and what it says about it.
pub struct BuildCommandPlan {
    pub argv: Vec<String>,
    /// Comment lines emitted directly above `build_command` in the config.
    pub notes: Vec<String>,
    /// Lines for `init`'s own stdout, under "before this works, edit ...".
    pub warnings: Vec<String>,
}

/// Decide what `build_command` to scaffold from the builds the repo recorded.
///
/// **Decision 41.** Three cases, and none of them writes a board as fact:
///
/// - **None recorded** — a bare template, exactly as before.
/// - **One** — the recorded command, verbatim except that its board is
///   redacted to [`BOARD_PLACEHOLDER`] and quoted back in a comment with the
///   build's age. A wrong board can no longer build silently; it costs one
///   paste to confirm.
/// - **Several** — nothing is chosen. Every candidate is named with the board
///   it recorded, in the config and on stdout, and the command is the same
///   bare template as the none case.
pub fn scaffold_build_command(recorded: &[RecordedBuild], build_dir_rel: &str) -> BuildCommandPlan {
    let template = || -> Vec<String> {
        ["west", "build", "-d", build_dir_rel, "-b", BOARD_PLACEHOLDER]
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let describe = |b: &RecordedBuild| -> String {
        let board = b
            .command
            .as_deref()
            .map(split_argv)
            .and_then(|a| board_in_argv(&a))
            .unwrap_or_else(|| "no board recorded".to_string());
        let age = b
            .age
            .as_deref()
            .map(|a| format!(", built {a}"))
            .unwrap_or_default();
        format!("{} — {board}{age}", b.label)
    };

    match recorded {
        [] => BuildCommandPlan {
            argv: template(),
            notes: vec![
                "`init` found no recorded build in this repo, so the command below is a".to_string(),
                "template rather than anything observed. Check it against how you actually"
                    .to_string(),
                "build, and replace the board.".to_string(),
            ],
            warnings: vec![
                "no build_info.yml anywhere in this repo, so the build command below is a \
                 template — check it against how you actually build."
                    .to_string(),
            ],
        },
        [only] => {
            let Some(command) = only.command.as_deref() else {
                return BuildCommandPlan {
                    argv: template(),
                    notes: vec![
                        format!("`init` found {} but it records no west command, so the", only.label),
                        "command below is a template rather than anything observed.".to_string(),
                    ],
                    warnings: vec![format!(
                        "{} records no west command, so the build command below is a template — \
                         check it against how you actually build.",
                        only.label
                    )],
                };
            };
            let age = only
                .age
                .as_deref()
                .map(|a| format!(", built {a}"))
                .unwrap_or_default();
            let (argv, board) = redact_board(&with_build_dir(&split_argv(command), build_dir_rel));
            let mut notes = vec![
                format!("`init` derived this from {}{age}.", only.label),
                "That file records whatever was LAST built in this repo, which is not the"
                    .to_string(),
                "same fact as which board is wired to your probe — so the board is not"
                    .to_string(),
                "written below as though it were (embarch-api/spec.md §2).".to_string(),
            ];
            let warnings = match &board {
                Some(board) => {
                    notes.push(format!("The board it recorded was: {board}"));
                    notes.push(format!(
                        "Confirm that is the board on your desk, then paste it over {BOARD_PLACEHOLDER}."
                    ));
                    vec![format!(
                        "set the board in `build_command` (it's {BOARD_PLACEHOLDER} right now). {} \
                         recorded `-b {board}`{age}, but that is whatever was last built here, not \
                         what is on your probe — confirm it before you paste it in.",
                        only.label
                    )]
                }
                None => {
                    notes.push(format!(
                        "It named no board, so one was added as {BOARD_PLACEHOLDER}."
                    ));
                    vec![format!(
                        "{} recorded no board, so `build_command` has none to check — add \
                         `-b <your board>` to it.",
                        only.label
                    )]
                }
            };
            // A recorded command with no `-b` at all still must not ship
            // boardless: west would take its default and that is a guess too.
            let argv = if board.is_none() && board_in_argv(&argv).is_none() {
                let mut argv = argv;
                argv.push("-b".to_string());
                argv.push(BOARD_PLACEHOLDER.to_string());
                argv
            } else {
                argv
            };
            BuildCommandPlan {
                argv,
                notes,
                warnings,
            }
        }
        several => {
            let mut notes = vec![format!(
                "`init` found {} recorded builds in this repo and chose none of them:",
                several.len()
            )];
            let mut warning = vec![format!(
                "{} recorded builds here, and `init` will not pick one for you:",
                several.len()
            )];
            for b in several {
                notes.push(format!("  {}", describe(b)));
                warning.push(format!("      {}", describe(b)));
            }
            notes.push(
                "The command below is a template. Paste the right one over it, keeping".to_string(),
            );
            notes.push(format!("`-d {build_dir_rel}`."));
            warning.push(format!(
                "    paste the one matching the board on your desk into `build_command`, keeping \
                 `-d {build_dir_rel}`."
            ));
            BuildCommandPlan {
                argv: template(),
                notes,
                warnings: vec![warning.join("\n")],
            }
        }
    }
}

pub struct Scaffold {
    pub toml: String,
    /// Things `init` could not work out, to print rather than guess at
    /// (decision 13).
    pub warnings: Vec<String>,
}

/// Build the config text for a `discovery = "zephyr-west"` project
/// (decision 17, `embarch-api` decision 12): no
/// `build_command`/`chip`/`artifact_path`/`artifact_path_for_core` — those
/// are resolved live, per call, by `embarch-api` instead.
pub fn render_zephyr_west_config(
    name: &str,
    source_path: &Path,
    west_binary: &str,
    build_dir_root: &str,
) -> String {
    format!(
        "# Written by `embarch init`. Local to this clone — excluded via\n\
         # .git/info/exclude, so nothing tracked by this repo was modified.\n\
         \n\
         [core]\n\
         # Not an address: Core is found at first use, every time. Don't replace\n\
         # this with an IP — under WSL2 that IP changes on every restart.\n\
         base_url = \"auto\"\n\
         \n\
         [[projects]]\n\
         name = {name:?}\n\
         source_path = {source:?}\n\
         # Zephyr/west detected here (boards/*/*.yml + app/*/CMakeLists.txt): board,\n\
         # chip, and artifact path are resolved live, per call, instead of stored —\n\
         # see `embarch-api list-targets {name}` and embarch-api decision 12 (decisions/zephyr.md).\n\
         discovery = \"zephyr-west\"\n\
         west_binary = {west_binary:?}\n\
         # Per-target subdirectories are computed under this, never shared between\n\
         # distinct (board, variant, revision, app) targets.\n\
         build_dir_root = {build_dir_root:?}\n\
         flash_format = \"hex\"\n\
         build_timeout_secs = 900\n",
        name = name,
        source = source_path.to_string_lossy(),
        west_binary = west_binary,
        build_dir_root = build_dir_root,
    )
}

/// Build the config text for a repo.
///
/// Pure: everything it needs is already resolved by the caller, so the
/// interesting derivations are testable without a repo on disk.
pub fn render_config(
    name: &str,
    source_path: &Path,
    build_command: &[String],
    build_command_notes: &[String],
    artifact_path: &str,
    unc_artifact: Option<&str>,
) -> String {
    let argv = build_command
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    // Where `build_command` came from and how far it can be trusted, in the
    // file the user will actually open — decision 41. `init`'s stdout says the
    // same thing, and scrolls away.
    let notes = build_command_notes
        .iter()
        .map(|l| {
            if l.is_empty() {
                "#\n".to_string()
            } else {
                format!("# {l}\n")
            }
        })
        .collect::<String>();
    let unc_line = match unc_artifact {
        Some(p) => format!(
            "# Windows-visible form of the same file, for a Core running on the Windows\n\
             # side of this WSL2 split (decision 16, decisions/mirrors.md).\nartifact_path_for_core = {:?}\n",
            p
        ),
        None => String::new(),
    };
    format!(
        "# Written by `embarch init`. Local to this clone — excluded via\n\
         # .git/info/exclude, so nothing tracked by this repo was modified.\n\
         \n\
         [core]\n\
         # Not an address: Core is found at first use, every time. Don't replace\n\
         # this with an IP — under WSL2 that IP changes on every restart.\n\
         base_url = \"auto\"\n\
         \n\
         [[projects]]\n\
         name = {name:?}\n\
         source_path = {source:?}\n\
         {notes}\
         build_command = [{argv}]\n\
         artifact_path = {artifact_path:?}\n\
         # A probe-rs target name, NOT your Zephyr board name. Find it with:\n\
         #   probe-rs chip list | grep -i <your soc>\n\
         chip = \"CHANGE-ME\"\n\
         flash_format = \"hex\"\n\
         build_timeout_secs = 900\n\
         {unc_line}",
        name = name,
        source = source_path.to_string_lossy(),
        notes = notes,
        argv = argv,
        artifact_path = artifact_path,
        unc_line = unc_line,
    )
}

fn add_to_git_exclude(repo: &Path) -> Result<bool> {
    let exclude = repo.join(".git").join("info").join("exclude");
    let existing = std::fs::read_to_string(&exclude).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == EXCLUDE_ENTRY) {
        return Ok(false);
    }
    if let Some(dir) = exclude.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{EXCLUDE_MARKER}\n{EXCLUDE_ENTRY}\n"));
    std::fs::write(&exclude, text)
        .with_context(|| format!("could not write {}", exclude.display()))?;
    Ok(true)
}

fn remove_from_git_exclude(repo: &Path) -> Result<bool> {
    let exclude = repo.join(".git").join("info").join("exclude");
    let Ok(existing) = std::fs::read_to_string(&exclude) else {
        return Ok(false);
    };
    let kept: Vec<&str> = existing
        .lines()
        .filter(|l| l.trim() != EXCLUDE_ENTRY && l.trim() != EXCLUDE_MARKER)
        .collect();
    if kept.len() == existing.lines().count() {
        return Ok(false);
    }
    let mut text = kept.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    std::fs::write(&exclude, text)
        .with_context(|| format!("could not write {}", exclude.display()))?;
    Ok(true)
}

/// Register the MCP server at local scope, or print the command if the
/// `claude` CLI isn't available. Never writes a `.mcp.json` — that file is
/// tracked, and this must not touch tracked files (decision 12).
fn register_mcp(api: &Path, config: &Path) -> bool {
    let args = [
        "mcp".to_string(),
        "add".to_string(),
        MCP_SERVER_NAME.to_string(),
        "--".to_string(),
        api.to_string_lossy().into_owned(),
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
    ];

    match Command::new("claude").args(&args).status() {
        Ok(s) if s.success() => true,
        _ => {
            println!(
                "  could not register it automatically — run this yourself:\n    claude {}",
                args.join(" ")
            );
            false
        }
    }
}

pub fn init(uninstall: bool) -> i32 {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not read the current directory: {e}");
            return 1;
        }
    };
    let Some(repo) = find_repo_root(&cwd) else {
        eprintln!("not inside a git repository — run `embarch init` from a firmware repo.");
        return 1;
    };

    if uninstall {
        return uninit(&repo);
    }

    let embarch_dir = repo.join("embarch");
    let config_path = embarch_dir.join("embarch.toml");
    println!("Repo: {}", repo.display());

    if config_path.exists() {
        println!(
            "{} already exists — leaving it alone. Delete it, or run `embarch init --uninstall` \
             first, to regenerate.",
            config_path.display()
        );
        return 1;
    }

    let name = repo
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "firmware".to_string());
    let mut warnings = Vec::new();
    let build_dir_rel = "embarch/build";
    let build_info = repo.join("build").join("build_info.yml");

    // decision 17: a repo shaped like a real Zephyr/west
    // project (several boards/variants/revisions worth discovering live,
    // not one to guess) gets the minimal discovery = "zephyr-west" schema
    // instead of a single hand-picked board — `embarch init`'s old behavior
    // silently picked the wrong one of several real boards in the
    // reference-dut repo, with no signal a choice had even been made.
    if crate::zephyr::looks_zephyr_west_shaped(&repo) {
        println!("Detected a Zephyr/west project (boards/*/*.yml + app/*/CMakeLists.txt).");
        let west_binary = std::fs::read_to_string(&build_info)
            .ok()
            .and_then(|y| parse_west_command(&y))
            .and_then(|cmd| split_argv(&cmd).into_iter().next())
            .unwrap_or_else(|| {
                warnings.push(format!(
                    "no {} found, so west_binary defaults to `west` (found on PATH) — set it to the \
                     exact binary this repo's build uses if that's wrong (e.g. a workspace venv path).",
                    build_info.display()
                ));
                "west".to_string()
            });

        let scaffold = Scaffold {
            toml: render_zephyr_west_config(&name, &repo, &west_binary, build_dir_rel),
            warnings,
        };

        if let Err(e) = std::fs::create_dir_all(&embarch_dir) {
            eprintln!("could not create {}: {e}", embarch_dir.display());
            return 1;
        }
        if let Err(e) = std::fs::write(&config_path, &scaffold.toml) {
            eprintln!("could not write {}: {e}", config_path.display());
            return 1;
        }
        println!("Wrote {}", config_path.display());

        match add_to_git_exclude(&repo) {
            Ok(true) => println!("Excluded embarch/ via .git/info/exclude (nothing tracked changed)"),
            Ok(false) => println!("embarch/ was already excluded"),
            Err(e) => println!("Could not update .git/info/exclude: {e:#}"),
        }

        print!("Registering the MCP server for this repo... ");
        match locate::locate_api(None) {
            Some(api) => {
                if register_mcp(&api.path, &config_path) {
                    println!("done");
                }
            }
            None => println!(
                "\n  embarch-api not found — register it once you have it:\n    \
                 claude mcp add {MCP_SERVER_NAME} -- <path to embarch-api> --config {}",
                config_path.display()
            ),
        }

        println!("\n{} has no chip/build_command to edit — both are resolved live, per call.", config_path.display());
        for w in &scaffold.warnings {
            println!("  - {w}");
        }
        println!(
            "\nThen: `embarch status`, `embarch-api --config {} list-targets {name}` to see what's \
             buildable, and `embarch-api --config {} build {name} --board <board> [--variant <v>] \
             [--revision <r>] [--app <a>]`.",
            config_path.display(),
            config_path.display()
        );
        return 0;
    }

    // Derive the build command from what west actually ran, when it can — and
    // from *every* recorded build, not just the one at `build/`, so a repo
    // holding several is reported rather than silently resolved (decision 41).
    let now = SystemTime::now();
    let recorded: Vec<RecordedBuild> = find_build_infos(&repo)
        .into_iter()
        .map(|path| RecordedBuild {
            label: path
                .strip_prefix(&repo)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string(),
            command: std::fs::read_to_string(&path)
                .ok()
                .and_then(|y| parse_west_command(&y)),
            age: std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| recorded_age(t, now)),
        })
        .collect();

    match recorded.len() {
        0 => {}
        1 => println!("Derived the build command from {}", recorded[0].label),
        n => println!("Found {n} recorded builds — see below; `init` picked none of them."),
    }
    let plan = scaffold_build_command(&recorded, build_dir_rel);
    let build_command = plan.argv;
    warnings.extend(plan.warnings);
    if build_command.iter().any(|a| a == "always") && build_command.iter().any(|a| a == "-p") {
        warnings.push(
            "your build command has `-p always`, so every EmbArch build is a full \
             rebuild. Now that EmbArch has its own build directory, you can probably \
             drop it."
                .to_string(),
        );
    }

    // Look for where a real build put its artifact rather than assuming.
    let artifact_path = match find_artifact(&repo.join("build"), "zephyr.hex") {
        Some(found) => {
            let rel = found
                .strip_prefix(repo.join("build"))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "zephyr/zephyr.hex".to_string());
            println!("Found a previous build's artifact at build/{rel}");
            format!("{build_dir_rel}/{rel}")
        }
        None => {
            warnings.push(
                "no previous build found, so artifact_path is the conventional location — if \
                 your SDK uses sysbuild the real path is build/<app>/zephyr/zephyr.hex instead."
                    .to_string(),
            );
            format!("{build_dir_rel}/zephyr/zephyr.hex")
        }
    };

    let unc = std::env::var("WSL_DISTRO_NAME")
        .ok()
        .filter(|d| !d.is_empty())
        .map(|distro| wsl_unc_path(&distro, &repo.join(&artifact_path)));

    let scaffold = Scaffold {
        toml: render_config(
            &name,
            &repo,
            &build_command,
            &plan.notes,
            &artifact_path,
            unc.as_deref(),
        ),
        warnings,
    };

    if let Err(e) = std::fs::create_dir_all(&embarch_dir) {
        eprintln!("could not create {}: {e}", embarch_dir.display());
        return 1;
    }
    if let Err(e) = std::fs::write(&config_path, &scaffold.toml) {
        eprintln!("could not write {}: {e}", config_path.display());
        return 1;
    }
    println!("Wrote {}", config_path.display());

    match add_to_git_exclude(&repo) {
        Ok(true) => println!("Excluded embarch/ via .git/info/exclude (nothing tracked changed)"),
        Ok(false) => println!("embarch/ was already excluded"),
        Err(e) => println!("Could not update .git/info/exclude: {e:#}"),
    }

    print!("Registering the MCP server for this repo... ");
    match locate::locate_api(None) {
        Some(api) => {
            if register_mcp(&api.path, &config_path) {
                println!("done");
            }
        }
        None => println!(
            "\n  embarch-api not found — register it once you have it:\n    \
             claude mcp add {MCP_SERVER_NAME} -- <path to embarch-api> --config {}",
            config_path.display()
        ),
    }

    println!("\nBefore this works, edit {}:", config_path.display());
    println!("  - set `chip` to your probe-rs target name (it's CHANGE-ME right now)");
    for w in &scaffold.warnings {
        println!("  - {w}");
    }
    println!("\nThen: `embarch status`, and `embarch-api --config {} build {name}`.", config_path.display());
    0
}

fn uninit(repo: &Path) -> i32 {
    let embarch_dir = repo.join("embarch");
    println!("Repo: {}", repo.display());

    match std::fs::remove_dir_all(&embarch_dir) {
        Ok(()) => println!("Removed {}", embarch_dir.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No {} to remove", embarch_dir.display())
        }
        Err(e) => println!("Could not remove {}: {e}", embarch_dir.display()),
    }

    match remove_from_git_exclude(repo) {
        Ok(true) => println!("Removed embarch/ from .git/info/exclude"),
        Ok(false) => println!("Nothing to remove from .git/info/exclude"),
        Err(e) => println!("Could not update .git/info/exclude: {e:#}"),
    }

    match Command::new("claude")
        .args(["mcp", "remove", MCP_SERVER_NAME])
        .status()
    {
        Ok(s) if s.success() => println!("Unregistered the MCP server"),
        _ => println!("Could not unregister the MCP server — run: claude mcp remove {MCP_SERVER_NAME}"),
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Shaped exactly like a real west build_info.yml, including the `cmake:`
    // block ahead of it that a naive "find command:" search would trip over.
    const BUILD_INFO: &str = "cmake:\n  application:\n    source-dir: '/repo/app/hb'\n  board:\n    name: 'roadrunner'\nversion: '0.1.0'\nwest:\n  command: '/ws/.venv/bin/west build -p always -b roadrunner@2/nrf54l15/cpuapp app/reference-dut'\n  topdir: '/ws'\n";

    #[test]
    fn west_command_is_extracted_from_the_west_block() {
        assert_eq!(
            parse_west_command(BUILD_INFO).as_deref(),
            Some("/ws/.venv/bin/west build -p always -b roadrunner@2/nrf54l15/cpuapp app/reference-dut")
        );
    }

    #[test]
    fn a_file_without_a_west_block_yields_nothing() {
        assert_eq!(parse_west_command("cmake:\n  application:\n    x: 'y'\n"), None);
    }

    #[test]
    fn argv_splitting_keeps_quoted_paths_together() {
        assert_eq!(
            split_argv("west build -b 'my board' app"),
            vec!["west", "build", "-b", "my board", "app"]
        );
        assert_eq!(split_argv("  west   build  "), vec!["west", "build"]);
        assert!(split_argv("").is_empty());
    }

    #[test]
    fn build_dir_is_inserted_after_the_subcommand() {
        let argv = split_argv("/ws/.venv/bin/west build -p always -b brd app/hb");
        let out = with_build_dir(&argv, "embarch/build");
        assert_eq!(out[0], "/ws/.venv/bin/west");
        assert_eq!(out[1], "build");
        assert_eq!(out[2], "-d");
        assert_eq!(out[3], "embarch/build");
        assert!(out.ends_with(&["app/hb".to_string()]));
    }

    #[test]
    fn an_existing_build_dir_is_replaced_not_duplicated() {
        let argv = split_argv("west build -d somewhere/else -b brd app");
        let out = with_build_dir(&argv, "embarch/build");
        assert_eq!(out.iter().filter(|a| *a == "-d").count(), 1);
        assert!(!out.iter().any(|a| a == "somewhere/else"));
        assert!(out.contains(&"embarch/build".to_string()));

        let argv = split_argv("west build --build-dir=somewhere/else -b brd app");
        let out = with_build_dir(&argv, "embarch/build");
        assert!(!out.iter().any(|a| a.contains("somewhere/else")));
    }

    #[test]
    fn unc_path_matches_what_a_windows_core_needs() {
        assert_eq!(
            wsl_unc_path("Ubuntu-24.04", Path::new("/home/me/fw/embarch/build/zephyr/zephyr.hex")),
            "\\\\wsl.localhost\\Ubuntu-24.04\\home\\me\\fw\\embarch\\build\\zephyr\\zephyr.hex"
        );
    }

    #[test]
    fn rendered_config_quotes_windows_paths_correctly() {
        let cfg = render_config(
            "fw",
            Path::new("/home/me/fw"),
            &["west".to_string(), "build".to_string()],
            &[],
            "embarch/build/zephyr/zephyr.hex",
            Some("\\\\wsl.localhost\\Ubuntu\\home\\me\\fw\\x.hex"),
        );
        // Backslashes must survive into the TOML as escaped literals, or Core
        // gets a mangled path — the failure `embarch-api` spec.md §4 records.
        assert!(cfg.contains(r#"artifact_path_for_core = "\\\\wsl.localhost\\Ubuntu\\home\\me\\fw\\x.hex""#), "{cfg}");
        assert!(cfg.contains(r#"base_url = "auto""#));
        assert!(cfg.contains(r#"chip = "CHANGE-ME""#));
    }

    #[test]
    fn rendered_config_parses_as_toml() {
        let cfg = render_config(
            "fw",
            Path::new("/home/me/fw"),
            &["west".to_string(), "build".to_string(), "-d".to_string(), "embarch/build".to_string()],
            &["derived from build/build_info.yml".to_string(), String::new()],
            "embarch/build/zephyr/zephyr.hex",
            None,
        );
        let parsed: toml::Value = toml::from_str(&cfg).expect("scaffolded config must be valid TOML");
        assert_eq!(parsed["core"]["base_url"].as_str(), Some("auto"));
        assert_eq!(parsed["projects"][0]["name"].as_str(), Some("fw"));
        // Notes are comments, so they can say anything without breaking the
        // one property every other test here depends on.
        assert!(cfg.contains("# derived from build/build_info.yml\n#\n"), "{cfg}");
    }

    // ---- decision 41: an inferred board is never written as fact ----------

    fn recorded(label: &str, command: Option<&str>, age: Option<&str>) -> RecordedBuild {
        RecordedBuild {
            label: label.to_string(),
            command: command.map(str::to_string),
            age: age.map(str::to_string),
        }
    }

    fn rendered(plan: &BuildCommandPlan) -> String {
        render_config(
            "fw",
            Path::new("/home/me/fw"),
            &plan.argv,
            &plan.notes,
            "embarch/build/zephyr/zephyr.hex",
            None,
        )
    }

    #[test]
    fn the_board_is_the_only_field_redacted_out_of_a_recorded_command() {
        let (argv, board) = redact_board(&split_argv(
            "/ws/.venv/bin/west build -p always -b roadrunner@2/nrf54l15/cpuapp app/reference-dut",
        ));
        assert_eq!(board.as_deref(), Some("roadrunner@2/nrf54l15/cpuapp"));
        assert_eq!(
            argv,
            split_argv("/ws/.venv/bin/west build -p always -b CHANGE-ME app/reference-dut")
        );

        let (argv, board) = redact_board(&split_argv("west build --board=nrf52dk/nrf52832 app"));
        assert_eq!(board.as_deref(), Some("nrf52dk/nrf52832"));
        assert!(argv.contains(&"--board=CHANGE-ME".to_string()));

        // Nothing to displace, nothing changed.
        let argv = split_argv("west build app");
        assert_eq!(redact_board(&argv), (argv.clone(), None));
    }

    #[test]
    fn one_recorded_build_is_inferred_and_marked_never_asserted() {
        let plan = scaffold_build_command(
            &[recorded("build/build_info.yml", Some("west build -b roadrunner@2/nrf54l15/cpuapp app/hb"), Some("7 days ago"))],
            "embarch/build",
        );
        // The recorded command survives except for the one hardware claim.
        assert!(plan.argv.contains(&"app/hb".to_string()));
        assert!(plan.argv.contains(&BOARD_PLACEHOLDER.to_string()));
        assert!(!plan.argv.iter().any(|a| a.contains("roadrunner")));

        let cfg = rendered(&plan);
        let parsed: toml::Value = toml::from_str(&cfg).expect("must stay valid TOML");
        let cmd = parsed["projects"][0]["build_command"].as_array().unwrap();
        // The load-bearing assertion of this whole task: the board `init`
        // inferred is nowhere in the config except inside a comment.
        assert!(
            !cmd.iter().any(|v| v.as_str().unwrap().contains("roadrunner")),
            "{cfg}"
        );
        for line in cfg.lines().filter(|l| l.contains("roadrunner")) {
            assert!(line.trim_start().starts_with('#'), "{line}");
        }
        // ...but it is still there to paste, with how stale it is.
        assert!(cfg.contains("The board it recorded was: roadrunner@2/nrf54l15/cpuapp"), "{cfg}");
        assert!(cfg.contains("built 7 days ago"), "{cfg}");
        assert!(
            plan.warnings.iter().any(|w| w.contains("roadrunner") && w.contains("confirm")),
            "{:?}",
            plan.warnings
        );
    }

    #[test]
    fn a_recorded_command_with_no_board_still_never_ships_boardless() {
        let plan = scaffold_build_command(
            &[recorded("build/build_info.yml", Some("west build app/hb"), None)],
            "embarch/build",
        );
        assert_eq!(board_in_argv(&plan.argv).as_deref(), Some(BOARD_PLACEHOLDER));
    }

    #[test]
    fn several_recorded_builds_are_all_named_and_none_is_picked() {
        let plan = scaffold_build_command(
            &[
                recorded("build/build_info.yml", Some("west build -b devkit/nrf52840 app/hb"), Some("today")),
                recorded("build-prod/build_info.yml", Some("west build -b roadrunner@2/nrf54l15/cpuapp app/hb"), Some("30 days ago")),
                recorded("twister-out/x/build_info.yml", None, None),
            ],
            "embarch/build",
        );
        // Nothing chosen: the command is the same template the no-build case
        // gets, and carries neither candidate's board or app path.
        assert_eq!(
            plan.argv,
            scaffold_build_command(&[], "embarch/build").argv,
            "a several-builds repo must not inherit one of them"
        );

        let cfg = rendered(&plan);
        toml::from_str::<toml::Value>(&cfg).expect("must stay valid TOML");
        let warning = plan.warnings.join("\n");
        for text in [&cfg, &warning] {
            for candidate in [
                "build/build_info.yml",
                "build-prod/build_info.yml",
                "twister-out/x/build_info.yml",
                "devkit/nrf52840",
                "roadrunner@2/nrf54l15/cpuapp",
            ] {
                assert!(text.contains(candidate), "missing {candidate} in:\n{text}");
            }
        }
        assert!(warning.contains("will not pick one for you"), "{warning}");
        assert!(cfg.contains("chose none of them"), "{cfg}");
        // The one with no west command is named too, rather than dropped.
        assert!(warning.contains("no board recorded"), "{warning}");
    }

    #[test]
    fn no_recorded_build_keeps_the_behaviour_it_always_had() {
        let plan = scaffold_build_command(&[], "embarch/build");
        assert_eq!(
            plan.argv,
            split_argv("west build -d embarch/build -b CHANGE-ME")
        );
        assert!(plan.warnings.iter().any(|w| w.contains("template")));
        toml::from_str::<toml::Value>(&rendered(&plan)).expect("must stay valid TOML");
    }

    #[test]
    fn an_age_is_days_since_the_build_and_nothing_when_the_clock_is_nonsense() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        let ago = |secs: u64| recorded_age(now - std::time::Duration::from_secs(secs), now);
        assert_eq!(ago(0).as_deref(), Some("today"));
        assert_eq!(ago(86_400).as_deref(), Some("yesterday"));
        assert_eq!(ago(7 * 86_400 + 5).as_deref(), Some("7 days ago"));
        assert_eq!(
            recorded_age(now + std::time::Duration::from_secs(86_400), now),
            None
        );
    }

    #[test]
    fn every_recorded_build_in_the_tree_is_found_not_only_the_one_at_build() {
        let dir = tempdir();
        let write = |rel: &str| {
            let p = dir.path().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, "west:\n  command: 'west build -b b app'\n").unwrap();
        };
        write("build/build_info.yml");
        write("build-prod/build_info.yml");
        write("twister-out/a/b/build_info.yml");
        // Dotted directories are somebody else's cache, and `.git` holds no
        // builds — neither is walked.
        write(".cache/build/build_info.yml");
        // Deeper than the walk's bound.
        write("a/b/c/d/e/build_info.yml");

        let found: Vec<String> = find_build_infos(dir.path())
            .iter()
            .map(|p| p.strip_prefix(dir.path()).unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            found,
            // Component-wise, which is how `PathBuf` orders: `build` sorts
            // before `build-prod` even though `build/` does not.
            vec![
                "build/build_info.yml",
                "build-prod/build_info.yml",
                "twister-out/a/b/build_info.yml",
            ]
        );
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let base = std::env::temp_dir().join(format!(
            "embarch-umbrella-init-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }
}

