//! `embarch init` — integrate the firmware repo in the current directory.
//!
//! design.md §3 decisions 10, 12, 13. The whole point is that a firmware repo
//! you don't own ends up with **nothing tracked modified**: the config lives
//! in an `embarch/` folder excluded through `.git/info/exclude` (local to this
//! clone, unlike a committed `.gitignore`), and the MCP server is registered
//! at Claude Code's local scope rather than by writing a `.mcp.json`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::locate;

const EXCLUDE_MARKER: &str = "# added by `embarch init`";
const EXCLUDE_ENTRY: &str = "embarch/";
const MCP_SERVER_NAME: &str = "embarch";

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
/// build-directory trap (`embarch-api/design.md` §6). `west build -b <board>
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
/// A separate build directory isn't optional (design.md §3 decision 10):
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
/// (`embarch-api/design.md` §4, §9) — what a Windows-hosted Core needs in
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
/// (`embarch-dev-bench/design.md` §3 decision 4's correction). Shortest match
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

pub struct Scaffold {
    pub toml: String,
    /// Things `init` could not work out, to print rather than guess at
    /// (design.md §3 decision 13).
    pub warnings: Vec<String>,
}

/// Build the config text for a `discovery = "zephyr-west"` project
/// (design.md §3 decision 17, `embarch-api/design.md` §3 decision 12): no
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
         # see `embarch-api list-targets {name}` and embarch-api/design.md §3 decision 12.\n\
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
    artifact_path: &str,
    unc_artifact: Option<&str>,
) -> String {
    let argv = build_command
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let unc_line = match unc_artifact {
        Some(p) => format!(
            "# Windows-visible form of the same file, for a Core running on the Windows\n\
             # side of this WSL2 split (embarch-api/design.md §9).\nartifact_path_for_core = {:?}\n",
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
/// tracked, and this must not touch tracked files (design.md §3 decision 12).
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

    // design.md §3 decision 17: a repo shaped like a real Zephyr/west
    // project (several boards/variants/revisions worth discovering live,
    // not one to guess) gets the minimal discovery = "zephyr-west" schema
    // instead of a single hand-picked board — `embarch init`'s old behavior
    // silently picked the wrong one of several real boards in the
    // healthband repo, with no signal a choice had even been made.
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
        match locate::locate_api() {
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

    // Derive the build command from what west actually ran, when it can.
    let build_command = match std::fs::read_to_string(&build_info)
        .ok()
        .and_then(|y| parse_west_command(&y))
    {
        Some(recorded) => {
            println!("Derived the build command from {}", build_info.display());
            let argv = with_build_dir(&split_argv(&recorded), build_dir_rel);
            if argv.iter().any(|a| a == "always") && argv.iter().any(|a| a == "-p") {
                warnings.push(
                    "your build command has `-p always`, so every EmbArch build is a full \
                     rebuild. Now that EmbArch has its own build directory, you can probably \
                     drop it."
                        .to_string(),
                );
            }
            argv
        }
        None => {
            warnings.push(format!(
                "no {} found, so the build command below is a guess — check it against how you \
                 actually build.",
                build_info.display()
            ));
            ["west", "build", "-d", build_dir_rel, "-b", "CHANGE-ME"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
    };

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
        toml: render_config(&name, &repo, &build_command, &artifact_path, unc.as_deref()),
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
    match locate::locate_api() {
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

    // Shaped exactly like a real west build_info.yml, including the `cmake:`
    // block ahead of it that a naive "find command:" search would trip over.
    const BUILD_INFO: &str = "cmake:\n  application:\n    source-dir: '/repo/app/hb'\n  board:\n    name: 'roadrunner'\nversion: '0.1.0'\nwest:\n  command: '/ws/.venv/bin/west build -p always -b roadrunner@2/nrf54l15/cpuapp app/healthband'\n  topdir: '/ws'\n";

    #[test]
    fn west_command_is_extracted_from_the_west_block() {
        assert_eq!(
            parse_west_command(BUILD_INFO).as_deref(),
            Some("/ws/.venv/bin/west build -p always -b roadrunner@2/nrf54l15/cpuapp app/healthband")
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
            "embarch/build/zephyr/zephyr.hex",
            Some("\\\\wsl.localhost\\Ubuntu\\home\\me\\fw\\x.hex"),
        );
        // Backslashes must survive into the TOML as escaped literals, or Core
        // gets a mangled path — the failure embarch-api/design.md §9 records.
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
            "embarch/build/zephyr/zephyr.hex",
            None,
        );
        let parsed: toml::Value = toml::from_str(&cfg).expect("scaffolded config must be valid TOML");
        assert_eq!(parsed["core"]["base_url"].as_str(), Some("auto"));
        assert_eq!(parsed["projects"][0]["name"].as_str(), Some("fw"));
    }
}
