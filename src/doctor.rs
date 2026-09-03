//! `embarch doctor` — spec.md's check chain, each pass/warn/fail plus a fix
//! line for anything short of a pass.
//!
//! Ordered the same as spec.md's table, and largely dependency-ordered too:
//! checks 4/5/11/12/13/15 need check 3's winning candidate, checks 7-9 need
//! check 6's config. When a prerequisite check didn't pass, the checks that
//! depend on it report themselves `Warn`-skipped rather than re-deriving (or
//! silently repeating) the same failure — the exit code still reflects the
//! one real failure, not N copies of it.
//!
//! **A skip always names the number it could not get and why.** That is the
//! rule check 11 was violating for months by returning a hardcoded warn whose
//! stated reason had stopped being true (decision 33).

use std::path::{Path, PathBuf};
use std::process::Command;

use embarch_topology::software::{self as topology, ProbeOutcome, TopologyClass};

use crate::config::{self, Config, ProjectConfig};
use crate::env;
use crate::locate::{self, Located};
use crate::setup;
use crate::state;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

pub struct Check {
    pub n: u8,
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

fn check(n: u8, name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        n,
        name,
        status,
        detail: detail.into(),
        fix: None,
    }
}

fn with_fix(mut c: Check, fix: impl Into<String>) -> Check {
    c.fix = Some(fix.into());
    c
}

/// Everything gathered while probing Core, threaded into the checks that
/// need an authenticated call (4, 5, 12) so there is exactly one HTTP round
/// trip to a reachable Core, not three.
struct CoreProbe {
    winner_base_url: Option<String>,
    winner_class: Option<TopologyClass>,
    attempts: Vec<topology::Attempt>,
}

/// `config`'s `[core].base_url`, when it's a literal address rather than
/// `"auto"` — a config predating decision 9, or one that opted back out of
/// discovery. Every real config in the suite uses `"auto"` today, but
/// `doctor` diagnosing a Core other than the one a declared `base_url`
/// actually names would be worse than the extra branch this avoids.
fn declared_base_url(config: Option<&Config>) -> Option<&str> {
    let core = &config?.core;
    if core.is_auto() {
        return None;
    }
    Some(core.base_url.trim_end_matches('/'))
}

async fn probe_topology(config: Option<&Config>, host: Option<&str>, port: u16) -> CoreProbe {
    // embarch-topology/design.md decisions 2, 3: live, in-process, every
    // call — `doctor` still wants a probe result even for a declared
    // `base_url` (unlike embarch-api's `core_client.rs`, which trusts a
    // declared address outright), so this always passes through the crate's
    // one probing implementation rather than short-circuiting locally.
    let resolved =
        topology::resolve_software_topology(port, host, declared_base_url(config)).await;
    CoreProbe {
        winner_base_url: resolved.winner.as_ref().map(|c| c.base_url.clone()),
        winner_class: resolved.winner.as_ref().map(|c| c.class),
        attempts: resolved.attempts,
    }
}

fn attempts_detail(attempts: &[topology::Attempt]) -> String {
    attempts
        .iter()
        .map(|a| {
            let why = match a.outcome {
                ProbeOutcome::Unreachable => "nothing listening".to_string(),
                ProbeOutcome::NotCore { status } => format!("answered HTTP {status}, but isn't Core"),
                ProbeOutcome::Core { .. } => unreachable!("a hit would have won"),
            };
            format!("{} ({}) — {why}", a.candidate.base_url, a.candidate.class.as_str())
        })
        .collect::<Vec<_>>()
        .join("; ")
}

// ---- check 1: binaries -----------------------------------------------------

fn binary_version(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok().map(|s| s.trim().to_string())
}

/// Compare each component's real `--version` output against a suite
/// manifest's recorded tag, when both a manifest and a real version are
/// available. `None` for a component means "nothing to say" (manifest
/// absent, or that binary's `--version` didn't resolve) rather than a
/// mismatch — check_binaries decides what silence means.
fn manifest_mismatches(m: &crate::manifest::Manifest, c_ver: Option<&str>, a_ver: Option<&str>) -> Vec<String> {
    let mut mismatches = Vec::new();
    // Umbrella can check its own version against the manifest with no
    // subprocess at all — it's this binary's own compiled-in Cargo version.
    let self_ver = format!("embarch {}", env!("CARGO_PKG_VERSION"));
    if !crate::manifest::agrees(&m.components.embarch, &self_ver) {
        mismatches.push(format!("embarch: manifest says {}, this binary is {self_ver}", m.components.embarch));
    }
    if let Some(v) = c_ver {
        if !crate::manifest::agrees(&m.components.embarch_core, v) {
            mismatches.push(format!("embarch-core: manifest says {}, binary says {v}", m.components.embarch_core));
        }
    }
    if let Some(v) = a_ver {
        if !crate::manifest::agrees(&m.components.embarch_api, v) {
            mismatches.push(format!("embarch-api: manifest says {}, binary says {v}", m.components.embarch_api));
        }
    }
    mismatches
}

/// `c_ver`/`a_ver` are each component's `--version` output, resolved **once**
/// in the driver: check 15 wants Core's, and spawning the same binary twice to
/// ask it the same question would let the two checks disagree.
fn check_binaries(
    core: Option<&Located>,
    api: Option<&Located>,
    c_ver: Option<&str>,
    a_ver: Option<&str>,
) -> Check {
    match (core, api) {
        (Some(c), Some(a)) => {
            let c_display = c_ver.unwrap_or("version unknown");
            let a_display = a_ver.unwrap_or("version unknown");
            let found = format!(
                "embarch-core: {} ({c_display}); embarch-api: {} ({a_display})",
                c.path.display(),
                a.path.display()
            );

            let manifest = crate::manifest::find_next_to_me().and_then(|p| crate::manifest::load(&p));
            match manifest {
                None => check(
                    1,
                    "binaries found",
                    Status::Pass,
                    format!(
                        "{found}. No suite manifest next to this binary — either not installed from a \
                         suite archive (milestone-6.md §3.7), or a per-repo/debug build; \
                         version-vs-manifest comparison skipped."
                    ),
                ),
                Some(m) => {
                    let mismatches = manifest_mismatches(&m, c_ver, a_ver);
                    if mismatches.is_empty() {
                        check(
                            1,
                            "binaries found",
                            Status::Pass,
                            format!("{found}. Matches suite manifest v{} ({}).", m.suite_version, m.target),
                        )
                    } else {
                        with_fix(
                            check(
                                1,
                                "binaries found",
                                Status::Fail,
                                format!("{found}. Suite manifest v{} mismatch: {}", m.suite_version, mismatches.join("; ")),
                            ),
                            "reinstall from a matching suite archive, so all three binaries come from the \
                             same release",
                        )
                    }
                }
            }
        }
        _ => with_fix(
            check(
                1,
                "binaries found",
                Status::Fail,
                format!(
                    "embarch-core: {}; embarch-api: {}",
                    core.map(|c| c.path.display().to_string()).unwrap_or_else(|| "not found".to_string()),
                    api.map(|a| a.path.display().to_string()).unwrap_or_else(|| "not found".to_string()),
                ),
            ),
            "download the suite archive and unpack both binaries next to `embarch`, or set \
             EMBARCH_CORE_EXE / EMBARCH_API_BIN",
        ),
    }
}

// ---- check 2: service installed and running --------------------------------

fn check_service(probe: &CoreProbe, host: Option<&str>, core: Option<&Located>) -> Check {
    if probe.winner_base_url.is_some() {
        return check(
            2,
            "Core service installed, and running",
            Status::Pass,
            "Core answered a probe, so it's running. (Can't tell installed-as-a-service apart from \
             `embarch up --foreground` without side effects — either is fine.)",
        );
    }

    let class = setup::infer_class(host, core);
    let fix = match (class, core) {
        (TopologyClass::Remote, _) => {
            "Core runs on another machine. On that machine: `embarch-core install` (elevated).".to_string()
        }
        (TopologyClass::WslHost, Some(c)) => format!(
            "Core belongs on the Windows side. In an **elevated Windows** shell: \"{}\" install",
            setup::windows_display_path(&c.path)
        ),
        (TopologyClass::Local, Some(c)) => {
            format!("sudo \"{}\" install   (or, if already installed: sudo \"{}\" start)", c.path.display(), c.path.display())
        }
        (_, None) => "embarch-core not found — run `embarch setup` first.".to_string(),
    };
    with_fix(
        check(2, "Core service installed, and running", Status::Fail, "not reachable"),
        fix,
    )
}

// ---- check 3: Core reachable ------------------------------------------------

fn check_reachable(probe: &CoreProbe) -> Check {
    match (&probe.winner_base_url, &probe.winner_class) {
        (Some(url), Some(class)) => check(
            3,
            "Core reachable",
            Status::Pass,
            format!("{url} ({})", class.as_str()),
        ),
        _ => with_fix(
            check(
                3,
                "Core reachable",
                Status::Fail,
                format!("nothing answered. Tried: {}", attempts_detail(&probe.attempts)),
            ),
            "start Core (`embarch up`), or pass a host if it's on another machine",
        ),
    }
}

// ---- check 4: token resolves and matches -----------------------------------

/// This check's own per-request budget — coincidentally the same value
/// `embarch-topology`'s candidate-probing uses internally, but a separate
/// constant: this is an *authenticated* request to an already-resolved
/// `base_url`, not a topology candidate probe, so it has no reason to share
/// that crate-internal value even if the number happens to match today.
const AUTHED_GET_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Everything `GET /status` answered with, parsed once
/// ([embarch-core/interfaces.md](../embarch-core/interfaces.md)'s `/status`
/// row). Checks 5, 11 and 15 each want a different field off the same body,
/// and there is still exactly one authenticated round trip.
struct AuthedStatus {
    probes: Vec<serde_json::Value>,
    /// `study_designer_schema_version` — `embarch-study-designer`'s
    /// `HOST_TYPE_SCHEMA_VERSION` as compiled into the Core that answered.
    /// `None` for a Core predating the field, which check 11 reports as a
    /// missing number rather than as agreement.
    study_designer_schema_version: Option<u32>,
    /// `core_version` — the answering Core's own crate version
    /// (`embarch-core` decision 13, 2026-09-03). `None` for a Core predating
    /// it. Deliberately **not** one of check 11's schema numbers: check 15
    /// asks a different question with it.
    core_version: Option<String>,
}

async fn authed_get(base_url: &str, path: &str, token: &str) -> Result<(u16, String), String> {
    let client = reqwest::Client::new();
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .bearer_auth(token)
        .timeout(AUTHED_GET_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Ok((status, body))
}

async fn check_token(probe: &CoreProbe, config: Option<&Config>) -> (Check, Option<AuthedStatus>) {
    let Some(base_url) = &probe.winner_base_url else {
        return (
            check(4, "token resolves and matches", Status::Warn, "skipped — Core isn't reachable (see check 3)"),
            None,
        );
    };

    let (token_cfg, token_env) = config
        .map(|c| (c.core.token.clone(), c.core.token_env.clone()))
        .unwrap_or((None, None));

    let token = match crate::token::resolve_token(token_cfg, token_env) {
        Ok(t) => t,
        Err(e) => {
            return (
                with_fix(
                    check(4, "token resolves and matches", Status::Fail, format!("{e:#}")),
                    "see ../embarch-doc/embarch-token.md",
                ),
                None,
            )
        }
    };

    match authed_get(base_url, "/status", &token).await {
        Ok((200, body)) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
            let probes = parsed
                .as_ref()
                .and_then(|v| v.get("probes"))
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            let study_designer_schema_version = parsed
                .as_ref()
                .and_then(|v| v.get("study_designer_schema_version"))
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok());
            let core_version = parsed
                .as_ref()
                .and_then(|v| v.get("core_version"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            (
                check(4, "token resolves and matches", Status::Pass, "authenticated (200)"),
                Some(AuthedStatus { probes, study_designer_schema_version, core_version }),
            )
        }
        Ok((401, _)) => (
            with_fix(
                check(4, "token resolves and matches", Status::Fail, "Core rejected the token (401)"),
                "the resolved token doesn't match Core's. See ../embarch-doc/embarch-token.md — if \
                 Core was reinstalled its token file changed underneath the old value.",
            ),
            None,
        ),
        Ok((status, body)) => (
            with_fix(
                check(4, "token resolves and matches", Status::Fail, format!("unexpected HTTP {status}: {body}")),
                "this isn't a token problem — something answered but isn't behaving like Core",
            ),
            None,
        ),
        Err(e) => (
            with_fix(
                check(4, "token resolves and matches", Status::Fail, e),
                "Core answered the unauthenticated topology probe but not this request — check for a \
                 flaky connection",
            ),
            None,
        ),
    }
}

// ---- check 5: probe list ----------------------------------------------------

fn check_probes(authed: Option<&AuthedStatus>) -> Check {
    match authed {
        None => check(5, "at least one debug probe visible", Status::Warn, "skipped — no authenticated status (see check 4)"),
        Some(a) if a.probes.is_empty() => {
            check(5, "at least one debug probe visible", Status::Warn, "no probes reported — fine if none is plugged in right now")
        }
        Some(a) => check(5, "at least one debug probe visible", Status::Pass, format!("{} probe(s)", a.probes.len())),
    }
}

// ---- check 6: config loads, source_path exists -----------------------------

fn check_config(config_path: Option<&Path>) -> (Check, Option<Config>) {
    let Some(path) = config_path else {
        return (
            with_fix(
                check(6, "embarch-api config loads", Status::Fail, "no embarch/embarch.toml found"),
                "run `embarch init` from inside the firmware repo",
            ),
            None,
        );
    };

    let config = match Config::load_from_path(path) {
        Ok(c) => c,
        Err(e) => {
            return (
                check(6, "embarch-api config loads", Status::Fail, format!("{e:#}")),
                None,
            )
        }
    };

    let missing: Vec<&str> = config
        .projects
        .iter()
        .filter(|p| !p.source_path.exists())
        .map(|p| p.name.as_str())
        .collect();

    if missing.is_empty() {
        let c = check(
            6,
            "embarch-api config loads",
            Status::Pass,
            format!("{} ({} project(s), every source_path exists)", path.display(), config.projects.len()),
        );
        (c, Some(config))
    } else {
        let c = with_fix(
            check(
                6,
                "embarch-api config loads",
                Status::Fail,
                format!("source_path missing for: {}", missing.join(", ")),
            ),
            "fix `source_path` in embarch/embarch.toml for the project(s) listed",
        );
        (c, Some(config))
    }
}

// ---- check 7: build_command[0] resolves ------------------------------------

fn is_executable(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Resolve `program` the way a shell would: as a path (if it looks like one)
/// relative to `cwd`, otherwise by searching `PATH`.
fn resolve_program(program: &str, cwd: &Path) -> Option<PathBuf> {
    let looks_like_path = program.contains('/') || program.contains('\\') || program.contains(':');
    if looks_like_path {
        let candidate = if Path::new(program).is_absolute() {
            PathBuf::from(program)
        } else {
            cwd.join(program)
        };
        return is_executable(&candidate).then_some(candidate);
    }

    let path_var = std::env::var("PATH").ok()?;
    locate::path_dirs(&path_var, cfg!(windows))
        .into_iter()
        .map(|dir| dir.join(program))
        .find(|c| is_executable(c))
}

fn check_build_commands(projects: &[ProjectConfig]) -> Check {
    if projects.is_empty() {
        return check(7, "build_command[0] resolves to an executable", Status::Warn, "no projects configured");
    }

    let mut unresolved = Vec::new();
    for p in projects {
        if p.is_zephyr_west() {
            // design.md §3 decision 17: a zephyr-west project has no
            // build_command at all — west_binary is the equivalent
            // executable-on-PATH preflight.
            let Some(west) = p.west_binary.as_ref().and_then(|w| w.to_str()) else {
                unresolved.push(format!("{}: west_binary is not set", p.name));
                continue;
            };
            if resolve_program(west, &p.source_path).is_none() {
                unresolved.push(format!("{}: west_binary `{west}` not found on PATH or at that path", p.name));
            }
            continue;
        }
        let Some(program) = p.build_command.as_ref().and_then(|c| c.first()) else {
            unresolved.push(format!("{}: build_command is empty", p.name));
            continue;
        };
        if resolve_program(program, &p.build_dir()).is_none() {
            unresolved.push(format!("{}: `{program}` not found on PATH or at that path", p.name));
        }
    }

    if unresolved.is_empty() {
        check(7, "build_command[0] resolves to an executable", Status::Pass, format!("{} project(s) checked", projects.len()))
    } else {
        with_fix(
            check(7, "build_command[0] resolves to an executable", Status::Fail, unresolved.join("; ")),
            "install the missing tool, or fix build_command/west_binary in embarch/embarch.toml",
        )
    }
}

// ---- check 8: chip placeholder / live target discovery -----------------------

const CHIP_PLACEHOLDER: &str = "CHANGE-ME";

/// For a `discovery = "static"` project: `chip` isn't still `init`'s
/// placeholder. For a `discovery = "zephyr-west"` project (`design.md` §3
/// decision 17): there's nowhere for a placeholder to live at all — `chip`
/// is resolved per call — so this checks the thing that actually matters
/// instead, that at least one live-discovered target is file-backing-valid,
/// i.e. `boards/`/`app/` aren't empty or broken.
fn check_chip(projects: &[ProjectConfig]) -> Check {
    if projects.is_empty() {
        return check(8, "chip resolvable (static: not a placeholder; zephyr-west: a real target exists)", Status::Warn, "no projects configured");
    }

    let mut problems = Vec::new();
    for p in projects {
        if p.is_zephyr_west() {
            let count = crate::zephyr::count_valid_targets(&p.source_path);
            if count == 0 {
                problems.push(format!(
                    "{}: no valid targets found under boards/ + app/ — run `embarch-api list-targets {}` for detail",
                    p.name, p.name
                ));
            }
        } else if p.chip.as_deref() == Some(CHIP_PLACEHOLDER) {
            problems.push(format!("{}: chip still CHANGE-ME", p.name));
        }
    }

    if problems.is_empty() {
        check(8, "chip resolvable (static: not a placeholder; zephyr-west: a real target exists)", Status::Pass, format!("{} project(s) checked", projects.len()))
    } else {
        with_fix(
            check(8, "chip resolvable (static: not a placeholder; zephyr-west: a real target exists)", Status::Fail, problems.join("; ")),
            "static: cargo install probe-rs-tools && probe-rs chip list | grep -i <your soc>, then set \
             `chip` in embarch/embarch.toml. zephyr-west: confirm boards/*/*.yml and app/*/CMakeLists.txt \
             exist and declare at least one real, file-backed target.",
        )
    }
}

// ---- check 9: artifact_path / artifact_path_for_core -----------------------

/// `\\wsl.localhost\<distro>\<tail>` back to `/<tail>` — the reverse of
/// `init::wsl_unc_path`. Also accepts the older `\\wsl$\` alias.
fn unc_to_wsl_path(unc: &str) -> Option<(String, PathBuf)> {
    let rest = unc.strip_prefix(r"\\wsl.localhost\").or_else(|| unc.strip_prefix(r"\\wsl$\"))?;
    let mut parts = rest.splitn(2, '\\');
    let distro = parts.next()?.to_string();
    let tail = parts.next().unwrap_or("").replace('\\', "/");
    Some((distro, PathBuf::from(format!("/{tail}"))))
}

fn check_artifact_paths(projects: &[ProjectConfig]) -> Check {
    if projects.is_empty() {
        return check(9, "artifact_path resolvable / matches artifact_path_for_core", Status::Warn, "no projects configured");
    }

    let under_wsl2 = env::under_wsl2();
    let current_distro = std::env::var("WSL_DISTRO_NAME").ok();

    let mut notes = Vec::new();
    let mut worst = Status::Pass;
    let mut fix = None;

    for p in projects {
        if p.is_zephyr_west() {
            // design.md §3 decision 17: artifact_path and artifact_path_for_core
            // are both computed together, per call, from the same resolved
            // build dir — there's nothing stored to compare here. All this
            // check can verify ahead of time is that the WSL2 UNC-path
            // translation itself would succeed for this repo, when it applies.
            if under_wsl2 && current_distro.is_none() {
                notes.push(format!("{}: under WSL2 but WSL_DISTRO_NAME is unset — artifact_path_for_core can't be computed at call time", p.name));
                worst = Status::Fail;
            } else {
                notes.push(format!("{}: ok — computed per call, nothing to compare ahead of time", p.name));
            }
            continue;
        }

        let Some(resolved) = p.resolved_artifact_path() else {
            notes.push(format!("{}: no artifact_path configured", p.name));
            worst = Status::Fail;
            continue;
        };
        if !resolved.exists() {
            notes.push(format!("{}: no artifact at {} yet (build it first)", p.name, resolved.display()));
            if worst == Status::Pass {
                worst = Status::Warn;
            }
            continue;
        }

        let Some(unc) = &p.artifact_path_for_core else {
            notes.push(format!("{}: ok (no artifact_path_for_core set)", p.name));
            continue;
        };

        if !under_wsl2 {
            notes.push(format!("{}: artifact_path_for_core set but this only matters under WSL2 (topology iii) — skipped", p.name));
            if worst == Status::Pass {
                worst = Status::Warn;
            }
            continue;
        }

        match unc_to_wsl_path(unc) {
            Some((distro, translated)) if current_distro.as_deref() == Some(distro.as_str()) => {
                let same = match (std::fs::canonicalize(&resolved), std::fs::canonicalize(&translated)) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => false,
                };
                if same {
                    notes.push(format!("{}: ok — artifact_path_for_core names the same file", p.name));
                } else {
                    notes.push(format!(
                        "{}: artifact_path resolves to {} but artifact_path_for_core resolves to {} — different files",
                        p.name,
                        resolved.display(),
                        translated.display()
                    ));
                    worst = Status::Fail;
                    fix = Some(
                        "regenerate artifact_path_for_core (rerun `embarch init`, or fix it by hand) so \
                         both name the same build output — see ../embarch-doc/embarch-api/design.md §12"
                            .to_string(),
                    );
                }
            }
            _ => {
                notes.push(format!("{}: artifact_path_for_core names a different WSL distro — can't verify from here", p.name));
                if worst == Status::Pass {
                    worst = Status::Warn;
                }
            }
        }
    }

    let mut c = check(9, "artifact_path resolvable / matches artifact_path_for_core", worst, notes.join("; "));
    c.fix = fix;
    c
}

// ---- check 10: MCP registration ---------------------------------------------

const MCP_SERVER_NAME: &str = "embarch";

fn check_mcp(config_path: Option<&Path>, api: Option<&Located>) -> Check {
    let fix = || {
        format!(
            "claude mcp add {MCP_SERVER_NAME} -- {} --config {}",
            api.map(|a| a.path.display().to_string()).unwrap_or_else(|| "<path to embarch-api>".to_string()),
            config_path.map(|p| p.display().to_string()).unwrap_or_else(|| "<repo>/embarch/embarch.toml".to_string()),
        )
    };

    match Command::new("claude").args(["mcp", "get", MCP_SERVER_NAME]).output() {
        Ok(o) if o.status.success() => check(10, "MCP server registered", Status::Pass, "registered"),
        Ok(_) => with_fix(
            check(10, "MCP server registered", Status::Fail, "not registered"),
            fix(),
        ),
        Err(_) => with_fix(
            check(10, "MCP server registered", Status::Warn, "claude CLI not found here — can't verify"),
            fix(),
        ),
    }
}

// ---- /dev-bench/hello, fetched once for checks 11 and 13 --------------------

/// What `/dev-bench/hello` answered
/// ([embarch-core/interfaces.md](../embarch-core/interfaces.md)), parsed once.
///
/// **Fetched in the driver rather than by each check that wants it**, because
/// this endpoint is not a read: it opens the serial link to the bench long
/// enough to handshake and closes it again, and Core guards it with a `409`
/// against an in-flight study. Two checks asking separately would be two link
/// opens for one answer.
struct HelloAck {
    /// `embarch-study-designer`'s `DEV_BENCH_WIRE_SCHEMA_VERSION` as compiled
    /// into the firmware currently flashed on the bench.
    schema_version: Option<u32>,
    /// **Core's own verdict** on that number against the wire constant *Core*
    /// was built against. Check 11 reports this rather than recomputing it:
    /// Core's compiled wire constant is not served anywhere, and a second
    /// comparison here would be a mirror that drifts.
    compatible: Option<bool>,
    firmware_version: Option<String>,
    raw: String,
}

/// Why there is no [`HelloAck`]. Carrying the reason rather than an
/// `Option<HelloAck>` is what lets checks 11 and 13 each say *which* state
/// they are in instead of reporting a bare "unavailable".
enum HelloOutcome {
    Answered(HelloAck),
    /// `404` — Core sees no bench. An ordinary state on a machine that has
    /// none, not a fault.
    NoBench,
    /// Anything else: Core unreachable, no token, a `409` mid-study, an HTTP
    /// error. The string is the reason, phrased to follow "skipped — ".
    Unavailable(String),
}

async fn fetch_dev_bench_hello(
    probe: &CoreProbe,
    authed: Option<&AuthedStatus>,
    config: Option<&Config>,
) -> HelloOutcome {
    let Some(base_url) = &probe.winner_base_url else {
        return HelloOutcome::Unavailable("Core isn't reachable (see check 3)".to_string());
    };
    if authed.is_none() {
        return HelloOutcome::Unavailable("no authenticated status (see check 4)".to_string());
    }

    let (token_cfg, token_env) = config
        .map(|c| (c.core.token.clone(), c.core.token_env.clone()))
        .unwrap_or((None, None));
    let token = match crate::token::resolve_token(token_cfg, token_env) {
        Ok(t) => t,
        Err(_) => return HelloOutcome::Unavailable("could not resolve token".to_string()),
    };

    match authed_get(base_url, "/dev-bench/hello", &token).await {
        Ok((200, body)) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
            HelloOutcome::Answered(HelloAck {
                schema_version: parsed
                    .as_ref()
                    .and_then(|v| v.get("schema_version"))
                    .and_then(|v| v.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                compatible: parsed.as_ref().and_then(|v| v.get("compatible")).and_then(|v| v.as_bool()),
                firmware_version: parsed
                    .as_ref()
                    .and_then(|v| v.get("firmware_version"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                raw: body,
            })
        }
        Ok((404, _)) => HelloOutcome::NoBench,
        Ok((409, body)) => HelloOutcome::Unavailable(format!("dev-bench is busy: {body}")),
        Ok((status, body)) => HelloOutcome::Unavailable(format!("HTTP {status}: {body}")),
        Err(e) => HelloOutcome::Unavailable(e),
    }
}

// ---- check 11: the study-designer schema versions ---------------------------

/// The numbers check 11 compares, each one either a value or the reason it
/// isn't there. Split out from the check so the comparison can be tested with
/// the numbers injected, without a live Core or a bench (decision 33).
struct SchemaVersions<'a> {
    /// `/status`'s `study_designer_schema_version`: the host-type constant
    /// **the deployed Core** was built against.
    core_host: Result<u32, &'a str>,
    /// `HOST_TYPE_SCHEMA_VERSION` as compiled into **this** binary. Not
    /// optional: it is a compile-time constant of the binary doing the
    /// asking, so it is the one number that is always available.
    local_host: u32,
    /// `/dev-bench/hello`'s `schema_version`: the wire constant **the flashed
    /// bench** was built against, paired with Core's own `compatible` verdict
    /// on it.
    bench_wire: Result<(u32, Option<bool>), &'a str>,
}

const CHECK_11_NAME: &str = "study-designer schema versions agree";

/// Judge the three numbers. Pure — every input is injected, nothing is
/// fetched here.
///
/// **What each comparison can actually prove**, and why they are not the same
/// comparison twice:
///
/// - `core_host` versus `local_host` is the `embarch-api` <-> `embarch-core`
///   hop, the one `embarch-api` itself refuses to submit a `Study` across
///   (`embarch-core-client`). A difference is a **fail**: the pair on this
///   machine cannot run a study at all.
/// - The bench's wire version is a **different sequence** —
///   `DEV_BENCH_WIRE_SCHEMA_VERSION` counts its own history and is only
///   guaranteed to be `<=` the host one, so it can never be compared against
///   either host number. What is comparable is Core's `compatible` verdict,
///   which is Core comparing the bench's number against Core's own compiled
///   wire constant. `compatible: false` is the 2026-08-26 state — Core at
///   wire v13 against a bench flashed to v14 — which the handshake refused
///   correctly and loudly to whoever called it by hand, and which `doctor`
///   reported as "not available yet" the whole time.
fn judge_schema_versions(v: &SchemaVersions<'_>) -> Check {
    const N: u8 = 11;

    let mut parts: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut worst = Status::Pass;

    /// A `Fail` always wins; a `Warn` only upgrades a `Pass`.
    fn degrade(s: Status, worst: &mut Status) {
        if s == Status::Fail || *worst == Status::Pass {
            *worst = s;
        }
    }

    match v.core_host {
        Ok(core) => {
            parts.push(format!(
                "host type: Core serves v{core}, this embarch was built against v{}",
                v.local_host
            ));
            if core != v.local_host {
                degrade(Status::Fail, &mut worst);
                fixes.push(
                    "the deployed Core and this suite install were built against different \
                     embarch-study-designer host types — embarch-api will refuse to submit a study. \
                     Redeploy Core from this build (`embarch deploy-core`), or reinstall the suite \
                     archive that matches the deployed Core."
                        .to_string(),
                );
            }
        }
        Err(why) => {
            parts.push(format!(
                "host type: Core's version unavailable — {why}; this embarch was built against v{}",
                v.local_host
            ));
            degrade(Status::Warn, &mut worst);
        }
    }

    match v.bench_wire {
        Ok((wire, Some(true))) => {
            parts.push(format!("dev-bench wire: bench reports v{wire}, and Core accepts it"))
        }
        Ok((wire, Some(false))) => {
            parts.push(format!(
                "dev-bench wire: bench reports v{wire}, and Core refuses it — the flashed firmware \
                 and the deployed Core were built against different wire versions"
            ));
            degrade(Status::Fail, &mut worst);
            fixes.push(
                "rebuild and reflash dev-bench from a checkout matching the deployed Core (check 13 \
                 names the checkout doctor compares against), or redeploy Core from the build that \
                 firmware came from."
                    .to_string(),
            );
        }
        Ok((wire, None)) => {
            parts.push(format!(
                "dev-bench wire: bench reports v{wire}, but Core returned no `compatible` verdict to \
                 judge it by"
            ));
            degrade(Status::Warn, &mut worst);
        }
        Err(why) => {
            parts.push(format!("dev-bench wire: unavailable — {why}"));
            degrade(Status::Warn, &mut worst);
        }
    }

    let c = check(N, CHECK_11_NAME, worst, parts.join("; "));
    if fixes.is_empty() {
        c
    } else {
        with_fix(c, fixes.join(" "))
    }
}

fn check_schema_versions(authed: Option<&AuthedStatus>, hello: &HelloOutcome) -> Check {
    let core_host = match authed {
        None => Err("no authenticated /status (see checks 3 and 4)"),
        Some(a) => a.study_designer_schema_version.ok_or(
            "the Core that answered serves no `study_designer_schema_version` — it predates \
             2026-08-25",
        ),
    };

    let bench_wire = match hello {
        HelloOutcome::Answered(ack) => match ack.schema_version {
            Some(wire) => Ok((wire, ack.compatible)),
            None => Err("dev-bench answered without a `schema_version`"),
        },
        HelloOutcome::NoBench => Err("no dev-bench plugged in"),
        HelloOutcome::Unavailable(why) => Err(why.as_str()),
    };

    judge_schema_versions(&SchemaVersions {
        core_host,
        local_host: embarch_study_designer::HOST_TYPE_SCHEMA_VERSION,
        bench_wire,
    })
}

// ---- check 12: dev-bench port -----------------------------------------------

async fn check_dev_bench(probe: &CoreProbe, authed: Option<&AuthedStatus>, config: Option<&Config>) -> Check {
    let Some(base_url) = &probe.winner_base_url else {
        return check(12, "dev-bench port detected", Status::Warn, "skipped — Core isn't reachable (see check 3)");
    };
    // Not otherwise consulted here — its only job was proving a token exists
    // (check 4). Re-deriving that same token below is cheap and avoids
    // threading a raw secret through one more layer of state.
    if authed.is_none() {
        return check(12, "dev-bench port detected", Status::Warn, "skipped — no authenticated status (see check 4)");
    }

    let (token_cfg, token_env) = config
        .map(|c| (c.core.token.clone(), c.core.token_env.clone()))
        .unwrap_or((None, None));
    let token = match crate::token::resolve_token(token_cfg, token_env) {
        Ok(t) => t,
        Err(_) => return check(12, "dev-bench port detected", Status::Warn, "skipped — could not resolve token"),
    };

    match authed_get(base_url, "/dev-bench/port", &token).await {
        Ok((200, body)) => check(12, "dev-bench port detected", Status::Pass, format!("detected: {body}")),
        Ok((404, _)) => check(12, "dev-bench port detected", Status::Pass, "not plugged in (expected if you have no bench)"),
        Ok((status, body)) => check(12, "dev-bench port detected", Status::Warn, format!("HTTP {status}: {body}")),
        Err(e) => check(12, "dev-bench port detected", Status::Warn, e),
    }
}

// ---- check 13: stale dev-bench firmware ------------------------------------

/// Where the local `embarch-dev-bench` checkout lives, for check 13's
/// `git describe`. `EMBARCH_DEV_BENCH_REPO_PATH` overrides whatever `setup
/// --dev-bench-repo` saved (`state.rs`'s `dev_bench_repo_path`, decision 19's
/// "machine-level setup state" field) — same override-beats-saved-state
/// convention `EMBARCH_CORE_EXE`/`EMBARCH_DEV_BENCH_PORT` already use
/// elsewhere in this suite.
/// Pure: `env_override` beats `saved.dev_bench_repo_path` — split out from
/// [`dev_bench_repo_path`] so the precedence is testable without mutating
/// real process env vars (same split `state.rs`'s `config_dir`/
/// `config_dir_from` already uses).
fn dev_bench_repo_path_from(env_override: Option<&str>, saved: &state::State) -> Option<PathBuf> {
    env_override.map(PathBuf::from).or_else(|| saved.dev_bench_repo_path.clone())
}

fn dev_bench_repo_path(saved: &state::State) -> Option<PathBuf> {
    dev_bench_repo_path_from(std::env::var("EMBARCH_DEV_BENCH_REPO_PATH").ok().as_deref(), saved)
}

/// `git describe --always --dirty --abbrev=8` against `repo_path` — the same
/// invocation `embarch-dev-bench/app/CMakeLists.txt` runs at build time to
/// produce `HelloAck.firmware_version`, so a matching value here means
/// "this checkout, built and flashed as-is."
fn git_describe(repo_path: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=8"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("could not run git in {}: {e}", repo_path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "git describe failed in {}: {}",
            repo_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `embarch-dev-bench/design.md` §3 decision 25 /
/// `embarch-umbrella/design.md` §3 decision 19: compares the currently
/// flashed dev-bench's `HelloAck.firmware_version` (over `GET
/// /dev-bench/hello`, `embarch-core/design.md`'s handshake-only endpoint —
/// no `Study` involved) against `git describe` run against whichever local
/// `embarch-dev-bench` checkout is configured. A mismatch means "you changed
/// dev-bench firmware and haven't reflashed it," caught here instead of as a
/// confusing mid-study failure.
fn check_firmware_version(hello: &HelloOutcome, saved: &state::State) -> Check {
    const N: u8 = 13;
    const NAME: &str = "dev-bench firmware matches the local checkout";

    let ack = match hello {
        HelloOutcome::Answered(ack) => ack,
        HelloOutcome::NoBench => {
            return check(N, NAME, Status::Pass, "not plugged in (expected if you have no bench)")
        }
        HelloOutcome::Unavailable(why) => return check(N, NAME, Status::Warn, format!("skipped — {why}")),
    };
    let Some(repo_path) = dev_bench_repo_path(saved) else {
        return check(
            N,
            NAME,
            Status::Warn,
            "skipped — no embarch-dev-bench checkout configured",
        );
    };

    let local_version = match git_describe(&repo_path) {
        Ok(v) => v,
        Err(e) => {
            return with_fix(
                check(N, NAME, Status::Warn, format!("could not compute local git describe: {e}")),
                format!("confirm {} is a valid embarch-dev-bench git checkout", repo_path.display()),
            );
        }
    };

    match &ack.firmware_version {
        Some(remote) if *remote == local_version => {
            check(N, NAME, Status::Pass, format!("firmware_version '{remote}' matches {}", repo_path.display()))
        }
        Some(remote) => with_fix(
            check(
                N,
                NAME,
                Status::Fail,
                format!(
                    "dev-bench reports firmware_version '{remote}', but {} is at '{local_version}'",
                    repo_path.display()
                ),
            ),
            format!(
                "rebuild and reflash dev-bench from {}: `west build -b <board> app && west flash` \
                 (or, for a board using embarch-core's native flashing support, `embarch-api flash`)",
                repo_path.display()
            ),
        ),
        None => check(N, NAME, Status::Warn, format!("unexpected /dev-bench/hello response: {}", ack.raw)),
    }
}

// ---- check 15: is the deployed Core the build that was deployed? ------------

const CHECK_15_NAME: &str = "the running Core is the located build";

/// `/status`'s `core_version` against the located `embarch-core` binary's own
/// `--version` (`embarch-core` decision 13, `embarch-dev-workflow.md` §4a).
///
/// **A different question from check 11's, which is why it is a different
/// check.** Check 11 asks whether the pieces agree on a *wire contract*;
/// this asks whether the Core answering on the network is the binary someone
/// just built and deployed. `deploy-core` has printed `landed` twice in one
/// session with nothing installed, when the elevated child was cancelled, and
/// its own check compares byte length — which cannot tell a release rebuild of
/// one constant from the previous build.
///
/// **The honest limit, stated in the check's own output rather than only
/// here:** `core_version` is `CARGO_PKG_VERSION`, so it only moves when the
/// crate version moves. This catches a **cross-version** stale deploy and
/// cannot see a same-version one. Strictly better than nothing; not a hash
/// comparison.
///
/// **Warn, never fail**, per `embarch-core` decision 13's "consumers warn,
/// never refuse" and this sub-project's decision 24: independent per-repo
/// versions are an expected state in a suite still iterating this fast.
fn judge_core_build(served: Option<&str>, located_version_output: Option<&str>) -> Check {
    const N: u8 = 15;
    const LIMIT: &str = "only moves with the crate version, so a same-version stale deploy is \
                         invisible to this";

    let Some(served) = served else {
        return check(
            N,
            CHECK_15_NAME,
            Status::Warn,
            "the Core that answered serves no `core_version` — it predates embarch-core decision 13 \
             (2026-09-03), so which build is running can't be read over HTTP at all",
        );
    };
    let Some(local) = located_version_output.and_then(crate::manifest::version_from_output) else {
        return check(
            N,
            CHECK_15_NAME,
            Status::Warn,
            format!(
                "Core answered with core_version {served}, but there is no local embarch-core \
                 `--version` to compare it against (see check 1)"
            ),
        );
    };

    if served == local {
        check(
            N,
            CHECK_15_NAME,
            Status::Pass,
            format!("running Core answered core_version {served}, matching the located binary ({LIMIT})"),
        )
    } else {
        with_fix(
            check(
                N,
                CHECK_15_NAME,
                Status::Warn,
                format!(
                    "running Core answered core_version {served}, but the located embarch-core binary \
                     is {local} — the running service is not the build on disk"
                ),
            ),
            "re-run `embarch deploy-core` and confirm the elevated step actually ran; it reports \
             `landed` even when the elevated child was cancelled and nothing was installed \
             (embarch-dev-workflow.md §4a).",
        )
    }
}

fn check_core_build(authed: Option<&AuthedStatus>, core_version_output: Option<&str>) -> Check {
    match authed {
        None => check(
            15,
            CHECK_15_NAME,
            Status::Warn,
            "skipped — no authenticated /status (see checks 3 and 4)",
        ),
        Some(a) => judge_core_build(a.core_version.as_deref(), core_version_output),
    }
}

// ---- driver ------------------------------------------------------------------

pub async fn doctor(json: bool) -> i32 {
    let under_wsl2 = env::under_wsl2();
    let saved = state::load();
    let core = locate::locate_core(saved.core_exe.as_deref(), under_wsl2);
    let api = locate::locate_api();

    let config_path = config::find_config_path();
    let (check6, config) = check_config(config_path.as_deref());

    let host = config.as_ref().and_then(|c| c.core.host.clone()).or(saved.host.clone());
    let port = config.as_ref().map(|c| c.core.port).unwrap_or(topology::DEFAULT_CORE_PORT);

    let core_probe = probe_topology(config.as_ref(), host.as_deref(), port).await;

    // Resolved once, here, because two checks want them: check 1 compares
    // both against the suite manifest and check 15 compares Core's against
    // what the running service answers with.
    let core_version_output = core.as_ref().and_then(|c| binary_version(&c.path));
    let api_version_output = api.as_ref().and_then(|a| binary_version(&a.path));

    let check1 = check_binaries(
        core.as_ref(),
        api.as_ref(),
        core_version_output.as_deref(),
        api_version_output.as_deref(),
    );
    let check2 = check_service(&core_probe, host.as_deref(), core.as_ref());
    let check3 = check_reachable(&core_probe);
    let (check4, authed) = check_token(&core_probe, config.as_ref()).await;
    let check5 = check_probes(authed.as_ref());
    let projects: &[ProjectConfig] = config.as_ref().map(|c| c.projects.as_slice()).unwrap_or(&[]);
    let check7 = check_build_commands(projects);
    let check8 = check_chip(projects);
    let check9 = check_artifact_paths(projects);
    let check10 = check_mcp(config_path.as_deref(), api.as_ref());
    // One handshake, two checks: `/dev-bench/hello` opens the serial link, so
    // checks 11 and 13 share one answer rather than opening it twice.
    let hello = fetch_dev_bench_hello(&core_probe, authed.as_ref(), config.as_ref()).await;
    let check11 = check_schema_versions(authed.as_ref(), &hello);
    let check12 = check_dev_bench(&core_probe, authed.as_ref(), config.as_ref()).await;
    let check13 = check_firmware_version(&hello, &saved);
    let check14 = check_flash_backend(core.as_ref());
    let check15 = check_core_build(authed.as_ref(), core_version_output.as_deref());

    let checks = vec![
        check1, check2, check3, check4, check5, check6, check7, check8, check9, check10, check11, check12,
        check13, check14, check15,
    ];

    let any_fail = checks.iter().any(|c| c.status == Status::Fail);

    if json {
        println!("{}", render_json(&checks, any_fail));
    } else {
        render_human(&checks);
    }

    if any_fail {
        1
    } else {
        0
    }
}

// ---- check 14: the flashing backend each chip family resolves to ------------

/// Asks the located `embarch-core` which program it would flash with
/// ([embarch-core/design.md](../embarch-core/design.md) §3 decision 36).
///
/// **Why this is a `doctor` check and not left to the moment of a flash.**
/// Core refuses to flash an nRF54L part with probe-rs — that family stores
/// code in RRAM, which probe-rs does not model — so it needs a vendor tool
/// (`nrfutil`, `jlink`, `nrfjprog`) that cannot be bundled for licensing
/// reasons and therefore might simply be absent. Discovering that at the
/// moment someone flashes is the worst time; discovering it in `doctor` is
/// the point of `doctor`.
///
/// **It deliberately runs the *located* core binary rather than reasoning
/// here**, which on this suite's own bench means running a Windows `.exe`
/// from WSL2. That is the correct answer rather than an accident: the tool has
/// to exist on the machine running Core, not the machine running `doctor`, and
/// invoking Core's own binary is the only thing that answers the question
/// about the right machine. A second implementation of the search here would
/// be a mirror that drifts — the same mistake `doctor`'s check 8 was
/// refactored out of.
fn check_flash_backend(core: Option<&Located>) -> Check {
    const NAME: &str = "flashing backend available for every chip family";
    let Some(core) = core else {
        return check(14, NAME, Status::Warn, "skipped — embarch-core not located (see check 1)");
    };

    let output = match Command::new(&core.path).arg("flash-backend").output() {
        Ok(o) => o,
        Err(e) => {
            return check(
                14,
                NAME,
                Status::Warn,
                format!("couldn't run `{} flash-backend`: {e}", core.path.display()),
            )
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut unavailable: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split('\t');
        let (Some(chip), Some(backend)) = (parts.next(), parts.next()) else { continue };
        if backend == "UNAVAILABLE" {
            unavailable.push(chip.to_string());
        } else {
            rows.push((chip.to_string(), backend.to_string()));
        }
    }

    if rows.is_empty() && unavailable.is_empty() {
        // An older Core predating the subcommand answers with a clap error.
        return check(
            14,
            NAME,
            Status::Warn,
            "this embarch-core has no `flash-backend` subcommand — it predates §3 decision 36 and \
             will flash every target with probe-rs, including Nordic RRAM parts",
        );
    }

    let summary = rows
        .iter()
        .map(|(c, b)| format!("{c}={b}"))
        .collect::<Vec<_>>()
        .join(", ");

    if unavailable.is_empty() {
        return check(14, NAME, Status::Pass, summary);
    }

    with_fix(
        check(
            14,
            NAME,
            Status::Fail,
            format!("no backend for {}{}{summary}", unavailable.join(", "), if summary.is_empty() { "" } else { " — resolved: " }),
        ),
        // Core's own error already names the tools, the URLs and the override
        // variables; pointing at it beats paraphrasing it into a second place
        // that can go stale.
        format!(
            "install a vendor flashing tool on the machine running embarch-core, then re-run. \
             `{} flash-backend` prints exactly which tools it looked for and where.",
            core.path.display()
        ),
    )
}

fn render_human(checks: &[Check]) {
    for c in checks {
        println!("[{:>2}] {} {} — {}", c.n, c.status.label(), c.name, c.detail);
        if let Some(fix) = &c.fix {
            println!("       fix: {fix}");
        }
    }
}

fn render_json(checks: &[Check], any_fail: bool) -> String {
    let checks_json: Vec<_> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "n": c.n,
                "name": c.name,
                "status": c.status.as_str(),
                "detail": c.detail,
                "fix": c.fix,
            })
        })
        .collect();
    serde_json::json!({ "success": !any_fail, "checks": checks_json }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut base = std::env::temp_dir();
        base.push(format!(
            "embarch-umbrella-doctor-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git").args(args).current_dir(dir).status().unwrap();
        assert!(status.success(), "git {args:?} failed in {}", dir.display());
    }

    fn init_repo(dir: &Path) {
        git(dir, &["init", "-q"]);
        git(dir, &["config", "user.email", "test@example.com"]);
        git(dir, &["config", "user.name", "test"]);
        std::fs::write(dir.join("f.txt"), "1").unwrap();
        git(dir, &["add", "f.txt"]);
        git(dir, &["commit", "-q", "-m", "first"]);
    }

    #[test]
    fn dev_bench_repo_path_env_override_beats_saved_state() {
        let saved = state::State { dev_bench_repo_path: Some(PathBuf::from("/saved/path")), ..Default::default() };
        assert_eq!(
            dev_bench_repo_path_from(Some("/env/path"), &saved),
            Some(PathBuf::from("/env/path"))
        );
    }

    #[test]
    fn dev_bench_repo_path_falls_back_to_saved_state_with_no_override() {
        let saved = state::State { dev_bench_repo_path: Some(PathBuf::from("/saved/path")), ..Default::default() };
        assert_eq!(dev_bench_repo_path_from(None, &saved), Some(PathBuf::from("/saved/path")));
    }

    #[test]
    fn dev_bench_repo_path_is_none_when_neither_is_set() {
        assert_eq!(dev_bench_repo_path_from(None, &state::State::default()), None);
    }

    #[test]
    fn git_describe_matches_the_same_invocation_dev_bench_builds_with() {
        let dir = tempdir();
        init_repo(dir.path());
        let described = git_describe(dir.path()).unwrap();
        // No tag exists, so `--always` falls back to the abbreviated commit
        // hash — exactly what embarch-dev-bench/app/CMakeLists.txt embeds as
        // APP_FIRMWARE_VERSION for an untagged checkout.
        assert!(!described.is_empty());
        assert!(!described.contains("dirty"));
    }

    #[test]
    fn git_describe_flags_an_uncommitted_change_as_dirty() {
        let dir = tempdir();
        init_repo(dir.path());
        std::fs::write(dir.path().join("f.txt"), "2").unwrap();
        let described = git_describe(dir.path()).unwrap();
        assert!(described.ends_with("-dirty"));
    }

    #[test]
    fn git_describe_errors_outside_a_git_checkout() {
        let dir = tempdir();
        assert!(git_describe(dir.path()).is_err());
    }

    #[test]
    fn unc_round_trips_with_wsl_unc_path() {
        let unc = crate::init::wsl_unc_path("Ubuntu-24.04", Path::new("/home/me/fw/embarch/build/zephyr/zephyr.hex"));
        let (distro, back) = unc_to_wsl_path(&unc).expect("should parse the UNC form it just produced");
        assert_eq!(distro, "Ubuntu-24.04");
        assert_eq!(back, PathBuf::from("/home/me/fw/embarch/build/zephyr/zephyr.hex"));
    }

    #[test]
    fn unc_parsing_rejects_non_unc_input() {
        assert!(unc_to_wsl_path("/home/me/fw/zephyr.hex").is_none());
        assert!(unc_to_wsl_path(r"C:\ProgramData\embarch\token").is_none());
    }

    #[test]
    fn wsl_dollar_alias_is_also_accepted() {
        let (distro, back) = unc_to_wsl_path(r"\\wsl$\Ubuntu-24.04\home\me\x.hex").unwrap();
        assert_eq!(distro, "Ubuntu-24.04");
        assert_eq!(back, PathBuf::from("/home/me/x.hex"));
    }

    #[test]
    fn resolve_program_finds_an_absolute_path() {
        // /bin/sh (or its equivalent) exists on every unix test runner this
        // crate builds on.
        let sh = if cfg!(unix) { "/bin/sh" } else { "C:\\Windows\\System32\\cmd.exe" };
        assert_eq!(resolve_program(sh, Path::new("/")), Some(PathBuf::from(sh)));
    }

    #[test]
    fn resolve_program_reports_missing_absolute_path() {
        assert_eq!(resolve_program("/no/such/binary-xyz", Path::new("/")), None);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_program_searches_path_for_a_bare_name() {
        // `sh` is on PATH in any environment this test runs in.
        assert!(resolve_program("sh", Path::new("/")).is_some());
    }

    #[test]
    fn chip_placeholder_is_caught() {
        let projects = vec![sample_project("fw", "CHANGE-ME")];
        let c = check_chip(&projects);
        assert_eq!(c.status, Status::Fail);
        assert!(c.fix.is_some());
    }

    #[test]
    fn a_real_chip_passes() {
        let projects = vec![sample_project("fw", "nRF54L15_M33")];
        let c = check_chip(&projects);
        assert_eq!(c.status, Status::Pass);
    }

    // ---- check 11: the comparison, with every number injected ---------------
    //
    // decision 33: this is the boundary the check exists at, and it is
    // reachable with no Core, no bench and no network — which is the whole
    // reason the numbers are threaded in as a struct rather than fetched
    // inside the check.

    fn versions<'a>(
        core_host: Result<u32, &'a str>,
        local_host: u32,
        bench_wire: Result<(u32, Option<bool>), &'a str>,
    ) -> SchemaVersions<'a> {
        SchemaVersions { core_host, local_host, bench_wire }
    }

    #[test]
    fn matching_host_versions_and_an_accepted_bench_pass() {
        let c = judge_schema_versions(&versions(Ok(17), 17, Ok((15, Some(true)))));
        assert_eq!(c.status, Status::Pass);
        // Every number is in the message, never a hardcoded string.
        assert!(c.detail.contains("v17"), "{}", c.detail);
        assert!(c.detail.contains("v15"), "{}", c.detail);
        assert!(c.fix.is_none());
    }

    #[test]
    fn a_host_version_disagreement_fails_and_names_both_numbers() {
        let c = judge_schema_versions(&versions(Ok(16), 17, Ok((15, Some(true)))));
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("v16") && c.detail.contains("v17"), "{}", c.detail);
        assert!(c.fix.as_deref().unwrap().contains("deploy-core"));
    }

    #[test]
    fn a_bench_core_refuses_fails_even_when_the_host_pair_agrees() {
        // The 2026-08-26 state: Core and api fine, bench flashed past Core.
        let c = judge_schema_versions(&versions(Ok(17), 17, Ok((14, Some(false)))));
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("v14"), "{}", c.detail);
        assert!(c.fix.as_deref().unwrap().contains("reflash"));
    }

    #[test]
    fn a_host_disagreement_still_fails_when_the_bench_number_is_missing() {
        // A Warn from the missing bench number must not mask a Fail.
        let c = judge_schema_versions(&versions(Ok(16), 17, Err("no dev-bench plugged in")));
        assert_eq!(c.status, Status::Fail);
    }

    #[test]
    fn an_unavailable_core_version_is_a_skip_that_says_why_not_a_pass() {
        let c = judge_schema_versions(&versions(
            Err("Core isn't reachable (see check 3)"),
            17,
            Err("no dev-bench plugged in"),
        ));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("Core isn't reachable"), "{}", c.detail);
        // The number that *is* available is still reported.
        assert!(c.detail.contains("v17"), "{}", c.detail);
        // And never the reason that stopped being true.
        assert!(!c.detail.contains("not available yet"), "{}", c.detail);
    }

    #[test]
    fn a_missing_bench_number_is_a_skip_that_says_why_not_a_pass() {
        let c = judge_schema_versions(&versions(Ok(17), 17, Err("no dev-bench plugged in")));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("no dev-bench plugged in"), "{}", c.detail);
    }

    #[test]
    fn a_bench_number_with_no_verdict_to_judge_it_by_is_a_warn() {
        let c = judge_schema_versions(&versions(Ok(17), 17, Ok((15, None))));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("no `compatible` verdict"), "{}", c.detail);
    }

    #[test]
    fn the_local_host_version_is_this_binarys_compiled_constant() {
        // The check has to compare against a real constant, not a literal
        // this test would have to be updated alongside.
        let c = check_schema_versions(None, &HelloOutcome::NoBench);
        assert!(
            c.detail.contains(&format!("v{}", embarch_study_designer::HOST_TYPE_SCHEMA_VERSION)),
            "{}",
            c.detail
        );
        assert_eq!(c.status, Status::Warn);
    }

    // ---- check 15: core_version, a different question ------------------------

    #[test]
    fn a_running_core_matching_the_located_binary_passes() {
        let c = judge_core_build(Some("0.1.0"), Some("embarch-core 0.1.0"));
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains("0.1.0"));
    }

    #[test]
    fn a_stale_cross_version_deploy_warns_and_names_both_builds() {
        let c = judge_core_build(Some("0.1.0"), Some("embarch-core 0.2.0"));
        // Warn, never fail — embarch-core decision 13, and decision 24 here.
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("0.1.0") && c.detail.contains("0.2.0"), "{}", c.detail);
        assert!(c.fix.as_deref().unwrap().contains("deploy-core"));
    }

    #[test]
    fn a_same_version_stale_deploy_is_invisible_and_the_check_says_so() {
        // The honest limit, asserted rather than only documented: identical
        // crate versions read as a match however different the binaries are.
        let c = judge_core_build(Some("0.1.0"), Some("embarch-core 0.1.0"));
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains("same-version stale deploy is invisible"), "{}", c.detail);
    }

    #[test]
    fn a_core_predating_core_version_is_a_skip_that_says_what_it_predates() {
        let c = judge_core_build(None, Some("embarch-core 0.1.0"));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("decision 13"), "{}", c.detail);
    }

    #[test]
    fn nothing_local_to_compare_against_is_a_skip_naming_check_1() {
        let c = judge_core_build(Some("0.1.0"), None);
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("check 1"), "{}", c.detail);
    }

    #[test]
    fn check_15_skips_when_there_is_no_authenticated_status() {
        let c = check_core_build(None, Some("embarch-core 0.1.0"));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.starts_with("skipped —"), "{}", c.detail);
    }

    fn sample_project(name: &str, chip: &str) -> ProjectConfig {
        ProjectConfig {
            name: name.to_string(),
            source_path: PathBuf::from("/repo"),
            discovery: config::Discovery::Static,
            build_cwd: None,
            build_command: Some(vec!["west".to_string(), "build".to_string()]),
            artifact_path: Some(PathBuf::from("build/zephyr/zephyr.hex")),
            chip: Some(chip.to_string()),
            artifact_path_for_core: None,
            west_binary: None,
        }
    }
}
