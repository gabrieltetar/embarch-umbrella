//! `embarch doctor` — design.md §5's twelve checks, each pass/warn/fail plus
//! a fix line for anything short of a pass. milestone-6.md §3.4.
//!
//! Ordered the same as design.md §5's table, and largely dependency-ordered
//! too: checks 4/5/12 need check 3's winning candidate, checks 7-9 need
//! check 6's config. When a prerequisite check didn't pass, the checks that
//! depend on it report themselves `Warn`-skipped rather than re-deriving (or
//! silently repeating) the same failure — the exit code still reflects the
//! one real failure, not N copies of it.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, Config, ProjectConfig};
use crate::locate::{self, Located};
use crate::setup;
use crate::state;
use crate::topology::{self, ProbeOutcome, TopologyClass};
use crate::{env, probe};

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
fn declared_candidate(config: Option<&Config>) -> Option<topology::Candidate> {
    let core = &config?.core;
    if core.is_auto() {
        return None;
    }
    let base_url = core.base_url.trim_end_matches('/').to_string();
    let class = if base_url.contains("127.0.0.1") || base_url.contains("localhost") {
        TopologyClass::Local
    } else {
        TopologyClass::Remote
    };
    Some(topology::Candidate { class, base_url })
}

async fn resolve_candidates(candidates: &[topology::Candidate]) -> CoreProbe {
    let client = reqwest::Client::new();
    let client = &client;
    let attempts = topology::resolve(candidates, move |url| async move {
        probe::probe_core(client, &url).await
    })
    .await;

    let winner = topology::winner(&attempts);
    CoreProbe {
        winner_base_url: winner.map(|a| a.candidate.base_url.clone()),
        winner_class: winner.map(|a| a.candidate.class),
        attempts,
    }
}

async fn probe_topology(config: Option<&Config>, host: Option<&str>, port: u16) -> CoreProbe {
    if let Some(declared) = declared_candidate(config) {
        return resolve_candidates(std::slice::from_ref(&declared)).await;
    }

    let under_wsl2 = env::under_wsl2();
    let gateway = if under_wsl2 { env::default_gateway() } else { None };
    let candidates = topology::candidates(under_wsl2, gateway.as_deref(), host, port);
    resolve_candidates(&candidates).await
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

fn check_binaries(core: Option<&Located>, api: Option<&Located>) -> Check {
    match (core, api) {
        (Some(c), Some(a)) => {
            let c_ver = binary_version(&c.path);
            let a_ver = binary_version(&a.path);
            let c_display = c_ver.as_deref().unwrap_or("version unknown");
            let a_display = a_ver.as_deref().unwrap_or("version unknown");
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
                    let mismatches = manifest_mismatches(&m, c_ver.as_deref(), a_ver.as_deref());
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

struct AuthedStatus {
    probes: Vec<serde_json::Value>,
}

async fn authed_get(base_url: &str, path: &str, token: &str) -> Result<(u16, String), String> {
    let client = reqwest::Client::new();
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .bearer_auth(token)
        .timeout(probe::PROBE_TIMEOUT)
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
            let probes = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("probes").cloned())
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            (
                check(4, "token resolves and matches", Status::Pass, "authenticated (200)"),
                Some(AuthedStatus { probes }),
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
        let Some(program) = p.build_command.first() else {
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
            "install the missing tool, or fix build_command in embarch/embarch.toml",
        )
    }
}

// ---- check 8: chip placeholder ----------------------------------------------

const CHIP_PLACEHOLDER: &str = "CHANGE-ME";

fn check_chip(projects: &[ProjectConfig]) -> Check {
    if projects.is_empty() {
        return check(8, "chip is not still a placeholder", Status::Warn, "no projects configured");
    }
    let placeholders: Vec<&str> = projects
        .iter()
        .filter(|p| p.chip == CHIP_PLACEHOLDER)
        .map(|p| p.name.as_str())
        .collect();

    if placeholders.is_empty() {
        check(8, "chip is not still a placeholder", Status::Pass, format!("{} project(s) checked", projects.len()))
    } else {
        with_fix(
            check(8, "chip is not still a placeholder", Status::Fail, format!("still CHANGE-ME for: {}", placeholders.join(", "))),
            "cargo install probe-rs-tools && probe-rs chip list | grep -i <your soc>, then set `chip` \
             in embarch/embarch.toml",
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
        let resolved = p.resolved_artifact_path();
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

// ---- check 11: study_designer_schema_version -------------------------------

fn check_schema_version() -> Check {
    check(
        11,
        "study_designer_schema_version agrees",
        Status::Warn,
        "not available yet — embarch-study-designer isn't wired into embarch-core/embarch-api as a \
         dependency yet (embarch.md §3), so neither side has a version to compare",
    )
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

    let check1 = check_binaries(core.as_ref(), api.as_ref());
    let check2 = check_service(&core_probe, host.as_deref(), core.as_ref());
    let check3 = check_reachable(&core_probe);
    let (check4, authed) = check_token(&core_probe, config.as_ref()).await;
    let check5 = check_probes(authed.as_ref());
    let projects: &[ProjectConfig] = config.as_ref().map(|c| c.projects.as_slice()).unwrap_or(&[]);
    let check7 = check_build_commands(projects);
    let check8 = check_chip(projects);
    let check9 = check_artifact_paths(projects);
    let check10 = check_mcp(config_path.as_deref(), api.as_ref());
    let check11 = check_schema_version();
    let check12 = check_dev_bench(&core_probe, authed.as_ref(), config.as_ref()).await;

    let checks = vec![
        check1, check2, check3, check4, check5, check6, check7, check8, check9, check10, check11, check12,
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

    fn sample_project(name: &str, chip: &str) -> ProjectConfig {
        ProjectConfig {
            name: name.to_string(),
            source_path: PathBuf::from("/repo"),
            build_cwd: None,
            build_command: vec!["west".to_string(), "build".to_string()],
            artifact_path: PathBuf::from("build/zephyr/zephyr.hex"),
            chip: chip.to_string(),
            artifact_path_for_core: None,
        }
    }
}
