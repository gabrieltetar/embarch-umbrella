//! `embarch agent up | down | status | shell`: start, stop, check and enter the
//! agent's container (decision 67).
//!
//! Everything goes through [`ContainerRuntime`], one adapter over Docker or
//! Podman, and every process through [`Process`], so a test runs each verb
//! against a fake that records every argv. Nothing here runs a container in a
//! test and nothing was run against a real one.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Result};

use crate::agent::{
    forbidden_findings, image_tag, parse_container_toml, sha256_hex, ContainerRecord,
    Runtime, Topology, CHECK_TIMEOUT_SECS, CORE_ADDR_PLACEHOLDER, CORE_ADDR_START_FILE, MODEL_API_PORT, OFF_LIST_PROBE_ADDR,
    TARGET_DEFINITION,
};
use crate::state::{RegisteredContainer, State};

/// The file in the definition folder, beside the token file's host-side twin.
pub const FINGERPRINT_FILE: &str = "core-fingerprint";
const CONTAINER_TOML: &str = "container.toml";
const CONTAINERFILE: &str = "Containerfile";
const BUILD_CONTEXT_DIR: &str = "build-context";
const AGENT_USER: &str = "agent";
const ROOT_SCRIPT: &str = "entrypoint-root.sh";
const AGENT_SCRIPT: &str = "entrypoint-agent.sh";

/// What a finished process left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[cfg(test)]
impl Output {
    pub fn ok(stdout: &str) -> Self {
        Output { code: 0, stdout: stdout.to_string(), stderr: String::new() }
    }
    pub fn fail(code: i32, stderr: &str) -> Self {
        Output { code, stdout: String::new(), stderr: stderr.to_string() }
    }
}

/// Runs a program. The real one is `std::process`; a test's records the argv.
pub trait Process {
    /// Run and capture output.
    fn run(&self, program: &str, args: &[String]) -> Result<Output>;
    /// Run with this terminal's stdin, stdout and stderr; return the exit code.
    fn run_inherit(&self, program: &str, args: &[String]) -> Result<i32>;
}

/// The real [`Process`].
pub struct RealProcess;

impl Process for RealProcess {
    fn run(&self, program: &str, args: &[String]) -> Result<Output> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("could not run {program}"))?;
        Ok(Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
    fn run_inherit(&self, program: &str, args: &[String]) -> Result<i32> {
        let st = std::process::Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("could not run {program}"))?;
        Ok(st.code().unwrap_or(-1))
    }
}

/// How `exec` runs a command in the container.
#[derive(Debug, Clone, Default)]
pub struct ExecSpec {
    pub user: Option<String>,
    pub workdir: Option<String>,
    /// `-it`, with this terminal's own streams.
    pub interactive: bool,
}

/// What a container runtime does for `embarch agent`.
pub trait ContainerRuntime {
    /// Build `tag` from `containerfile` with `context` as the build context.
    fn build(&self, tag: &str, containerfile: &Path, context: &Path) -> Result<()>;
    fn image_exists(&self, tag: &str) -> Result<bool>;
    /// Idempotent on both runtimes: creating an existing volume changes nothing.
    fn volume_create(&self, name: &str) -> Result<()>;
    /// `run_args` is what follows `run`. Returns the container id.
    fn run(&self, run_args: &[String]) -> Result<String>;
    fn stop(&self, name: &str) -> Result<()>;
    fn rm(&self, name: &str) -> Result<()>;
    /// The command's own exit code is the [`Output`]'s, not an error.
    fn exec(&self, name: &str, spec: &ExecSpec, cmd: &[&str]) -> Result<Output>;
    /// `<kind> inspect <name>` as the runtime's JSON; `None` when it is absent.
    fn inspect(&self, kind: &str, name: &str) -> Result<Option<String>>;
}

/// Docker and Podman differ in the binary and nothing else here: the verbs
/// used are the same on both, which is the point of the adapter. A fork a test
/// shows is a branch on `runtime`, with its reason beside it.
pub struct CliRuntime {
    binary: String,
    proc: Rc<dyn Process>,
}

impl CliRuntime {
    pub fn docker(binary: &Path, proc: Rc<dyn Process>) -> Self {
        CliRuntime { binary: binary.to_string_lossy().into_owned(), proc }
    }
    pub fn podman(binary: &Path, proc: Rc<dyn Process>) -> Self {
        CliRuntime { binary: binary.to_string_lossy().into_owned(), proc }
    }
    pub fn for_runtime(runtime: Runtime, binary: &Path, proc: Rc<dyn Process>) -> Self {
        match runtime {
            Runtime::Docker => Self::docker(binary, proc),
            Runtime::Podman => Self::podman(binary, proc),
        }
    }
    fn must(&self, args: Vec<String>) -> Result<Output> {
        let out = self.proc.run(&self.binary, &args)?;
        if out.code != 0 {
            bail!("`{} {}` failed ({}): {}", self.binary, args.join(" "), out.code, out.stderr.trim());
        }
        Ok(out)
    }
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

impl ContainerRuntime for CliRuntime {
    fn build(&self, tag: &str, containerfile: &Path, context: &Path) -> Result<()> {
        let args = vec![
            "build".to_string(),
            "--tag".to_string(),
            tag.to_string(),
            "--file".to_string(),
            containerfile.to_string_lossy().into_owned(),
            context.to_string_lossy().into_owned(),
        ];
        // Inherited, so the person sees the build's progress.
        let code = self.proc.run_inherit(&self.binary, &args)?;
        if code != 0 {
            bail!("`{} build` for {tag} failed ({code})", self.binary);
        }
        Ok(())
    }
    fn image_exists(&self, tag: &str) -> Result<bool> {
        Ok(self.proc.run(&self.binary, &strings(&["image", "inspect", tag]))?.code == 0)
    }
    fn volume_create(&self, name: &str) -> Result<()> {
        self.must(strings(&["volume", "create", name])).map(|_| ())
    }
    fn run(&self, run_args: &[String]) -> Result<String> {
        let mut args = vec!["run".to_string()];
        args.extend(run_args.iter().cloned());
        Ok(self.must(args)?.stdout.trim().to_string())
    }
    fn stop(&self, name: &str) -> Result<()> {
        self.must(strings(&["stop", name])).map(|_| ())
    }
    fn rm(&self, name: &str) -> Result<()> {
        self.must(strings(&["rm", name])).map(|_| ())
    }
    fn exec(&self, name: &str, spec: &ExecSpec, cmd: &[&str]) -> Result<Output> {
        let mut args = vec!["exec".to_string()];
        if spec.interactive {
            args.push("-it".to_string());
        }
        if let Some(u) = &spec.user {
            args.extend(["-u".to_string(), u.clone()]);
        }
        if let Some(w) = &spec.workdir {
            args.extend(["-w".to_string(), w.clone()]);
        }
        args.push(name.to_string());
        args.extend(cmd.iter().map(|s| s.to_string()));
        if spec.interactive {
            let code = self.proc.run_inherit(&self.binary, &args)?;
            return Ok(Output { code, stdout: String::new(), stderr: String::new() });
        }
        self.proc.run(&self.binary, &args)
    }
    fn inspect(&self, kind: &str, name: &str) -> Result<Option<String>> {
        let out = self.proc.run(&self.binary, &strings(&[kind, "inspect", name]))?;
        Ok((out.code == 0).then_some(out.stdout))
    }
}

/// The runtime's default bridge network, whose gateway is the host from a
/// container on a Linux host. **From memory, to be checked** for Podman.
pub fn default_network(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Docker => "bridge",
        Runtime::Podman => "podman",
    }
}

/// The first string value under a key named `key` (case-insensitive) in
/// `json`, depth first. Docker and Podman spell the same fields differently,
/// so the adapter reads the JSON by name and not by a Go template.
fn find_string(v: &serde_json::Value, key: &str) -> Option<String> {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if k.eq_ignore_ascii_case(key) {
                    if let Some(s) = val.as_str().filter(|s| !s.is_empty()) {
                        return Some(s.to_string());
                    }
                }
            }
            m.values().find_map(|val| find_string(val, key))
        }
        serde_json::Value::Array(a) => a.iter().find_map(|val| find_string(val, key)),
        _ => None,
    }
}

fn find_bool(v: &serde_json::Value, key: &str) -> Option<bool> {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if k.eq_ignore_ascii_case(key) {
                    if let Some(b) = val.as_bool() {
                        return Some(b);
                    }
                }
            }
            m.values().find_map(|val| find_bool(val, key))
        }
        serde_json::Value::Array(a) => a.iter().find_map(|val| find_bool(val, key)),
        _ => None,
    }
}

/// The gateway in a `network inspect`'s JSON.
pub fn gateway_from_inspect(json: &str) -> Option<String> {
    find_string(&serde_json::from_str(json).ok()?, "gateway")
}

/// Whether a `container inspect`'s JSON says it is running.
pub fn running_from_inspect(json: &str) -> bool {
    serde_json::from_str(json).ok().and_then(|v| find_bool(&v, "running")).unwrap_or(false)
}

/// The text to name the install, when no runtime binary is on `PATH`.
fn install_pointer(runtime: Runtime) -> String {
    format!(
        "`{bin}` is not on PATH, so nothing can start, stop or check the agent's container. Install {name} first \
         (the owner's first-container step: docs.docker.com/engine/install for Docker, podman.io/docs/installation for Podman), \
         then run this again. `embarch init --container --runtime podman` records Podman instead.",
        bin = runtime.binary(),
        name = match runtime {
            Runtime::Docker => "Docker Engine",
            Runtime::Podman => "Podman",
        }
    )
}

/// Find `binary` in a `PATH` value.
pub fn find_on_path(binary: &str, path_var: Option<&OsString>) -> Option<PathBuf> {
    let path_var = path_var?;
    std::env::split_paths(path_var).map(|d| d.join(binary)).find(|p| p.is_file())
}

/// What a verb needs from the machine, resolved by the caller.
pub struct Ctx {
    pub state: State,
    /// Core's data directory as seen from here; the host-side fingerprint is
    /// beside the token file in it. `None` for a remote Core.
    pub core_data_dir: Option<PathBuf>,
    pub path_var: Option<OsString>,
    pub proc: Rc<dyn Process>,
    pub cwd: PathBuf,
}

/// One registered agent.
pub struct Target {
    pub repo: PathBuf,
    pub container: RegisteredContainer,
    pub record: ContainerRecord,
}

/// The agent a verb acts on: the one named, or the one whose repo holds the
/// current folder, or the only one registered.
fn pick(ctx: &Ctx, name: Option<&str>) -> Result<(PathBuf, RegisteredContainer)> {
    let all: Vec<(&PathBuf, &RegisteredContainer)> =
        ctx.state.registered_repos.iter().filter_map(|r| r.container.as_ref().map(|c| (&r.path, c))).collect();
    let listing = || all.iter().map(|(_, c)| c.name.as_str()).collect::<Vec<_>>().join(", ");
    if all.is_empty() {
        bail!("no repo has an agent container: run `embarch init --container` in a firmware repo first");
    }
    let found = match name {
        Some(n) => all.iter().find(|(_, c)| c.name == n),
        None => all
            .iter()
            .find(|(p, _)| ctx.cwd.starts_with(p))
            .or_else(|| (all.len() == 1).then(|| &all[0])),
    };
    match found {
        Some((p, c)) => Ok(((*p).clone(), (*c).clone())),
        None => match name {
            Some(n) => bail!("no agent named {n}: registered are {}", listing()),
            None => bail!("which agent? run from inside its repo or name one: {}", listing()),
        },
    }
}

fn load_target(ctx: &Ctx, name: Option<&str>) -> Result<Target> {
    let (repo, container) = pick(ctx, name)?;
    let path = container.definition_dir.join(CONTAINER_TOML);
    let text = std::fs::read_to_string(&path).with_context(|| format!("could not read {}: run `embarch init --container` again", path.display()))?;
    let record = parse_container_toml(&text).map_err(|e| anyhow!("{} does not parse: {e}", path.display()))?;
    Ok(Target { repo, container, record })
}

fn runtime_for(ctx: &Ctx, runtime: Runtime) -> Result<CliRuntime> {
    let bin = find_on_path(runtime.binary(), ctx.path_var.as_ref()).ok_or_else(|| anyhow!(install_pointer(runtime)))?;
    Ok(CliRuntime::for_runtime(runtime, &bin, ctx.proc.clone()))
}

/// The value of `--<flag>` in a rendered vector.
fn arg_value<'a>(args: &'a [String], prefix: &str) -> Option<&'a str> {
    args.iter().find_map(|a| a.strip_prefix(prefix))
}

fn container_name(args: &[String]) -> Result<&str> {
    arg_value(args, "--name=").ok_or_else(|| anyhow!("the recorded vector names no container (--name)"))
}

fn volume_name(args: &[String]) -> Result<&str> {
    args.iter()
        .find_map(|a| a.strip_prefix("--mount=type=volume,source=").and_then(|r| r.split(',').next()))
        .ok_or_else(|| anyhow!("the recorded vector names no volume"))
}

/// The recorded vector with Core's address filled in, refused if the record
/// was edited or the scan names anything.
fn checked_vector(record: &ContainerRecord, core_addr: &str) -> Result<Vec<String>> {
    if record.hand_edited() {
        bail!("{CONTAINER_TOML} was edited by hand: its vector no longer hashes to the hash it records. Delete it and run `embarch init --container` to render it again");
    }
    let args: Vec<String> = record.run_args.iter().map(|a| a.replace(CORE_ADDR_PLACEHOLDER, core_addr)).collect();
    let findings = forbidden_findings(&args);
    if !findings.is_empty() {
        bail!("the recorded vector is refused: {}", findings.join("; "));
    }
    Ok(args)
}

/// Stage the build context: the Containerfile and every requirements file it
/// copies, each re-read from the workspace and held to the hash the
/// Containerfile records, so a file changed since `init` is refused, not built.
fn stage_context(target: &Target, containerfile: &str) -> Result<(PathBuf, PathBuf)> {
    let ctx_dir = target.container.exchange_dir.join(BUILD_CONTEXT_DIR);
    let _ = std::fs::remove_dir_all(&ctx_dir);
    std::fs::create_dir_all(ctx_dir.join("requirements")).with_context(|| format!("could not create {}", ctx_dir.display()))?;
    let lines: Vec<&str> = containerfile.lines().collect();
    let facts = crate::agent_init::read_workspace_facts(&target.repo, true);
    for (i, line) in lines.iter().enumerate() {
        let Some(name) = line.strip_prefix("COPY requirements/").and_then(|r| r.split_whitespace().next()) else { continue };
        let want = i
            .checked_sub(1)
            .and_then(|j| lines[j].strip_prefix(&format!("# {name} sha256 ")))
            .ok_or_else(|| anyhow!("the Containerfile copies requirements/{name} with no recorded hash above it"))?;
        let text = facts
            .requirements
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| t)
            .ok_or_else(|| anyhow!("requirements/{name} is not in {}'s workspace any more: run `embarch init --container` again", target.repo.display()))?;
        if sha256_hex(text.as_bytes()) != want.trim() {
            bail!("requirements/{name} changed since `init` rendered the Containerfile: run `embarch init --container` again");
        }
        std::fs::write(ctx_dir.join("requirements").join(name), text)?;
    }
    let file = ctx_dir.join(CONTAINERFILE);
    std::fs::write(&file, containerfile)?;
    Ok((file, ctx_dir))
}

/// Core's address as the container sees it (decision 63).
fn resolve_core_addr(record: &ContainerRecord, rt: &dyn ContainerRuntime, proc: &dyn Process) -> Result<String> {
    let wsl = if record.topology == Topology::WslHost {
        proc.run("ip", &strings(&["route", "show", "default"]))
            .ok()
            .filter(|o| o.code == 0)
            .and_then(|o| embarch_topology::software::parse_default_gateway(&o.stdout))
    } else {
        None
    };
    let bridge = if record.topology == Topology::Linux {
        rt.inspect("network", default_network(record.runtime))?.and_then(|j| gateway_from_inspect(&j))
    } else {
        None
    };
    crate::agent::core_addr_from_container(record.topology, record.runtime, wsl.as_deref(), bridge.as_deref())
}

/// `embarch agent up [<name>]`. Returns the lines to print.
pub fn up(ctx: &Ctx, name: Option<&str>) -> Result<Vec<String>> {
    let target = load_target(ctx, name)?;
    let rt = runtime_for(ctx, target.record.runtime)?;
    let def = &target.container.definition_dir;
    let containerfile = std::fs::read_to_string(def.join(CONTAINERFILE))
        .with_context(|| format!("could not read {}", def.join(CONTAINERFILE).display()))?;
    if image_tag(&containerfile) != target.record.image_tag {
        bail!("the Containerfile no longer matches the image tag {} that {CONTAINER_TOML} records: it was edited by hand", target.record.image_tag);
    }
    let mut lines = Vec::new();
    // Check the record before any side effect; the address is filled in below.
    checked_vector(&target.record, "0.0.0.0")?;
    let cname = container_name(&target.record.run_args)?.to_string();
    if rt.inspect("container", &cname)?.is_some() {
        bail!("{cname} already exists: run `embarch agent down {}` first", target.container.name);
    }
    if rt.image_exists(&target.record.image_tag)? {
        lines.push(format!("image {} exists", target.record.image_tag));
    } else {
        let (file, dir) = stage_context(&target, &containerfile)?;
        rt.build(&target.record.image_tag, &file, &dir)?;
        lines.push(format!("built {}", target.record.image_tag));
    }
    rt.volume_create(volume_name(&target.record.run_args)?)?;
    let addr = resolve_core_addr(&target.record, &rt, ctx.proc.as_ref())?;
    let addr_file = def.join(CORE_ADDR_START_FILE);
    std::fs::create_dir_all(addr_file.parent().expect("a file under start/"))?;
    std::fs::write(&addr_file, format!("{addr}\n")).with_context(|| format!("could not write {}", addr_file.display()))?;
    let mut args = checked_vector(&target.record, &addr)?;
    debug_assert_eq!(args.first().map(String::as_str), Some("run"));
    args.remove(0);
    args.push(format!("{TARGET_DEFINITION}/{ROOT_SCRIPT}"));
    args.push(format!("{TARGET_DEFINITION}/{AGENT_SCRIPT}"));
    let id = rt.run(&args)?;
    lines.push(format!("started {cname} ({id}); Core at {addr}:{}", target.record.core_port));
    Ok(lines)
}

/// `embarch agent down [<name>]`: the volume and the exchange folder stay.
pub fn down(ctx: &Ctx, name: Option<&str>) -> Result<Vec<String>> {
    let target = load_target(ctx, name)?;
    let rt = runtime_for(ctx, target.record.runtime)?;
    let cname = container_name(&target.record.run_args)?.to_string();
    let Some(json) = rt.inspect("container", &cname)? else {
        return Ok(vec![format!("{cname} does not exist")]);
    };
    if running_from_inspect(&json) {
        rt.stop(&cname)?;
    }
    rt.rm(&cname)?;
    Ok(vec![format!("stopped and removed {cname}; the volume and the exchange folder stay")])
}

/// One thing `status` checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn finding(name: &'static str, ok: bool, detail: impl Into<String>) -> Finding {
    Finding { name, ok, detail: detail.into() }
}

fn read_trimmed(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// `embarch agent status [<name>]`. The fingerprint is read from the
/// definition folder, which the container mounts read-only, never from the
/// agent's writable `embarch/` seed.
pub fn status(ctx: &Ctx, name: Option<&str>) -> Result<Vec<Finding>> {
    let target = load_target(ctx, name)?;
    let rt = runtime_for(ctx, target.record.runtime)?;
    let def = &target.container.definition_dir;
    let rec = &target.record;
    let mut out = Vec::new();

    out.push(if rec.hand_edited() {
        finding("definition", false, format!("{CONTAINER_TOML} was edited by hand: its vector no longer hashes to the hash it records"))
    } else {
        finding("definition", true, format!("{CONTAINER_TOML} hashes to {}", rec.run_args_sha256))
    });
    let scan = forbidden_findings(&rec.run_args);
    if !scan.is_empty() {
        out.push(finding("vector", false, scan.join("; ")));
    }
    out.push(match std::fs::read_to_string(def.join(CONTAINERFILE)) {
        Ok(t) if image_tag(&t) == rec.image_tag => finding("containerfile", true, format!("matches {}", rec.image_tag)),
        Ok(_) => finding("containerfile", false, format!("does not match the image tag {} that {CONTAINER_TOML} records", rec.image_tag)),
        Err(e) => finding("containerfile", false, format!("unreadable: {e}")),
    });

    let copy = read_trimmed(&def.join(FINGERPRINT_FILE));
    let host = ctx.core_data_dir.as_ref().and_then(|d| read_trimmed(&d.join(FINGERPRINT_FILE)));
    out.push(match (copy, host) {
        (Some(c), Some(h)) if c == h => finding("fingerprint", true, "the definition's copy matches the host's"),
        (Some(c), Some(h)) => finding("fingerprint", false, format!("the definition's copy ({c}) differs from the host's ({h}): another Core, or a copy edited by hand")),
        (None, _) => finding("fingerprint", true, "no copy in the definition folder yet (the elevated install writes it); nothing to compare"),
        (Some(_), None) => finding("fingerprint", true, "no host-side fingerprint beside the token file; nothing to compare"),
    });

    let cname = container_name(&rec.run_args)?.to_string();
    let running = rt.inspect("container", &cname)?.is_some_and(|j| running_from_inspect(&j));
    if !running {
        out.push(finding("running", false, format!("{cname} is not running: `embarch agent up`")));
        return Ok(out);
    }
    out.push(finding("running", true, cname.clone()));
    let Some(addr) = read_trimmed(&def.join(CORE_ADDR_START_FILE)).filter(|a| !a.is_empty()) else {
        out.push(finding("core", false, format!("no {CORE_ADDR_START_FILE} in the definition folder: `embarch agent down` and `up`")));
        return Ok(out);
    };
    let spec = ExecSpec { user: Some(AGENT_USER.to_string()), ..Default::default() };
    let t = CHECK_TIMEOUT_SECS.to_string();
    let probe = |host: &str, port: u16| rt.exec(&cname, &spec, &["nc", "-z", "-w", &t, host, &port.to_string()]);
    out.push(match probe(&addr, rec.core_port) {
        Ok(o) if o.code == 0 => finding("core", true, format!("{addr}:{} answers from inside", rec.core_port)),
        Ok(o) => finding("core", false, format!("{addr}:{} does not answer from inside ({})", rec.core_port, o.code)),
        Err(e) => finding("core", false, format!("could not check: {e:#}")),
    });
    out.push(match probe(OFF_LIST_PROBE_ADDR, MODEL_API_PORT) {
        Ok(o) if o.code != 0 => finding("firewall", true, format!("{OFF_LIST_PROBE_ADDR}:{MODEL_API_PORT}, off the list, is not reachable")),
        Ok(_) => finding("firewall", false, format!("{OFF_LIST_PROBE_ADDR}:{MODEL_API_PORT}, off the list, is reachable from inside")),
        Err(e) => finding("firewall", false, format!("could not check: {e:#}")),
    });
    Ok(out)
}

/// `embarch agent shell [--claude]`: into the agent's clone as the agent user.
pub fn shell(ctx: &Ctx, name: Option<&str>, claude: bool) -> Result<i32> {
    let target = load_target(ctx, name)?;
    let rt = runtime_for(ctx, target.record.runtime)?;
    let cname = container_name(&target.record.run_args)?.to_string();
    let folder = target.repo.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let spec = ExecSpec { user: Some(AGENT_USER.to_string()), workdir: Some(format!("/work/{folder}")), interactive: true };
    Ok(rt.exec(&cname, &spec, &[if claude { "claude" } else { "bash" }])?.code)
}

/// The real machine's answers for [`Ctx`].
pub fn ctx_from_env() -> Ctx {
    let state = crate::state::load();
    let core_data_dir = state
        .topology
        .as_deref()
        .and_then(crate::setup::topology_class_from_str)
        .and_then(crate::setup::data_dir_for);
    Ctx {
        state,
        core_data_dir,
        path_var: std::env::var_os("PATH"),
        proc: Rc::new(RealProcess),
        cwd: std::env::current_dir().unwrap_or_default(),
    }
}

/// Print a verb's result and return the exit code.
pub fn report(result: Result<Vec<String>>) -> i32 {
    match result {
        Ok(lines) => {
            lines.iter().for_each(|l| println!("{l}"));
            0
        }
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

/// Print `status`'s findings and return the exit code: 1 when any failed.
pub fn report_status(result: Result<Vec<Finding>>) -> i32 {
    match result {
        Ok(findings) => {
            for f in &findings {
                println!("{} {}: {}", if f.ok { "ok  " } else { "FAIL" }, f.name, f.detail);
            }
            i32::from(findings.iter().any(|f| !f.ok))
        }
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

/// A [`Process`] that records every call and answers from a script, for
/// tests of this module and of `main`'s wiring.
#[cfg(test)]
pub struct FakeProcess {
    pub log: std::cell::RefCell<Vec<String>>,
    /// `(substring of "<program> <args>", answer)`, first match wins; no match
    /// answers success with no output.
    pub script: std::cell::RefCell<Vec<(String, Output)>>,
}

#[cfg(test)]
impl FakeProcess {
    pub fn new() -> Rc<Self> {
        Rc::new(FakeProcess { log: Default::default(), script: Default::default() })
    }
    pub fn answer(&self, needle: &str, out: Output) {
        self.script.borrow_mut().push((needle.to_string(), out));
    }
    fn call(&self, program: &str, args: &[String]) -> Output {
        let line = format!("{program} {}", args.join(" "));
        self.log.borrow_mut().push(line.clone());
        self.script.borrow().iter().find(|(n, _)| line.contains(n.as_str())).map(|(_, o)| o.clone()).unwrap_or_else(|| Output::ok(""))
    }
    pub fn lines(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

#[cfg(test)]
impl Process for FakeProcess {
    fn run(&self, program: &str, args: &[String]) -> Result<Output> {
        Ok(self.call(program, args))
    }
    fn run_inherit(&self, program: &str, args: &[String]) -> Result<i32> {
        Ok(self.call(program, args).code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{hash_args, container_toml, render_containerfile, AgentContainer, Toolchain};
    use crate::state::RegisteredRepo;
    use std::time::SystemTime;

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "embarch-umbrella-agent-run-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    /// A temp machine: a definition folder written the way `init` writes it,
    /// a state naming it, and a `docker` file on PATH.
    struct Fixture {
        _t: TempDir,
        root: PathBuf,
        ctx: Ctx,
        fake: Rc<FakeProcess>,
    }

    fn plan(root: &Path, class: Topology, runtime: Runtime) -> AgentContainer {
        let mut p = AgentContainer {
            name: "fw".into(),
            repo: root.join("repos/fw"),
            west_workspace: Vec::new(),
            class,
            runtime,
            image_tag: String::new(),
            core_port: 4884,
            network_allow: vec!["api.anthropic.com".into()],
            agent_token: root.join("core/agents/fw/agent-token"),
            dev_agent_token: None,
            definition_dir: root.join("def/fw"),
            exchange_dir: root.join("ex/fw"),
            bin_dir: root.join("bin"),
            env: Vec::new(),
            toolchain: Toolchain::NotWest,
        };
        p.image_tag = image_tag(&render_containerfile(&p));
        p
    }

    fn fixture(class: Topology, runtime: Runtime, with_binary: bool) -> Fixture {
        let t = tempdir();
        let root = t.0.clone();
        let plan = plan(&root, class, runtime);
        std::fs::create_dir_all(&plan.definition_dir).unwrap();
        std::fs::create_dir_all(&plan.exchange_dir).unwrap();
        std::fs::create_dir_all(&plan.repo).unwrap();
        std::fs::write(plan.definition_dir.join(CONTAINER_TOML), container_toml(&plan)).unwrap();
        std::fs::write(plan.definition_dir.join(CONTAINERFILE), render_containerfile(&plan)).unwrap();
        let bindir = root.join("pathbin");
        std::fs::create_dir_all(&bindir).unwrap();
        if with_binary {
            std::fs::write(bindir.join(runtime.binary()), "").unwrap();
        }
        let state = State {
            registered_repos: vec![RegisteredRepo {
                path: plan.repo.clone(),
                container: Some(RegisteredContainer {
                    name: "fw".into(),
                    definition_dir: plan.definition_dir.clone(),
                    exchange_dir: plan.exchange_dir.clone(),
                }),
            }],
            ..Default::default()
        };
        let fake = FakeProcess::new();
        let ctx = Ctx {
            state,
            core_data_dir: Some(root.join("core")),
            path_var: Some(bindir.into_os_string()),
            proc: fake.clone(),
            cwd: root.clone(),
        };
        Fixture { _t: t, root, ctx, fake }
    }

    const BRIDGE: &str = r#"[{"Name":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]"#;
    const RUNNING: &str = r#"[{"State":{"Running":true}}]"#;

    fn bin(f: &Fixture, rt: &str) -> String {
        f.root.join("pathbin").join(rt).to_string_lossy().into_owned()
    }

    #[test]
    fn up_builds_only_when_the_image_is_missing_and_runs_the_recorded_vector() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::fail(1, "no such object"));
        f.fake.answer("image inspect", Output::fail(1, "no such image"));
        f.fake.answer("network inspect bridge", Output::ok(BRIDGE));
        f.fake.answer("run ", Output::ok("abc123\n"));
        let lines = up(&f.ctx, None).unwrap();
        assert!(lines.iter().any(|l| l.starts_with("built ")));
        let log = f.fake.lines();
        let d = bin(&f, "docker");
        let tag = plan(&f.root, Topology::Linux, Runtime::Docker).image_tag;
        assert!(log.iter().any(|l| l.starts_with(&format!("{d} build --tag {tag} --file "))));
        assert!(log.contains(&format!("{d} volume create embarch-agent-fw")));
        let run = log.iter().find(|l| l.starts_with(&format!("{d} run --detach"))).expect("a run");
        assert!(run.contains("--env=EMBARCH_CORE_ADDR=172.17.0.1"));
        assert!(!run.contains("<core-addr>"));
        assert!(run.ends_with(&format!("{tag} /etc/embarch-agent/entrypoint-root.sh /etc/embarch-agent/entrypoint-agent.sh")));
        let written = std::fs::read_to_string(f.root.join("def/fw/start/core-addr")).unwrap();
        assert_eq!(written, "172.17.0.1\n");
        // Build, then the volume, then run.
        let at = |s: &str| log.iter().position(|l| l.contains(s)).unwrap();
        assert!(at(" build ") < at("volume create") && at("volume create") < at(" run "));
    }

    #[test]
    fn up_does_not_build_when_an_image_carries_the_hash() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::fail(1, ""));
        f.fake.answer("network inspect bridge", Output::ok(BRIDGE));
        let lines = up(&f.ctx, Some("fw")).unwrap();
        assert!(lines[0].ends_with("exists"));
        assert!(f.fake.lines().iter().all(|l| !l.contains(" build ")));
    }

    #[test]
    fn up_on_the_wsl_host_takes_the_default_gateway() {
        let f = fixture(Topology::WslHost, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::fail(1, ""));
        f.fake.answer("ip route", Output::ok("default via 172.28.64.1 dev eth0 proto kernel\n"));
        up(&f.ctx, None).unwrap();
        let run = f.fake.lines().into_iter().find(|l| l.contains(" run --detach")).unwrap();
        assert!(run.contains("--env=EMBARCH_CORE_ADDR=172.28.64.1"));
    }

    #[test]
    fn up_refuses_a_hand_edited_definition_before_any_side_effect() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        let p = f.root.join("def/fw/container.toml");
        let t = std::fs::read_to_string(&p).unwrap().replace("--cap-drop=ALL", "--cap-drop=NONE");
        std::fs::write(&p, t).unwrap();
        let e = up(&f.ctx, None).unwrap_err().to_string();
        assert!(e.contains("edited by hand"), "{e}");
        assert!(f.fake.lines().is_empty());
    }

    #[test]
    fn up_refuses_when_the_container_exists() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::ok(RUNNING));
        let e = up(&f.ctx, None).unwrap_err().to_string();
        assert!(e.contains("agent down"), "{e}");
        assert!(f.fake.lines().iter().all(|l| !l.contains(" run ")));
    }

    #[test]
    fn up_on_podman_uses_the_podman_binary_and_its_network() {
        let f = fixture(Topology::Linux, Runtime::Podman, true);
        f.fake.answer("container inspect", Output::fail(1, ""));
        f.fake.answer("network inspect podman", Output::ok(r#"[{"name":"podman","subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]}]"#));
        up(&f.ctx, None).unwrap();
        let log = f.fake.lines();
        let p = bin(&f, "podman");
        assert!(log.iter().all(|l| l.starts_with(&p) || l.starts_with("ip ")));
        assert!(log.iter().any(|l| l.contains("--env=EMBARCH_CORE_ADDR=10.88.0.1")));
    }

    #[test]
    fn down_stops_then_removes_and_leaves_the_volume() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::ok(RUNNING));
        down(&f.ctx, None).unwrap();
        let d = bin(&f, "docker");
        assert_eq!(
            f.fake.lines(),
            vec![format!("{d} container inspect embarch-agent-fw"), format!("{d} stop embarch-agent-fw"), format!("{d} rm embarch-agent-fw")]
        );
    }

    #[test]
    fn down_of_a_missing_container_removes_nothing() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::fail(1, ""));
        let lines = down(&f.ctx, None).unwrap();
        assert!(lines[0].contains("does not exist"));
        assert_eq!(f.fake.lines().len(), 1);
    }

    #[test]
    fn shell_execs_into_bash_or_claude_in_the_clone() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        shell(&f.ctx, None, false).unwrap();
        shell(&f.ctx, None, true).unwrap();
        let d = bin(&f, "docker");
        assert_eq!(
            f.fake.lines(),
            vec![
                format!("{d} exec -it -u agent -w /work/fw embarch-agent-fw bash"),
                format!("{d} exec -it -u agent -w /work/fw embarch-agent-fw claude"),
            ]
        );
    }

    fn healthy(f: &Fixture) {
        f.fake.answer("container inspect", Output::ok(RUNNING));
        f.fake.answer("nc -z -w 3 192.0.2.1 443", Output::fail(1, ""));
        std::fs::create_dir_all(f.root.join("def/fw/start")).unwrap();
        std::fs::write(f.root.join("def/fw/start/core-addr"), "172.17.0.1\n").unwrap();
    }

    fn failing(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().filter(|f| !f.ok).map(|f| f.name).collect()
    }

    #[test]
    fn status_is_clean_when_everything_agrees() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        healthy(&f);
        std::fs::write(f.root.join("def/fw/core-fingerprint"), "ab:cd\n").unwrap();
        std::fs::create_dir_all(f.root.join("core")).unwrap();
        std::fs::write(f.root.join("core/core-fingerprint"), "ab:cd").unwrap();
        let r = status(&f.ctx, None).unwrap();
        assert!(failing(&r).is_empty(), "{r:?}");
        let log = f.fake.lines();
        assert!(log.iter().any(|l| l.ends_with("exec -u agent embarch-agent-fw nc -z -w 3 172.17.0.1 4884")));
    }

    #[test]
    fn status_names_a_hand_edited_container_toml() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        healthy(&f);
        let p = f.root.join("def/fw/container.toml");
        let t = std::fs::read_to_string(&p).unwrap().replace("--cap-drop=ALL", "--cap-drop=NONE");
        std::fs::write(&p, t).unwrap();
        assert_eq!(failing(&status(&f.ctx, None).unwrap()), ["definition"]);
    }

    #[test]
    fn status_names_a_fingerprint_copy_that_differs() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        healthy(&f);
        std::fs::create_dir_all(f.root.join("core")).unwrap();
        std::fs::write(f.root.join("def/fw/core-fingerprint"), "aa").unwrap();
        std::fs::write(f.root.join("core/core-fingerprint"), "bb").unwrap();
        assert_eq!(failing(&status(&f.ctx, None).unwrap()), ["fingerprint"]);
    }

    #[test]
    fn status_never_reads_the_agents_writable_seed_for_the_fingerprint() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        healthy(&f);
        std::fs::create_dir_all(f.root.join("core")).unwrap();
        std::fs::write(f.root.join("core/core-fingerprint"), "bb").unwrap();
        std::fs::write(f.root.join("def/fw/core-fingerprint"), "bb").unwrap();
        // The agent rewrites its seed to a fingerprint of its own.
        std::fs::create_dir_all(f.root.join("ex/fw/outbox/embarch")).unwrap();
        std::fs::write(f.root.join("ex/fw/outbox/embarch/core-fingerprint"), "agent-chosen").unwrap();
        assert!(failing(&status(&f.ctx, None).unwrap()).is_empty());
    }

    #[test]
    fn status_names_an_off_list_address_that_answers() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        healthy(&f);
        f.fake.script.borrow_mut().insert(0, ("nc -z -w 3 192.0.2.1 443".into(), Output::ok("")));
        assert_eq!(failing(&status(&f.ctx, None).unwrap()), ["firewall"]);
    }

    #[test]
    fn status_names_a_core_that_does_not_answer() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        healthy(&f);
        f.fake.script.borrow_mut().insert(0, ("nc -z -w 3 172.17.0.1 4884".into(), Output::fail(1, "")));
        assert_eq!(failing(&status(&f.ctx, None).unwrap()), ["core"]);
    }

    #[test]
    fn status_of_a_stopped_container_checks_nothing_inside() {
        let f = fixture(Topology::Linux, Runtime::Docker, true);
        f.fake.answer("container inspect", Output::fail(1, ""));
        let r = status(&f.ctx, None).unwrap();
        assert_eq!(failing(&r), ["running"]);
        assert!(f.fake.lines().iter().all(|l| !l.contains(" exec ")));
    }

    #[test]
    fn every_verb_refuses_with_the_install_pointer_when_no_runtime_is_on_path() {
        let f = fixture(Topology::Linux, Runtime::Docker, false);
        for e in [
            up(&f.ctx, None).unwrap_err(),
            down(&f.ctx, None).unwrap_err(),
            status(&f.ctx, None).map(|_| ()).unwrap_err(),
            shell(&f.ctx, None, false).map(|_| ()).unwrap_err(),
        ] {
            let m = e.to_string();
            assert!(m.contains("`docker` is not on PATH") && m.contains("docs.docker.com/engine/install"), "{m}");
        }
        assert!(f.fake.lines().is_empty());
        let p = fixture(Topology::Linux, Runtime::Podman, false);
        assert!(up(&p.ctx, None).unwrap_err().to_string().contains("podman.io"));
    }

    #[test]
    fn no_agent_named_or_registered_is_a_plain_error() {
        let mut f = fixture(Topology::Linux, Runtime::Docker, true);
        assert!(up(&f.ctx, Some("nope")).unwrap_err().to_string().contains("registered are fw"));
        f.ctx.state.registered_repos.clear();
        assert!(up(&f.ctx, None).unwrap_err().to_string().contains("embarch init --container"));
    }

    #[test]
    fn the_gateway_is_read_from_either_runtimes_json() {
        assert_eq!(gateway_from_inspect(BRIDGE).as_deref(), Some("172.17.0.1"));
        assert_eq!(gateway_from_inspect(r#"[{"subnets":[{"gateway":"10.88.0.1"}]}]"#).as_deref(), Some("10.88.0.1"));
        assert_eq!(gateway_from_inspect("[{}]"), None);
        assert_eq!(gateway_from_inspect("not json"), None);
        assert!(running_from_inspect(RUNNING));
        assert!(!running_from_inspect(r#"[{"State":{"Running":false}}]"#));
    }

    #[test]
    fn the_root_script_reads_the_address_up_writes() {
        let p = plan(Path::new("/x"), Topology::Linux, Runtime::Docker);
        let s = crate::agent::render_entrypoint_root(&p, CORE_ADDR_PLACEHOLDER);
        assert!(s.contains("CORE_HOST=$(cat /etc/embarch-agent/start/core-addr"));
        assert!(!s.contains("CORE_HOST='<core-addr>'"));
    }

    #[test]
    fn the_vector_hash_used_is_the_one_container_toml_records() {
        let p = plan(Path::new("/x"), Topology::Linux, Runtime::Docker);
        let rec = parse_container_toml(&container_toml(&p)).unwrap();
        assert_eq!(hash_args(&rec.run_args), rec.run_args_sha256);
        assert!(!rec.hand_edited());
    }
}
