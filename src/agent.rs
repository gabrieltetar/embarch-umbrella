//! The agent's container: a typed plan and two pure renderers.
//!
//! `embarch-umbrella` decision 62. Nothing here starts a container, writes a
//! file or reads the environment; `run_args` and `container_toml` return text
//! and later units (`embarch init --container`, starting the container) do
//! the acting. The hardening and mounts come from the HIL design's "A person's
//! act" section (`embarch-doc/notes/hil/12-prevention.md`).
//!
//! The rule that matters: **the person's token is never mounted.** Every
//! rendered vector is scanned by [`forbidden_findings`]; [`try_run_args`] is
//! the entry point a caller that will act on the vector must use.

// Nothing calls this yet: EMB-445 to EMB-448 do (decision 62).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Where the agent's token file appears inside the container.
const TARGET_TOKEN: &str = "/run/embarch/token";
/// Where the development Core's agent token appears, when there is one.
const TARGET_DEV_TOKEN: &str = "/run/embarch/dev-token";
const TARGET_DEFINITION: &str = "/etc/embarch-agent";
const TARGET_EXCHANGE: &str = "/exchange.git";
const TARGET_OUTBOX: &str = "/outbox";
const TARGET_CLAUDE_CONFIG: &str = "/home/agent/.claude";
const TARGET_PERSON_REPO: &str = "/person/repo";
const TARGET_WORK: &str = "/work";
const TARGET_BIN: &str = "/opt/embarch/bin";

/// What stands in for the Core address in the recorded vector: the address is
/// re-resolved at every use and never persisted (decision 6), so the hash
/// must not depend on it.
pub const CORE_ADDR_PLACEHOLDER: &str = "<core-addr>";

/// Capabilities the root entrypoint needs to apply the firewall and then drop
/// to the agent user. Assumed, not measured: EMB-445 and EMB-446 settle them.
const ALLOWED_CAPS: [&str; 4] = ["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"];

/// Targets that must be mounted read-only, whatever the plan says.
const READ_ONLY_TARGETS: [&str; 6] = [
    TARGET_DEFINITION,
    TARGET_PERSON_REPO,
    TARGET_TOKEN,
    TARGET_DEV_TOKEN,
    TARGET_BIN,
    // west projects under /work are checked by prefix, see `target_must_be_read_only`.
    "/work/",
];

const FORBIDDEN_ENV_NAMES: [&str; 2] = ["SSH_AUTH_SOCK", "GIT_ASKPASS"];
const FORBIDDEN_ENV_PREFIXES: [&str; 3] = ["VSCODE_", "REMOTE_CONTAINERS", "SSH_ASKPASS"];
const HOST_NAMESPACE_OPTIONS: [&str; 6] = ["network", "net", "pid", "ipc", "uts", "userns"];

/// Where the agent runs, from the container runtime's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Topology {
    Linux,
    WslHost,
    DockerDesktop,
    Macos,
}

impl Topology {
    pub fn as_str(self) -> &'static str {
        match self {
            Topology::Linux => "linux",
            Topology::WslHost => "wsl-host",
            Topology::DockerDesktop => "docker-desktop",
            Topology::Macos => "macos",
        }
    }

    /// `linux` and `wsl-host` are the two the owner verifies; the other two
    /// are rendered from the design and marked unverified.
    pub fn verified(self) -> bool {
        matches!(self, Topology::Linux | Topology::WslHost)
    }

    /// Whether the runtime already resolves `host.docker.internal`.
    fn runtime_resolves_host_alias(self) -> bool {
        matches!(self, Topology::DockerDesktop | Topology::Macos)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    Docker,
    Podman,
}

impl Runtime {
    pub fn binary(self) -> &'static str {
        match self {
            Runtime::Docker => "docker",
            Runtime::Podman => "podman",
        }
    }
}

/// One west project mounted read-only under `/work/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WestProject {
    pub name: String,
    pub path: PathBuf,
}

/// Everything the renderers need; nothing here is read from the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContainer {
    pub name: String,
    /// The person's repo, mounted read-only.
    pub repo: PathBuf,
    pub west_workspace: Vec<WestProject>,
    pub class: Topology,
    pub runtime: Runtime,
    pub image_tag: String,
    pub core_port: u16,
    /// The agent token file; the only token file mounted.
    pub agent_token: PathBuf,
    /// The development Core's agent token, set only when that file exists.
    pub dev_agent_token: Option<PathBuf>,
    /// `~/.config/embarch/agents/<name>/`, mounted read-only.
    pub definition_dir: PathBuf,
    /// `~/.local/share/embarch/agents/<name>/`: holds `exchange.git`,
    /// `outbox/` and `claude-config/`.
    pub exchange_dir: PathBuf,
    /// The canonical bin dir, mounted read-only.
    pub bin_dir: PathBuf,
    /// Extra `--env` variables; the only ones beyond the fixed set.
    pub env: Vec<(String, String)>,
}

impl AgentContainer {
    fn container_name(&self) -> String {
        format!("embarch-agent-{}", self.name)
    }

    fn mounts(&self) -> Vec<String> {
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let ro = |src: &str, dst: &str| format!("--mount=type=bind,source={src},target={dst},readonly");
        let rw = |src: &str, dst: &str| format!("--mount=type=bind,source={src},target={dst}");
        let ex = s(&self.exchange_dir);
        let mut v = vec![
            ro(&s(&self.definition_dir), TARGET_DEFINITION),
            rw(&format!("{ex}/exchange.git"), TARGET_EXCHANGE),
            rw(&format!("{ex}/outbox"), TARGET_OUTBOX),
            rw(&format!("{ex}/claude-config"), TARGET_CLAUDE_CONFIG),
            ro(&s(&self.repo), TARGET_PERSON_REPO),
            format!("--mount=type=volume,source={},target={TARGET_WORK}", self.container_name()),
        ];
        for p in &self.west_workspace {
            v.push(ro(&s(&p.path), &format!("{TARGET_WORK}/{}", p.name)));
        }
        v.push(ro(&s(&self.agent_token), TARGET_TOKEN));
        if let Some(dev) = &self.dev_agent_token {
            v.push(ro(&s(dev), TARGET_DEV_TOKEN));
        }
        v.push(ro(&s(&self.bin_dir), TARGET_BIN));
        v
    }

    fn env_vars(&self, core_addr: &str) -> Vec<String> {
        let mut v = vec![
            format!("EMBARCH_AGENT_NAME={}", self.name),
            format!("EMBARCH_CORE_ADDR={core_addr}"),
            format!("EMBARCH_CORE_PORT={}", self.core_port),
            format!("EMBARCH_TOPOLOGY={}", self.class.as_str()),
            format!("EMBARCH_TOKEN_FILE={TARGET_TOKEN}"),
        ];
        if self.dev_agent_token.is_some() {
            v.push(format!("EMBARCH_DEV_TOKEN_FILE={TARGET_DEV_TOKEN}"));
        }
        for (k, val) in &self.env {
            v.push(format!("{k}={val}"));
        }
        v
    }
}

/// The arguments after the runtime binary (`docker run ...`), unchecked.
/// Prefer [`try_run_args`] before acting on the result.
pub fn run_args(plan: &AgentContainer, core_addr: &str) -> Vec<String> {
    let mut a: Vec<String> = [
        "run",
        "--detach",
        "--init",
        "--restart=no",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(ALLOWED_CAPS.iter().map(|c| format!("--cap-add={c}")));
    a.push(format!("--name={}", plan.container_name()));
    a.push(format!("--hostname={}", plan.container_name()));
    a.push(format!("--label=embarch.agent={}", plan.name));
    a.push(format!("--label=embarch.topology={}", plan.class.as_str()));
    if !plan.class.runtime_resolves_host_alias() {
        a.push("--add-host=host.docker.internal:host-gateway".to_string());
    }
    a.extend(plan.mounts());
    a.extend(plan.env_vars(core_addr).into_iter().map(|e| format!("--env={e}")));
    a.push(plan.image_tag.clone());
    a
}

/// [`run_args`], refused with the findings when the scan names any.
pub fn try_run_args(plan: &AgentContainer, core_addr: &str) -> Result<Vec<String>, Vec<String>> {
    let args = run_args(plan, core_addr);
    let findings = forbidden_findings(&args);
    if findings.is_empty() {
        Ok(args)
    } else {
        Err(findings)
    }
}

fn mount_fields(value: &str) -> Vec<(&str, &str)> {
    value
        .split(',')
        .map(|f| f.split_once('=').unwrap_or((f, "")))
        .collect()
}

fn is_home_like(src: &str) -> bool {
    let t = src.trim_end_matches(['/', '\\']);
    if matches!(t, "~" | "$HOME" | "${HOME}" | "/root" | "/home" | "/Users" | "") {
        return true;
    }
    let parts: Vec<&str> = t.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        ["home", _] | ["Users", _] => true,
        // A drive root: `/mnt/c`, `c:`, `C:\`.
        ["mnt", d] if d.len() == 1 => true,
        [d] if d.len() == 2 && d.ends_with(':') => true,
        _ => false,
    }
}

fn is_runtime_socket(src: &str) -> bool {
    src.ends_with(".sock") || src.contains("docker.sock") || src.contains("podman.sock") || src.contains("containerd.sock")
}

fn last_component(src: &str) -> &str {
    src.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next().unwrap_or("")
}

/// A folder that holds token files: Core's data directory, or a `tokens`
/// folder. A token *file* is mounted alone, never its folder.
fn is_token_folder(src: &str) -> bool {
    let last = last_component(src);
    matches!(last, "embarch" | "tokens" | "token" | "person-token") && !src.contains("/agents/")
}

fn target_must_be_read_only(target: &str) -> bool {
    READ_ONLY_TARGETS.iter().any(|t| {
        if t.ends_with('/') {
            target.starts_with(t)
        } else {
            target == *t
        }
    })
}

fn allowed_target(t: &str) -> bool {
    matches!(
        t,
        TARGET_DEFINITION
            | TARGET_EXCHANGE
            | TARGET_OUTBOX
            | TARGET_CLAUDE_CONFIG
            | TARGET_PERSON_REPO
            | TARGET_WORK
            | TARGET_TOKEN
            | TARGET_DEV_TOKEN
            | TARGET_BIN
    ) || t.starts_with("/work/")
}

/// Scan a rendered vector for anything the hardening forbids; empty means
/// clean. Pure text, so the same scan covers a plan, a hand-edited
/// `container.toml` and a test's deliberately bad vector.
pub fn forbidden_findings(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    // Normalise `--opt value` and `--opt=value` to (name, value).
    let mut opts: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--") {
            if let Some((n, v)) = rest.split_once('=') {
                opts.push((n.to_string(), v.to_string()));
            } else if i + 1 < args.len() && !args[i + 1].starts_with('-') && !is_flag_only(rest) {
                opts.push((rest.to_string(), args[i + 1].clone()));
                i += 1;
            } else {
                opts.push((rest.to_string(), String::new()));
            }
        } else if matches!(a.as_str(), "-v" | "-e" | "-p") && i + 1 < args.len() {
            let n = match a.as_str() {
                "-v" => "volume",
                "-e" => "env",
                _ => "publish",
            };
            opts.push((n.to_string(), args[i + 1].clone()));
            i += 1;
        }
        i += 1;
    }
    for (name, value) in &opts {
        let n = name.as_str();
        if n == "privileged" {
            out.push("--privileged".into());
        } else if HOST_NAMESPACE_OPTIONS.contains(&n) && value == "host" {
            out.push(format!("--{n}=host"));
        } else if n == "device" || n.starts_with("device-") {
            out.push(format!("--{n}"));
        } else if n == "volume" {
            out.push(format!("--volume {value} (use --mount)"));
        } else if n == "env-file" {
            out.push("--env-file (only variables the plan names)".into());
        } else if n == "cap-add" && !ALLOWED_CAPS.contains(&value.as_str()) {
            out.push(format!("--cap-add={value}"));
        } else if n == "security-opt" && value != "no-new-privileges" {
            out.push(format!("--security-opt={value}"));
        } else if n == "env" {
            let Some((k, _)) = value.split_once('=') else {
                out.push(format!("--env={value} (inherits the host's value)"));
                continue;
            };
            if FORBIDDEN_ENV_NAMES.contains(&k) || FORBIDDEN_ENV_PREFIXES.iter().any(|p| k.starts_with(p)) {
                out.push(format!("--env {k}"));
            }
        } else if n == "mount" {
            check_mount(value, &mut out);
        }
    }
    for a in args {
        for piece in a.split([',', '=', ':']) {
            if piece.ends_with("person-token") {
                out.push(format!("a path ending in person-token: {piece}"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn is_flag_only(name: &str) -> bool {
    matches!(name, "detach" | "init" | "privileged" | "rm" | "interactive" | "tty")
}

fn check_mount(value: &str, out: &mut Vec<String>) {
    let fields = mount_fields(value);
    let get = |k: &str| fields.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
    let mut ok_keys = true;
    for (k, _) in &fields {
        if !matches!(*k, "type" | "source" | "target" | "readonly") {
            ok_keys = false;
        }
    }
    let dup = |k: &str| fields.iter().filter(|(n, _)| *n == k).count() > 1;
    if !ok_keys || dup("source") || dup("target") || dup("type") {
        out.push(format!("a mount with unexpected or repeated fields: {value}"));
        return;
    }
    let (Some(kind), Some(source), Some(target)) = (get("type"), get("source"), get("target")) else {
        out.push(format!("a mount missing type, source or target: {value}"));
        return;
    };
    if !allowed_target(target) {
        out.push(format!("a mount at {target}, which the plan does not name"));
    }
    if kind == "volume" {
        return;
    }
    if kind != "bind" {
        out.push(format!("a {kind} mount: {value}"));
        return;
    }
    if is_runtime_socket(source) {
        out.push(format!("a runtime socket mounted: {source}"));
    }
    if is_home_like(source) {
        out.push(format!("a home folder or drive root mounted: {source}"));
    }
    if is_token_folder(source) {
        out.push(format!("a token folder mounted: {source}"));
    }
    let file = last_component(source);
    if (file == "token" || file.ends_with("-token")) && target != TARGET_TOKEN && target != TARGET_DEV_TOKEN {
        out.push(format!("a token file mounted at {target}: {source}"));
    }
    if target_must_be_read_only(target) && get("readonly").is_none() {
        out.push(format!("{target} must be read-only"));
    }
}

/// SHA-256 of the vector, one element per line, as lower-case hex.
fn hash_args(args: &[String]) -> String {
    let mut h = Sha256::new();
    for a in args {
        h.update(a.as_bytes());
        h.update(b"\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash `container.toml` records for this plan.
pub fn definition_hash(plan: &AgentContainer) -> String {
    hash_args(&run_args(plan, CORE_ADDR_PLACEHOLDER))
}

/// What `container.toml` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub name: String,
    pub runtime: Runtime,
    pub topology: Topology,
    /// False for `docker-desktop` and `macos`, which are rendered from the
    /// design and not yet run by anyone.
    pub topology_verified: bool,
    pub image_tag: String,
    pub core_port: u16,
    /// The vector with [`CORE_ADDR_PLACEHOLDER`] for the Core address.
    pub run_args: Vec<String>,
    pub run_args_sha256: String,
}

impl ContainerRecord {
    /// True when the recorded vector no longer hashes to the recorded hash.
    pub fn hand_edited(&self) -> bool {
        hash_args(&self.run_args) != self.run_args_sha256
    }
}

/// Render `container.toml`.
pub fn container_toml(plan: &AgentContainer) -> String {
    let args = run_args(plan, CORE_ADDR_PLACEHOLDER);
    let rec = ContainerRecord {
        name: plan.name.clone(),
        runtime: plan.runtime,
        topology: plan.class,
        topology_verified: plan.class.verified(),
        image_tag: plan.image_tag.clone(),
        core_port: plan.core_port,
        run_args_sha256: hash_args(&args),
        run_args: args,
    };
    let body = toml::to_string(&rec).expect("a ContainerRecord always serialises");
    format!("# Written by `embarch init --container`; edit the plan, not this file.\n{body}")
}

/// Read a `container.toml` back.
pub fn parse_container_toml(text: &str) -> Result<ContainerRecord, toml::de::Error> {
    toml::from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(class: Topology) -> AgentContainer {
        let wsl = class == Topology::WslHost;
        AgentContainer {
            name: "bench1".into(),
            repo: "/src/fw".into(),
            west_workspace: vec![
                WestProject { name: "zephyr".into(), path: "/ws/zephyr".into() },
                WestProject { name: "nrf".into(), path: "/ws/nrf".into() },
            ],
            class,
            runtime: Runtime::Docker,
            image_tag: "embarch-agent:1".into(),
            core_port: 7010,
            agent_token: if wsl { "/mnt/c/ProgramData/embarch/agents/bench1/agent-token" } else { "/var/lib/embarch/agents/bench1/agent-token" }.into(),
            dev_agent_token: Some("/var/lib/embarch-dev/agents/bench1/agent-token".into()),
            definition_dir: "/h/.config/embarch/agents/bench1".into(),
            exchange_dir: "/h/.local/share/embarch/agents/bench1".into(),
            bin_dir: "/opt/embarch/bin-host".into(),
            env: vec![("EMBARCH_LOG".into(), "info".into())],
        }
    }

    fn golden(class: Topology, host_alias: bool) -> Vec<String> {
        let mut v: Vec<String> = vec![
            "run", "--detach", "--init", "--restart=no", "--security-opt=no-new-privileges", "--cap-drop=ALL",
            "--cap-add=NET_ADMIN", "--cap-add=NET_RAW", "--cap-add=SETUID", "--cap-add=SETGID",
            "--name=embarch-agent-bench1", "--hostname=embarch-agent-bench1",
            "--label=embarch.agent=bench1",
        ].into_iter().map(String::from).collect();
        v.push(format!("--label=embarch.topology={}", class.as_str()));
        if host_alias {
            v.push("--add-host=host.docker.internal:host-gateway".into());
        }
        let token = if class == Topology::WslHost { "/mnt/c/ProgramData/embarch/agents/bench1/agent-token" } else { "/var/lib/embarch/agents/bench1/agent-token" };
        v.extend([
            "--mount=type=bind,source=/h/.config/embarch/agents/bench1,target=/etc/embarch-agent,readonly".to_string(),
            "--mount=type=bind,source=/h/.local/share/embarch/agents/bench1/exchange.git,target=/exchange.git".into(),
            "--mount=type=bind,source=/h/.local/share/embarch/agents/bench1/outbox,target=/outbox".into(),
            "--mount=type=bind,source=/h/.local/share/embarch/agents/bench1/claude-config,target=/home/agent/.claude".into(),
            "--mount=type=bind,source=/src/fw,target=/person/repo,readonly".into(),
            "--mount=type=volume,source=embarch-agent-bench1,target=/work".into(),
            "--mount=type=bind,source=/ws/zephyr,target=/work/zephyr,readonly".into(),
            "--mount=type=bind,source=/ws/nrf,target=/work/nrf,readonly".into(),
            format!("--mount=type=bind,source={token},target=/run/embarch/token,readonly"),
            "--mount=type=bind,source=/var/lib/embarch-dev/agents/bench1/agent-token,target=/run/embarch/dev-token,readonly".into(),
            "--mount=type=bind,source=/opt/embarch/bin-host,target=/opt/embarch/bin,readonly".into(),
            "--env=EMBARCH_AGENT_NAME=bench1".into(),
            "--env=EMBARCH_CORE_ADDR=10.0.0.1:7010".into(),
            "--env=EMBARCH_CORE_PORT=7010".into(),
            format!("--env=EMBARCH_TOPOLOGY={}", class.as_str()),
            "--env=EMBARCH_TOKEN_FILE=/run/embarch/token".into(),
            "--env=EMBARCH_DEV_TOKEN_FILE=/run/embarch/dev-token".into(),
            "--env=EMBARCH_LOG=info".into(),
            "embarch-agent:1".into(),
        ]);
        v
    }

    #[test]
    fn golden_per_topology() {
        for (class, alias) in [
            (Topology::Linux, true),
            (Topology::WslHost, true),
            (Topology::DockerDesktop, false),
            (Topology::Macos, false),
        ] {
            let got = try_run_args(&plan(class), "10.0.0.1:7010").unwrap_or_else(|f| panic!("{class:?}: {f:?}"));
            assert_eq!(got, golden(class, alias), "{class:?}");
        }
    }

    #[test]
    fn dev_token_only_when_present() {
        let mut p = plan(Topology::Linux);
        p.dev_agent_token = None;
        let a = run_args(&p, "x");
        assert!(!a.iter().any(|s| s.contains("dev-token") || s.contains("DEV_TOKEN")));
    }

    fn with(extra: &[&str]) -> Vec<String> {
        let mut a = run_args(&plan(Topology::Linux), "x");
        let img = a.pop().unwrap();
        a.extend(extra.iter().map(|s| s.to_string()));
        a.push(img);
        a
    }

    #[test]
    fn every_listed_option_is_refused() {
        let bad: Vec<Vec<&str>> = vec![
            vec!["--privileged"],
            vec!["--network=host"],
            vec!["--network", "host"],
            vec!["--net=host"],
            vec!["--pid=host"],
            vec!["--ipc=host"],
            vec!["--uts=host"],
            vec!["--userns=host"],
            vec!["--device=/dev/ttyACM0"],
            vec!["--device", "/dev/bus/usb"],
            vec!["--cap-add=SYS_ADMIN"],
            vec!["--security-opt=seccomp=unconfined"],
            vec!["--env=SSH_AUTH_SOCK=/tmp/x"],
            vec!["--env=GIT_ASKPASS=/x"],
            vec!["--env=VSCODE_IPC_HOOK_CLI=/x"],
            vec!["--env=REMOTE_CONTAINERS_IPC=/x"],
            vec!["--env=HOME"],
            vec!["--env-file=/x"],
            vec!["-v", "/a:/b"],
        ];
        for extra in bad {
            assert!(!forbidden_findings(&with(&extra)).is_empty(), "accepted {extra:?}");
        }
        assert!(forbidden_findings(&with(&[])).is_empty());
    }

    #[test]
    fn every_forbidden_mount_is_refused() {
        let bad = [
            "--mount=type=bind,source=/var/run/docker.sock,target=/work/s",
            "--mount=type=bind,source=/run/podman/podman.sock,target=/work/s",
            "--mount=type=bind,source=/home/gabriel,target=/work/h",
            "--mount=type=bind,source=/mnt/c,target=/work/c",
            "--mount=type=bind,source=/mnt/c/,target=/work/c",
            "--mount=type=bind,source=/var/lib/embarch,target=/work/t",
            "--mount=type=bind,source=/etc/tokens,target=/work/t",
            "--mount=type=bind,source=/x/person-token,target=/work/p,readonly",
            "--mount=type=bind,source=/x/agent-token,target=/work/p,readonly",
            "--mount=type=bind,source=/a,target=/etc,readonly",
            "--mount=type=bind,source=/a,target=/work/a,source=/home/x",
            "--mount=type=bind,source=/a,target=/person/repo",
        ];
        for m in bad {
            assert!(!forbidden_findings(&with(&[m])).is_empty(), "accepted {m}");
        }
    }

    #[test]
    fn plan_with_a_token_folder_or_person_token_is_refused() {
        let mut p = plan(Topology::Linux);
        p.exchange_dir = "/var/lib/embarch".into();
        // exchange_dir itself is a parent; the rendered sources end in exchange.git etc.
        // so the folder case is the definition dir.
        p.definition_dir = "/var/lib/embarch".into();
        assert!(try_run_args(&p, "x").is_err());

        let mut p = plan(Topology::Linux);
        p.agent_token = "/var/lib/embarch/person-token".into();
        assert!(try_run_args(&p, "x").is_err());

        let mut p = plan(Topology::Linux);
        p.env = vec![("SSH_AUTH_SOCK".into(), "/s".into())];
        assert!(try_run_args(&p, "x").is_err());

        let mut p = plan(Topology::Linux);
        p.repo = "/home/gabriel".into();
        assert!(try_run_args(&p, "x").is_err());
    }

    #[test]
    fn toml_round_trips_and_records_the_hash() {
        for class in [Topology::Linux, Topology::WslHost, Topology::DockerDesktop, Topology::Macos] {
            let p = plan(class);
            let text = container_toml(&p);
            let rec = parse_container_toml(&text).unwrap();
            assert_eq!(rec.topology, class);
            assert_eq!(rec.topology_verified, class.verified());
            assert_eq!(rec.run_args, run_args(&p, CORE_ADDR_PLACEHOLDER));
            assert_eq!(rec.run_args_sha256, definition_hash(&p));
            assert_eq!(rec.run_args_sha256.len(), 64);
            assert!(!rec.hand_edited());
            assert_eq!(container_toml(&p), text, "deterministic");
        }
    }

    #[test]
    fn a_hand_edited_toml_is_noticed() {
        let text = container_toml(&plan(Topology::Linux));
        let edited = text.replace("--cap-drop=ALL", "--cap-drop=NONE");
        assert_ne!(edited, text);
        assert!(parse_container_toml(&edited).unwrap().hand_edited());
    }

    #[test]
    fn the_hash_ignores_the_core_address() {
        let p = plan(Topology::Linux);
        assert!(!container_toml(&p).contains("10.0.0.1"));
        assert_eq!(definition_hash(&p), hash_args(&run_args(&p, CORE_ADDR_PLACEHOLDER)));
    }
}
