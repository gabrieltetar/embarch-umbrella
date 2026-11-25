//! The agent's container: a typed plan and two pure renderers.
//!
//! `embarch-umbrella` decisions 62 and 63. Nothing here starts a container, writes a
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

/// Capabilities the root entrypoint holds to apply the firewall and then drop
/// to the agent user (decision 63). `SETPCAP` is what lets `setpriv` clear the
/// bounding set. Assumed, not measured. The agent half holds none.
const ALLOWED_CAPS: [&str; 5] = ["NET_ADMIN", "NET_RAW", "SETUID", "SETGID", "SETPCAP"];

/// The agent user the root half drops to.
const AGENT_UID: u32 = 1000;
/// The one port an allowlisted model-API host is reached on.
const MODEL_API_PORT: u16 = 443;
/// An address no allowlist holds (RFC 5737 TEST-NET-1), for the off-list check.
const OFF_LIST_PROBE_ADDR: &str = "192.0.2.1";
/// Seconds a firewall self-check connection may take.
const CHECK_TIMEOUT_SECS: u32 = 3;
/// Set in the agent's environment: no traffic beyond the model API. From the
/// issue, unverified.
const DISABLE_NONESSENTIAL_TRAFFIC: &str = "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1";

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
    /// The model API's hosts (`api.anthropic.com` and what a login needs):
    /// the `[network] allow` data besides Core. Port 443 only.
    pub network_allow: Vec<String>,
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
    /// What the image carries to build the person's repo (decision 64).
    pub toolchain: Toolchain,
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
        v.push(DISABLE_NONESSENTIAL_TRAFFIC.to_string());
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
    /// The firewall's allowlist: data only the person's account writes.
    pub network: NetworkAllow,
}

/// `[network]` in `container.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAllow {
    /// Core as `<core-addr>:<port>` (the address is a placeholder, never
    /// persisted), then the model API's hosts.
    pub allow: Vec<String>,
}

impl ContainerRecord {
    /// The model-API hosts: every entry but Core's.
    pub fn allowed_hosts(&self) -> Vec<String> {
        let core = format!("{CORE_ADDR_PLACEHOLDER}:{}", self.core_port);
        self.network.allow.iter().filter(|a| **a != core).cloned().collect()
    }
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
        network: NetworkAllow {
            allow: std::iter::once(format!("{CORE_ADDR_PLACEHOLDER}:{}", plan.core_port))
                .chain(plan.network_allow.iter().cloned())
                .collect(),
        },
    };
    let body = toml::to_string(&rec).expect("a ContainerRecord always serialises");
    format!("# Written by `embarch init --container`; edit the plan, not this file.\n{body}")
}

/// Read a `container.toml` back.
pub fn parse_container_toml(text: &str) -> Result<ContainerRecord, toml::de::Error> {
    toml::from_str(text)
}

/// Where Core is, from inside a container of this class. `core_host` is a
/// host name or address with no port. `wsl_gateway` is what the host side
/// finds with `embarch_topology::software::parse_default_gateway`;
/// `bridge_gateway` is the runtime bridge's gateway. Mirrored WSL networking
/// is not a class and is not handled: it is a row a later measurement fills.
pub fn core_addr_from_container(
    class: Topology,
    runtime: Runtime,
    wsl_gateway: Option<&str>,
    bridge_gateway: Option<&str>,
) -> anyhow::Result<String> {
    match class {
        Topology::Linux => bridge_gateway.map(str::to_string).ok_or_else(|| {
            anyhow::anyhow!(
                "no {} bridge gateway given: the agent reaches Core at it, so Core must be bound to that address or to 0.0.0.0 (a loopback-only Core is unreachable from the container)",
                runtime.binary()
            )
        }),
        Topology::WslHost => wsl_gateway
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("no WSL gateway given: the host side finds it from the default route; Core must be bound to it or to 0.0.0.0")),
        Topology::DockerDesktop | Topology::Macos => Ok("host.docker.internal".to_string()),
    }
}

/// Quote a value for a POSIX shell.
fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// The POSIX shell script run as root before anything else (decision 63):
/// drop all egress, allow loopback, established flows, DNS to the resolver in
/// `/etc/resolv.conf`, Core's address and port, and TCP 443 to the resolved
/// model-API hosts; check the rules; then drop to the agent user with no
/// capabilities and exec the agent half (the script's arguments). Pure text.
/// `core_host` is Core's address as the container sees it, with no port.
pub fn render_entrypoint_root(plan: &AgentContainer, core_host: &str) -> String {
    let mut s = String::new();
    let mut l = |line: String| {
        s.push_str(&line);
        s.push('\n');
    };
    l("#!/bin/sh".into());
    l("# Written by embarch (umbrella decision 63). The root half: it sets the egress rules".into());
    l("# and then drops to the agent user. The agent cannot change any of it.".into());
    l("set -eu".into());
    l("fail() { echo \"embarch-agent: $*\" >&2; exit 1; }".into());
    l("[ \"$#\" -gt 0 ] || fail 'no agent command given'".into());
    l(format!("CORE_HOST={}", sh_quote(core_host)));
    l(format!("CORE_PORT={}", plan.core_port));
    l("iptables -F OUTPUT".into());
    l("iptables -P OUTPUT DROP".into());
    l("ip6tables -F OUTPUT".into());
    l("ip6tables -P OUTPUT DROP".into());
    l("iptables -A OUTPUT -o lo -j ACCEPT".into());
    l("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT".into());
    l("for ns in $(awk '$1 == \"nameserver\" && $2 ~ /^[0-9.]+$/ { print $2 }' /etc/resolv.conf); do".into());
    l("  iptables -A OUTPUT -p udp -d \"$ns\" --dport 53 -j ACCEPT".into());
    l("  iptables -A OUTPUT -p tcp -d \"$ns\" --dport 53 -j ACCEPT".into());
    l("done".into());
    l("CORE_IPS=$(getent ahostsv4 \"$CORE_HOST\" | awk '{ print $1 }' | sort -u)".into());
    l("[ -n \"$CORE_IPS\" ] || fail \"cannot resolve Core at $CORE_HOST\"".into());
    l("for core_ip in $CORE_IPS; do".into());
    l("  iptables -A OUTPUT -p tcp -d \"$core_ip\" --dport \"$CORE_PORT\" -j ACCEPT".into());
    l("done".into());
    l("ipset create embarch-allow hash:ip -exist".into());
    for host in &plan.network_allow {
        l(format!("for a in $(getent ahostsv4 {} | awk '{{ print $1 }}' | sort -u); do", sh_quote(host)));
        l("  case \" $CORE_IPS \" in *\" $a \"*) continue ;; esac".into());
        l("  ipset add embarch-allow \"$a\" -exist".into());
        l("done".into());
    }
    l(format!("iptables -A OUTPUT -p tcp --dport {MODEL_API_PORT} -m set --match-set embarch-allow dst -j ACCEPT"));
    l("check() { timeout {t} nc -z -w {t} \"$1\" \"$2\" >/dev/null 2>&1; }".replace("{t}", &CHECK_TIMEOUT_SECS.to_string()));
    l("for core_ip in $CORE_IPS; do check \"$core_ip\" \"$CORE_PORT\" && ok=1; done".into());
    l("[ \"${ok:-}\" = 1 ] || fail \"the firewall check failed: Core is not reachable\"".into());
    l(format!("if check {OFF_LIST_PROBE_ADDR} {MODEL_API_PORT}; then fail 'the firewall check failed: an address off the list is reachable'; fi"));
    l(format!(
        "exec setpriv --reuid={AGENT_UID} --regid={AGENT_UID} --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \"$@\""
    ));
    s
}

/// What a rendered script allows on Core's host beyond Core's own port: every
/// rule that names Core's address and a port other than `core_port`, and any
/// rule that names the host without a port. Empty means clean.
pub fn core_host_findings(script: &str, core_host: &str, core_port: u16) -> Vec<String> {
    let mut out = Vec::new();
    for line in script.lines() {
        let t = line.trim();
        let names_core = t.contains("$core_ip") || t.contains("$CORE_HOST") || t.contains(core_host);
        if !t.starts_with("iptables ") || !t.contains("-A OUTPUT") || !names_core {
            continue;
        }
        match t.split_once("--dport ") {
            Some((_, rest)) => {
                let port = rest.split_whitespace().next().unwrap_or("").trim_matches('"');
                if port != "$CORE_PORT" && port != core_port.to_string() {
                    out.push(format!("a rule allows port {port} on Core's host: {t}"));
                }
            }
            None => out.push(format!("a rule allows every port on Core's host: {t}")),
        }
    }
    out
}

/// One bind mount the image's west workspace needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The project's absolute path on the host.
    pub source: PathBuf,
    /// Where it appears in the container: `/work/<path>`.
    pub target: String,
    pub read_only: bool,
}

/// `west list -f "{path} {abspath}"`, **from memory**: the format fields
/// `{path}` and `{abspath}` are to be checked against the installed west.
pub const WEST_LIST_FORMAT: &str = "{path} {abspath}";

fn clean_west_path(p: &str) -> String {
    let p = p.trim().trim_end_matches('/');
    p.strip_prefix("./").unwrap_or(p).to_string()
}

/// Parse `west list -f "{path} {abspath}"` as `init` runs it on the host.
/// Every project but the manifest repo (`manifest_path`, as west prints its
/// `path`) becomes a read-only `/work/<path>` bind; the manifest repo is the
/// agent's own clone (EMB-451). A project whose path is absolute or climbs
/// out with `..` is skipped, since its target would leave `/work`. A line
/// with no second field is skipped. Pure.
pub fn west_mounts(west_list: &str, manifest_path: &str) -> Vec<Mount> {
    let manifest = clean_west_path(manifest_path);
    let mut out = Vec::new();
    for line in west_list.lines() {
        let Some((path, abspath)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        let path = clean_west_path(path);
        let abspath = abspath.trim();
        if path.is_empty()
            || abspath.is_empty()
            || path == manifest
            || path.starts_with('/')
            || path.split('/').any(|c| c == "..")
        {
            continue;
        }
        out.push(Mount { source: PathBuf::from(abspath), target: format!("{TARGET_WORK}/{path}"), read_only: true });
    }
    out
}

/// The plan's `west_workspace` form of [`west_mounts`]' result.
pub fn west_projects(mounts: &[Mount]) -> Vec<WestProject> {
    let prefix = format!("{TARGET_WORK}/");
    mounts
        .iter()
        .filter_map(|m| Some(WestProject { name: m.target.strip_prefix(&prefix)?.to_string(), path: m.source.clone() }))
        .collect()
}

/// What the image carries to build the person's repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Toolchain {
    /// A Zephyr and west repo (`looks_zephyr_west_shaped`).
    ZephyrWest {
        /// `zephyr/SDK_VERSION`, read on the host by `init`.
        sdk_version: String,
        /// SDK toolchains to install (`setup.sh -t`). **Assumed:** `init`
        /// has no source for the person's SoC yet, so the caller names them.
        sdk_toolchains: Vec<String>,
        /// `zephyr/scripts/requirements*.txt`: file name and the SHA-256 of
        /// its contents. The caller puts the files in the build context
        /// under `requirements/`; the hash makes a changed file a new tag.
        requirements: Vec<(String, String)>,
    },
    /// Anything else: no toolchain lines and no workspace mounts. That case
    /// is otherwise out of decision 64's pass.
    NotWest,
}

impl Toolchain {
    /// Choose from what `init` found: `shaped` is `looks_zephyr_west_shaped`;
    /// `sdk_version_text` is `zephyr/SDK_VERSION`. A shaped repo with no
    /// readable SDK version is `NotWest`: the image must not guess one.
    pub fn from_workspace(
        shaped: bool,
        sdk_version_text: Option<&str>,
        sdk_toolchains: &[&str],
        requirements: &[(&str, &str)],
    ) -> Toolchain {
        let version = sdk_version_text.and_then(parse_sdk_version);
        match (shaped, version) {
            (true, Some(sdk_version)) => Toolchain::ZephyrWest {
                sdk_version,
                sdk_toolchains: sdk_toolchains.iter().map(|s| s.to_string()).collect(),
                requirements: requirements
                    .iter()
                    .map(|(name, text)| (name.to_string(), sha256_hex(text.as_bytes())))
                    .collect(),
            },
            _ => Toolchain::NotWest,
        }
    }
}

/// The first line of `zephyr/SDK_VERSION`, when it is dotted digits with an
/// optional `-suffix` (`0.16.8`, `0.17.0-rc1`): it goes into a download URL
/// and a shell line, so anything else is refused.
pub fn parse_sdk_version(text: &str) -> Option<String> {
    let v = text.lines().next()?.trim();
    let (core, suffix) = v.split_once('-').map_or((v, None), |(c, s)| (c, Some(s)));
    let core_ok = !core.is_empty() && core.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let suffix_ok = suffix.is_none_or(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()));
    (core_ok && suffix_ok).then(|| v.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Binary the root script calls, and the Debian package that provides it.
/// Held as data so a test can hold the script to it.
pub const FIREWALL_BINARIES: [(&str, &str); 9] = [
    ("iptables", "iptables"),
    ("ip6tables", "iptables"),
    ("ipset", "ipset"),
    ("nc", "netcat-openbsd"),
    ("getent", "libc-bin"),
    ("timeout", "coreutils"),
    ("setpriv", "util-linux"),
    ("awk", "gawk"),
    ("sort", "coreutils"),
];

/// Packages the Zephyr build needs, **from memory** of Zephyr's Getting
/// Started list: to be checked against the pinned Zephyr's documentation.
const ZEPHYR_PACKAGES: [&str; 13] = [
    "build-essential", "ca-certificates", "ccache", "cmake", "curl", "device-tree-compiler", "file", "git", "gperf",
    "ninja-build", "python3", "python3-pip", "python3-venv",
];

const BASE_IMAGE: &str = "debian:bookworm-slim";
const SDK_DIR: &str = "/opt/zephyr-sdk";
const VENV_DIR: &str = "/opt/venv";

/// The Containerfile for the plan, pure text (decision 64). Nothing builds
/// it here. The tag is [`image_tag`] of this text.
pub fn render_containerfile(plan: &AgentContainer) -> String {
    let mut pkgs: Vec<&str> = FIREWALL_BINARIES.iter().map(|(_, p)| *p).collect();
    pkgs.push("git");
    pkgs.push("xz-utils");
    pkgs.push("wget");
    if matches!(plan.toolchain, Toolchain::ZephyrWest { .. }) {
        pkgs.extend(ZEPHYR_PACKAGES);
    }
    // `curl` is how Claude Code is installed below, for every repo.
    pkgs.push("curl");
    pkgs.push("ca-certificates");
    pkgs.sort_unstable();
    pkgs.dedup();

    let mut s = String::new();
    let mut l = |line: &str| {
        s.push_str(line);
        s.push('\n');
    };
    l("# Written by embarch (umbrella decision 64). Nothing here is built by embarch-umbrella;");
    l("# the tag is the SHA-256 of this text, so a changed file is a new image.");
    l(&format!("FROM {BASE_IMAGE}"));
    l("ENV DEBIAN_FRONTEND=noninteractive");
    l("# The firewall script's binaries (decision 63), then git and the tools below. No sudo.");
    l("RUN apt-get update \\");
    l(" && apt-get install -y --no-install-recommends \\");
    for p in &pkgs {
        l(&format!("    {p} \\"));
    }
    l(" && rm -rf /var/lib/apt/lists/*");
    match &plan.toolchain {
        Toolchain::NotWest => {
            l("# Toolchain: this repo is not a Zephyr and west repo. No SDK, west or Python requirements are");
            l("# installed and no west workspace is mounted; a later pass owns that case.");
        }
        Toolchain::ZephyrWest { sdk_version, sdk_toolchains, requirements } => {
            l("# Zephyr SDK at the version the workspace pins (zephyr/SDK_VERSION). URL and setup flags");
            l("# are from memory of the SDK's release layout: check against the installed SDK.");
            let v = sdk_version;
            l(&format!("RUN wget -q https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v{v}/zephyr-sdk-{v}_linux-x86_64_minimal.tar.xz \\"));
            l(&format!(" && mkdir -p {SDK_DIR} \\"));
            l(&format!(" && tar -xJf zephyr-sdk-{v}_linux-x86_64_minimal.tar.xz --strip-components=1 -C {SDK_DIR} \\"));
            l(&format!(" && rm zephyr-sdk-{v}_linux-x86_64_minimal.tar.xz \\"));
            let targets: String = sdk_toolchains.iter().map(|t| format!(" -t {t}")).collect();
            l(&format!(" && {SDK_DIR}/setup.sh{targets} -h -c"));
            l(&format!("ENV ZEPHYR_SDK_INSTALL_DIR={SDK_DIR} ZEPHYR_TOOLCHAIN_VARIANT=zephyr"));
            l("# west and the workspace's Python requirements, in a venv (Debian refuses a system-wide pip).");
            l(&format!("RUN python3 -m venv {VENV_DIR} && {VENV_DIR}/bin/pip install --no-cache-dir west"));
            l(&format!("ENV PATH={VENV_DIR}/bin:$PATH"));
            for (name, sha) in requirements {
                l(&format!("# {name} sha256 {sha}"));
                l(&format!("COPY requirements/{name} /tmp/requirements/{name}"));
                l(&format!("RUN pip install --no-cache-dir -r /tmp/requirements/{name}"));
            }
        }
    }
    l(&format!("RUN useradd --create-home --uid {AGENT_UID} --shell /bin/sh agent"));
    l("# Claude Code, installed as its documentation says (native installer, from memory: check it).");
    l("USER agent");
    l("RUN curl -fsSL https://claude.ai/install.sh | bash");
    l("ENV PATH=/home/agent/.local/bin:$PATH");
    l("# The entrypoint is the root script (decision 63), which drops to the agent user itself.");
    l("USER root");
    s
}

/// The image tag: `embarch-agent:` and the SHA-256 of the Containerfile
/// text. Equal text, equal tag; any change, a new one.
pub fn image_tag(containerfile: &str) -> String {
    format!("embarch-agent:{}", sha256_hex(containerfile.as_bytes()))
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
            network_allow: vec!["api.anthropic.com".into(), "console.anthropic.com".into()],
            agent_token: if wsl { "/mnt/c/ProgramData/embarch/agents/bench1/agent-token" } else { "/var/lib/embarch/agents/bench1/agent-token" }.into(),
            dev_agent_token: Some("/var/lib/embarch-dev/agents/bench1/agent-token".into()),
            definition_dir: "/h/.config/embarch/agents/bench1".into(),
            exchange_dir: "/h/.local/share/embarch/agents/bench1".into(),
            bin_dir: "/opt/embarch/bin-host".into(),
            env: vec![("EMBARCH_LOG".into(), "info".into())],
            toolchain: Toolchain::NotWest,
        }
    }

    fn golden(class: Topology, host_alias: bool) -> Vec<String> {
        let mut v: Vec<String> = vec![
            "run", "--detach", "--init", "--restart=no", "--security-opt=no-new-privileges", "--cap-drop=ALL",
            "--cap-add=NET_ADMIN", "--cap-add=NET_RAW", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP",
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
            "--env=CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1".into(),
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

    const FIXTURE_TOML: &str = r#"
name = "bench1"
runtime = "docker"
topology = "linux"
topology_verified = true
image_tag = "embarch-agent:1"
core_port = 7010
run_args = []
run_args_sha256 = ""

[network]
allow = ["<core-addr>:7010", "api.anthropic.com", "console.anthropic.com"]
"#;

    fn plan_from_fixture(class: Topology) -> AgentContainer {
        let rec = parse_container_toml(FIXTURE_TOML).unwrap();
        let mut p = plan(class);
        p.network_allow = rec.allowed_hosts();
        p
    }

    fn golden_script(core: &str) -> String {
        r#"#!/bin/sh
# Written by embarch (umbrella decision 63). The root half: it sets the egress rules
# and then drops to the agent user. The agent cannot change any of it.
set -eu
fail() { echo "embarch-agent: $*" >&2; exit 1; }
[ "$#" -gt 0 ] || fail 'no agent command given'
CORE_HOST='@CORE@'
CORE_PORT=7010
iptables -F OUTPUT
iptables -P OUTPUT DROP
ip6tables -F OUTPUT
ip6tables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for ns in $(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ { print $2 }' /etc/resolv.conf); do
  iptables -A OUTPUT -p udp -d "$ns" --dport 53 -j ACCEPT
  iptables -A OUTPUT -p tcp -d "$ns" --dport 53 -j ACCEPT
done
CORE_IPS=$(getent ahostsv4 "$CORE_HOST" | awk '{ print $1 }' | sort -u)
[ -n "$CORE_IPS" ] || fail "cannot resolve Core at $CORE_HOST"
for core_ip in $CORE_IPS; do
  iptables -A OUTPUT -p tcp -d "$core_ip" --dport "$CORE_PORT" -j ACCEPT
done
ipset create embarch-allow hash:ip -exist
for a in $(getent ahostsv4 'api.anthropic.com' | awk '{ print $1 }' | sort -u); do
  case " $CORE_IPS " in *" $a "*) continue ;; esac
  ipset add embarch-allow "$a" -exist
done
for a in $(getent ahostsv4 'console.anthropic.com' | awk '{ print $1 }' | sort -u); do
  case " $CORE_IPS " in *" $a "*) continue ;; esac
  ipset add embarch-allow "$a" -exist
done
iptables -A OUTPUT -p tcp --dport 443 -m set --match-set embarch-allow dst -j ACCEPT
check() { timeout 3 nc -z -w 3 "$1" "$2" >/dev/null 2>&1; }
for core_ip in $CORE_IPS; do check "$core_ip" "$CORE_PORT" && ok=1; done
[ "${ok:-}" = 1 ] || fail "the firewall check failed: Core is not reachable"
if check 192.0.2.1 443; then fail 'the firewall check failed: an address off the list is reachable'; fi
exec setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- "$@"
"#
        .replace("@CORE@", core)
    }

    #[test]
    fn the_root_script_is_golden_per_topology() {
        let rows = [
            (Topology::Linux, Some("172.17.0.1"), None, "172.17.0.1"),
            (Topology::WslHost, None, Some("172.20.0.1"), "172.20.0.1"),
            (Topology::DockerDesktop, None, None, "host.docker.internal"),
            (Topology::Macos, None, None, "host.docker.internal"),
        ];
        for (class, bridge, wsl, want) in rows {
            let core = core_addr_from_container(class, Runtime::Docker, wsl, bridge).unwrap();
            assert_eq!(core, want);
            let script = render_entrypoint_root(&plan_from_fixture(class), &core);
            assert_eq!(script, golden_script(want), "{class:?}");
            assert!(core_host_findings(&script, &core, 7010).is_empty(), "{class:?}");
        }
    }

    #[test]
    fn the_script_names_no_port_on_cores_host_but_cores() {
        let script = render_entrypoint_root(&plan_from_fixture(Topology::Linux), "172.17.0.1");
        for port in [7080, 22, 4893] {
            let bad = format!("{script}iptables -A OUTPUT -p tcp -d \"$core_ip\" --dport {port} -j ACCEPT\n");
            assert!(!core_host_findings(&bad, "172.17.0.1", 7010).is_empty(), "{port}");
            let bad = format!("{script}iptables -A OUTPUT -p tcp -d 172.17.0.1 --dport {port} -j ACCEPT\n");
            assert!(!core_host_findings(&bad, "172.17.0.1", 7010).is_empty(), "{port}");
        }
        let bad = format!("{script}iptables -A OUTPUT -d \"$core_ip\" -j ACCEPT\n");
        assert!(!core_host_findings(&bad, "172.17.0.1", 7010).is_empty());
        // The only other ports in the script are DNS and the model API's.
        for line in script.lines().filter(|l| l.contains("--dport")) {
            assert!(
                ["53", "443", "\"$CORE_PORT\""].iter().any(|p| line.contains(&format!("--dport {p}"))),
                "{line}"
            );
        }
    }

    #[test]
    fn the_script_fails_closed_and_drops_everything() {
        let script = render_entrypoint_root(&plan_from_fixture(Topology::Linux), "172.17.0.1");
        let at = |needle: &str| script.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
        assert!(script.contains("set -eu"));
        // A failed check exits non-zero, before the drop and the exec.
        assert!(script.contains("fail() { echo \"embarch-agent: $*\" >&2; exit 1; }"));
        assert!(script.contains("|| fail \"the firewall check failed: Core is not reachable\""));
        assert!(script.contains("then fail 'the firewall check failed: an address off the list is reachable'"));
        assert!(at("Core is not reachable") < at("exec setpriv"));
        assert!(at("an address off the list") < at("exec setpriv"));
        assert!(at("iptables -P OUTPUT DROP") < at("iptables -A OUTPUT"));
        assert!(script.contains("ip6tables -P OUTPUT DROP"));
        for flag in ["--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--reuid=1000"] {
            assert!(script.contains(flag), "{flag}");
        }
    }

    #[test]
    fn every_core_addr_row() {
        use Topology::*;
        let g = |c, r, w, b| core_addr_from_container(c, r, w, b);
        assert_eq!(g(Linux, Runtime::Docker, None, Some("172.17.0.1")).unwrap(), "172.17.0.1");
        assert_eq!(g(Linux, Runtime::Podman, None, Some("10.88.0.1")).unwrap(), "10.88.0.1");
        let e = g(Linux, Runtime::Podman, None, None).unwrap_err().to_string();
        assert!(e.contains("Core must be bound") && e.contains("0.0.0.0") && e.contains("podman"), "{e}");
        assert_eq!(g(WslHost, Runtime::Docker, Some("172.20.0.1"), Some("172.17.0.1")).unwrap(), "172.20.0.1");
        assert!(g(WslHost, Runtime::Docker, None, Some("172.17.0.1")).is_err());
        assert_eq!(g(DockerDesktop, Runtime::Docker, None, None).unwrap(), "host.docker.internal");
        assert_eq!(g(Macos, Runtime::Docker, None, None).unwrap(), "host.docker.internal");
    }

    #[test]
    fn the_allowlist_round_trips_through_the_toml() {
        let p = plan(Topology::Linux);
        let rec = parse_container_toml(&container_toml(&p)).unwrap();
        assert_eq!(rec.network.allow, ["<core-addr>:7010", "api.anthropic.com", "console.anthropic.com"]);
        assert_eq!(rec.allowed_hosts(), p.network_allow);
        assert!(!container_toml(&p).contains("10.0.0.1"));
    }

    // ---- decision 64: the image and the west mounts ----

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(tag: &str) -> Fixture {
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let d = std::env::temp_dir().join(format!("embarch-agent-114-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Fixture(d)
        }
        fn write(&self, rel: &str, text: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A Zephyr and west workspace: `init`'s own shape check passes on it.
    fn west_fixture() -> Fixture {
        let f = Fixture::new("west");
        f.write("fw/boards/acme/b1/board.yml", "board:\n  name: b1\n");
        f.write("fw/app/main/CMakeLists.txt", "project(main)\n");
        f.write("zephyr/SDK_VERSION", "0.16.8\n");
        f.write("zephyr/scripts/requirements-base.txt", "pyyaml\n");
        f.write("zephyr/scripts/requirements-run-test.txt", "pytest\n");
        f
    }

    fn toolchain_of(f: &Fixture) -> Toolchain {
        let sdk = std::fs::read_to_string(f.0.join("zephyr/SDK_VERSION")).ok();
        let mut reqs: Vec<(String, String)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(f.0.join("zephyr/scripts")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("requirements") && name.ends_with(".txt") {
                    reqs.push((name, std::fs::read_to_string(e.path()).unwrap()));
                }
            }
        }
        reqs.sort();
        let reqs: Vec<(&str, &str)> = reqs.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let shaped = crate::zephyr::looks_zephyr_west_shaped(&f.0.join("fw"));
        Toolchain::from_workspace(shaped, sdk.as_deref(), &["arm-zephyr-eabi"], &reqs)
    }

    fn plan_with(t: Toolchain) -> AgentContainer {
        let mut p = plan(Topology::Linux);
        p.toolchain = t;
        p
    }

    const GOLDEN_CONTAINERFILE_NOT_WEST_HEAD: &str = "# Written by embarch (umbrella decision 64). Nothing here is built by embarch-umbrella;\n# the tag is the SHA-256 of this text, so a changed file is a new image.\nFROM debian:bookworm-slim\nENV DEBIAN_FRONTEND=noninteractive\n";

    #[test]
    fn containerfile_is_golden_with_the_sdk_version_from_the_fixture() {
        let f = west_fixture();
        let t = toolchain_of(&f);
        assert!(matches!(&t, Toolchain::ZephyrWest { sdk_version, .. } if sdk_version == "0.16.8"));
        let got = render_containerfile(&plan_with(t));
        let h_base = sha256_hex(b"pyyaml\n");
        let h_run = sha256_hex(b"pytest\n");
        let want = format!(
            "# Written by embarch (umbrella decision 64). Nothing here is built by embarch-umbrella;
# the tag is the SHA-256 of this text, so a changed file is a new image.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
# The firewall script's binaries (decision 63), then git and the tools below. No sudo.
RUN apt-get update \\
 && apt-get install -y --no-install-recommends \\
    build-essential \\
    ca-certificates \\
    ccache \\
    cmake \\
    coreutils \\
    curl \\
    device-tree-compiler \\
    file \\
    gawk \\
    git \\
    gperf \\
    ipset \\
    iptables \\
    libc-bin \\
    netcat-openbsd \\
    ninja-build \\
    python3 \\
    python3-pip \\
    python3-venv \\
    util-linux \\
    wget \\
    xz-utils \\
 && rm -rf /var/lib/apt/lists/*
# Zephyr SDK at the version the workspace pins (zephyr/SDK_VERSION). URL and setup flags
# are from memory of the SDK's release layout: check against the installed SDK.
RUN wget -q https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.8/zephyr-sdk-0.16.8_linux-x86_64_minimal.tar.xz \\
 && mkdir -p /opt/zephyr-sdk \\
 && tar -xJf zephyr-sdk-0.16.8_linux-x86_64_minimal.tar.xz --strip-components=1 -C /opt/zephyr-sdk \\
 && rm zephyr-sdk-0.16.8_linux-x86_64_minimal.tar.xz \\
 && /opt/zephyr-sdk/setup.sh -t arm-zephyr-eabi -h -c
ENV ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk ZEPHYR_TOOLCHAIN_VARIANT=zephyr
# west and the workspace's Python requirements, in a venv (Debian refuses a system-wide pip).
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir west
ENV PATH=/opt/venv/bin:$PATH
# requirements-base.txt sha256 {h_base}
COPY requirements/requirements-base.txt /tmp/requirements/requirements-base.txt
RUN pip install --no-cache-dir -r /tmp/requirements/requirements-base.txt
# requirements-run-test.txt sha256 {h_run}
COPY requirements/requirements-run-test.txt /tmp/requirements/requirements-run-test.txt
RUN pip install --no-cache-dir -r /tmp/requirements/requirements-run-test.txt
RUN useradd --create-home --uid 1000 --shell /bin/sh agent
# Claude Code, installed as its documentation says (native installer, from memory: check it).
USER agent
RUN curl -fsSL https://claude.ai/install.sh | bash
ENV PATH=/home/agent/.local/bin:$PATH
# The entrypoint is the root script (decision 63), which drops to the agent user itself.
USER root
"
        );
        assert_eq!(got, want);
    }

    #[test]
    fn the_image_installs_every_binary_the_root_script_calls() {
        let script = render_entrypoint_root(&plan(Topology::Linux), "10.0.0.1");
        // Every command the script runs: the first word of each pipeline stage.
        let known: Vec<&str> = FIREWALL_BINARIES.iter().map(|(b, _)| *b).collect();
        let skip = [
            "exit", "echo", "set", "exec", "fail", "check", "case", "esac", "[", "done", "fi", "do", "then", "continue", "for", "if",
            "ok=1", "!",
        ];
        let mut called: Vec<String> = Vec::new();
        for line in script.lines() {
            if line.starts_with('#') {
                continue;
            }
            let mut text = line.replace("$(", "|").replace("&&", "|").replace("||", "|").replace(';', "|");
            for kw in ["then ", "do ", "if "] {
                text = text.replace(kw, "|");
            }
            for stage in text.split('|') {
                let w = stage.trim().trim_start_matches('!').trim();
                let w = w.split_whitespace().next().unwrap_or("");
                if w.is_empty() || w.contains('=') || w.starts_with('"') || w.starts_with('\'') || w.starts_with('$') {
                    continue;
                }
                if w.starts_with("for") || w.starts_with("case") || w.starts_with("fail") || w.starts_with("check") {
                    continue;
                }
                if skip.contains(&w) || w.ends_with(')') || w.ends_with('}') {
                    continue;
                }
                called.push(w.to_string());
            }
        }
        called.sort();
        called.dedup();
        for c in &called {
            assert!(known.contains(&c.as_str()), "the script calls {c}, which FIREWALL_BINARIES does not name");
        }
        for b in known {
            assert!(script.contains(b), "FIREWALL_BINARIES names {b}, which the script does not call");
        }
        for tc in [Toolchain::NotWest, toolchain_of(&west_fixture())] {
            let cf = render_containerfile(&plan_with(tc));
            for (b, pkg) in FIREWALL_BINARIES {
                assert!(cf.contains(&format!("    {pkg} \\\n")), "{b}: package {pkg} missing");
            }
            assert!(!cf.contains("    sudo \\\n"));
            assert!(cf.contains("useradd --create-home --uid 1000"));
        }
    }

    const WEST_LIST: &str = "app /ws/app\nzephyr /ws/zephyr\nmodules/hal/nordic /ws/modules/hal/nordic\nbootloader/mcuboot /ws/bootloader/mcuboot\n";

    #[test]
    fn west_list_gives_read_only_mounts_without_the_manifest_repo() {
        let m = west_mounts(WEST_LIST, "app");
        let got: Vec<(String, String, bool)> =
            m.iter().map(|m| (m.source.to_string_lossy().into_owned(), m.target.clone(), m.read_only)).collect();
        assert_eq!(
            got,
            vec![
                ("/ws/zephyr".into(), "/work/zephyr".into(), true),
                ("/ws/modules/hal/nordic".into(), "/work/modules/hal/nordic".into(), true),
                ("/ws/bootloader/mcuboot".into(), "/work/bootloader/mcuboot".into(), true),
            ]
        );
        assert!(m.iter().all(|m| m.target != "/work/app"));
        // `./app/` is the same repo.
        assert_eq!(west_mounts(WEST_LIST, "./app/"), m);
    }

    #[test]
    fn west_mounts_skip_paths_that_leave_work_and_malformed_lines() {
        let m = west_mounts("../x /ws/x\n/abs /ws/abs\nlonely\n\nok /ws/ok\n", "none");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].target, "/work/ok");
    }

    #[test]
    fn west_mounts_pass_the_run_args_scan() {
        let mut p = plan(Topology::Linux);
        p.west_workspace = west_projects(&west_mounts(WEST_LIST, "app"));
        assert_eq!(p.west_workspace.len(), 3);
        let a = try_run_args(&p, "10.0.0.1").unwrap();
        assert!(a.contains(&"--mount=type=bind,source=/ws/modules/hal/nordic,target=/work/modules/hal/nordic,readonly".to_string()));
    }

    #[test]
    fn a_non_west_repo_gets_no_mounts_and_the_toolchain_comment() {
        let f = Fixture::new("plain");
        f.write("src/main.c", "int main(void){return 0;}\n");
        f.write("zephyr/SDK_VERSION", "0.16.8\n");
        assert!(!crate::zephyr::looks_zephyr_west_shaped(&f.0));
        let t = Toolchain::from_workspace(false, Some("0.16.8"), &["arm-zephyr-eabi"], &[]);
        assert_eq!(t, Toolchain::NotWest);
        assert!(west_mounts("", "").is_empty());
        let cf = render_containerfile(&plan_with(t));
        assert!(cf.starts_with(GOLDEN_CONTAINERFILE_NOT_WEST_HEAD));
        assert!(cf.contains("# Toolchain: this repo is not a Zephyr and west repo."));
        assert!(!cf.contains("zephyr-sdk") && !cf.contains("venv"));
        assert!(!cf.contains("RUN wget") && !cf.contains("pip install"));
    }

    #[test]
    fn a_shaped_repo_with_no_readable_sdk_version_is_not_given_a_guess() {
        assert_eq!(Toolchain::from_workspace(true, None, &[], &[]), Toolchain::NotWest);
        for bad in ["", "latest\n", "0.16.8; rm -rf /\n", "../x", "0..1"] {
            assert_eq!(parse_sdk_version(bad), None, "{bad:?}");
        }
        assert_eq!(parse_sdk_version("0.17.0-rc1\nignored"), Some("0.17.0-rc1".into()));
    }

    #[test]
    fn the_tag_changes_when_the_text_changes_and_only_then() {
        let f = west_fixture();
        let a = render_containerfile(&plan_with(toolchain_of(&f)));
        let a2 = render_containerfile(&plan_with(toolchain_of(&f)));
        assert_eq!(image_tag(&a), image_tag(&a2));
        assert_eq!(image_tag(&a), format!("embarch-agent:{}", sha256_hex(a.as_bytes())));
        // A new SDK pin.
        f.write("zephyr/SDK_VERSION", "0.17.0\n");
        assert_ne!(image_tag(&a), image_tag(&render_containerfile(&plan_with(toolchain_of(&f)))));
        f.write("zephyr/SDK_VERSION", "0.16.8\n");
        // A changed requirements file, with the same names.
        f.write("zephyr/scripts/requirements-base.txt", "pyyaml\nextra\n");
        assert_ne!(image_tag(&a), image_tag(&render_containerfile(&plan_with(toolchain_of(&f)))));
        f.write("zephyr/scripts/requirements-base.txt", "pyyaml\n");
        assert_eq!(image_tag(&a), image_tag(&render_containerfile(&plan_with(toolchain_of(&f)))));
        // Things that are not in the text do not move it: the name, the Core port, the mounts.
        let mut p = plan_with(toolchain_of(&f));
        p.name = "other".into();
        p.core_port = 1;
        p.west_workspace.clear();
        assert_eq!(image_tag(&render_containerfile(&p)), image_tag(&a));
    }
}
