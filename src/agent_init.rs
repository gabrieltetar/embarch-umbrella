//! What `embarch init` does outside the repo: register it, and with
//! `--container` set up the agent's container definition and exchange folder
//! (decision 65).
//!
//! Everything that touches the machine takes its folders and answers as a
//! [`Host`], so a test runs it against a temp home and never the real
//! `~/.config`, `~/.local/share` or state file. Nothing here builds or starts
//! the image (EMB-448).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

use crate::agent::{
    container_toml, image_tag, render_containerfile, render_entrypoint_agent, render_entrypoint_root, DEFINITION_SKILL_FILE, west_mounts, west_projects,
    AgentContainer, Runtime, Toolchain, Topology, CORE_ADDR_PLACEHOLDER,
};
use crate::install;
use crate::state::{self, RegisteredContainer, RegisteredRepo, State};

const EXCHANGE_GIT: &str = "exchange.git";
const OUTBOX: &str = "outbox";
const CLAUDE_CONFIG: &str = "claude-config";
/// The refspec the person's fetch line uses: the agent's branches land under
/// `refs/remotes/agent/`, never over the person's own.
const FETCH_REFSPEC: &str = "+refs/heads/*:refs/remotes/agent/*";
/// **Assumed.** `init` has no source for the person's SoC, and `setup.sh`
/// with no `-t` installs every toolchain; the suite's targets are Cortex-M.
const DEFAULT_SDK_TOOLCHAIN: &str = "arm-zephyr-eabi";
const CLONE_BUILD_ROOT: &str = "/work/build";
const PUBLISH_FOLDER: &str = "/outbox/publish";
/// The model API's host. The hosts a login needs are **to be measured**.
const MODEL_API_HOST: &str = "api.anthropic.com";
/// Where the clone's config template sits in the definition folder.
const CLONE_CONFIG_FILE: &str = "embarch.toml.template";

/// The two folders everything is made under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    /// `~/.config/embarch/agents/` (`%APPDATA%\embarch\agents\`).
    pub definition_root: PathBuf,
    /// `~/.local/share/embarch/agents/` (`%LOCALAPPDATA%\embarch\agents\`).
    pub exchange_root: PathBuf,
}

/// Resolve [`Roots`] from environment values, pure like `state::config_dir_from`.
pub fn roots_from(
    windows: bool,
    appdata: Option<&str>,
    xdg_config_home: Option<&str>,
    local_appdata: Option<&str>,
    xdg_data_home: Option<&str>,
    home: Option<&str>,
) -> Option<Roots> {
    let config = state::config_dir_from(windows, appdata, xdg_config_home, home)?;
    let bin = install::canonical_bin_dir_from(windows, local_appdata, xdg_data_home, home)?;
    Some(Roots { definition_root: config.join("agents"), exchange_root: bin.parent()?.join("agents") })
}

/// Everything the machine answers, resolved by the caller.
pub struct Host {
    pub roots: Roots,
    pub state_path: PathBuf,
    /// Where the container runs, from the saved topology; `None` until
    /// `embarch setup` has run.
    pub class: Option<Topology>,
    /// Core's data directory as seen from here (the agent's token sits under
    /// it). `None` for a remote Core.
    pub core_data_dir: Option<PathBuf>,
    pub bin_dir: PathBuf,
    pub core_port: u16,
    /// `west list -f "{path} {abspath}"` as run on the host, when it ran.
    pub west_list: Option<String>,
}

/// What `init` read from the repo's workspace on the host.
#[derive(Debug, Default, Clone)]
pub struct WorkspaceFacts {
    pub shaped: bool,
    pub sdk_version_text: Option<String>,
    /// `zephyr/scripts/requirements*.txt`: file name and contents.
    pub requirements: Vec<(String, String)>,
}

/// Read the SDK version and requirements from `zephyr/` beside the repo (the
/// usual west layout) or inside it.
pub fn read_workspace_facts(repo: &Path, shaped: bool) -> WorkspaceFacts {
    let mut facts = WorkspaceFacts { shaped, ..Default::default() };
    let roots = [repo.parent().map(Path::to_path_buf), Some(repo.to_path_buf())];
    for root in roots.into_iter().flatten() {
        let zephyr = root.join("zephyr");
        let Ok(v) = std::fs::read_to_string(zephyr.join("SDK_VERSION")) else { continue };
        facts.sdk_version_text = Some(v);
        if let Ok(entries) = std::fs::read_dir(zephyr.join("scripts")) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("requirements") && name.ends_with(".txt") {
                    if let Ok(text) = std::fs::read_to_string(e.path()) {
                        facts.requirements.push((name, text));
                    }
                }
            }
        }
        facts.requirements.sort();
        break;
    }
    facts
}

/// A name safe in a path, a mount and a container name: letters, digits, `_`,
/// `.` and `-`, starting with a letter or digit.
fn sanitize(folder: &str) -> String {
    let s: String = folder
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') { c } else { '-' })
        .collect();
    let s = s.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()).to_string();
    if s.is_empty() {
        "firmware".to_string()
    } else {
        s
    }
}

/// The agent's name for `repo`: its folder's name, sanitized, with `-2`,
/// `-3`... when another repo holds it. A repo that already has a container
/// keeps its name.
pub fn choose_name(repo: &Path, registered: &[RegisteredRepo]) -> String {
    if let Some(c) = registered.iter().find(|r| r.path == repo).and_then(|r| r.container.as_ref()) {
        return c.name.clone();
    }
    let base = sanitize(&repo.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let taken = |n: &str| {
        registered.iter().any(|r| r.path != repo && r.container.as_ref().is_some_and(|c| c.name == n))
    };
    if !taken(&base) {
        return base;
    }
    (2..).map(|i| format!("{base}-{i}")).find(|n| !taken(n)).expect("an unbounded range")
}

/// The plan for `repo`, pure. The west workspace is mounted only for a
/// `ZephyrWest` toolchain, so the Containerfile's `NotWest` comment ("no west
/// workspace is mounted") stays true of the run arguments (decision 65).
pub fn build_plan(
    repo: &Path,
    name: &str,
    runtime: Runtime,
    host: &Host,
    facts: &WorkspaceFacts,
) -> Result<AgentContainer> {
    let class = host.class.ok_or_else(|| anyhow!("no topology is saved yet: run `embarch setup` first"))?;
    let data = host
        .core_data_dir
        .as_ref()
        .ok_or_else(|| anyhow!("Core is remote: its token directory is not on this machine, so no agent token can be mounted"))?;
    let requirements: Vec<(&str, &str)> = facts.requirements.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect();
    let toolchain = Toolchain::from_workspace(
        facts.shaped,
        facts.sdk_version_text.as_deref(),
        &[DEFAULT_SDK_TOOLCHAIN],
        &requirements,
    );
    let west_workspace = match (&toolchain, &host.west_list) {
        (Toolchain::ZephyrWest { .. }, Some(list)) => {
            let manifest = repo.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            west_projects(&west_mounts(list, &manifest))
        }
        _ => Vec::new(),
    };
    let mut plan = AgentContainer {
        name: name.to_string(),
        repo: repo.to_path_buf(),
        west_workspace,
        class,
        runtime,
        image_tag: String::new(),
        core_port: host.core_port,
        network_allow: vec![MODEL_API_HOST.to_string()],
        agent_token: data.join("agents").join(name).join("agent-token"),
        dev_agent_token: None,
        definition_dir: host.roots.definition_root.join(name),
        exchange_dir: host.roots.exchange_root.join(name),
        bin_dir: host.bin_dir.clone(),
        env: Vec::new(),
        toolchain,
    };
    plan.image_tag = image_tag(&render_containerfile(&plan));
    Ok(plan)
}

/// The clone's config template (decision 65): Core is found at first use
/// (container mode overrides the address later), builds under `/work/build`,
/// published files under the outbox. The clone sits at `/work/<repo folder>` (decision 66).
pub fn render_clone_config(plan: &AgentContainer) -> String {
    let folder = plan.repo.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let project = if matches!(plan.toolchain, Toolchain::ZephyrWest { .. }) {
        format!(
            "[[projects]]\nname = {:?}\nsource_path = {:?}\ndiscovery = \"zephyr-west\"\nwest_binary = \"west\"\nbuild_dir_root = {:?}\nflash_format = \"hex\"\nbuild_timeout_secs = 900\n\n",
            plan.name,
            format!("/work/{folder}"),
            CLONE_BUILD_ROOT,
        )
    } else {
        "# No [[projects]]: this repo is not a Zephyr and west repo (decision 64's NotWest).\n\n".to_string()
    };
    format!(
        "# Written by `embarch init --container`. The agent's clone seeds its embarch/embarch.toml from this.\n\n[core]\nbase_url = \"auto\"\n\n{project}[publish]\nfolder = {PUBLISH_FOLDER:?}\n"
    )
}

/// Every file the definition folder holds, relative path and text.
pub fn definition_files(plan: &AgentContainer) -> Vec<(&'static str, String)> {
    vec![
        ("Containerfile", render_containerfile(plan)),
        ("container.toml", container_toml(plan)),
        // The Core address is re-resolved at every start (decision 6), so the
        // script carries the placeholder and the start (EMB-448) substitutes it.
        ("entrypoint-root.sh", render_entrypoint_root(plan, CORE_ADDR_PLACEHOLDER)),
        (CLONE_CONFIG_FILE, render_clone_config(plan)),
        // The agent half (decision 66) and the skill it copies into the clone.
        ("entrypoint-agent.sh", render_entrypoint_agent(plan)),
        (DEFINITION_SKILL_FILE, crate::init::SKILL_TEXT.to_string()),
    ]
}

/// The person's fetch line for the exchange.
pub fn fetch_line(plan_exchange_dir: &Path) -> String {
    format!("git fetch {} '{FETCH_REFSPEC}'", plan_exchange_dir.join(EXCHANGE_GIT).display())
}

fn state_of(host: &Host) -> State {
    state::load_from(&host.state_path).unwrap_or_default()
}

/// Add or update the repo's entry, keeping an existing container entry when
/// this run made none.
fn upsert(state: &mut State, repo: &Path, container: Option<RegisteredContainer>) {
    match state.registered_repos.iter_mut().find(|r| r.path == repo) {
        Some(r) => {
            if container.is_some() {
                r.container = container;
            }
        }
        None => state.registered_repos.push(RegisteredRepo { path: repo.to_path_buf(), container }),
    }
}

fn write_definition(plan: &AgentContainer, lines: &mut Vec<String>) -> Result<()> {
    for dir in [
        plan.definition_dir.clone(),
        plan.exchange_dir.clone(),
        plan.exchange_dir.join(OUTBOX),
        plan.exchange_dir.join(CLAUDE_CONFIG),
    ] {
        std::fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    }
    for (file, text) in definition_files(plan) {
        let path = plan.definition_dir.join(file);
        match std::fs::read_to_string(&path) {
            Ok(old) if old == text => lines.push(format!("{} is up to date", path.display())),
            // A generated file that differs may carry the person's edit
            // (`container.toml`'s hash exists to notice one): never overwrite.
            Ok(_) => lines.push(format!(
                "kept {} (it differs from what `init` renders; delete it to regenerate)",
                path.display()
            )),
            Err(_) => {
                std::fs::write(&path, &text).with_context(|| format!("could not write {}", path.display()))?;
                #[cfg(unix)]
                if file.ends_with(".sh") {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
                }
                lines.push(format!("Wrote {}", path.display()));
            }
        }
    }
    let bare = plan.exchange_dir.join(EXCHANGE_GIT);
    if bare.join("HEAD").exists() {
        lines.push(format!("{} already exists", bare.display()));
    } else {
        let out = Command::new("git").args(["init", "--bare", "--quiet"]).arg(&bare).output()
            .context("could not run `git init --bare`")?;
        if !out.status.success() {
            bail!("`git init --bare {}` failed: {}", bare.display(), String::from_utf8_lossy(&out.stderr).trim());
        }
        lines.push(format!("Created {}", bare.display()));
    }
    lines.push(format!("Created {} and {}", plan.exchange_dir.join(OUTBOX).display(), plan.exchange_dir.join(CLAUDE_CONFIG).display()));
    Ok(())
}

/// Register `repo`, and with `runtime` set up its container. Returns what to
/// print. The registry is written even when the container step fails.
pub fn setup_repo(repo: &Path, runtime: Option<Runtime>, host: &Host, facts: &WorkspaceFacts) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut state = state_of(host);
    let mut container = None;
    let mut failure = None;
    if let Some(runtime) = runtime {
        let name = choose_name(repo, &state.registered_repos);
        match build_plan(repo, &name, runtime, host, facts).and_then(|plan| {
            write_definition(&plan, &mut lines)?;
            Ok(plan)
        }) {
            Ok(plan) => {
                if facts.shaped && plan.west_workspace.is_empty() && matches!(plan.toolchain, Toolchain::ZephyrWest { .. }) {
                    lines.push("no `west list` output, so no west project is mounted beside the clone; run `west update` and `init --container` again.".to_string());
                }
                lines.push(format!("\nTo take the agent's work, run:\n  {}", fetch_line(&plan.exchange_dir)));
                container = Some(RegisteredContainer {
                    name: plan.name.clone(),
                    definition_dir: plan.definition_dir.clone(),
                    exchange_dir: plan.exchange_dir.clone(),
                });
            }
            Err(e) => failure = Some(e),
        }
    }
    upsert(&mut state, repo, container);
    state::save_to(&host.state_path, &state)?;
    lines.push(format!("Registered {} in {}", repo.display(), host.state_path.display()));
    match failure {
        Some(e) => Err(e.context(lines.join("\n"))),
        None => Ok(lines),
    }
}

/// `--dry-run`: every folder and file, nothing written.
pub fn plan_repo(repo: &Path, runtime: Option<Runtime>, host: &Host, facts: &WorkspaceFacts) -> Vec<String> {
    let state = state_of(host);
    let mut lines = vec![format!("Would register {} in {}", repo.display(), host.state_path.display())];
    let Some(runtime) = runtime else { return lines };
    let name = choose_name(repo, &state.registered_repos);
    match build_plan(repo, &name, runtime, host, facts) {
        Ok(plan) => {
            lines.push(format!("Would create the definition folder {}", plan.definition_dir.display()));
            for (file, _) in definition_files(&plan) {
                lines.push(format!("Would write {}", plan.definition_dir.join(file).display()));
            }
            lines.push(format!("Would create the exchange folder {}", plan.exchange_dir.display()));
            lines.push(format!("Would create the bare repo {}", plan.exchange_dir.join(EXCHANGE_GIT).display()));
            lines.push(format!("Would create {}", plan.exchange_dir.join(OUTBOX).display()));
            lines.push(format!("Would create {}", plan.exchange_dir.join(CLAUDE_CONFIG).display()));
            lines.push(format!("Would print: {}", fetch_line(&plan.exchange_dir)));
        }
        Err(e) => lines.push(format!("Could not plan the container: {e:#}")),
    }
    lines
}

/// `--uninstall`: drop the repo from the registry and, after `confirm` says
/// yes, the container's two folders.
pub fn uninstall_repo(repo: &Path, host: &Host, confirm: &mut dyn FnMut(&str) -> bool) -> Result<Vec<String>> {
    let mut state = state_of(host);
    let mut lines = Vec::new();
    let Some(pos) = state.registered_repos.iter().position(|r| r.path == repo) else {
        lines.push(format!("{} was not registered", repo.display()));
        return Ok(lines);
    };
    let entry = state.registered_repos.remove(pos);
    state::save_to(&host.state_path, &state)?;
    lines.push(format!("Removed {} from {}", repo.display(), host.state_path.display()));
    if let Some(c) = entry.container {
        let question = format!(
            "The exchange {} may hold work you have not fetched yet; fetch it first with:\n  {}\nRemove {} and {}? Type `yes` to remove them",
            c.exchange_dir.display(),
            fetch_line(&c.exchange_dir),
            c.definition_dir.display(),
            c.exchange_dir.display(),
        );
        if confirm(&question) {
            for dir in [&c.definition_dir, &c.exchange_dir] {
                match std::fs::remove_dir_all(dir) {
                    Ok(()) => lines.push(format!("Removed {}", dir.display())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => lines.push(format!("No {} to remove", dir.display())),
                    Err(e) => lines.push(format!("Could not remove {}: {e}", dir.display())),
                }
            }
        } else {
            lines.push(format!("Kept {} and {}", c.definition_dir.display(), c.exchange_dir.display()));
        }
    }
    Ok(lines)
}

/// `--uninstall --dry-run`.
pub fn plan_uninstall(repo: &Path, host: &Host) -> Vec<String> {
    let state = state_of(host);
    let mut lines = Vec::new();
    match state.registered_repos.iter().find(|r| r.path == repo) {
        None => lines.push(format!("{} is not registered; nothing to remove from {}", repo.display(), host.state_path.display())),
        Some(r) => {
            lines.push(format!("Would remove {} from {}", repo.display(), host.state_path.display()));
            if let Some(c) = &r.container {
                lines.push(format!(
                    "Would ask for a typed yes, then remove {} and {}",
                    c.definition_dir.display(),
                    c.exchange_dir.display()
                ));
            }
        }
    }
    lines
}

/// The real machine's answers. `west list` is run from the repo.
pub fn host_from_env(repo: &Path, state_path: PathBuf) -> Result<Host> {
    let var = |k: &str| std::env::var(k).ok();
    let roots = roots_from(
        cfg!(windows),
        var("APPDATA").as_deref(),
        var("XDG_CONFIG_HOME").as_deref(),
        var("LOCALAPPDATA").as_deref(),
        var("XDG_DATA_HOME").as_deref(),
        var("HOME").as_deref(),
    )
    .context("could not determine the config and data folders")?;
    let saved = state::load();
    let class = match saved.topology.as_deref().and_then(crate::setup::topology_class_from_str) {
        Some(embarch_topology::software::TopologyClass::Local) if cfg!(windows) => Some(Topology::DockerDesktop),
        Some(embarch_topology::software::TopologyClass::Local) if cfg!(target_os = "macos") => Some(Topology::Macos),
        Some(embarch_topology::software::TopologyClass::Local) => Some(Topology::Linux),
        Some(embarch_topology::software::TopologyClass::WslHost) => Some(Topology::WslHost),
        _ => None,
    };
    let core_data_dir = saved
        .topology
        .as_deref()
        .and_then(crate::setup::topology_class_from_str)
        .and_then(crate::setup::data_dir_for);
    let west_list = Command::new("west")
        .args(["list", "-f", crate::agent::WEST_LIST_FORMAT])
        .current_dir(repo)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    Ok(Host {
        roots,
        state_path,
        class,
        core_data_dir,
        bin_dir: install::canonical_bin_dir()?,
        core_port: embarch_topology::software::DEFAULT_CORE_PORT,
        west_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "embarch-umbrella-agent-init-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    fn host_in(home: &Path) -> Host {
        let roots = roots_from(false, None, None, None, None, Some(home.to_str().unwrap())).unwrap();
        Host {
            roots,
            state_path: home.join(".config/embarch/umbrella.toml"),
            class: Some(Topology::Linux),
            core_data_dir: Some(home.join("core-data")),
            bin_dir: home.join(".local/share/embarch/bin"),
            core_port: 4884,
            west_list: None,
        }
    }

    fn git_repo(dir: &Path, name: &str) -> PathBuf {
        let repo = dir.join(name);
        std::fs::create_dir_all(&repo).unwrap();
        assert!(Command::new("git").args(["init", "--quiet"]).arg(&repo).status().unwrap().success());
        repo
    }

    fn porcelain(repo: &Path) -> String {
        let o = Command::new("git").arg("-C").arg(repo).args(["status", "--porcelain"]).output().unwrap();
        String::from_utf8(o.stdout).unwrap()
    }

    fn zephyr_facts() -> WorkspaceFacts {
        WorkspaceFacts {
            shaped: true,
            sdk_version_text: Some("0.16.8\n".into()),
            requirements: vec![("requirements-base.txt".into(), "west\n".into())],
        }
    }

    #[test]
    fn container_init_writes_every_file_and_leaves_the_repo_clean() {
        let t = tempdir();
        let repo = git_repo(&t.0, "fw");
        let host = host_in(&t.0.join("home"));
        setup_repo(&repo, Some(Runtime::Docker), &host, &zephyr_facts()).unwrap();
        let def = host.roots.definition_root.join("fw");
        let ex = host.roots.exchange_root.join("fw");
        for f in ["Containerfile", "container.toml", "entrypoint-root.sh", "entrypoint-agent.sh", DEFINITION_SKILL_FILE, CLONE_CONFIG_FILE] {
            assert!(def.join(f).is_file(), "{f}");
        }
        assert!(ex.join("exchange.git/HEAD").is_file());
        assert!(ex.join("outbox").is_dir() && ex.join("claude-config").is_dir());
        let cfg = std::fs::read_to_string(def.join(CLONE_CONFIG_FILE)).unwrap();
        assert!(cfg.contains("base_url = \"auto\"") && cfg.contains("/work/build") && cfg.contains("/outbox/publish"));
        assert_eq!(porcelain(&repo), "");
        // A second run changes nothing and keeps the registry at one entry.
        setup_repo(&repo, Some(Runtime::Docker), &host, &zephyr_facts()).unwrap();
        assert_eq!(state::load_from(&host.state_path).unwrap().registered_repos.len(), 1);
    }

    #[test]
    fn a_hand_edited_definition_file_is_kept() {
        let t = tempdir();
        let repo = git_repo(&t.0, "fw");
        let host = host_in(&t.0.join("home"));
        setup_repo(&repo, Some(Runtime::Docker), &host, &zephyr_facts()).unwrap();
        let f = host.roots.definition_root.join("fw/container.toml");
        std::fs::write(&f, "edited").unwrap();
        let lines = setup_repo(&repo, Some(Runtime::Docker), &host, &zephyr_facts()).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "edited");
        assert!(lines.iter().any(|l| l.starts_with("kept ")));
    }

    #[test]
    fn the_fetch_line_names_the_bare_repo_and_the_agent_refspec() {
        let t = tempdir();
        let repo = git_repo(&t.0, "fw");
        let host = host_in(&t.0.join("home"));
        let lines = setup_repo(&repo, Some(Runtime::Podman), &host, &WorkspaceFacts::default()).unwrap();
        let want = format!(
            "git fetch {} '+refs/heads/*:refs/remotes/agent/*'",
            host.roots.exchange_root.join("fw/exchange.git").display()
        );
        assert!(lines.iter().any(|l| l.contains(&want)), "{lines:?}");
    }

    #[test]
    fn state_lists_the_repo_with_and_without_a_container() {
        let t = tempdir();
        let host = host_in(&t.0.join("home"));
        let plain = git_repo(&t.0, "plain");
        let boxed = git_repo(&t.0, "boxed");
        setup_repo(&plain, None, &host, &WorkspaceFacts::default()).unwrap();
        setup_repo(&boxed, Some(Runtime::Docker), &host, &WorkspaceFacts::default()).unwrap();
        // A later plain `init` does not drop the container entry.
        setup_repo(&boxed, None, &host, &WorkspaceFacts::default()).unwrap();
        let s = state::load_from(&host.state_path).unwrap();
        assert_eq!(s.registered_repos.len(), 2);
        assert_eq!(s.registered_repos[0], RegisteredRepo { path: plain, container: None });
        let c = s.registered_repos[1].container.as_ref().unwrap();
        assert_eq!(c.name, "boxed");
        assert_eq!(c.exchange_dir, host.roots.exchange_root.join("boxed"));
    }

    #[test]
    fn a_state_file_without_the_field_loads() {
        let s: State = toml::from_str("schema_version = 1\ntopology = \"local\"\n").unwrap();
        assert!(s.registered_repos.is_empty());
        let text = toml::to_string_pretty(&State { registered_repos: vec![RegisteredRepo { path: "/r".into(), container: None }], ..Default::default() }).unwrap();
        assert_eq!(toml::from_str::<State>(&text).unwrap().registered_repos.len(), 1);
    }

    #[test]
    fn a_taken_name_gets_a_suffix_and_an_owned_name_is_kept() {
        let c = |n: &str| Some(RegisteredContainer { name: n.into(), definition_dir: "/d".into(), exchange_dir: "/e".into() });
        let reg = vec![
            RegisteredRepo { path: "/a/fw".into(), container: c("fw") },
            RegisteredRepo { path: "/b/fw".into(), container: c("fw-2") },
        ];
        assert_eq!(choose_name(Path::new("/c/fw"), &reg), "fw-3");
        assert_eq!(choose_name(Path::new("/a/fw"), &reg), "fw");
        assert_eq!(choose_name(Path::new("/c/other"), &reg), "other");
        assert_eq!(choose_name(Path::new("/c/my repo"), &reg), "my-repo");
    }

    #[test]
    fn uninstall_removes_the_entry_and_only_after_yes_the_folders() {
        let t = tempdir();
        let repo = git_repo(&t.0, "fw");
        let host = host_in(&t.0.join("home"));
        setup_repo(&repo, Some(Runtime::Docker), &host, &WorkspaceFacts::default()).unwrap();
        let def = host.roots.definition_root.join("fw");
        let ex = host.roots.exchange_root.join("fw");

        let mut asked = Vec::new();
        uninstall_repo(&repo, &host, &mut |q| {
            asked.push(q.to_string());
            false
        })
        .unwrap();
        assert!(state::load_from(&host.state_path).unwrap().registered_repos.is_empty());
        assert!(def.is_dir() && ex.is_dir(), "no yes, no removal");
        assert!(asked[0].contains("not yet fetched") || asked[0].contains("have not fetched"));

        setup_repo(&repo, Some(Runtime::Docker), &host, &WorkspaceFacts::default()).unwrap();
        uninstall_repo(&repo, &host, &mut |_| true).unwrap();
        assert!(!def.exists() && !ex.exists());
    }

    #[test]
    fn dry_run_writes_nothing_and_names_every_path() {
        let t = tempdir();
        let repo = git_repo(&t.0, "fw");
        let home = t.0.join("home");
        let host = host_in(&home);
        let lines = plan_repo(&repo, Some(Runtime::Docker), &host, &zephyr_facts()).join("\n");
        assert!(!home.exists(), "a dry run created {home:?}");
        let def = host.roots.definition_root.join("fw");
        let ex = host.roots.exchange_root.join("fw");
        for p in [
            def.join("Containerfile"),
            def.join("container.toml"),
            def.join("entrypoint-root.sh"),
            def.join(CLONE_CONFIG_FILE),
            ex.join("exchange.git"),
            ex.join("outbox"),
            ex.join("claude-config"),
            host.state_path.clone(),
        ] {
            assert!(lines.contains(&p.display().to_string()), "{p:?} not named in:\n{lines}");
        }
        assert!(lines.contains("git fetch"));
        assert!(plan_uninstall(&repo, &host).join("\n").contains("not registered"));
        assert!(!home.exists());
    }

    #[test]
    fn the_west_workspace_is_mounted_only_with_a_zephyr_toolchain() {
        let t = tempdir();
        let repo = t.0.join("fw");
        let mut host = host_in(&t.0.join("home"));
        host.west_list = Some("fw /ws/fw\nzephyr /ws/zephyr\n".into());
        let with = build_plan(&repo, "fw", Runtime::Docker, &host, &zephyr_facts()).unwrap();
        assert_eq!(with.west_workspace.len(), 1);
        assert_eq!(with.west_workspace[0].name, "zephyr");
        // Shaped but no readable SDK version: NotWest, and no mounts.
        let mut facts = zephyr_facts();
        facts.sdk_version_text = None;
        let without = build_plan(&repo, "fw", Runtime::Docker, &host, &facts).unwrap();
        assert_eq!(without.toolchain, Toolchain::NotWest);
        assert!(without.west_workspace.is_empty());
        assert!(!crate::agent::run_args(&without, "h").iter().any(|a| a.contains("target=/work/zephyr")));
    }

    #[test]
    fn a_remote_core_or_no_saved_topology_refuses_the_container_but_still_registers() {
        let t = tempdir();
        let repo = git_repo(&t.0, "fw");
        let mut host = host_in(&t.0.join("home"));
        host.class = None;
        assert!(setup_repo(&repo, Some(Runtime::Docker), &host, &WorkspaceFacts::default()).is_err());
        assert_eq!(state::load_from(&host.state_path).unwrap().registered_repos.len(), 1);
        assert!(!host.roots.definition_root.exists());
    }

    #[test]
    fn roots_follow_xdg_and_windows_variables() {
        let r = roots_from(false, None, Some("/c"), None, Some("/d"), Some("/h")).unwrap();
        assert_eq!(r.definition_root, PathBuf::from("/c/embarch/agents"));
        assert_eq!(r.exchange_root, PathBuf::from("/d/embarch/agents"));
        let w = roots_from(true, Some("A"), None, Some("L"), None, None).unwrap();
        assert_eq!(w.definition_root, PathBuf::from("A").join("embarch").join("agents"));
        assert_eq!(w.exchange_root, PathBuf::from("L").join("embarch").join("agents"));
    }
}
