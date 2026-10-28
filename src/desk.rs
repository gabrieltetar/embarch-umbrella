//! `setup`'s optional desk steps (decision 58): register `embarch-desk`'s
//! systemd user service and install its Claude Code plugin, when the binary is
//! found, and reverse both on `--uninstall`.
//!
//! Every external command goes through [`Runner`], so tests mock both and the
//! real run is the owner's.

use std::path::Path;
use std::process::Command;

use crate::locate::Located;

pub const PLUGIN: &str = "embarch-desk@embarch";

/// What a command said, for the one place that reads it (`plugin list`).
pub struct Out {
    pub ok: bool,
    pub text: String,
}

pub trait Runner {
    fn run(&self, program: &Path, args: &[&str]) -> std::io::Result<Out>;
}

/// The real thing. Output is captured and echoed on failure only, so a clean
/// run prints just our own outcome line.
pub struct Real;

impl Runner for Real {
    fn run(&self, program: &Path, args: &[&str]) -> std::io::Result<Out> {
        let o = Command::new(program).args(args).output()?;
        let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        Ok(Out { ok: o.status.success(), text })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// Not attempted, and why. Not a failure.
    Skipped(String),
    Failed(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub name: &'static str,
    pub outcome: Outcome,
}

impl Step {
    pub fn failed(&self) -> bool {
        matches!(self.outcome, Outcome::Failed(_))
    }
    pub fn render(&self, dry_run: bool) -> String {
        match &self.outcome {
            Outcome::Done if dry_run => format!("  {}: would run", self.name),
            Outcome::Done => format!("  {}: done", self.name),
            Outcome::Skipped(why) => format!("  {}: skipped — {why}", self.name),
            Outcome::Failed(why) => format!("  {}: FAILED — {why}", self.name),
        }
    }
}

const SERVICE: &str = "desk service";
const PLUGIN_STEP: &str = "desk plugin";

fn tail(text: &str) -> String {
    let t = text.trim();
    if t.is_empty() { "no output".into() } else { t.lines().last().unwrap_or("").to_string() }
}

/// `setup`'s desk steps. `desk` is `locate_desk()`, `claude` is
/// `locate_claude()`, `linux` says a systemd user service can exist here.
pub fn install(desk: Option<&Located>, claude: Option<&Path>, linux: bool, dry_run: bool, r: &dyn Runner) -> Vec<Step> {
    let Some(desk) = desk else {
        let why = "embarch-desk not found (EMBARCH_DESK_BIN, PATH, or the install directory)".to_string();
        return vec![
            Step { name: SERVICE, outcome: Outcome::Skipped(why.clone()) },
            Step { name: PLUGIN_STEP, outcome: Outcome::Skipped(why) },
        ];
    };
    let service = if !linux {
        Outcome::Skipped("the desk's service is a systemd user unit; this is not Linux".into())
    } else if dry_run {
        Outcome::Done
    } else {
        exec(r, &desk.path, &["service", "install"], "")
    };
    let plugin = match claude {
        None => Outcome::Skipped("`claude` is not on PATH".into()),
        Some(_) if dry_run => Outcome::Done,
        Some(c) => exec(
            r,
            c,
            &["plugin", "install", PLUGIN],
            "; if the `embarch` marketplace is unknown, from an embarch-desk checkout run \
             `claude plugin marketplace add \"$PWD\"` and re-run setup",
        ),
    };
    vec![Step { name: SERVICE, outcome: service }, Step { name: PLUGIN_STEP, outcome: plugin }]
}

/// `setup --uninstall`'s reverse. The plugin is removed only when `plugin list`
/// shows it, so a machine that never had it is not a failure. The service
/// goes first: its unit names an installed binary the later install undo
/// deletes.
pub fn uninstall(desk: Option<&Located>, claude: Option<&Path>, linux: bool, r: &dyn Runner) -> Vec<Step> {
    let service = match desk {
        None => Outcome::Skipped("embarch-desk not found".into()),
        Some(_) if !linux => Outcome::Skipped("not Linux".into()),
        Some(d) => exec(r, &d.path, &["service", "uninstall"], ""),
    };
    let plugin = match claude {
        None => Outcome::Skipped("`claude` is not on PATH".into()),
        Some(c) => match r.run(c, &["plugin", "list"]) {
            Ok(o) if o.ok && !o.text.contains(PLUGIN) => Outcome::Skipped("plugin not installed".into()),
            // A list that failed says nothing about the plugin: try anyway.
            _ => exec(r, c, &["plugin", "uninstall", PLUGIN], ""),
        },
    };
    vec![Step { name: SERVICE, outcome: service }, Step { name: PLUGIN_STEP, outcome: plugin }]
}

fn exec(r: &dyn Runner, program: &Path, args: &[&str], hint: &str) -> Outcome {
    match r.run(program, args) {
        Ok(o) if o.ok => Outcome::Done,
        Ok(o) => Outcome::Failed(format!("`{} {}` exited non-zero ({}){hint}", program.display(), args.join(" "), tail(&o.text))),
        Err(e) => Outcome::Failed(format!("could not run {}: {e}", program.display())),
    }
}

/// Print the steps; true when any failed.
pub fn report(heading: &str, steps: &[Step], dry_run: bool) -> bool {
    println!("\n{heading}");
    for s in steps {
        let line = s.render(dry_run);
        if s.failed() { eprintln!("{line}") } else { println!("{line}") }
    }
    steps.iter().any(Step::failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locate::FoundBy;
    use std::cell::RefCell;
    use std::path::PathBuf;

    struct Mock {
        calls: RefCell<Vec<String>>,
        fail: Vec<&'static str>,
        list_text: &'static str,
    }
    impl Mock {
        fn new() -> Self {
            Mock { calls: RefCell::new(vec![]), fail: vec![], list_text: "" }
        }
    }
    impl Runner for Mock {
        fn run(&self, program: &Path, args: &[&str]) -> std::io::Result<Out> {
            let line = format!("{} {}", program.file_name().unwrap().to_string_lossy(), args.join(" "));
            self.calls.borrow_mut().push(line.clone());
            let text = if args == ["plugin", "list"] { self.list_text.to_string() } else { "boom".into() };
            Ok(Out { ok: !self.fail.iter().any(|f| line.contains(f)), text })
        }
    }

    fn desk() -> Located {
        Located { path: PathBuf::from("/x/embarch-desk"), found_by: FoundBy::Path, windows_exe_from_wsl2: false }
    }
    const CLAUDE: &str = "/x/claude";

    #[test]
    fn installs_both_when_desk_is_found() {
        let m = Mock::new();
        let steps = install(Some(&desk()), Some(Path::new(CLAUDE)), true, false, &m);
        assert!(steps.iter().all(|s| s.outcome == Outcome::Done));
        assert_eq!(*m.calls.borrow(), ["embarch-desk service install", "claude plugin install embarch-desk@embarch"]);
    }

    #[test]
    fn skips_both_by_name_when_desk_is_missing() {
        let m = Mock::new();
        let steps = install(None, Some(Path::new(CLAUDE)), true, false, &m);
        assert!(m.calls.borrow().is_empty());
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|s| matches!(s.outcome, Outcome::Skipped(_)) && !s.failed()));
        assert!(steps[0].render(false).contains("desk service") && steps[1].render(false).contains("desk plugin"));
    }

    #[test]
    fn no_claude_skips_only_the_plugin() {
        let m = Mock::new();
        let steps = install(Some(&desk()), None, true, false, &m);
        assert_eq!(steps[0].outcome, Outcome::Done);
        assert!(matches!(&steps[1].outcome, Outcome::Skipped(w) if w.contains("claude")));
        assert_eq!(m.calls.borrow().len(), 1);
    }

    #[test]
    fn not_linux_skips_the_service_but_not_the_plugin() {
        let m = Mock::new();
        let steps = install(Some(&desk()), Some(Path::new(CLAUDE)), false, false, &m);
        assert!(matches!(steps[0].outcome, Outcome::Skipped(_)));
        assert_eq!(steps[1].outcome, Outcome::Done);
    }

    #[test]
    fn a_failed_service_still_tries_the_plugin_and_is_reported() {
        let mut m = Mock::new();
        m.fail = vec!["service install"];
        let steps = install(Some(&desk()), Some(Path::new(CLAUDE)), true, false, &m);
        assert!(steps[0].failed());
        assert_eq!(steps[1].outcome, Outcome::Done);
    }

    #[test]
    fn a_failed_plugin_install_names_the_marketplace_fix() {
        let mut m = Mock::new();
        m.fail = vec!["plugin install"];
        let steps = install(Some(&desk()), Some(Path::new(CLAUDE)), true, false, &m);
        assert!(matches!(&steps[1].outcome, Outcome::Failed(w) if w.contains("marketplace add")));
    }

    #[test]
    fn dry_run_runs_nothing() {
        let m = Mock::new();
        let steps = install(Some(&desk()), Some(Path::new(CLAUDE)), true, true, &m);
        assert!(m.calls.borrow().is_empty());
        assert!(steps[0].render(true).contains("would run"));
    }

    #[test]
    fn uninstall_reverses_both_service_first() {
        let mut m = Mock::new();
        m.list_text = "  ❯ embarch-desk@embarch\n    Version: 0.5.0";
        let steps = uninstall(Some(&desk()), Some(Path::new(CLAUDE)), true, &m);
        assert!(steps.iter().all(|s| s.outcome == Outcome::Done));
        assert_eq!(
            *m.calls.borrow(),
            ["embarch-desk service uninstall", "claude plugin list", "claude plugin uninstall embarch-desk@embarch"]
        );
    }

    #[test]
    fn uninstall_skips_a_plugin_that_was_never_installed() {
        let m = Mock::new();
        let steps = uninstall(Some(&desk()), Some(Path::new(CLAUDE)), true, &m);
        assert!(matches!(steps[1].outcome, Outcome::Skipped(_)));
        assert!(!m.calls.borrow().iter().any(|c| c.contains("plugin uninstall")));
    }

    #[test]
    fn uninstall_with_no_desk_still_removes_the_plugin() {
        let mut m = Mock::new();
        m.list_text = "embarch-desk@embarch";
        let steps = uninstall(None, Some(Path::new(CLAUDE)), true, &m);
        assert!(matches!(steps[0].outcome, Outcome::Skipped(_)));
        assert_eq!(steps[1].outcome, Outcome::Done);
    }

    #[test]
    fn uninstall_failure_is_reported() {
        let mut m = Mock::new();
        m.fail = vec!["service uninstall"];
        let steps = uninstall(Some(&desk()), None, true, &m);
        assert!(steps[0].failed());
    }
}
