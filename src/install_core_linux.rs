//! The Linux half of `embarch install-core` (EMB-340, embarch-umbrella
//! decision 70): a generated POSIX shell script that puts a verified Core
//! under a system user of its own.
//!
//! It follows the Windows half's shape (`install_core_win`, decision 69): one
//! function per step, the same seven steps and transcript lines, so the
//! transcript parser and the `Host` seam are the Windows module's. Nothing here
//! runs elevated by itself, and nothing in the tests runs `sudo`, `useradd` or
//! any step: the script is checked as text and with `sh -n`, and the sequence
//! runs against a fake host.

use std::fmt::Write as _;

pub use crate::install_core_win::{parse_transcript, Host};

/// The unit's name (Core decision 157); the label the service manager uses.
pub const SERVICE: &str = "com.embarch.core";
/// The account Core runs as, and its group.
pub const SERVICE_USER: &str = "embarch";
/// The group holding the engineer and the service, for the token files and
/// the firmware staging folder.
pub const USERS_GROUP: &str = "embarch-users";
/// Groups that own serial and USB devices on some distributions; each is
/// joined only where it exists.
pub const DEVICE_GROUPS: [&str; 2] = ["dialout", "plugdev"];
/// Where installed binaries go, `<OPT_DIR>/<version>/embarch-core`.
pub const OPT_DIR: &str = "/opt/embarch/core";
/// The only data dir installed (Core reads its record there).
pub const DATA_DIR: &str = "/var/lib/embarch";
/// The grant step, which only `--agent-in-container` adds (decision 72).
pub const GRANT_STEP: &str = "7 grant";
/// Where polkit reads rules; the grant is one file here.
pub const POLKIT_RULES_DIR: &str = "/etc/polkit-1/rules.d";
/// The grant's file name. `50-` sorts it among the local rules.
pub const POLKIT_RULE_FILE: &str = "50-embarch-core.rules";
/// The unit as systemd names it, which is what polkit's `unit` detail holds
/// (the label is [`SERVICE`]; systemd's `.service` suffix is assumed, decision 70).
pub const UNIT: &str = "com.embarch.core.service";
/// The one polkit action systemd asks about for start and stop.
pub const POLKIT_ACTION: &str = "org.freedesktop.systemd1.manage-units";

/// What the script is built from. Paths are strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinInputs {
    /// The suite version; it names the install folder.
    pub version: String,
    /// The verified `embarch-core` inside `release-staging/<n>/`.
    pub staged_bin: String,
    /// Its SHA-256, lowercase hex, as the record holds it.
    pub binary_sha256: String,
    /// The engineer, `$SUDO_USER`, taken by the unprivileged half.
    pub engineer: String,
    /// `--bind` for `install --service`.
    pub bind: String,
    /// `--agent-in-container`: add the start-and-stop grant (decision 72).
    pub agent_in_container: bool,
}

/// Every folder and file the script writes, derived once so the plan and the
/// script cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinPaths {
    pub bin_dir: String,
    pub bin: String,
    pub data_dir: String,
    pub store: String,
    pub public_key: String,
    pub firmware_staging: String,
    pub results: String,
    pub logs: String,
    pub token: String,
    pub person_token: String,
    pub fingerprint: String,
}

pub fn paths(version: &str) -> LinPaths {
    let bin_dir = format!("{OPT_DIR}/{version}");
    LinPaths {
        bin: format!("{bin_dir}/embarch-core"),
        bin_dir,
        data_dir: DATA_DIR.to_string(),
        store: format!("{DATA_DIR}/store"),
        public_key: format!("{DATA_DIR}/store/public-key"),
        firmware_staging: format!("{DATA_DIR}/staging"),
        results: format!("{DATA_DIR}/study_results"),
        logs: format!("{DATA_DIR}/logs"),
        token: format!("{DATA_DIR}/token"),
        person_token: format!("{DATA_DIR}/person-token"),
        fingerprint: format!("{DATA_DIR}/core-fingerprint"),
    }
}

impl LinInputs {
    fn paths(&self) -> LinPaths {
        paths(&self.version)
    }

    /// Refuses what must not reach a script: a version that is not a safe
    /// folder name, a hash of the wrong shape, an engineer that is not an
    /// ordinary account name (or is root or the service), a quote anywhere.
    pub fn validate(&self) -> Result<(), String> {
        let safe = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c));
        if !safe(&self.version) || self.version.starts_with('.') {
            return Err(format!("suite version {:?} is not usable as a folder name", self.version));
        }
        let hex = self.binary_sha256.len() == 64
            && self.binary_sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        if !hex {
            return Err("the core binary's hash is not 64 lowercase hex".to_string());
        }
        let name_ok = !self.engineer.is_empty()
            && self.engineer.len() <= 32
            && self.engineer.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-".contains(c))
            && !self.engineer.starts_with('-');
        if !name_ok || self.engineer == "root" || self.engineer == SERVICE_USER {
            return Err(format!(
                "{:?} is not the engineer's account: run under `sudo` from your own login, not from root",
                self.engineer
            ));
        }
        let bind_ok = !self.bind.is_empty() && self.bind.chars().all(|c| c.is_ascii_alphanumeric() || ".:[]-".contains(c));
        if !bind_ok {
            return Err(format!("{:?} is not a usable --bind address", self.bind));
        }
        if self.staged_bin.contains('\'') || self.staged_bin.contains('\n') {
            return Err(format!("path {:?} holds a quote or a newline", self.staged_bin));
        }
        Ok(())
    }
}

fn header() -> &'static str {
    r#"#!/bin/sh
# Generated by `embarch install-core` (embarch-umbrella decision 70).
# Runs as root. Every line goes to stdout, which the caller reads as the
# transcript; nothing here prompts.
exec 2>&1
set -eu
umask 022
step='0 preflight'
trap 'rc=$?; [ "$rc" -eq 0 ] || echo "FAILED: step $step: exited $rc"' EXIT
fail() { echo "FAILED: step $step: $1"; trap - EXIT; exit 1; }
echo '=== embarch install-core: Linux half ==='
"#
}

const FOOTER: &str = "echo '=== done ==='\n";

/// The store check on its own, so it can be run against a temp dir: a store
/// that exists is refused unless it is a real directory owned by the service.
fn store_check(store: &str) -> String {
    format!(
        "if [ -e '{store}' ] || [ -L '{store}' ]; then\n\
         \x20 if [ -L '{store}' ] || [ ! -d '{store}' ]; then fail \"the store {store} exists and is not a plain directory; nothing was written\"; fi\n\
         \x20 owner=$(stat -c %U '{store}')\n\
         \x20 if [ \"$owner\" != '{user}' ]; then fail \"the store {store} exists and is owned by $owner, not {user}; nothing was written\"; fi\n\
         fi\n",
        user = SERVICE_USER,
    )
}

/// Step 0, before anything is written: root, a systemd to register with, the
/// engineer's account, and a store that is not someone else's.
pub fn step_preflight(i: &LinInputs) -> String {
    let mut s = format!(
        "[ \"$(id -u)\" -eq 0 ] || fail 'not running as root'\n\
         command -v systemctl >/dev/null 2>&1 || fail 'no systemctl: only systemd hosts are supported'\n\
         id -u '{eng}' >/dev/null 2>&1 || fail 'the engineer account {eng} does not exist'\n",
        eng = i.engineer,
    );
    s += &store_check(&i.paths().store);
    s += "echo 'STEP 0 OK preflight'\n";
    s
}

/// Step 1: `/opt/embarch/core/<version>/`, root-owned `0755`, the verified
/// binary copied in and hashed again.
pub fn step_binary(i: &LinInputs) -> String {
    let p = i.paths();
    format!(
        "step='1 binary'\n\
         install -d -m 0755 -o root -g root /opt/embarch '{OPT_DIR}' '{dir}'\n\
         install -m 0755 -o root -g root '{staged}' '{bin}'\n\
         h=$(sha256sum '{bin}' | cut -d' ' -f1)\n\
         [ \"$h\" = '{sha}' ] || fail \"the copied binary hashes to $h, not {sha}\"\n\
         echo 'STEP 1 OK binary {bin}'\n",
        dir = p.bin_dir,
        bin = p.bin,
        staged = i.staged_bin,
        sha = i.binary_sha256,
    )
}

/// Step 2: the accounts and the protected store. The `embarch` user (no
/// login, no home) and the `embarch-users` group are made when absent; the
/// store starts empty, `embarch`'s alone, and is never emptied here.
/// `study_results/` and `logs/` are the service's to write (Core puts run
/// directories and its daily log files in the data dir beside the tokens,
/// which is root-owned); `logs/` is `embarch-users`-readable (decision 70).
pub fn step_store(i: &LinInputs) -> String {
    let p = i.paths();
    let mut s = format!(
        "step='2 store'\n\
         getent group '{users}' >/dev/null || groupadd --system '{users}'\n\
         if ! id -u '{user}' >/dev/null 2>&1; then\n\
         \x20 nologin=$(command -v nologin || true)\n\
         \x20 [ -n \"$nologin\" ] || nologin=/usr/sbin/nologin\n\
         \x20 useradd --system --user-group --no-create-home --home-dir /nonexistent --shell \"$nologin\" '{user}'\n\
         fi\n",
        user = SERVICE_USER,
        users = USERS_GROUP,
    );
    for g in DEVICE_GROUPS {
        let _ = writeln!(s, "getent group '{g}' >/dev/null && usermod -aG '{g}' '{SERVICE_USER}' || true");
    }
    let _ = write!(
        s,
        "usermod -aG '{users}' '{user}'\n\
         usermod -aG '{users}' '{eng}'\n\
         install -d -m 0755 -o root -g root '{data}'\n\
         install -d -m 0700 -o '{user}' -g '{user}' '{store}'\n\
         install -d -m 0750 -o '{user}' -g '{users}' '{results}'\n\
         install -d -m 0750 -o '{user}' -g '{users}' '{logs}'\n\
         echo 'STEP 2 OK store {store}'\n",
        user = SERVICE_USER,
        users = USERS_GROUP,
        eng = i.engineer,
        data = p.data_dir,
        store = p.store,
        results = p.results,
        logs = p.logs,
    );
    s
}

/// Step 3: the firmware staging folder, `root:embarch-users` `0770`.
pub fn step_firmware_staging(i: &LinInputs) -> String {
    let dir = i.paths().firmware_staging;
    format!(
        "step='3 firmware-staging'\n\
         install -d -m 0770 -o root -g '{USERS_GROUP}' '{dir}'\n\
         echo 'STEP 3 OK firmware-staging {dir}'\n",
    )
}

/// Step 4: both token files, written when absent (32 random bytes as 64 hex,
/// Core's shape) under `umask 077` so they are never readable before the
/// `chown`; each ends `embarch:embarch-users` `0640`.
pub fn step_tokens(i: &LinInputs) -> String {
    let p = i.paths();
    format!(
        "step='4 tokens'\n\
         for t in '{token}' '{person}'; do\n\
         \x20 if [ ! -e \"$t\" ]; then\n\
         \x20   (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > \"$t\")\n\
         \x20 fi\n\
         \x20 chown '{user}:{users}' \"$t\"\n\
         \x20 chmod 0640 \"$t\"\n\
         done\n\
         echo 'STEP 4 OK tokens'\n",
        token = p.token,
        person = p.person_token,
        user = SERVICE_USER,
        users = USERS_GROUP,
    )
}

/// Step 5: the installed binary registers itself, writing the unit with
/// `User=embarch` (Core decision 157).
pub fn step_register(i: &LinInputs) -> String {
    format!(
        "step='5 register'\n\
         rc=0\n\
         '{bin}' install --service --bind '{bind}' || rc=$?\n\
         [ \"$rc\" -eq 0 ] || fail \"install --service exited $rc\"\n\
         echo 'STEP 5 OK register User={SERVICE_USER}'\n",
        bin = i.paths().bin,
        bind = i.bind,
    )
}

/// Step 6: start, wait for `active`, read `store/public-key`, write
/// `core-fingerprint` (SHA-256 of the raw key) root-owned `0644`, print it.
/// The hex is turned back into bytes with `printf` octal escapes, which every
/// POSIX shell has, rather than `xxd`.
pub fn step_start_and_fingerprint(i: &LinInputs) -> String {
    let p = i.paths();
    format!(
        "step='6 start-and-fingerprint'\n\
         systemctl start '{SERVICE}'\n\
         n=0\n\
         until systemctl is-active --quiet '{SERVICE}'; do\n\
         \x20 n=$((n + 1)); [ \"$n\" -le 30 ] || fail 'the service did not become active in 30 s'\n\
         \x20 sleep 1\n\
         done\n\
         pub='{public_key}'\n\
         n=0\n\
         while [ ! -e \"$pub\" ]; do\n\
         \x20 n=$((n + 1)); [ \"$n\" -le 30 ] || fail \"no public key at $pub\"\n\
         \x20 sleep 1\n\
         done\n\
         hex=$(tr -d ' \\n' < \"$pub\")\n\
         printf '%s' \"$hex\" | grep -Eq '^[0-9a-f]{{64}}$' || fail 'the public key is not 64 lowercase hex'\n\
         raw=''\n\
         i=0\n\
         while [ \"$i\" -lt 64 ]; do\n\
         \x20 b=$(printf '%s' \"$hex\" | cut -c \"$((i + 1))-$((i + 2))\")\n\
         \x20 raw=\"$raw$(printf '\\\\%03o' \"$((0x$b))\")\"\n\
         \x20 i=$((i + 2))\n\
         done\n\
         fp=$(printf \"$raw\" | sha256sum | cut -d' ' -f1)\n\
         printf '%s' \"$fp\" > '{fingerprint}'\n\
         chown root:root '{fingerprint}'\n\
         chmod 0644 '{fingerprint}'\n\
         echo \"FINGERPRINT $fp\"\n\
         echo 'STEP 6 OK start-and-fingerprint'\n",
        public_key = p.public_key,
        fingerprint = p.fingerprint,
    )
}

/// The polkit rule the grant installs: `engineer` may `start` or `stop`
/// `com.embarch.core.service`, and nothing else is mentioned, so every other
/// unit and verb keeps polkit's default. Pure; one string per line so the
/// script can write it with `printf` and no here-document.
pub fn polkit_rule_lines(engineer: &str) -> Vec<String> {
    vec![
        "// Generated by `embarch install-core --agent-in-container` (embarch-umbrella decision 72).".to_string(),
        "polkit.addRule(function(action, subject) {".to_string(),
        format!("  if (action.id == \"{POLKIT_ACTION}\" &&"),
        format!("      action.lookup(\"unit\") == \"{UNIT}\" &&"),
        "      (action.lookup(\"verb\") == \"start\" || action.lookup(\"verb\") == \"stop\") &&".to_string(),
        format!("      subject.user == \"{engineer}\") {{"),
        "    return polkit.Result.YES;".to_string(),
        "  }".to_string(),
        "});".to_string(),
    ]
}

/// Step 7, only with `--agent-in-container`: write the polkit rule to a
/// temporary file and install it root-owned `0644` (never writable by the
/// engineer, whose edit would widen it).
pub fn step_grant(i: &LinInputs) -> String {
    let mut s = format!(
        "step='{GRANT_STEP}'\n\
         install -d -m 0755 -o root -g root '{POLKIT_RULES_DIR}'\n\
         rule=$(mktemp)\n\
         : > \"$rule\"\n"
    );
    for line in polkit_rule_lines(&i.engineer) {
        let _ = writeln!(s, "printf '%s\\n' '{line}' >> \"$rule\"");
    }
    let _ = write!(
        s,
        "install -m 0644 -o root -g root \"$rule\" '{POLKIT_RULES_DIR}/{POLKIT_RULE_FILE}'\n\
         rm -f \"$rule\"\n\
         echo 'STEP 7 OK grant {POLKIT_RULES_DIR}/{POLKIT_RULE_FILE}'\n"
    );
    s
}

/// The whole script, in step order.
pub fn build_script(i: &LinInputs) -> String {
    let mut s = String::from(header());
    s += &step_preflight(i);
    s += &step_binary(i);
    s += &step_store(i);
    s += &step_firmware_staging(i);
    s += &step_tokens(i);
    s += &step_register(i);
    s += &step_start_and_fingerprint(i);
    if i.agent_in_container {
        s += &step_grant(i);
    }
    s += FOOTER;
    s
}

/// What `--dry-run` prints for the Linux half: the plan, then the script it
/// would run, every command, with the values not known before a verified
/// release exists as placeholders. Nothing is run or written.
pub fn render_plan(bind: &str, engineer: Option<&str>, agent_in_container: bool) -> String {
    let placeholder = LinInputs {
        version: "<suite version>".to_string(),
        staged_bin: format!("{DATA_DIR}/release-staging/<n>/embarch-core"),
        binary_sha256: "<sha256 from installed-release.json>".to_string(),
        engineer: engineer.unwrap_or("<your account>").to_string(),
        bind: bind.to_string(),
        agent_in_container,
    };
    let p = placeholder.paths();
    let mut s = String::from("  Linux half (one POSIX shell script run as root, its stdout read as the transcript):\n");
    let _ = writeln!(s, "    0. preflight: root, systemctl, your account; refuse a {} that exists and is not a plain directory owned by {SERVICE_USER}; nothing is written before this", p.store);
    let _ = writeln!(s, "    1. {}: root, 0755; the verified embarch-core copied in and hashed again", p.bin_dir);
    let _ = writeln!(s, "    2. user {SERVICE_USER} (no login) and group {USERS_GROUP} when absent, {SERVICE_USER} joins {}, {placeholder_eng} joins {USERS_GROUP}; {}: {SERVICE_USER} 0700, starts empty; {}, {}: {SERVICE_USER}:{USERS_GROUP} 0750", DEVICE_GROUPS.join("/"), p.store, p.results, p.logs, placeholder_eng = placeholder.engineer);
    let _ = writeln!(s, "    3. {}: root:{USERS_GROUP} 0770", p.firmware_staging);
    let _ = writeln!(s, "    4. {} and {}: written when absent; {SERVICE_USER}:{USERS_GROUP} 0640", p.token, p.person_token);
    let _ = writeln!(s, "    5. {} install --service --bind {bind}: writes the unit with User={SERVICE_USER}", p.bin);
    let _ = writeln!(s, "    6. systemctl start {SERVICE}, wait for active, write {} (SHA-256 of {}): root 0644; print it", p.fingerprint, p.public_key);
    if agent_in_container {
        let _ = writeln!(s, "    7. (--agent-in-container) {POLKIT_RULES_DIR}/{POLKIT_RULE_FILE}: {} may start and stop {UNIT}, no other unit and no other verb", placeholder.engineer);
    } else {
        let _ = writeln!(s, "    (no --agent-in-container: {} gets no right to start or stop {UNIT}; both need root)", placeholder.engineer);
    }
    s += "  The script, as it would run:\n";
    for line in build_script(&placeholder).lines() {
        let _ = writeln!(s, "    | {line}");
    }
    s
}

/// Builds the script, runs it through `host`, parses the transcript. Returns
/// the fingerprint, or every reason it did not get one.
pub fn run_linux_half<H: Host>(host: &H, inputs: &LinInputs) -> Result<String, Vec<String>> {
    inputs.validate().map_err(|e| vec![e])?;
    let transcript = host.run_script(&build_script(inputs)).map_err(|e| vec![e])?;
    parse_transcript(&transcript, inputs.agent_in_container).map(|o| o.fingerprint)
}

/// Runs the script with `sh -s`, the script on stdin (no file for another
/// local user to swap), as the current process: the verify-and-stage half has
/// already needed root, so this is root or the step 0 check says so.
#[cfg(unix)]
pub struct RealHost;

#[cfg(unix)]
impl Host for RealHost {
    fn run_script(&self, script: &str) -> Result<String, String> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new("/bin/sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("couldn't launch /bin/sh: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("no stdin for /bin/sh")?
            .write_all(script.as_bytes())
            .map_err(|e| format!("couldn't hand the script to /bin/sh: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("/bin/sh did not finish: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if text.trim().is_empty() {
            return Err("the script printed no transcript".to_string());
        }
        println!("--- script transcript ---\n{}\n-------------------------", text.trim_end());
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::process::Command;

    fn inputs() -> LinInputs {
        LinInputs {
            version: "1.4.0".into(),
            staged_bin: "/var/lib/embarch/release-staging/3/embarch-core".into(),
            binary_sha256: "ab".repeat(32),
            engineer: "gabriel".into(),
            bind: "127.0.0.1".into(),
            agent_in_container: false,
        }
    }

    fn with_grant() -> LinInputs {
        LinInputs { agent_in_container: true, ..inputs() }
    }

    #[test]
    fn paths_are_derived_once() {
        let p = paths("1.4.0");
        assert_eq!(p.bin, "/opt/embarch/core/1.4.0/embarch-core");
        assert_eq!(p.store, "/var/lib/embarch/store");
        assert_eq!(p.firmware_staging, "/var/lib/embarch/staging");
        assert_eq!(p.fingerprint, "/var/lib/embarch/core-fingerprint");
    }

    #[test]
    fn preflight_refuses_a_foreign_store_before_anything_is_written() {
        let s = step_preflight(&inputs());
        assert!(s.contains("[ \"$(id -u)\" -eq 0 ]"));
        assert!(s.contains("id -u 'gabriel'"));
        assert!(s.contains("if [ -e '/var/lib/embarch/store' ] || [ -L '/var/lib/embarch/store' ]"));
        assert!(s.contains("owner=$(stat -c %U '/var/lib/embarch/store')"));
        assert!(s.contains("nothing was written"));
        for writer in ["install ", "useradd", "groupadd", "chown", "mkdir"] {
            assert!(!s.contains(writer), "preflight must not write: {writer}");
        }
    }

    #[test]
    fn binary_step_is_golden() {
        let s = step_binary(&inputs());
        assert!(s.contains("install -d -m 0755 -o root -g root /opt/embarch '/opt/embarch/core' '/opt/embarch/core/1.4.0'"));
        assert!(s.contains("install -m 0755 -o root -g root '/var/lib/embarch/release-staging/3/embarch-core' '/opt/embarch/core/1.4.0/embarch-core'"));
        assert!(s.contains("sha256sum '/opt/embarch/core/1.4.0/embarch-core'"));
        assert!(s.contains(&"ab".repeat(32)));
    }

    #[test]
    fn store_step_makes_the_accounts_and_an_embarch_only_store() {
        let s = step_store(&inputs());
        assert!(s.contains("groupadd --system 'embarch-users'"));
        assert!(s.contains("useradd --system --user-group --no-create-home --home-dir /nonexistent --shell \"$nologin\" 'embarch'"));
        assert!(s.contains("getent group 'dialout' >/dev/null && usermod -aG 'dialout' 'embarch' || true"));
        assert!(s.contains("getent group 'plugdev' >/dev/null && usermod -aG 'plugdev' 'embarch' || true"));
        assert!(s.contains("usermod -aG 'embarch-users' 'gabriel'"));
        assert!(s.contains("install -d -m 0755 -o root -g root '/var/lib/embarch'"));
        assert!(s.contains("install -d -m 0700 -o 'embarch' -g 'embarch' '/var/lib/embarch/store'"));
        assert!(s.contains("install -d -m 0750 -o 'embarch' -g 'embarch-users' '/var/lib/embarch/study_results'"));
        assert!(s.contains("install -d -m 0750 -o 'embarch' -g 'embarch-users' '/var/lib/embarch/logs'"));
        assert!(!s.contains("rm "), "the store is never emptied");
    }

    #[test]
    fn firmware_staging_step_is_golden() {
        let s = step_firmware_staging(&inputs());
        assert!(s.contains("install -d -m 0770 -o root -g 'embarch-users' '/var/lib/embarch/staging'"));
    }

    #[test]
    fn token_step_writes_only_when_absent_and_never_world_readable() {
        let s = step_tokens(&inputs());
        assert!(s.contains("if [ ! -e \"$t\" ]; then"));
        assert!(s.contains("(umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > \"$t\")"));
        assert!(s.contains("chown 'embarch:embarch-users' \"$t\""));
        assert!(s.contains("chmod 0640 \"$t\""));
        assert!(s.contains("'/var/lib/embarch/token' '/var/lib/embarch/person-token'"));
    }

    #[test]
    fn register_step_runs_the_installed_binary_with_the_bind() {
        let s = step_register(&inputs());
        assert!(s.contains("'/opt/embarch/core/1.4.0/embarch-core' install --service --bind '127.0.0.1'"));
        assert!(s.contains("User=embarch"));
    }

    #[test]
    fn fingerprint_step_hashes_the_raw_key_and_publishes_it_readable() {
        let s = step_start_and_fingerprint(&inputs());
        assert!(s.contains("systemctl start 'com.embarch.core'"));
        assert!(s.contains("grep -Eq '^[0-9a-f]{64}$'"));
        assert!(s.contains("sha256sum"));
        assert!(s.contains("chown root:root '/var/lib/embarch/core-fingerprint'"));
        assert!(s.contains("chmod 0644 '/var/lib/embarch/core-fingerprint'"));
        assert!(s.contains("echo \"FINGERPRINT $fp\""));
    }

    #[test]
    fn the_whole_script_runs_the_steps_in_order_and_ends_with_the_marker() {
        let s = build_script(&inputs());
        let at = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
        let marks: Vec<usize> = (0..7).map(|n| at(&format!("STEP {n} OK"))).collect();
        assert!(marks.windows(2).all(|w| w[0] < w[1]));
        assert!(at("=== done ===") > marks[6]);
        assert!(s.starts_with("#!/bin/sh"));
    }

    #[test]
    fn the_script_is_valid_sh() {
        let out = Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(build_script(&inputs()))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn the_polkit_rule_is_golden_and_names_only_start_and_stop_of_the_one_unit() {
        let rule = polkit_rule_lines("gabriel").join("\n");
        assert_eq!(
            rule,
            "// Generated by `embarch install-core --agent-in-container` (embarch-umbrella decision 72).\n\
             polkit.addRule(function(action, subject) {\n\
             \x20 if (action.id == \"org.freedesktop.systemd1.manage-units\" &&\n\
             \x20     action.lookup(\"unit\") == \"com.embarch.core.service\" &&\n\
             \x20     (action.lookup(\"verb\") == \"start\" || action.lookup(\"verb\") == \"stop\") &&\n\
             \x20     subject.user == \"gabriel\") {\n\
             \x20   return polkit.Result.YES;\n\
             \x20 }\n\
             });"
        );
        assert_eq!(rule.matches("polkit.addRule").count(), 1);
        assert_eq!(rule.matches(".service").count(), 1, "one unit");
        for other in ["restart", "reload", "enable", "disable", "edit", "set-property", "manage-unit-files", "polkit.Result.AUTH"] {
            assert!(!rule.contains(other), "{other}");
        }
    }

    #[test]
    fn the_grant_step_installs_the_rule_root_owned_and_runs_nothing_else() {
        let s = step_grant(&with_grant());
        assert!(s.contains("install -m 0644 -o root -g root \"$rule\" '/etc/polkit-1/rules.d/50-embarch-core.rules'"));
        assert!(s.contains("subject.user == \"gabriel\""));
        assert!(s.contains("echo 'STEP 7 OK grant"));
        for other in ["systemctl", "usermod", "chmod 0666", "visudo", "sudoers", "chown"] {
            assert!(!s.contains(other), "{other}");
        }
    }

    #[test]
    fn without_the_flag_the_script_has_no_grant_step_at_all() {
        let s = build_script(&inputs());
        for gone in ["polkit", "rules.d", "STEP 7", "manage-units"] {
            assert!(!s.contains(gone), "{gone} in a script built without --agent-in-container");
        }
        let g = build_script(&with_grant());
        assert!(g.find("STEP 6 OK").unwrap() < g.find("STEP 7 OK grant").unwrap());
        assert!(g.find("STEP 7 OK grant").unwrap() < g.find("=== done ===").unwrap());
    }

    #[test]
    fn the_script_with_the_grant_is_valid_sh_and_its_rule_file_comes_out_right() {
        let out = Command::new("/bin/sh").arg("-n").arg("-c").arg(build_script(&with_grant())).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // Run only the printf lines, into a temp file, and compare with the pure rule.
        let rule = std::env::temp_dir().join(format!("embarch-polkit-{}", std::process::id()));
        let printfs: String = step_grant(&with_grant())
            .lines()
            .filter(|l| l.starts_with("printf"))
            .map(|l| format!("{}\n", l.replace("\"$rule\"", &format!("'{}'", rule.display()))))
            .collect();
        let out = Command::new("/bin/sh").arg("-c").arg(printfs).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let written = std::fs::read_to_string(&rule).unwrap();
        let _ = std::fs::remove_file(&rule);
        assert_eq!(written, polkit_rule_lines("gabriel").join("\n") + "\n");
    }

    #[test]
    fn the_grant_transcript_needs_step_7() {
        let mut t = good_transcript().replace("=== done ===", "STEP 7 OK grant\n=== done ===");
        let host = Fake { reply: Ok(t.clone()), seen: RefCell::new(vec![]) };
        assert_eq!(run_linux_half(&host, &with_grant()).unwrap(), FP);
        t = good_transcript();
        let host = Fake { reply: Ok(t), seen: RefCell::new(vec![]) };
        assert!(run_linux_half(&host, &with_grant()).is_err());
    }

    /// Runs the header and the store check alone (no root, no write) against
    /// a temp path: `stat` and `test` only.
    fn run_store_check(store: &str) -> (bool, String) {
        let script = format!("{}{}{}", header(), store_check(store), "echo ok\n");
        let out = Command::new("/bin/sh").arg("-c").arg(script).output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[cfg(unix)]
    #[test]
    fn a_store_owned_by_someone_else_is_refused_and_nothing_is_written() {
        let d = std::env::temp_dir().join(format!("embarch-lin-store-{}", std::process::id()));
        let store = d.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let (ok, text) = run_store_check(store.to_str().unwrap());
        assert!(!ok);
        assert!(text.contains("FAILED: step 0 preflight: the store"), "{text}");
        assert!(text.contains("nothing was written"));
        assert_eq!(std::fs::read_dir(&store).unwrap().count(), 0);
        // a symlink is refused too, whoever it points at
        let link = d.join("link");
        std::os::unix::fs::symlink(&store, &link).unwrap();
        let (ok, text) = run_store_check(link.to_str().unwrap());
        assert!(!ok && text.contains("not a plain directory"), "{text}");
        // an absent store passes
        let (ok, text) = run_store_check(d.join("absent").to_str().unwrap());
        assert!(ok && text.contains("ok"), "{text}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn validate_refuses_what_must_not_reach_a_script() {
        let bad = |f: &dyn Fn(&mut LinInputs)| {
            let mut i = inputs();
            f(&mut i);
            assert!(i.validate().is_err());
        };
        assert!(inputs().validate().is_ok());
        bad(&|i| i.version = "../x".into());
        bad(&|i| i.version = "1.0'; rm -rf /; '".into());
        bad(&|i| i.binary_sha256 = "AB".repeat(32));
        bad(&|i| i.engineer = "root".into());
        bad(&|i| i.engineer = "embarch".into());
        bad(&|i| i.engineer = "".into());
        bad(&|i| i.engineer = "a b".into());
        bad(&|i| i.bind = "0.0.0.0; id".into());
        bad(&|i| i.staged_bin = "/tmp/it's".into());
    }

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn good_transcript() -> String {
        let mut t = String::from("=== embarch install-core: Linux half ===\n");
        for n in 0..7 {
            t += &format!("STEP {n} OK x\n");
        }
        t += &format!("FINGERPRINT {FP}\n=== done ===\n");
        t
    }

    struct Fake {
        reply: Result<String, String>,
        seen: RefCell<Vec<String>>,
    }

    impl Host for Fake {
        fn run_script(&self, script: &str) -> Result<String, String> {
            self.seen.borrow_mut().push(script.to_string());
            self.reply.clone()
        }
    }

    #[test]
    fn the_sequence_runs_the_built_script_and_returns_the_fingerprint() {
        let host = Fake { reply: Ok(good_transcript()), seen: RefCell::new(vec![]) };
        assert_eq!(run_linux_half(&host, &inputs()).unwrap(), FP);
        assert_eq!(host.seen.borrow().as_slice(), [build_script(&inputs())]);
    }

    #[test]
    fn a_failed_step_is_named_and_is_a_failure() {
        let t = "STEP 0 OK preflight\nFAILED: step 1 binary: the copied binary hashes to x\n";
        let host = Fake { reply: Ok(t.into()), seen: RefCell::new(vec![]) };
        let e = run_linux_half(&host, &inputs()).unwrap_err();
        assert!(e.iter().any(|p| p.contains("step 1 binary failed")), "{e:?}");
    }

    #[test]
    fn a_missing_transcript_is_a_failure() {
        let host = Fake { reply: Err("the script printed no transcript".into()), seen: RefCell::new(vec![]) };
        assert_eq!(run_linux_half(&host, &inputs()).unwrap_err(), vec!["the script printed no transcript".to_string()]);
    }

    #[test]
    fn bad_inputs_never_reach_the_host() {
        let host = Fake { reply: Ok(good_transcript()), seen: RefCell::new(vec![]) };
        let mut i = inputs();
        i.engineer = "root".into();
        assert!(run_linux_half(&host, &i).is_err());
        assert!(host.seen.borrow().is_empty());
    }

    #[test]
    fn the_dry_run_plan_names_every_path_and_prints_every_command() {
        let s = render_plan("127.0.0.1", None, false);
        for needle in [
            "/opt/embarch/core/<suite version>",
            "/var/lib/embarch/store",
            "/var/lib/embarch/staging",
            "/var/lib/embarch/token",
            "/var/lib/embarch/core-fingerprint",
            "embarch-users",
            "dialout/plugdev",
            "User=embarch",
            "install --service --bind '127.0.0.1'",
            "<your account>",
            "useradd --system --user-group",
            "systemctl start 'com.embarch.core'",
        ] {
            assert!(s.contains(needle), "missing {needle}");
        }
        assert!(s.contains("no --agent-in-container") && !s.contains("polkit"));
        let g = render_plan("127.0.0.1", Some("gabriel"), true);
        assert!(g.contains("7. (--agent-in-container)") && g.contains("/etc/polkit-1/rules.d/50-embarch-core.rules"));
    }
}
