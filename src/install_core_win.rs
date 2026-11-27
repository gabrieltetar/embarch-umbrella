//! The Windows half of `embarch install-core` (EMB-339, embarch-umbrella
//! decision 69): a generated PowerShell script that puts a verified Core
//! under its own account.
//!
//! Everything here is pure or runs against the small [`Host`] trait, so each
//! step of the script is golden-tested, the transcript parser is tested on
//! literals, and the sequence runs against a fake host. Nothing in this module
//! runs elevated by itself: [`RealHost`] (Windows only) asks for it.

#![cfg_attr(not(windows), allow(dead_code))]

use std::fmt::Write as _;

/// The service's name and the virtual account it runs as (Core decision 157).
pub const SERVICE: &str = "com.embarch.core";
pub const SERVICE_ACCOUNT: &str = r"NT SERVICE\com.embarch.core";
/// The end-of-script marker. Its absence is a failure, however many steps passed.
pub const DONE_MARKER: &str = "=== done ===";

/// The steps, in order: number and the name the transcript uses.
pub const STEPS: [(u8, &str); 7] = [
    (0, "preflight"),
    (1, "binary"),
    (2, "store"),
    (3, "firmware-staging"),
    (4, "tokens"),
    (5, "register"),
    (6, "start-and-fingerprint"),
];

/// The grant step, which only `--agent-in-container` adds (decision 72).
pub const GRANT_STEP: (u8, &str) = (7, "grant");
/// The service rights the grant gives the engineer, as SDDL letters
/// (decision 72): `RP` start, `WP` stop, `LC` query status. Nothing else:
/// no `DC` change config, no `WD` write DAC, no `WO` write owner.
pub const GRANT_RIGHTS: &str = "RPWPLC";

/// What the script is built from. Paths are Windows paths, as strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinInputs {
    /// `%ProgramFiles%`.
    pub program_files: String,
    /// `%ProgramData%\embarch`.
    pub data_dir: String,
    /// The suite version; it names the install folder.
    pub version: String,
    /// The verified `embarch-core.exe` inside `release-staging\<n>\`.
    pub staged_exe: String,
    /// Its SHA-256, lowercase hex, as the record holds it.
    pub binary_sha256: String,
    /// The engineer's SID, taken by the unelevated half.
    pub engineer_sid: String,
    /// `--bind` for `install --service`.
    pub bind: String,
    /// Where the elevated script logs.
    pub log: String,
    /// `--agent-in-container`: add the start-and-stop grant (decision 72).
    pub agent_in_container: bool,
}

/// Every folder and file the script writes, derived once so the plan and the
/// script cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinPaths {
    pub bin_dir: String,
    pub bin_exe: String,
    pub store: String,
    pub public_key: String,
    pub firmware_staging: String,
    pub token: String,
    pub person_token: String,
    pub fingerprint: String,
}

pub fn paths(program_files: &str, data_dir: &str, version: &str) -> WinPaths {
    let pf = program_files.trim_end_matches('\\');
    let dd = data_dir.trim_end_matches('\\');
    let bin_dir = format!(r"{pf}\EmbArch\core\{version}");
    WinPaths {
        bin_exe: format!(r"{bin_dir}\embarch-core.exe"),
        bin_dir,
        store: format!(r"{dd}\store"),
        public_key: format!(r"{dd}\store\public-key"),
        firmware_staging: format!(r"{dd}\staging"),
        token: format!(r"{dd}\token"),
        person_token: format!(r"{dd}\person-token"),
        fingerprint: format!(r"{dd}\core-fingerprint"),
    }
}

impl WinInputs {
    fn paths(&self) -> WinPaths {
        paths(&self.program_files, &self.data_dir, &self.version)
    }

    /// Refuses what must not reach a script: a version that is not a safe
    /// folder name, a hash or SID of the wrong shape, a quote anywhere.
    pub fn validate(&self) -> Result<(), String> {
        let safe = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c));
        if !safe(&self.version) {
            return Err(format!("suite version {:?} is not usable as a folder name", self.version));
        }
        let hex = self.binary_sha256.len() == 64
            && self.binary_sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        if !hex {
            return Err("the core binary's hash is not 64 lowercase hex".to_string());
        }
        if !(self.engineer_sid.starts_with("S-1-") && self.engineer_sid.chars().all(|c| c.is_ascii_digit() || c == 'S' || c == '-')) {
            return Err(format!("{:?} is not a SID", self.engineer_sid));
        }
        let bind_ok = !self.bind.is_empty() && self.bind.chars().all(|c| c.is_ascii_alphanumeric() || ".:[]-".contains(c));
        if !bind_ok {
            return Err(format!("{:?} is not a usable --bind address", self.bind));
        }
        for p in [&self.program_files, &self.data_dir, &self.staged_exe, &self.log] {
            if p.contains('\'') || p.contains('\n') {
                return Err(format!("path {p:?} holds a quote or a newline"));
            }
        }
        Ok(())
    }
}

const SID_ADMINS: &str = "*S-1-5-32-544";
const SID_SYSTEM: &str = "*S-1-5-18";
const SID_USERS: &str = "*S-1-5-32-545";

fn header(log: &str) -> String {
    r"# Generated by `embarch install-core` (embarch-umbrella decision 69).
# Runs elevated. Every step logs from inside this context; the caller reads
# the log, never this window.
$ErrorActionPreference = 'Stop'
$log = '@@LOG@@'
function Say($m) { $m | Tee-Object -FilePath $log -Append }
Set-Content -Path $log -Value '=== embarch install-core: Windows half ==='
function Grant($path, $grants) {
  $a = @($path, '/inheritance:r')
  foreach ($g in $grants) { $a += '/grant:r'; $a += $g }
  & icacls.exe @a 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw ('icacls failed on ' + $path + ' (' + $LASTEXITCODE + ')') }
}
$step = '0 preflight'
try {
"
    .replace("@@LOG@@", log)
}

const FOOTER: &str = r"} catch {
  Say ('FAILED: step ' + $step + ': ' + $_)
  exit 1
}
Say '=== done ==='
";

/// Step 0, before anything is written: the service SID, and a store that
/// exists is refused unless Administrators, SYSTEM or the service owns it.
pub fn step_preflight(i: &WinInputs) -> String {
    r"  $svcSid = ((& sc.exe showsid @@SVC@@) -join ' ') -replace '.*SERVICE SID:\s*(S-[0-9-]+).*', '$1'
  if ($svcSid -notmatch '^S-1-5-80-') { throw ('cannot work out the service SID: ' + $svcSid) }
  $store = '@@STORE@@'
  if (Test-Path -LiteralPath $store) {
    $owner = (Get-Acl -LiteralPath $store).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (@('S-1-5-32-544', 'S-1-5-18', $svcSid) -notcontains $owner) {
      throw ('the store ' + $store + ' exists and is owned by ' + $owner + ', not Administrators, SYSTEM or the service account; nothing was written')
    }
  }
  Say 'STEP 0 OK preflight'
"
    .replace("@@SVC@@", SERVICE)
    .replace("@@STORE@@", &i.paths().store)
}

/// Step 1: `<ProgramFiles>\EmbArch\core\<version>\`, Users read and execute,
/// the verified binary copied in and hashed again.
pub fn step_binary(i: &WinInputs) -> String {
    let p = i.paths();
    format!(
        "  $step = '1 binary'\n\
         \x20 New-Item -ItemType Directory -Force -Path '{dir}' | Out-Null\n\
         \x20 Grant '{dir}' @('{admins}:(OI)(CI)F', '{system}:(OI)(CI)F', '{users}:(OI)(CI)RX')\n\
         \x20 Copy-Item -LiteralPath '{staged}' -Destination '{exe}' -Force\n\
         \x20 $h = (Get-FileHash -Algorithm SHA256 -LiteralPath '{exe}').Hash.ToLower()\n\
         \x20 if ($h -ne '{sha}') {{ throw ('the copied binary hashes to ' + $h + ', not {sha}') }}\n\
         \x20 Say 'STEP 1 OK binary {exe}'\n",
        dir = p.bin_dir,
        exe = p.bin_exe,
        staged = i.staged_exe,
        sha = i.binary_sha256,
        admins = SID_ADMINS,
        system = SID_SYSTEM,
        users = SID_USERS,
    )
}

/// Step 2: the protected store, inheritance removed, the service, SYSTEM and
/// Administrators full. It starts empty and is never emptied here.
pub fn step_store(i: &WinInputs) -> String {
    format!(
        "  $step = '2 store'\n\
         \x20 New-Item -ItemType Directory -Force -Path $store | Out-Null\n\
         \x20 Grant $store @(('*' + $svcSid + ':(OI)(CI)F'), '{system}:(OI)(CI)F', '{admins}:(OI)(CI)F')\n\
         \x20 Say 'STEP 2 OK store {store}'\n",
        store = i.paths().store,
        admins = SID_ADMINS,
        system = SID_SYSTEM,
    )
}

/// Step 3: the firmware staging folder: Administrators full, the service
/// read, the engineer write.
pub fn step_firmware_staging(i: &WinInputs) -> String {
    let dir = i.paths().firmware_staging;
    format!(
        "  $step = '3 firmware-staging'\n\
         \x20 New-Item -ItemType Directory -Force -Path '{dir}' | Out-Null\n\
         \x20 Grant '{dir}' @('{admins}:(OI)(CI)F', ('*' + $svcSid + ':(OI)(CI)RX'), '*{sid}:(OI)(CI)M')\n\
         \x20 Say 'STEP 3 OK firmware-staging {dir}'\n",
        admins = SID_ADMINS,
        sid = i.engineer_sid,
    )
}

/// Step 4: both token files, written when absent (32 random bytes as 64 hex,
/// Core's shape); each grants the service and Administrators full and the
/// engineer read.
pub fn step_tokens(i: &WinInputs) -> String {
    let p = i.paths();
    format!(
        "  $step = '4 tokens'\n\
         \x20 foreach ($t in @('{token}', '{person}')) {{\n\
         \x20   if (-not (Test-Path -LiteralPath $t)) {{\n\
         \x20     $b = New-Object byte[] 32\n\
         \x20     $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider\n\
         \x20     $rng.GetBytes($b)\n\
         \x20     [System.IO.File]::WriteAllText($t, ([BitConverter]::ToString($b).Replace('-', '').ToLower()))\n\
         \x20   }}\n\
         \x20   Grant $t @(('*' + $svcSid + ':F'), '{admins}:F', '*{sid}:R')\n\
         \x20 }}\n\
         \x20 Say 'STEP 4 OK tokens'\n",
        token = p.token,
        person = p.person_token,
        admins = SID_ADMINS,
        sid = i.engineer_sid,
    )
}

/// Step 5: the installed binary registers itself under the virtual account
/// (Core decision 157). Native stderr must not terminate the script.
pub fn step_register(i: &WinInputs) -> String {
    format!(
        "  $step = '5 register'\n\
         \x20 $ErrorActionPreference = 'Continue'\n\
         \x20 & '{exe}' install --service --bind '{bind}' 2>&1 | Tee-Object -FilePath $log -Append\n\
         \x20 $code = $LASTEXITCODE\n\
         \x20 $ErrorActionPreference = 'Stop'\n\
         \x20 if ($code -ne 0) {{ throw ('install --service exited ' + $code) }}\n\
         \x20 Say 'STEP 5 OK register {account}'\n",
        exe = i.paths().bin_exe,
        bind = i.bind,
        account = SERVICE_ACCOUNT,
    )
}

/// Step 6: start, wait for `RUNNING`, read `store\public-key`, write
/// `core-fingerprint` (SHA-256 of the raw key) readable by Users, writable by
/// Administrators, and print it.
pub fn step_start_and_fingerprint(i: &WinInputs) -> String {
    let p = i.paths();
    format!(
        "  $step = '6 start-and-fingerprint'\n\
         \x20 & sc.exe start {svc} 2>&1 | Tee-Object -FilePath $log -Append\n\
         \x20 $running = $false\n\
         \x20 for ($i = 0; $i -lt 60; $i++) {{\n\
         \x20   if (((& sc.exe query {svc}) -join ' ') -match 'RUNNING') {{ $running = $true; break }}\n\
         \x20   Start-Sleep -Milliseconds 500\n\
         \x20 }}\n\
         \x20 if (-not $running) {{ throw 'the service did not reach RUNNING in 30 s' }}\n\
         \x20 $pub = '{public_key}'\n\
         \x20 for ($i = 0; $i -lt 60 -and -not (Test-Path -LiteralPath $pub); $i++) {{ Start-Sleep -Milliseconds 500 }}\n\
         \x20 if (-not (Test-Path -LiteralPath $pub)) {{ throw ('no public key at ' + $pub) }}\n\
         \x20 $hex = (Get-Content -Raw -LiteralPath $pub).Trim()\n\
         \x20 if ($hex -notmatch '^[0-9a-f]{{64}}$') {{ throw 'the public key is not 64 lowercase hex' }}\n\
         \x20 $raw = New-Object byte[] 32\n\
         \x20 for ($i = 0; $i -lt 32; $i++) {{ $raw[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }}\n\
         \x20 $fp = (([System.Security.Cryptography.SHA256]::Create().ComputeHash($raw) | ForEach-Object {{ $_.ToString('x2') }}) -join '')\n\
         \x20 [System.IO.File]::WriteAllText('{fingerprint}', $fp)\n\
         \x20 Grant '{fingerprint}' @('{admins}:F', '{users}:RX')\n\
         \x20 Say ('FINGERPRINT ' + $fp)\n\
         \x20 Say 'STEP 6 OK start-and-fingerprint'\n",
        svc = SERVICE,
        public_key = p.public_key,
        fingerprint = p.fingerprint,
        admins = SID_ADMINS,
        users = SID_USERS,
    )
}

/// The one ACE the grant adds: allow `sid` start, stop and query status.
pub fn grant_ace(sid: &str) -> String {
    format!("(A;;{GRANT_RIGHTS};;;{sid})")
}

/// The service's security descriptor with one ACE added for `sid`: start,
/// stop and query status ([`GRANT_RIGHTS`]). Text in, text out. The ACE goes
/// at the end of the DACL, before the SACL when there is one, so every other
/// ACE stays where it was and in order. A descriptor that already holds this
/// exact ACE comes back unchanged, so a second install adds nothing. A
/// descriptor with no DACL is refused: it would read as "everyone", and
/// adding an ACE would turn it into a restrictive one. The generated step 7
/// makes the same edit in PowerShell and the transcript is checked against
/// this function (decision 72).
pub fn add_start_stop_ace(sddl: &str, sid: &str) -> Result<String, String> {
    let sddl = sddl.trim();
    let ok_sid = sid.starts_with("S-1-") && sid.chars().all(|c| c.is_ascii_digit() || c == 'S' || c == '-');
    if !ok_sid {
        return Err(format!("{sid:?} is not a SID"));
    }
    let Some(d) = sddl.find("D:") else {
        return Err("the descriptor has no DACL".to_string());
    };
    let ace = grant_ace(sid);
    if sddl.contains(&ace) {
        return Ok(sddl.to_string());
    }
    let end = sddl[d..].find("S:").map_or(sddl.len(), |s| d + s);
    Ok(format!("{}{}{}", &sddl[..end], ace, &sddl[end..]))
}

/// Step 7, only with `--agent-in-container`: add the grant to the service's
/// descriptor (`sc sdshow`, edit, `sc sdset`) and print the descriptor before
/// and after, for the caller to check against [`add_start_stop_ace`].
pub fn step_grant(i: &WinInputs) -> String {
    format!(
        "  $step = '7 grant'\n\
         \x20 $sd = ((& sc.exe sdshow {svc}) | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }}) -join ''\n\
         \x20 if ($sd -notmatch '^D:') {{ throw ('cannot read the service descriptor: ' + $sd) }}\n\
         \x20 $ace = '{ace}'\n\
         \x20 $new = $sd\n\
         \x20 if (-not $sd.Contains($ace)) {{\n\
         \x20   $s = $sd.IndexOf('S:')\n\
         \x20   if ($s -ge 0) {{ $new = $sd.Substring(0, $s) + $ace + $sd.Substring($s) }} else {{ $new = $sd + $ace }}\n\
         \x20   & sc.exe sdset {svc} $new | Out-Null\n\
         \x20   if ($LASTEXITCODE -ne 0) {{ throw ('sc sdset failed (' + $LASTEXITCODE + ')') }}\n\
         \x20 }}\n\
         \x20 $after = ((& sc.exe sdshow {svc}) | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }}) -join ''\n\
         \x20 Say ('GRANT-BEFORE ' + $sd)\n\
         \x20 Say ('GRANT-AFTER ' + $after)\n\
         \x20 Say 'STEP 7 OK grant {svc}'\n",
        svc = SERVICE,
        ace = grant_ace(&i.engineer_sid),
    )
}

/// The whole script, in step order.
pub fn build_script(i: &WinInputs) -> String {
    let mut s = header(&i.log);
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

/// What `--dry-run` prints for the Windows half: the paths and the ACLs it
/// would set. The version, SID and staging number are not known before a
/// verified release exists, so they print as placeholders.
pub fn render_plan(program_files: &str, data_dir: &str, bind: &str, engineer_sid: Option<&str>, agent_in_container: bool) -> String {
    let p = paths(program_files, data_dir, "<suite version>");
    let me = engineer_sid.unwrap_or("<your SID>");
    let mut s = String::from("  Windows half (one elevated PowerShell script, logged from inside it):\n");
    let _ = writeln!(s, "    0. preflight: refuse a store that exists owned by anyone but Administrators, SYSTEM or {SERVICE_ACCOUNT}; nothing is written before this");
    let _ = writeln!(s, "    1. {}: Administrators and SYSTEM full, Users read and execute; the verified embarch-core.exe copied in from release-staging and hashed again", p.bin_dir);
    let _ = writeln!(s, "    2. {}: inheritance removed; {SERVICE_ACCOUNT}, SYSTEM and Administrators full, nobody else; starts empty", p.store);
    let _ = writeln!(s, "    3. {}: Administrators full, {SERVICE_ACCOUNT} read, {me} write", p.firmware_staging);
    let _ = writeln!(s, "    4. {} and {}: written when absent; {SERVICE_ACCOUNT} and Administrators full, {me} read", p.token, p.person_token);
    let _ = writeln!(s, "    5. {} install --service --bind {bind}: registers it under {SERVICE_ACCOUNT}", p.bin_exe);
    let _ = writeln!(s, "    6. start {SERVICE}, wait for RUNNING, write {} (SHA-256 of {}): Administrators write, Users read; print it", p.fingerprint, p.public_key);
    if agent_in_container {
        let _ = writeln!(s, "    7. (--agent-in-container) add one ACE to {SERVICE}'s security descriptor: {me} may start, stop and query status ({GRANT_RIGHTS}), never change its configuration or its security");
    } else {
        let _ = writeln!(s, "    (no --agent-in-container: {me} gets no right to start or stop {SERVICE}; both need elevation)");
    }
    s
}

/// What a transcript says: the fingerprint, or every step that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub fingerprint: String,
    /// The service descriptor before and after step 7, when the grant ran.
    pub grant: Option<(String, String)>,
}

/// Reads the elevated script's transcript. `Ok` only when the script said it
/// was done, every step reported OK, and a 64-hex fingerprint was printed;
/// otherwise each failed or silent step is named. With `grant`, step 7 must
/// also have reported OK (`--agent-in-container`); without it a step 7 line is
/// not looked for.
pub fn parse_transcript(text: &str, grant: bool) -> Result<Outcome, Vec<String>> {
    let mut problems: Vec<String> = Vec::new();
    let mut ok = [false; STEPS.len()];
    let mut failed = [false; STEPS.len()];
    let mut fingerprint = None;
    let mut done = false;
    let (mut grant_ok, mut grant_failed) = (false, false);
    let (mut before, mut after) = (None, None);
    for line in text.replace('\u{0}', "").lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("STEP ") {
            if let Some(n) = rest.split_whitespace().next().and_then(|n| n.parse::<usize>().ok()) {
                if rest.split_whitespace().nth(1) == Some("OK") && n < ok.len() {
                    ok[n] = true;
                }
                if usize::from(GRANT_STEP.0) == n && rest.split_whitespace().nth(1) == Some("OK") {
                    grant_ok = true;
                }
            }
        } else if let Some(rest) = line.strip_prefix("FAILED: step ") {
            let (head, why) = rest.split_once(": ").unwrap_or((rest, "no reason given"));
            if let Some(n) = head.split_whitespace().next().and_then(|n| n.parse::<usize>().ok()) {
                if n < failed.len() {
                    failed[n] = true;
                }
                if usize::from(GRANT_STEP.0) == n {
                    grant_failed = true;
                }
            }
            problems.push(format!("step {head} failed: {why}"));
        } else if let Some(sd) = line.strip_prefix("GRANT-BEFORE ") {
            before = Some(sd.trim().to_string());
        } else if let Some(sd) = line.strip_prefix("GRANT-AFTER ") {
            after = Some(sd.trim().to_string());
        } else if let Some(fp) = line.strip_prefix("FINGERPRINT ") {
            fingerprint = Some(fp.trim().to_string());
        } else if line == DONE_MARKER {
            done = true;
        }
    }
    for (n, name) in STEPS {
        if !ok[n as usize] && !failed[n as usize] {
            problems.push(format!("step {n} {name}: no result in the transcript"));
        }
    }
    if grant && !grant_ok && !grant_failed {
        problems.push(format!("step {} {}: no result in the transcript", GRANT_STEP.0, GRANT_STEP.1));
    }
    if !done && problems.is_empty() {
        problems.push(format!("the transcript ends without '{DONE_MARKER}'"));
    }
    match fingerprint {
        Some(fp) if fp.len() == 64 && fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) => {
            if problems.is_empty() {
                let grant = if grant { before.zip(after) } else { None };
                return Ok(Outcome { fingerprint: fp, grant });
            }
        }
        Some(_) => problems.push("the fingerprint line is not 64 lowercase hex".to_string()),
        None => problems.push("no FINGERPRINT line in the transcript".to_string()),
    }
    Err(problems)
}

/// The Windows side. `run_script` runs the script elevated and returns its
/// transcript; a missing transcript is an `Err` (decision 50's rule).
pub trait Host {
    fn run_script(&self, script: &str) -> Result<String, String>;
}

/// Builds the script, runs it through `host`, parses the transcript.
/// Returns the fingerprint, or every reason it did not get one.
pub fn run_windows_half<H: Host>(host: &H, inputs: &WinInputs) -> Result<String, Vec<String>> {
    inputs.validate().map_err(|e| vec![e])?;
    let transcript = host.run_script(&build_script(inputs)).map_err(|e| vec![e])?;
    let outcome = parse_transcript(&transcript, inputs.agent_in_container)?;
    if inputs.agent_in_container && outcome.grant.is_none() {
        return Err(vec!["step 7 grant: the transcript does not show the descriptor before and after".to_string()]);
    }
    if let Some((before, after)) = &outcome.grant {
        let want = add_start_stop_ace(before, &inputs.engineer_sid).map_err(|e| vec![e])?;
        if want != *after {
            return Err(vec![format!(
                "step 7 grant: the service descriptor after the edit is not what was asked for.\n  before: {before}\n  wanted: {want}\n  found:  {after}\n\
                 The grant may be wrong; inspect it with `sc sdshow {SERVICE}`"
            )]);
        }
    }
    Ok(outcome.fingerprint)
}

/// The engineer's SID out of `whoami /user /fo csv /nh`:
/// `"HOST\name","S-1-5-21-..."`.
pub fn parse_whoami_sid(out: &str) -> Option<String> {
    out.split('"').map(str::trim).find(|f| f.starts_with("S-1-")).map(str::to_string)
}

/// Runs the script through `powershell.exe -Verb RunAs`, reading the log it
/// wrote from inside the elevated context.
#[cfg(windows)]
pub struct RealHost {
    pub script_path: std::path::PathBuf,
    pub log_path: std::path::PathBuf,
}

#[cfg(windows)]
impl Host for RealHost {
    fn run_script(&self, script: &str) -> Result<String, String> {
        std::fs::write(&self.script_path, script)
            .map_err(|e| format!("couldn't write {}: {e}", self.script_path.display()))?;
        let _ = std::fs::remove_file(&self.log_path);
        std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Start-Process powershell -Verb RunAs -Wait -ArgumentList \
                     '-NoProfile','-ExecutionPolicy','Bypass','-File','{}'",
                    self.script_path.display()
                ),
            ])
            .status()
            .map_err(|e| format!("couldn't launch powershell.exe: {e}"))?;
        let text = std::fs::read_to_string(&self.log_path).map_err(|_| {
            format!(
                "no transcript at {} — the elevated child never started, which is what a UAC \
                 prompt that never rendered looks like. Re-run",
                self.log_path.display()
            )
        })?;
        let text = text.replace('\u{0}', "");
        println!("--- elevated transcript ---\n{}\n---------------------------", text.trim_end());
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn inputs() -> WinInputs {
        WinInputs {
            program_files: r"C:\Program Files".into(),
            data_dir: r"C:\ProgramData\embarch".into(),
            version: "1.4.0".into(),
            staged_exe: r"C:\ProgramData\embarch\release-staging\3\embarch-core.exe".into(),
            binary_sha256: "ab".repeat(32),
            engineer_sid: "S-1-5-21-1-2-3-1001".into(),
            bind: "127.0.0.1".into(),
            log: r"C:\Users\e\AppData\Local\Temp\embarch-install-core.log".into(),
            agent_in_container: false,
        }
    }

    fn with_grant() -> WinInputs {
        WinInputs { agent_in_container: true, ..inputs() }
    }

    #[test]
    fn paths_are_derived_once() {
        let p = paths(r"C:\Program Files\", r"C:\ProgramData\embarch\", "1.4.0");
        assert_eq!(p.bin_exe, r"C:\Program Files\EmbArch\core\1.4.0\embarch-core.exe");
        assert_eq!(p.store, r"C:\ProgramData\embarch\store");
        assert_eq!(p.firmware_staging, r"C:\ProgramData\embarch\staging");
        assert_eq!(p.fingerprint, r"C:\ProgramData\embarch\core-fingerprint");
    }

    #[test]
    fn preflight_reads_the_owner_before_anything_is_written() {
        let s = step_preflight(&inputs());
        assert!(s.contains(r"$store = 'C:\ProgramData\embarch\store'"));
        assert!(s.contains("sc.exe showsid com.embarch.core"));
        assert!(s.contains("@('S-1-5-32-544', 'S-1-5-18', $svcSid) -notcontains $owner"));
        assert!(s.contains("nothing was written"));
        assert!(!s.contains("New-Item") && !s.contains("Grant "));
    }

    #[test]
    fn binary_step_is_golden() {
        let s = step_binary(&inputs());
        let dir = r"C:\Program Files\EmbArch\core\1.4.0";
        assert!(s.contains(&format!("Grant '{dir}' @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')")));
        assert!(s.contains(&format!(
            r"Copy-Item -LiteralPath 'C:\ProgramData\embarch\release-staging\3\embarch-core.exe' -Destination '{dir}\embarch-core.exe' -Force"
        )));
        assert!(s.contains(&"ab".repeat(32)));
        // The ACL is set before the binary is copied in.
        assert!(s.find("Grant ").unwrap() < s.find("Copy-Item").unwrap());
    }

    #[test]
    fn store_step_grants_the_service_system_and_admins_only() {
        let s = step_store(&inputs());
        assert!(s.contains("Grant $store @(('*' + $svcSid + ':(OI)(CI)F'), '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')"));
        assert!(!s.contains("S-1-5-32-545"));
        assert!(!s.contains("S-1-5-21"));
        assert!(!s.contains("Remove-Item"), "the store starts empty and is never emptied");
    }

    #[test]
    fn firmware_staging_step_is_golden() {
        let s = step_firmware_staging(&inputs());
        let dir = r"C:\ProgramData\embarch\staging";
        assert!(s.contains(&format!(
            "Grant '{dir}' @('*S-1-5-32-544:(OI)(CI)F', ('*' + $svcSid + ':(OI)(CI)RX'), '*S-1-5-21-1-2-3-1001:(OI)(CI)M')"
        )));
        assert!(!s.contains("release-staging"));
    }

    #[test]
    fn token_step_writes_only_when_absent_and_grants_the_engineer_read() {
        let s = step_tokens(&inputs());
        assert!(s.contains(r"@('C:\ProgramData\embarch\token', 'C:\ProgramData\embarch\person-token')"));
        assert!(s.contains("if (-not (Test-Path -LiteralPath $t))"));
        assert!(s.contains("$b = New-Object byte[] 32"));
        assert!(s.contains("Grant $t @(('*' + $svcSid + ':F'), '*S-1-5-32-544:F', '*S-1-5-21-1-2-3-1001:R')"));
    }

    #[test]
    fn register_step_runs_the_installed_binary_with_the_bind() {
        let s = step_register(&inputs());
        assert!(s.contains(
            r"& 'C:\Program Files\EmbArch\core\1.4.0\embarch-core.exe' install --service --bind '127.0.0.1'"
        ));
        assert!(s.contains("$ErrorActionPreference = 'Continue'"));
        assert!(s.contains("if ($code -ne 0) { throw"));
    }

    #[test]
    fn fingerprint_step_hashes_the_raw_key_and_locks_the_file() {
        let s = step_start_and_fingerprint(&inputs());
        assert!(s.contains("sc.exe start com.embarch.core"));
        assert!(s.contains("-match 'RUNNING'"));
        assert!(s.contains(r"$pub = 'C:\ProgramData\embarch\store\public-key'"));
        assert!(s.contains("[Convert]::ToByte($hex.Substring(2 * $i, 2), 16)"));
        assert!(s.contains(r"Grant 'C:\ProgramData\embarch\core-fingerprint' @('*S-1-5-32-544:F', '*S-1-5-32-545:RX')"));
        assert!(s.contains("Say ('FINGERPRINT ' + $fp)"));
    }

    #[test]
    fn the_whole_script_runs_the_steps_in_order_and_leaves_no_token() {
        let s = build_script(&inputs());
        assert!(!s.contains("@@"), "an unreplaced placeholder");
        let at = |m: &str| s.find(m).unwrap_or_else(|| panic!("missing {m}"));
        let marks: Vec<usize> = STEPS.iter().map(|(n, name)| at(&format!("Say 'STEP {n} OK {name}"))).collect();
        assert!(marks.windows(2).all(|w| w[0] < w[1]));
        assert!(s.contains(r"$log = 'C:\Users\e\AppData\Local\Temp\embarch-install-core.log'"));
        assert!(s.contains("FAILED: step"));
        assert!(s.ends_with("Say '=== done ==='\n"));
    }

    #[test]
    fn validate_refuses_what_must_not_reach_a_script() {
        let mut i = inputs();
        i.version = "1.0'; calc".into();
        assert!(i.validate().is_err());
        let mut i = inputs();
        i.binary_sha256 = "AB".repeat(32);
        assert!(i.validate().is_err());
        let mut i = inputs();
        i.engineer_sid = "S-1-5-21'".into();
        assert!(i.validate().is_err());
        let mut i = inputs();
        i.bind = "0.0.0.0'".into();
        assert!(i.validate().is_err());
        let mut i = inputs();
        i.data_dir = "C:\\it's".into();
        assert!(i.validate().is_err());
        assert!(inputs().validate().is_ok());
    }

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn good_transcript() -> String {
        let mut t = String::from("=== embarch install-core: Windows half ===\n");
        for (n, name) in STEPS {
            if n == 6 {
                t += &format!("FINGERPRINT {FP}\n");
            }
            t += &format!("STEP {n} OK {name}\n");
        }
        t + DONE_MARKER + "\n"
    }

    #[test]
    fn a_complete_transcript_yields_the_fingerprint() {
        assert_eq!(parse_transcript(&good_transcript(), false).unwrap().fingerprint, FP);
    }

    #[test]
    fn a_failed_step_is_named_and_is_a_failure() {
        let t = "STEP 0 OK preflight\nSTEP 1 OK binary x\nFAILED: step 2 store: icacls failed on C:\\x (5)\n";
        let e = parse_transcript(t, false).unwrap_err();
        assert!(e.iter().any(|m| m == r"step 2 store failed: icacls failed on C:\x (5)"), "{e:?}");
        assert!(e.iter().any(|m| m.starts_with("step 3 firmware-staging: no result")), "{e:?}");
        assert!(!e.iter().any(|m| m.starts_with("step 0") || m.starts_with("step 1 ")), "{e:?}");
    }

    #[test]
    fn a_preflight_refusal_names_step_0() {
        let t = "FAILED: step 0 preflight: the store C:\\s exists and is owned by S-1-5-21-9, not Administrators\n";
        let e = parse_transcript(t, false).unwrap_err();
        assert!(e[0].starts_with("step 0 preflight failed: the store"), "{e:?}");
    }

    #[test]
    fn a_transcript_without_the_done_marker_is_a_failure() {
        let t = good_transcript().replace(DONE_MARKER, "");
        let e = parse_transcript(&t, false).unwrap_err();
        assert!(e.iter().any(|m| m.contains("without '=== done ==='")), "{e:?}");
    }

    #[test]
    fn a_missing_or_malformed_fingerprint_is_a_failure() {
        let no_fp = good_transcript().replace(&format!("FINGERPRINT {FP}\n"), "");
        assert!(parse_transcript(&no_fp, false).unwrap_err().iter().any(|m| m.contains("no FINGERPRINT")));
        let bad = good_transcript().replace(FP, "xyz");
        assert!(parse_transcript(&bad, false).unwrap_err().iter().any(|m| m.contains("not 64 lowercase hex")));
    }

    #[test]
    fn utf16_nuls_in_the_transcript_are_ignored() {
        let t: String = good_transcript().chars().flat_map(|c| [c, '\u{0}']).collect();
        assert!(parse_transcript(&t, false).is_ok());
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
        assert_eq!(run_windows_half(&host, &inputs()).unwrap(), FP);
        assert_eq!(host.seen.borrow().as_slice(), [build_script(&inputs())]);
    }

    #[test]
    fn a_missing_transcript_is_a_failure() {
        let host = Fake { reply: Err("no transcript at X".into()), seen: RefCell::new(vec![]) };
        assert_eq!(run_windows_half(&host, &inputs()).unwrap_err(), vec!["no transcript at X".to_string()]);
    }

    #[test]
    fn bad_inputs_never_reach_the_host() {
        let host = Fake { reply: Ok(good_transcript()), seen: RefCell::new(vec![]) };
        let mut i = inputs();
        i.version = "../x".into();
        assert!(run_windows_half(&host, &i).is_err());
        assert!(host.seen.borrow().is_empty());
    }

    /// Windows' default service descriptor shape: a DACL, then a SACL.
    const SD: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
    const SID: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn the_grant_gives_start_stop_and_query_status_and_nothing_else() {
        assert_eq!(GRANT_RIGHTS, "RPWPLC");
        assert_eq!(grant_ace(SID), "(A;;RPWPLC;;;S-1-5-21-1-2-3-1001)");
        // None of change-config (DC), write-DAC (WD), write-owner (WO), delete (SD).
        for forbidden in ["DC", "WD", "WO", "SD", "CC", "RC", "LO", "CR"] {
            let rights = GRANT_RIGHTS.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap());
            assert!(!rights.clone().any(|r| r == forbidden), "{forbidden} must not be granted");
        }
    }

    #[test]
    fn the_descriptor_edit_adds_one_ace_before_the_sacl_and_keeps_the_rest_in_order() {
        let out = add_start_stop_ace(SD, SID).unwrap();
        assert_eq!(
            out,
            "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RPWPLC;;;S-1-5-21-1-2-3-1001)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        );
        // Removing the new ACE gives back the original text exactly.
        assert_eq!(out.replace(&grant_ace(SID), ""), SD);
        assert_eq!(out.matches(&grant_ace(SID)).count(), 1);
    }

    #[test]
    fn the_descriptor_edit_without_a_sacl_appends_and_without_a_dacl_refuses() {
        assert_eq!(
            add_start_stop_ace("D:(A;;CCLCSWLOCRRC;;;IU)\r\n", SID).unwrap(),
            "D:(A;;CCLCSWLOCRRC;;;IU)(A;;RPWPLC;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            add_start_stop_ace("D:AI(A;;CCLCSWLOCRRC;;;IU)", SID).unwrap(),
            "D:AI(A;;CCLCSWLOCRRC;;;IU)(A;;RPWPLC;;;S-1-5-21-1-2-3-1001)"
        );
        assert!(add_start_stop_ace("S:(AU;FA;CC;;;WD)", SID).is_err());
        assert!(add_start_stop_ace(SD, "S-1-5-21'").is_err());
    }

    #[test]
    fn a_second_install_adds_nothing() {
        let once = add_start_stop_ace(SD, SID).unwrap();
        assert_eq!(add_start_stop_ace(&once, SID).unwrap(), once);
    }

    #[test]
    fn the_grant_step_makes_the_same_edit_and_names_nothing_else() {
        let s = step_grant(&with_grant());
        assert!(s.contains("& sc.exe sdshow com.embarch.core"));
        assert!(s.contains("$ace = '(A;;RPWPLC;;;S-1-5-21-1-2-3-1001)'"));
        assert!(s.contains("$sd.Substring(0, $s) + $ace + $sd.Substring($s)"));
        assert!(s.contains("& sc.exe sdset com.embarch.core $new"));
        assert!(s.contains("Say 'STEP 7 OK grant"));
        for other in ["sc.exe config", "sc.exe create", "sc.exe delete", "sc.exe stop", "sc.exe start"] {
            assert!(!s.contains(other), "{other}");
        }
        assert_eq!(s.matches("sc.exe sdset").count(), 1);
    }

    #[test]
    fn without_the_flag_the_script_has_no_grant_step_at_all() {
        let s = build_script(&inputs());
        for gone in ["sdset", "sdshow", "GRANT-", "STEP 7", "RPWPLC"] {
            assert!(!s.contains(gone), "{gone} in a script built without --agent-in-container");
        }
        let g = build_script(&with_grant());
        assert!(g.find("STEP 6 OK").unwrap() < g.find("STEP 7 OK grant").unwrap());
        assert!(g.find("STEP 7 OK grant").unwrap() < g.find("Say '=== done ==='").unwrap());
        assert_eq!(g.matches("sc.exe sdset").count(), 1);
    }

    fn granted_transcript(before: &str, after: &str) -> String {
        good_transcript().replace(
            DONE_MARKER,
            &format!("GRANT-BEFORE {before}\nGRANT-AFTER {after}\nSTEP 7 OK grant com.embarch.core\n{DONE_MARKER}"),
        )
    }

    #[test]
    fn a_grant_transcript_must_show_step_7_and_both_descriptors() {
        let ok = granted_transcript(SD, &add_start_stop_ace(SD, SID).unwrap());
        assert_eq!(parse_transcript(&ok, true).unwrap().grant.unwrap().0, SD);
        // Asked for a grant, the plain transcript is a failure.
        let e = parse_transcript(&good_transcript(), true).unwrap_err();
        assert!(e.iter().any(|m| m.starts_with("step 7 grant: no result")), "{e:?}");
        // Not asked for one, a step 7 line is not looked for.
        assert!(parse_transcript(&good_transcript(), false).unwrap().grant.is_none());
        let bare = good_transcript().replace(DONE_MARKER, &format!("STEP 7 OK grant\n{DONE_MARKER}"));
        assert!(parse_transcript(&bare, true).unwrap().grant.is_none());
        let host = Fake { reply: Ok(bare), seen: RefCell::new(vec![]) };
        let e = run_windows_half(&host, &with_grant()).unwrap_err();
        assert!(e[0].contains("before and after"), "{e:?}");
        let failed = good_transcript().replace(DONE_MARKER, "FAILED: step 7 grant: sc sdset failed (5)");
        let e = parse_transcript(&failed, true).unwrap_err();
        assert!(e.iter().any(|m| m.contains("step 7 grant failed")), "{e:?}");
    }

    #[test]
    fn the_sequence_checks_the_descriptor_against_the_pure_edit() {
        let right = add_start_stop_ace(SD, SID).unwrap();
        let host = Fake { reply: Ok(granted_transcript(SD, &right)), seen: RefCell::new(vec![]) };
        assert_eq!(run_windows_half(&host, &with_grant()).unwrap(), FP);
        assert_eq!(host.seen.borrow().as_slice(), [build_script(&with_grant())]);
        // A descriptor that gained something else is a failure.
        let wrong = format!("{right}(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1001)");
        let host = Fake { reply: Ok(granted_transcript(SD, &wrong)), seen: RefCell::new(vec![]) };
        let e = run_windows_half(&host, &with_grant()).unwrap_err();
        assert!(e[0].contains("not what was asked for"), "{e:?}");
    }

    #[test]
    fn the_engineer_sid_comes_out_of_whoami_csv() {
        assert_eq!(
            parse_whoami_sid("\"HOST\\gabriel\",\"S-1-5-21-1-2-3-1001\"\r\n").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(parse_whoami_sid("ERROR: nope"), None);
    }

    #[test]
    fn the_dry_run_plan_names_every_path_and_acl() {
        let s = render_plan(r"C:\Program Files", r"C:\ProgramData\embarch", "127.0.0.1", None, false);
        for needle in [
            r"C:\Program Files\EmbArch\core\<suite version>",
            r"C:\ProgramData\embarch\store",
            r"C:\ProgramData\embarch\staging",
            r"C:\ProgramData\embarch\token",
            r"C:\ProgramData\embarch\core-fingerprint",
            "NT SERVICE\\com.embarch.core",
            "Users read and execute",
            "Administrators write, Users read",
            "install --service --bind 127.0.0.1",
            "<your SID>",
        ] {
            assert!(s.contains(needle), "missing {needle}");
        }
        assert!(s.contains("no --agent-in-container") && !s.contains("7. (--agent-in-container)"));
        let g = render_plan(r"C:\Program Files", r"C:\ProgramData\embarch", "127.0.0.1", None, true);
        assert!(g.contains("7. (--agent-in-container)") && g.contains("RPWPLC"));
    }
}
