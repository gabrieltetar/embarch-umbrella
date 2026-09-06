//! `embarch doctor` — spec.md's check chain, each pass/warn/fail plus a fix
//! line for anything short of a pass.
//!
//! Ordered the same as spec.md's table, and largely dependency-ordered too:
//! checks 4/5/11/12/13/15 need check 3's winning candidate, checks 11/14/15
//! shell out to a binary check 1 located, and checks 7-9 need
//! check 6's config. When a prerequisite check didn't pass, the checks that
//! depend on it report themselves `Warn`-skipped rather than re-deriving (or
//! silently repeating) the same failure — the exit code still reflects the
//! one real failure, not N copies of it.
//!
//! **A skip always names the number it could not get and why.** That is the
//! rule check 11 was violating for months by returning a hardcoded warn whose
//! stated reason had stopped being true (decision 33).

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

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
    /// A stable machine-readable outcome, for a check whose `status` alone
    /// does not say which state it is in (decision 37). `None` — every check
    /// but 10 today — renders as JSON `null` rather than being omitted, so
    /// the key is always present and a consumer never has to distinguish
    /// "absent" from "no code".
    ///
    /// **Never derived from `detail`.** The whole point is that a consumer
    /// does not have to match on a sentence written for a human.
    pub code: Option<&'static str>,
}

fn check(n: u8, name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        n,
        name,
        status,
        detail: detail.into(),
        fix: None,
        code: None,
    }
}

fn with_code(mut c: Check, code: &'static str) -> Check {
    c.code = Some(code);
    c
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
/// Which machine Core belongs to, for the two checks that must not demand a
/// local `embarch-core` where none belongs (decision 38). Only ever consulted
/// when no binary could be located at all, which is what makes the WSL2 arm
/// safe: decision 30's mirrored-networking ambiguity means a `local` winner
/// under WSL2 says "something answered at loopback", not "Core is in the
/// guest" — and a guest-local Core that `setup` installed would have been
/// located on `PATH` before this was asked.
fn core_belongs_to(winner: Option<TopologyClass>, host: Option<&str>, under_wsl2: bool) -> TopologyClass {
    match winner {
        Some(TopologyClass::Remote) => TopologyClass::Remote,
        _ if host.is_some() => TopologyClass::Remote,
        _ if under_wsl2 => TopologyClass::WslHost,
        Some(class) => class,
        None => TopologyClass::Local,
    }
}

fn check_binaries(
    core: Option<&Located>,
    api: Option<&Located>,
    c_ver: Option<&str>,
    a_ver: Option<&str>,
    class: TopologyClass,
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
                None => with_code(
                    check(
                        1,
                        "binaries found",
                        Status::Pass,
                        format!(
                            "{found}. No suite manifest next to this binary — either not installed from a \
                             suite archive (milestone-6.md §3.7), or a per-repo/debug build; \
                             version-vs-manifest comparison skipped."
                        ),
                    ),
                    "no-manifest",
                ),
                Some(m) => {
                    // The manifest describes the archive *this* binary came
                    // from. On `wsl-host` that is a Linux archive and Core is a
                    // Windows exe out of a different one, so the manifest has
                    // nothing to say about it and saying it anyway would be a
                    // confident verdict about the wrong artifact (decision 38).
                    let cross_target_core = c.windows_exe_from_wsl2 && !m.target.contains("windows");
                    let compared_core = if cross_target_core { None } else { c_ver };
                    let note = if cross_target_core {
                        format!(
                            " embarch-core is a Windows build and this manifest is the {} one; check 15 \
                             compares it against the running Core instead.",
                            if m.target.is_empty() { "untargeted" } else { &m.target }
                        )
                    } else {
                        String::new()
                    };
                    let mismatches = manifest_mismatches(&m, compared_core, a_ver);
                    if mismatches.is_empty() {
                        with_code(
                            check(
                                1,
                                "binaries found",
                                Status::Pass,
                                format!(
                                    "{found}. Matches suite manifest v{} ({}).{note}",
                                    m.suite_version, m.target
                                ),
                            ),
                            if cross_target_core { "manifest-partial" } else { "manifest-match" },
                        )
                    } else {
                        with_code(
                            with_fix(
                                check(
                                    1,
                                    "binaries found",
                                    Status::Fail,
                                    format!(
                                        "{found}. Suite manifest v{} mismatch: {}.{note}",
                                        m.suite_version,
                                        mismatches.join("; ")
                                    ),
                                ),
                                "reinstall from a matching suite archive, so all three binaries come from the \
                                 same release",
                            ),
                            "manifest-mismatch",
                        )
                    }
                }
            }
        }
        // Decision 38: on `wsl-host` and `remote` there is no local
        // `embarch-core` to expect, and `setup` already treats its absence as
        // correct. Reporting it as a Fail made the first line of the first live
        // `doctor` run a false red on a healthy machine.
        (None, Some(_)) if class != TopologyClass::Local => with_code(
            with_fix(
                check(
                    1,
                    "binaries found",
                    Status::Warn,
                    format!(
                        "embarch-api: {}; no embarch-core on this machine, which is correct for \
                         topology `{}` — Core's binary lives {}. Checks 14 and 15 cannot ask it \
                         anything, and say so.",
                        api.map(|a| a.path.display().to_string()).unwrap_or_default(),
                        class.as_str(),
                        if class == TopologyClass::Remote {
                            "on the machine running it"
                        } else {
                            "on the Windows side, and its service registration could not be read"
                        },
                    ),
                ),
                "nothing to fix unless checks 14 and 15 are wanted: point EMBARCH_CORE_EXE at the \
                 exe this machine's Core runs (on wsl-host, its /mnt/c path)",
            ),
            "core-not-local",
        ),
        _ => with_code(
            with_fix(
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
            "not-found",
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

/// Where a Linux kernel exposes one directory per enumerated USB device, each
/// with a world-readable `idVendor`. **Reading it needs no permission at all**,
/// which is the whole reason this check can see a probe the enumeration could
/// not open (decision 18): sysfs attributes are readable by anyone, while
/// `/dev/bus/usb/...` is the node a udev rule has to grant.
const SYSFS_USB_DEVICES: &str = "/sys/bus/usb/devices";

/// USB vendor IDs, lowercase hex as sysfs writes them, that mean "this is a
/// debug probe" strongly enough to turn a zero-probe warn into a fail.
///
/// **Deliberately not here: `0403` (FTDI).** Several JTAG adapters use it, and
/// so does every third USB-serial cable on the bench — including the outpost
/// link and the dev-bench console. A vendor ID that is a debug probe *some* of
/// the time would make this check fail on a machine with no probe at all,
/// which is worse than the warn it replaces.
const DEBUG_PROBE_VENDOR_IDS: &[(&str, &str)] = &[
    ("1366", "SEGGER — J-Link, including the on-board J-Link on every Nordic DK"),
    ("0d28", "ARM CMSIS-DAP / DAPLink"),
    ("0483", "STMicroelectronics — ST-Link"),
    ("1fc9", "NXP — LPC-Link2"),
    ("03eb", "Microchip/Atmel — EDBG, Atmel-ICE"),
    ("2e8a", "Raspberry Pi — Debug Probe"),
    ("1d50", "OpenMoko-assigned — Black Magic Probe"),
    ("0451", "Texas Instruments — XDS110"),
    ("c251", "Keil — ULINK"),
];

/// One USB device whose vendor ID is on the list above.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsbProbeHit {
    vendor_id: String,
    /// What `DEBUG_PROBE_VENDOR_IDS` calls that vendor.
    vendor: &'static str,
    /// The kernel's `product` string, when the device published one. Purely
    /// for the message — the verdict never depends on it.
    product: Option<String>,
}

/// What the USB device tree was able to say, which is not the same question as
/// what it holds. **Both "there is no probe" and "nobody could look" end in the
/// same warn today**, and the two have to stay distinguishable in `--json`
/// (decision 37) or a UI cannot tell a clean machine from an unanswerable one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UsbScan {
    /// Not a Linux host. macOS and Windows do not have this permission model,
    /// so decision 18 leaves their behaviour exactly as it was.
    NotLinux,
    /// Linux, but Core enumerates probes on a *different* machine — `wsl-host`
    /// or `remote`. Scanning this host's USB tree would answer confidently
    /// about the wrong computer, which is check 14's mistake (decision 31)
    /// repeated with a different peripheral.
    CoreElsewhere,
    /// Linux, Core on this machine: every device on the bus whose vendor ID is
    /// a known debug-probe vendor.
    Scanned(Vec<UsbProbeHit>),
}

/// Decides whether the scan can mean anything before running it. `cfg!` rather
/// than `#[cfg]` so the scanner and every branch below compile — and are
/// tested — on all three hosts.
fn usb_scan_for(class: Option<TopologyClass>) -> UsbScan {
    if !cfg!(target_os = "linux") {
        return UsbScan::NotLinux;
    }
    match class {
        Some(TopologyClass::Local) => {
            UsbScan::Scanned(scan_usb_debug_probes(Path::new(SYSFS_USB_DEVICES)))
        }
        _ => UsbScan::CoreElsewhere,
    }
}

/// Reads `<devices>/*/idVendor`. Interface directories (`1-2:1.0`) carry no
/// `idVendor`, so they drop out by failing the read rather than by a name
/// rule; a missing tree reads as an empty bus, never as an error, because a
/// diagnostic that fails to diagnose must not fail the run.
fn scan_usb_debug_probes(devices: &Path) -> Vec<UsbProbeHit> {
    let Ok(entries) = std::fs::read_dir(devices) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(raw) = std::fs::read_to_string(dir.join("idVendor")) else {
            continue;
        };
        let vendor_id = raw.trim().to_ascii_lowercase();
        let Some((_, vendor)) = DEBUG_PROBE_VENDOR_IDS.iter().find(|(id, _)| *id == vendor_id)
        else {
            continue;
        };
        let product = std::fs::read_to_string(dir.join("product"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        hits.push(UsbProbeHit { vendor_id, vendor, product });
    }
    hits.sort_by(|a, b| (&a.vendor_id, &a.product).cmp(&(&b.vendor_id, &b.product)));
    hits.dedup();
    hits
}

fn describe_hit(hit: &UsbProbeHit) -> String {
    match &hit.product {
        Some(p) => format!("{p} ({}, {})", hit.vendor_id, hit.vendor),
        None => format!("{} ({})", hit.vendor_id, hit.vendor),
    }
}

const CHECK_5_NAME: &str = "at least one debug probe visible";

fn check_probes(authed: Option<&AuthedStatus>, scan: &UsbScan) -> Check {
    let Some(a) = authed else {
        return with_code(
            check(5, CHECK_5_NAME, Status::Warn, "skipped — no authenticated status (see check 4)"),
            "no-status",
        );
    };
    if !a.probes.is_empty() {
        return with_code(
            check(5, CHECK_5_NAME, Status::Pass, format!("{} probe(s)", a.probes.len())),
            "probes-present",
        );
    }
    match scan {
        UsbScan::Scanned(hits) if !hits.is_empty() => {
            let listed = hits.iter().map(describe_hit).collect::<Vec<_>>().join("; ");
            with_code(
                with_fix(
                    check(
                        5,
                        CHECK_5_NAME,
                        Status::Fail,
                        format!(
                            "Core enumerated no probes, but this machine's USB bus holds {}. \
                             Attached and not permitted, not unplugged.",
                            listed
                        ),
                    ),
                    "the current user can't open the probe's USB node. Install debug-probe udev \
                     rules into /etc/udev/rules.d/ (probe-rs ships 69-probe-rs.rules), then \
                     `sudo udevadm control --reload && sudo udevadm trigger`, and unplug and \
                     re-plug the probe. Nothing here can grant that permission for you.",
                ),
                "probe-not-permitted",
            )
        }
        UsbScan::Scanned(_) => with_code(
            check(
                5,
                CHECK_5_NAME,
                Status::Warn,
                "no probes reported, and no known debug-probe vendor ID on this machine's USB bus \
                 either — genuinely nothing plugged in",
            ),
            "no-probe-found",
        ),
        UsbScan::NotLinux => with_code(
            check(5, CHECK_5_NAME, Status::Warn, "no probes reported — fine if none is plugged in right now"),
            "no-probe-unchecked",
        ),
        UsbScan::CoreElsewhere => with_code(
            check(
                5,
                CHECK_5_NAME,
                Status::Warn,
                "no probes reported — fine if none is plugged in right now. Core enumerates on \
                 another machine, so this host's USB bus can't tell attached-but-not-permitted \
                 apart from unplugged.",
            ),
            "no-probe-unchecked",
        ),
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

// ---- check 10: the MCP server is registered *and* answers --------------------

const MCP_SERVER_NAME: &str = "embarch";

/// How long the registered command gets to come up and answer one
/// `initialize`. Short on purpose: `doctor` is already the heavy command
/// (decision 11), and a server that needs longer than this to say hello is a
/// finding rather than a slow success. Measured against nothing — this is an
/// assumed budget, and the timeout outcome is reported distinctly (decision
/// 23) precisely so a wrong budget shows up as itself instead of as a failure.
const MCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The MCP protocol revision this handshake asks for. A server that speaks a
/// different one is expected to answer with the revision it does speak rather
/// than to error, so this number being stale is not by itself a failure —
/// what the check reads is whether a well-formed `result` came back at all.
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Cap on captured stderr, so a server that fails by printing forever cannot
/// grow `doctor`'s output without bound.
const MCP_STDERR_CAP: usize = 2000;

/// What `claude mcp get` said, in the four shapes that lead to different
/// verdicts. Separated from the verdict so the parse is testable without a
/// `claude` CLI on the machine running the tests.
#[derive(Debug, PartialEq, Eq)]
enum McpRegistration {
    /// No `claude` on `PATH` at all. Not a fault: `doctor` runs on machines
    /// that never registered anything.
    NoCli,
    /// `claude mcp get` exited non-zero — nothing is registered under this name.
    NotRegistered,
    /// Registered, and the entry named a command this check can spawn.
    Registered { command: String, args: Vec<String> },
    /// Registered, but nothing in the output looked like a command line.
    /// **Its own verdict, not a pass**: this check's whole reason for existing
    /// is that a registration entry proves nothing, so falling back to "well,
    /// it's registered" would be the bug decision 23 was written against.
    UnreadableEntry,
}

/// What one spawn of the registered command did. Three outcomes, kept apart
/// all the way into `--json` (decision 23, decision 37).
#[derive(Debug, PartialEq, Eq)]
enum HandshakeOutcome {
    /// A JSON-RPC `result` came back for our `initialize`. The string is
    /// whatever the server called itself, when it said.
    Answered(String),
    /// It never started, exited first, or answered an `error`.
    Failed(String),
    /// It started and said nothing in time.
    TimedOut,
}

/// Pull the command line out of `claude mcp get <name>`'s human output.
///
/// **The shape here is assumed, not measured** — see `open.md`: no walk of the
/// onboarding guide has yet run from an environment with the agent CLI
/// present, so nothing in this suite has ever seen this output for real. That
/// is why an output this cannot read is [`McpRegistration::UnreadableEntry`]
/// and a warn naming the reason, rather than either a pass or a fail: a
/// wrong guess here must not be able to invent a verdict about the server.
fn parse_registered_command(out: &str) -> Option<(String, Vec<String>)> {
    let field = |label: &str| {
        out.lines().find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(label)?.strip_prefix(':')?;
            Some(rest.trim().to_string())
        })
    };

    let command = field("Command").filter(|c| !c.is_empty())?;
    let args = field("Args").map(|a| split_args(&a)).unwrap_or_default();
    Some((command, args))
}

/// Split an argument line on whitespace, honouring double quotes so a config
/// path with a space in it survives — which on Windows is the common case,
/// not the exotic one.
fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut started = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        args.push(cur);
    }
    args
}

fn mcp_registration() -> McpRegistration {
    match Command::new("claude").args(["mcp", "get", MCP_SERVER_NAME]).output() {
        Ok(o) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout);
            match parse_registered_command(&out) {
                Some((command, args)) => McpRegistration::Registered { command, args },
                None => McpRegistration::UnreadableEntry,
            }
        }
        Ok(_) => McpRegistration::NotRegistered,
        Err(_) => McpRegistration::NoCli,
    }
}

/// Spawn `command` and complete one JSON-RPC `initialize` round trip over its
/// stdio, giving up after `timeout`.
///
/// **A hand-rolled one-shot exchange, deliberately not an MCP client**
/// (decision 23): one request, one matching response, no session kept. The
/// process is killed either way — this check starts a server it has no
/// intention of using.
fn mcp_initialize(command: &str, args: &[String], timeout: Duration) -> HandshakeOutcome {
    let mut child = match Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return HandshakeOutcome::Failed(format!("couldn't start `{command}`: {e}")),
    };

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "embarch-doctor", "version": env!("CARGO_PKG_VERSION") },
        },
    })
    .to_string();

    let mut stdin = child.stdin.take().expect("stdin piped");
    let stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    // Drained on its own thread rather than read at the end: a server that
    // fails by logging can fill the pipe buffer and block on the write, which
    // would turn every noisy failure into a timeout.
    let (err_tx, err_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf.truncate(MCP_STDERR_CAP);
        let _ = err_tx.send(String::from_utf8_lossy(&buf).trim().to_string());
    });

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // `stdin` is moved in and held until this thread ends, so the server
        // does not see EOF — an MCP server reads stdin for the life of the
        // session, and closing it is a shutdown signal, not a flush.
        //
        // **A broken pipe here is not the finding.** A server that dies on its
        // own arguments is gone before this write lands, and reporting
        // "couldn't write to its stdin" would name the symptom while the
        // reason — its own stderr, and the fact that it exited — is one line
        // away. So EPIPE falls through into the read loop, which sees EOF and
        // reports the exit. It also made this racy: whether the write beat the
        // exit decided which of two messages came out.
        if let Err(e) = writeln!(stdin, "{request}").and_then(|()| stdin.flush()) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                let _ = tx.send(HandshakeOutcome::Failed(format!("couldn't write to its stdin: {e}")));
                return;
            }
        }

        let mut saw_output = false;
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            saw_output = true;
            // Anything that is not our answer — a log line, a notification,
            // a banner — is skipped rather than read as a failure.
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            if v.get("id").and_then(|i| i.as_u64()) != Some(1) {
                continue;
            }
            let outcome = if let Some(result) = v.get("result") {
                let name = result
                    .get("serverInfo")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("no serverInfo");
                HandshakeOutcome::Answered(name.to_string())
            } else if let Some(err) = v.get("error") {
                HandshakeOutcome::Failed(format!("it answered a JSON-RPC error: {err}"))
            } else {
                HandshakeOutcome::Failed("it answered without a result or an error".to_string())
            };
            let _ = tx.send(outcome);
            return;
        }

        let _ = tx.send(HandshakeOutcome::Failed(if saw_output {
            "it exited without answering initialize".to_string()
        } else {
            "it exited without saying anything".to_string()
        }));
    });

    let outcome = rx.recv_timeout(timeout);
    // Killed either way: on success there is a live server we do not want, and
    // on a timeout killing it is also what unblocks the reader thread on EOF.
    let _ = child.kill();
    let _ = child.wait();

    match outcome {
        Ok(HandshakeOutcome::Failed(why)) => {
            let stderr = err_rx.recv_timeout(Duration::from_millis(500)).unwrap_or_default();
            HandshakeOutcome::Failed(if stderr.is_empty() {
                why
            } else {
                format!("{why} — stderr: {}", stderr.replace('\n', " / "))
            })
        }
        Ok(other) => other,
        Err(_) => HandshakeOutcome::TimedOut,
    }
}

/// The verdict, split out from both the `claude` call and the spawn so the
/// mapping is testable on its own.
fn judge_mcp(reg: &McpRegistration, handshake: Option<&HandshakeOutcome>, register_fix: &str) -> Check {
    const NAME: &str = "MCP server registered and answering";

    match (reg, handshake) {
        (McpRegistration::NoCli, _) => with_code(
            with_fix(
                check(10, NAME, Status::Warn, "claude CLI not found here — can't verify"),
                register_fix.to_string(),
            ),
            "no-cli",
        ),
        (McpRegistration::NotRegistered, _) => with_code(
            with_fix(check(10, NAME, Status::Fail, "not registered"), register_fix.to_string()),
            "not-registered",
        ),
        (McpRegistration::UnreadableEntry, _) => with_code(
            with_fix(
                check(
                    10,
                    NAME,
                    Status::Warn,
                    "registered, but `claude mcp get` named no command to spawn — can't handshake",
                ),
                format!("re-register it so the entry names the binary: {register_fix}"),
            ),
            "unreadable-entry",
        ),
        (McpRegistration::Registered { command, args }, outcome) => {
            let line = || {
                std::iter::once(command.clone())
                    .chain(args.iter().cloned())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            match outcome {
                // Only reachable if a caller forgets to run the handshake;
                // reported as itself rather than defaulting to a pass.
                None => with_code(
                    check(10, NAME, Status::Warn, "registered; handshake not attempted"),
                    "no-handshake",
                ),
                Some(HandshakeOutcome::Answered(server)) => with_code(
                    check(10, NAME, Status::Pass, format!("registered, and it answered initialize ({server})")),
                    "handshake-ok",
                ),
                Some(HandshakeOutcome::Failed(why)) => with_code(
                    with_fix(
                        check(10, NAME, Status::Fail, format!("registered, but the handshake failed — {why}")),
                        format!(
                            "the registration exists and the command behind it is broken, so re-adding it fixes \
                             nothing on its own. Run `{}` by hand to see why; if the binary moved, re-register: {register_fix}",
                            line()
                        ),
                    ),
                    "handshake-failed",
                ),
                Some(HandshakeOutcome::TimedOut) => with_code(
                    with_fix(
                        check(
                            10,
                            NAME,
                            Status::Fail,
                            format!(
                                "registered, but it answered nothing within {}s",
                                MCP_HANDSHAKE_TIMEOUT.as_secs()
                            ),
                        ),
                        format!(
                            "run `{}` by hand and send it an initialize — it started, so this is the server \
                             hanging rather than a missing registration",
                            line()
                        ),
                    ),
                    "handshake-timeout",
                ),
            }
        }
    }
}

fn check_mcp(config_path: Option<&Path>, api: Option<&Located>) -> Check {
    let register_fix = format!(
        "claude mcp add {MCP_SERVER_NAME} -- {} --config {}",
        api.map(|a| a.path.display().to_string()).unwrap_or_else(|| "<path to embarch-api>".to_string()),
        config_path.map(|p| p.display().to_string()).unwrap_or_else(|| "<repo>/embarch/embarch.toml".to_string()),
    );

    let reg = mcp_registration();
    let handshake = match &reg {
        McpRegistration::Registered { command, args } => {
            Some(mcp_initialize(command, args, MCP_HANDSHAKE_TIMEOUT))
        }
        _ => None,
    };
    judge_mcp(&reg, handshake.as_ref(), &register_fix)
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
/// the numbers injected, without a live Core, a bench, or an `embarch-api` on
/// disk (decisions 33, 35).
struct SchemaVersions<'a> {
    /// `/status`'s `study_designer_schema_version`: the host-type constant
    /// **the deployed Core** was built against.
    core_host: Result<u32, &'a str>,
    /// `host_type_schema_version` off the **located `embarch-api`**'s
    /// `--json versions` object (`embarch-api` decision 52) — the constant
    /// compiled into the binary that actually submits studies, and therefore
    /// the number this hop turns on.
    ///
    /// Fallible, and deliberately **not** defaulted to `umbrella_host` when it
    /// cannot be obtained: "could not ask `embarch-api`" is a different
    /// verdict from "they disagree", and a silent fallback would report a
    /// clean pass on exactly the mixed install this check exists to catch
    /// (decision 35).
    api_host: Result<u32, String>,
    /// `HOST_TYPE_SCHEMA_VERSION` as compiled into **this** binary. Always
    /// available — it is a compile-time constant of the binary doing the
    /// asking — but never the number the study hop turns on, because `embarch`
    /// submits no studies. Kept as a fourth number because disagreeing with
    /// `api_host` *is* a mixed install, and nothing else here notices one on a
    /// hand-built machine with no suite manifest for check 1 to read
    /// (decision 36).
    umbrella_host: u32,
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
/// - `core_host` versus `api_host` is the `embarch-api` <-> `embarch-core`
///   hop, the one `embarch-api` itself refuses to submit a `Study` across
///   (`embarch-core-client`). A difference is a **fail**: the pair on this
///   machine cannot run a study at all. Both sides are now the real
///   binaries' own numbers — Core's served one, and the located
///   `embarch-api`'s compiled one (decision 35).
/// - `api_host` versus `umbrella_host` is a **different question**: whether
///   the two halves of this install came from one build. A difference blocks
///   no study, because `embarch` never submits one, so it is a **warn** with
///   the same reinstall fix check 1 gives (decision 36).
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

    match (&v.core_host, &v.api_host) {
        (Ok(core), Ok(api)) => {
            parts.push(format!(
                "host type: Core serves v{core}, the located embarch-api was built against v{api}"
            ));
            if core != api {
                degrade(Status::Fail, &mut worst);
                fixes.push(
                    "the deployed Core and the located embarch-api were built against different \
                     embarch-study-designer host types — embarch-api will refuse to submit a study. \
                     Redeploy Core from this build (`embarch deploy-core`), or reinstall the suite \
                     archive that matches the deployed Core."
                        .to_string(),
                );
            }
        }
        (Err(why), Ok(api)) => {
            parts.push(format!(
                "host type: Core's version unavailable — {why}; the located embarch-api was built \
                 against v{api}"
            ));
            degrade(Status::Warn, &mut worst);
        }
        (Ok(core), Err(why)) => {
            parts.push(format!(
                "host type: Core serves v{core}, but the located embarch-api could not be asked — \
                 {why}"
            ));
            degrade(Status::Warn, &mut worst);
        }
        (Err(core_why), Err(api_why)) => {
            parts.push(format!(
                "host type: neither number is available — Core: {core_why}; embarch-api: {api_why}"
            ));
            degrade(Status::Warn, &mut worst);
        }
    }

    // The fourth number, and the only one that is free: this binary's own
    // compiled constant (decision 36). It settles nothing about running a
    // study — `embarch` submits none — so it never fails the check; what it
    // catches is `embarch` and `embarch-api` having come from two different
    // builds, which on a machine with no suite manifest nothing else here
    // would notice.
    match &v.api_host {
        Ok(api) if *api != v.umbrella_host => {
            parts.push(format!(
                "mixed install: this embarch was itself built against v{}, and it just located an \
                 embarch-api built against v{api}",
                v.umbrella_host
            ));
            degrade(Status::Warn, &mut worst);
            fixes.push(
                "embarch and embarch-api on this machine came from different builds. Reinstall \
                 both from one suite archive (check 1 compares all three against its manifest, \
                 where there is one). Nothing here blocks a study: embarch submits none, and it is \
                 embarch-api's number above that the study hop turns on."
                    .to_string(),
            );
        }
        Ok(_) => parts.push(format!("this embarch agrees at v{}", v.umbrella_host)),
        Err(_) => parts.push(format!(
            "this embarch was itself built against v{} — context only, and not a stand-in for the \
             number that could not be read",
            v.umbrella_host
        )),
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

/// Read `host_type_schema_version` out of what `embarch-api --json versions`
/// printed, or say why there is no number in it.
///
/// Split from the spawn so every failure shape — an `embarch-api` too old to
/// know the subcommand, one that printed something else, one that answered
/// without the field — is testable with no binary on disk (decision 35).
fn api_host_from_output(exit_code: Option<i32>, ok: bool, stdout: &str) -> Result<u32, String> {
    if !ok {
        // `versions` reads compiled constants and always exits 0
        // (`embarch-api` decision 52), so a non-zero exit is not this surface
        // answering. Clap exits 2 on a subcommand it does not know, which is
        // precisely an embarch-api predating that decision — the same
        // "warn naming what it predates" check 14 gives an older Core.
        return Err(match exit_code {
            Some(2) => "the located embarch-api has no `versions` subcommand (clap exited 2) — it \
                        predates embarch-api decision 52"
                .to_string(),
            Some(code) => format!(
                "`embarch-api --json versions` exited {code}, and it is a surface that always exits 0"
            ),
            None => "`embarch-api --json versions` was killed by a signal".to_string(),
        });
    }
    let parsed = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .map_err(|e| format!("`embarch-api --json versions` printed no JSON object ({e})"))?;
    parsed
        .get("host_type_schema_version")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            "`embarch-api --json versions` answered without a `host_type_schema_version`".to_string()
        })
}

/// Ask the **located** `embarch-api` which `embarch-study-designer` host type
/// schema version it compiled.
///
/// Same reasoning as check 14's shell-out: the number wanted is a fact about a
/// *different binary*, and only that binary can state it. `versions` loads no
/// config and contacts no Core precisely so it still answers on a machine
/// whose config or Core is the thing being diagnosed (`embarch-api`
/// decision 52).
///
/// **`--json` goes before the subcommand.** It is a flag on `embarch-api`'s
/// top-level parser and is not `global`, so `embarch-api versions --json`
/// exits 2 with `unexpected argument '--json' found` [verified 2026-09-04
/// against a local build] — which this function would then report as an
/// embarch-api too old to know the subcommand.
fn api_host_schema_version(api: Option<&Located>) -> Result<u32, String> {
    let Some(api) = api else {
        return Err("embarch-api not located (see check 1)".to_string());
    };
    match Command::new(&api.path).args(["--json", "versions"]).output() {
        Ok(o) => api_host_from_output(
            o.status.code(),
            o.status.success(),
            &String::from_utf8_lossy(&o.stdout),
        ),
        Err(e) => Err(format!("couldn't run `{} --json versions`: {e}", api.path.display())),
    }
}

fn check_schema_versions(
    authed: Option<&AuthedStatus>,
    hello: &HelloOutcome,
    api: Option<&Located>,
) -> Check {
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
        api_host: api_host_schema_version(api),
        umbrella_host: embarch_study_designer::HOST_TYPE_SCHEMA_VERSION,
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

// ---- check 16: what grows, and by how much ----------------------------------

/// `study_results/` usage, as `doctor` measures it.
struct ResultsUsage {
    entries: usize,
    bytes: u64,
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Count `study_results/<study_id>/` entries and the bytes under them.
/// `None` means the directory does not exist — a machine that has never run
/// a study, which is a state and not a failure.
fn measure_results(dir: &Path) -> Option<ResultsUsage> {
    let read = std::fs::read_dir(dir).ok()?;
    let mut usage = ResultsUsage { entries: 0, bytes: 0 };
    for entry in read.flatten() {
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            usage.entries += 1;
            usage.bytes += dir_bytes(&entry.path(), 0);
        }
    }
    Some(usage)
}

/// Sum of regular-file sizes under `dir`.
///
/// **`DirEntry::file_type` does not follow symlinks**, so a link into a
/// parent is neither descended into nor counted as a file — a `doctor` check
/// must not be the thing that spins forever on somebody's stray symlink. The
/// depth cap is the second belt: `study_results/<id>/streams/<file>` is three
/// levels, so six is slack rather than a real limit.
fn dir_bytes(dir: &Path, depth: usize) -> u64 {
    const MAX_DEPTH: usize = 6;
    if depth > MAX_DEPTH {
        return 0;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for entry in read.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() {
            total += dir_bytes(&entry.path(), depth + 1);
        } else if kind.is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

/// How many per-target build directories exist under a project's
/// `build_dir_root`. `None` means the root does not exist yet.
fn count_build_dirs(root: &Path) -> Option<usize> {
    let read = std::fs::read_dir(root).ok()?;
    Some(
        read.flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .count(),
    )
}

/// Check 16 — decision 26's unconditional half, and **only** that half.
///
/// It measures and never deletes. Two separate reasons, worth keeping apart:
///
/// - **`study_results/` retention is not this crate's**, and stopped being an
///   open problem when `embarch-core` shipped `sweep_study_results` /
///   `EMBARCH_STUDY_RESULTS_KEEP`. What is left for `doctor` is that the
///   sweep is a *count*, so the bytes behind those 50 runs are still nobody's
///   bound — which is exactly the number this reports.
/// - **Nothing here can name a valid build directory**, only count
///   directories. `crate::zephyr` counts targets and deliberately overcounts
///   (decision 17's amendment); naming them is `embarch-api list-targets`'s,
///   which this crate does not yet call. Deleting on an oracle this crate
///   does not have is what decision 26's "never a currently-valid target's
///   directory" clause exists to prevent.
fn check_growth(
    winner: Option<TopologyClass>,
    fallback: TopologyClass,
    projects: &[ProjectConfig],
) -> Check {
    let (class, assumed) = match winner {
        Some(c) => (c, false),
        None => (fallback, true),
    };
    let dir = setup::data_dir_for(class, cfg!(windows)).map(|d| d.join("study_results"));
    let note = match (class, &dir) {
        (TopologyClass::Remote, _) => {
            "study_results/ is on the remote Core's machine and can't be measured from here"
                .to_string()
        }
        (_, None) => format!("no data directory resolves for a {} Core here", class.as_str()),
        (_, Some(_)) if assumed => format!(
            "assuming a {} Core — check 3 found no winner to ask",
            class.as_str()
        ),
        _ => String::new(),
    };
    judge_growth(dir.as_deref(), &note, projects)
}

/// The pure half of check 16, so every test can hand it a temp directory.
/// **Nothing under test ever resolves a real data directory**, which is the
/// property that keeps `cargo test` off a live bench's captures.
fn judge_growth(results_dir: Option<&Path>, note: &str, projects: &[ProjectConfig]) -> Check {
    const NAME: &str = "Result and build-directory growth";

    let mut parts: Vec<String> = Vec::new();
    let mut measured = false;

    if let Some(dir) = results_dir {
        match measure_results(dir) {
            Some(u) => {
                measured = true;
                parts.push(format!(
                    "study_results/: {} entr{}, {} — swept to embarch-core's \
                     EMBARCH_STUDY_RESULTS_KEEP (default 50), which bounds the count and not the size",
                    u.entries,
                    if u.entries == 1 { "y" } else { "ies" },
                    human_bytes(u.bytes)
                ));
            }
            None => {
                measured = true;
                parts.push(format!("study_results/: nothing yet at {}", dir.display()));
            }
        }
    }

    let mut static_projects = 0usize;
    for project in projects {
        if !project.is_zephyr_west() {
            static_projects += 1;
            continue;
        }
        match project.resolved_build_dir_root() {
            None => parts.push(format!(
                "{}: zephyr-west with no build_dir_root in config, so nothing to count",
                project.name
            )),
            Some(root) => match count_build_dirs(&root) {
                Some(n) => {
                    measured = true;
                    parts.push(format!(
                        "{}: {n} build director{} under {} — nothing prunes these (decision 26)",
                        project.name,
                        if n == 1 { "y" } else { "ies" },
                        root.display()
                    ));
                }
                None => {
                    measured = true;
                    parts.push(format!(
                        "{}: no build directories yet under {}",
                        project.name,
                        root.display()
                    ));
                }
            },
        }
    }
    if static_projects > 0 {
        parts.push(format!(
            "{static_projects} static project(s): one build directory each by construction (decision 10)"
        ));
    }

    if !note.is_empty() {
        parts.push(note.to_string());
    }
    let detail = parts.join("; ");

    if measured {
        check(16, NAME, Status::Pass, detail)
    } else {
        check(
            16,
            NAME,
            Status::Warn,
            format!(
                "nothing to measure — {}",
                if detail.is_empty() {
                    "no config loaded and no reachable data directory".to_string()
                } else {
                    detail
                }
            ),
        )
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

    // Which machine Core belongs to, asked once and used by the two checks
    // that must not demand a local binary where none belongs (decision 38).
    let core_class = core_belongs_to(core_probe.winner_class, host.as_deref(), under_wsl2);

    let check1 = check_binaries(
        core.as_ref(),
        api.as_ref(),
        core_version_output.as_deref(),
        api_version_output.as_deref(),
        core_class,
    );
    let check2 = check_service(&core_probe, host.as_deref(), core.as_ref());
    let check3 = check_reachable(&core_probe);
    let (check4, authed) = check_token(&core_probe, config.as_ref()).await;
    // Decision 18: the USB-tree read only means something where Core
    // enumerates on *this* machine, and only on Linux.
    let usb_scan = usb_scan_for(core_probe.winner_class);
    let check5 = check_probes(authed.as_ref(), &usb_scan);
    let projects: &[ProjectConfig] = config.as_ref().map(|c| c.projects.as_slice()).unwrap_or(&[]);
    let check7 = check_build_commands(projects);
    let check8 = check_chip(projects);
    let check9 = check_artifact_paths(projects);
    let check10 = check_mcp(config_path.as_deref(), api.as_ref());
    // One handshake, two checks: `/dev-bench/hello` opens the serial link, so
    // checks 11 and 13 share one answer rather than opening it twice.
    let hello = fetch_dev_bench_hello(&core_probe, authed.as_ref(), config.as_ref()).await;
    let check11 = check_schema_versions(authed.as_ref(), &hello, api.as_ref());
    let check12 = check_dev_bench(&core_probe, authed.as_ref(), config.as_ref()).await;
    let check13 = check_firmware_version(&hello, &saved);
    let check14 = check_flash_backend(core.as_ref(), core_class);
    let check15 = check_core_build(authed.as_ref(), core_version_output.as_deref());
    // Check 3's winner is the honest source for *which machine* holds Core's
    // data directory; with no winner, this host's own shape is the stated
    // assumption rather than a silent one.
    let check16 = check_growth(
        core_probe.winner_class,
        if under_wsl2 { TopologyClass::WslHost } else { TopologyClass::Local },
        projects,
    );

    let checks = vec![
        check1, check2, check3, check4, check5, check6, check7, check8, check9, check10, check11, check12,
        check13, check14, check15, check16,
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
fn check_flash_backend(core: Option<&Located>, class: TopologyClass) -> Check {
    const NAME: &str = "flashing backend available for every chip family";
    let Some(core) = core else {
        // Decision 38: "see check 1" made this check unreadable on the one
        // topology it most needed to answer for — check 1 was itself wrong
        // there, and a reader who followed the pointer learned nothing about
        // flashing. It says what is missing and what would supply it.
        let detail = match class {
            TopologyClass::Remote => {
                "skipped — Core runs on another machine, and only its own binary can say which                  flashing program it would resolve there"
            }
            TopologyClass::WslHost => {
                "skipped — no embarch-core binary this host can run: nothing is registered \
                 as the Windows service (`sc.exe qc com.embarch.core`), no copy sits in a \
                 conventional Windows location, and EMBARCH_CORE_EXE is unset"
            }
            TopologyClass::Local => {
                "skipped — no embarch-core binary on this machine to ask; `embarch setup` installs one"
            }
        };
        return with_code(check(14, NAME, Status::Warn, detail), "core-not-located");
    };

    let output = match Command::new(&core.path).arg("flash-backend").output() {
        Ok(o) => o,
        Err(e) => {
            return with_code(
                check(
                    14,
                    NAME,
                    Status::Warn,
                    format!("couldn't run `{} flash-backend`: {e}", core.path.display()),
                ),
                "core-unrunnable",
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
        return with_code(
            check(
                14,
                NAME,
                Status::Warn,
                "this embarch-core has no `flash-backend` subcommand — it predates §3 decision 36 and \
                 will flash every target with probe-rs, including Nordic RRAM parts",
            ),
            "no-flash-backend-subcommand",
        );
    }

    let summary = rows
        .iter()
        .map(|(c, b)| format!("{c}={b}"))
        .collect::<Vec<_>>()
        .join(", ");

    if unavailable.is_empty() {
        return with_code(check(14, NAME, Status::Pass, summary), "every-family-covered");
    }

    with_code(with_fix(
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
    ), "family-uncovered")
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
                "code": c.code,
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

    // ---- check 5: attached-but-not-permitted (decision 18) -----------------

    fn usb_device(root: &Path, name: &str, vid: &str, product: Option<&str>) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        // The kernel writes a trailing newline; parsing has to survive it.
        std::fs::write(dir.join("idVendor"), format!("{vid}\n")).unwrap();
        if let Some(p) = product {
            std::fs::write(dir.join("product"), format!("{p}\n")).unwrap();
        }
    }

    fn no_probes() -> AuthedStatus {
        AuthedStatus { probes: Vec::new(), study_designer_schema_version: None, core_version: None }
    }

    #[test]
    fn check_5_fails_when_a_probe_is_on_the_bus_and_core_enumerated_none() {
        let dir = tempdir();
        usb_device(dir.path(), "1-2", "1366", Some("J-Link"));
        usb_device(dir.path(), "1-2:1.0", "", None); // an interface, no real idVendor
        let scan = UsbScan::Scanned(scan_usb_debug_probes(dir.path()));
        let c = check_probes(Some(&no_probes()), &scan);
        assert_eq!(c.status, Status::Fail);
        assert_eq!(c.code, Some("probe-not-permitted"));
        assert!(c.detail.contains("J-Link"), "{}", c.detail);
        let fix = c.fix.unwrap();
        assert!(fix.contains("udev"), "{fix}");
        assert!(fix.contains("udevadm"), "{fix}");
    }

    #[test]
    fn check_5_stays_a_warn_when_the_bus_holds_no_probe_vendor() {
        let dir = tempdir();
        usb_device(dir.path(), "1-1", "046d", Some("Webcam")); // Logitech, not a probe
        let scan = UsbScan::Scanned(scan_usb_debug_probes(dir.path()));
        let c = check_probes(Some(&no_probes()), &scan);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.code, Some("no-probe-found"));
        assert!(c.fix.is_none());
    }

    #[test]
    fn ftdi_is_not_a_probe_vendor_because_every_serial_cable_shares_it() {
        let dir = tempdir();
        usb_device(dir.path(), "1-1", "0403", Some("FT232R USB UART"));
        assert!(scan_usb_debug_probes(dir.path()).is_empty());
    }

    #[test]
    fn a_missing_sysfs_tree_reads_as_an_empty_bus_not_an_error() {
        let dir = tempdir();
        assert!(scan_usb_debug_probes(&dir.path().join("no-such-thing")).is_empty());
    }

    #[test]
    fn the_usb_scan_only_runs_on_linux_with_core_on_this_machine() {
        // The one assertion that has to hold on all three hosts: macOS and
        // Windows never scan, so decision 18 leaves them exactly as they were.
        let local = usb_scan_for(Some(TopologyClass::Local));
        if cfg!(target_os = "linux") {
            assert!(matches!(local, UsbScan::Scanned(_)));
        } else {
            assert_eq!(local, UsbScan::NotLinux);
        }
        for elsewhere in [TopologyClass::WslHost, TopologyClass::Remote] {
            let expected =
                if cfg!(target_os = "linux") { UsbScan::CoreElsewhere } else { UsbScan::NotLinux };
            assert_eq!(usb_scan_for(Some(elsewhere)), expected);
        }
    }

    #[test]
    fn check_5_on_a_non_linux_host_keeps_the_original_warn_wording() {
        let c = check_probes(Some(&no_probes()), &UsbScan::NotLinux);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.code, Some("no-probe-unchecked"));
        assert_eq!(c.detail, "no probes reported — fine if none is plugged in right now");
        assert!(c.fix.is_none());
    }

    #[test]
    fn check_5_says_so_when_core_enumerates_on_another_machine() {
        let c = check_probes(Some(&no_probes()), &UsbScan::CoreElsewhere);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.code, Some("no-probe-unchecked"));
        assert!(c.detail.contains("another machine"), "{}", c.detail);
    }

    #[test]
    fn check_5_passes_and_never_scans_when_core_reports_a_probe() {
        let authed = AuthedStatus {
            probes: vec![serde_json::json!({"identifier": "whatever"})],
            study_designer_schema_version: None,
            core_version: None,
        };
        let dir = tempdir();
        usb_device(dir.path(), "1-2", "1366", Some("J-Link"));
        let scan = UsbScan::Scanned(scan_usb_debug_probes(dir.path()));
        let c = check_probes(Some(&authed), &scan);
        assert_eq!(c.status, Status::Pass);
        assert_eq!(c.code, Some("probes-present"));
    }

    #[test]
    fn check_5_skips_distinguishably_when_there_is_no_authenticated_status() {
        let c = check_probes(None, &UsbScan::CoreElsewhere);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.code, Some("no-status"));
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

    /// The common case: `embarch` and the located `embarch-api` agree, so the
    /// fourth number (decision 36) is quiet and the matrix under test is the
    /// Core-versus-api one.
    fn versions<'a>(
        core_host: Result<u32, &'a str>,
        api_host: u32,
        bench_wire: Result<(u32, Option<bool>), &'a str>,
    ) -> SchemaVersions<'a> {
        SchemaVersions {
            core_host,
            api_host: Ok(api_host),
            umbrella_host: api_host,
            bench_wire,
        }
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

    // ---- check 11: where the host number comes from (decisions 35, 36) ------

    #[test]
    fn an_embarch_api_that_cannot_be_asked_is_a_skip_naming_why_never_a_silent_fallback() {
        // The whole point of decision 35: the numbers Core and *this* binary
        // hold agree here, so a fallback to the local constant would report a
        // clean Pass. It must not — nobody asked the binary that submits the
        // study.
        let c = judge_schema_versions(&SchemaVersions {
            core_host: Ok(17),
            api_host: Err("embarch-api not located (see check 1)".to_string()),
            umbrella_host: 17,
            bench_wire: Ok((15, Some(true))),
        });
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert!(c.detail.contains("embarch-api not located"), "{}", c.detail);
        // The number that *was* obtained is still printed, and the local
        // constant is labelled as context rather than as the comparison.
        assert!(c.detail.contains("v17"), "{}", c.detail);
        assert!(c.detail.contains("context only"), "{}", c.detail);
    }

    #[test]
    fn could_not_ask_and_they_disagree_are_different_verdicts() {
        let unasked = judge_schema_versions(&SchemaVersions {
            core_host: Ok(16),
            api_host: Err("embarch-api not located (see check 1)".to_string()),
            umbrella_host: 17,
            bench_wire: Err("no dev-bench plugged in"),
        });
        let disagree = judge_schema_versions(&versions(Ok(16), 17, Err("no dev-bench plugged in")));
        assert_eq!(unasked.status, Status::Warn);
        assert_eq!(disagree.status, Status::Fail);
    }

    #[test]
    fn an_embarch_disagreeing_with_the_api_it_located_warns_without_failing() {
        // Decision 36: a real mixed install, and the study hop is still fine —
        // embarch submits nothing, so this cannot be a Fail.
        let c = judge_schema_versions(&SchemaVersions {
            core_host: Ok(17),
            api_host: Ok(17),
            umbrella_host: 16,
            bench_wire: Ok((15, Some(true))),
        });
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert!(c.detail.contains("mixed install"), "{}", c.detail);
        assert!(c.detail.contains("v16") && c.detail.contains("v17"), "{}", c.detail);
        assert!(c.fix.as_deref().unwrap().contains("one suite archive"), "{:?}", c.fix);
    }

    #[test]
    fn a_core_api_disagreement_outranks_a_mixed_install_warning() {
        let c = judge_schema_versions(&SchemaVersions {
            core_host: Ok(15),
            api_host: Ok(17),
            umbrella_host: 16,
            bench_wire: Ok((15, Some(true))),
        });
        assert_eq!(c.status, Status::Fail);
        // Both fix lines survive: the blocking one and the mixed-install one.
        let fix = c.fix.as_deref().unwrap();
        assert!(fix.contains("deploy-core") && fix.contains("one suite archive"), "{fix}");
    }

    #[test]
    fn a_versions_object_yields_the_api_binarys_compiled_number() {
        let stdout = r#"{ "schema_version": 1, "success": true, "api_version": "0.1.0",
                          "host_type_schema_version": 17 }"#;
        assert_eq!(api_host_from_output(Some(0), true, stdout), Ok(17));
    }

    #[test]
    fn an_embarch_api_too_old_for_versions_says_what_it_predates() {
        // clap exits 2 on an unknown subcommand, printing its usage error to
        // stderr and nothing to stdout.
        let e = api_host_from_output(Some(2), false, "").unwrap_err();
        assert!(e.contains("no `versions` subcommand"), "{e}");
        assert!(e.contains("decision 52"), "{e}");
    }

    #[test]
    fn a_non_zero_exit_that_is_not_clap_is_reported_as_itself() {
        let e = api_host_from_output(Some(101), false, "").unwrap_err();
        assert!(e.contains("101"), "{e}");
    }

    #[test]
    fn an_answer_without_the_field_is_an_error_not_a_zero() {
        let e = api_host_from_output(Some(0), true, r#"{"success": true, "api_version": "0.1.0"}"#)
            .unwrap_err();
        assert!(e.contains("host_type_schema_version"), "{e}");
    }

    #[test]
    fn output_that_is_not_json_at_all_is_an_error() {
        let e = api_host_from_output(Some(0), true, "embarch-api 0.1.0").unwrap_err();
        assert!(e.contains("no JSON object"), "{e}");
    }

    fn a_located(path: &str, windows: bool) -> Located {
        Located {
            path: PathBuf::from(path),
            found_by: if windows {
                locate::FoundBy::WindowsServiceRegistration
            } else {
                locate::FoundBy::Path
            },
            windows_exe_from_wsl2: windows,
        }
    }

    /// The whole of task `umbrella/010`: on `wsl-host` there is no Linux
    /// `embarch-core` to sit beside `embarch`, `setup` already treats its
    /// absence as correct, and check 1 was calling the same machine broken.
    #[test]
    fn check_1_is_not_a_failure_where_no_local_core_belongs() {
        let api = a_located("/home/u/.local/share/embarch/bin/embarch-api", false);
        for class in [TopologyClass::WslHost, TopologyClass::Remote] {
            let c = check_binaries(None, Some(&api), None, None, class);
            assert_eq!(c.status, Status::Warn, "{class:?}");
            assert_eq!(c.code, Some("core-not-local"), "{class:?}");
            assert!(c.detail.contains(class.as_str()), "{}", c.detail);
        }
    }

    /// The half that must not soften: `local` is the topology where a missing
    /// Core really is a broken install, and `embarch-api` always runs on this
    /// side of the boundary whatever the class.
    #[test]
    fn check_1_still_fails_where_a_binary_really_is_missing() {
        let api = a_located("/usr/local/bin/embarch-api", false);
        let core = a_located("/mnt/c/x/embarch-core.exe", true);
        let local = check_binaries(None, Some(&api), None, None, TopologyClass::Local);
        assert_eq!(local.status, Status::Fail);
        assert_eq!(local.code, Some("not-found"));
        // No `embarch-api`, on the very topology that excuses a missing Core.
        let no_api = check_binaries(Some(&core), None, None, None, TopologyClass::WslHost);
        assert_eq!(no_api.status, Status::Fail);
        assert_eq!(no_api.code, Some("not-found"));
    }

    /// Only ever asked when nothing was located, so the WSL2 arm wins over a
    /// `local` winner: decision 30's ambiguity means loopback answering under
    /// WSL2 does not place Core in the guest.
    #[test]
    fn where_core_belongs_prefers_a_declared_host_then_the_wsl2_boundary() {
        assert_eq!(core_belongs_to(Some(TopologyClass::Local), Some("bench.local"), false), TopologyClass::Remote);
        assert_eq!(core_belongs_to(None, Some("bench.local"), true), TopologyClass::Remote);
        assert_eq!(core_belongs_to(Some(TopologyClass::Remote), None, true), TopologyClass::Remote);
        assert_eq!(core_belongs_to(Some(TopologyClass::Local), None, true), TopologyClass::WslHost);
        assert_eq!(core_belongs_to(None, None, true), TopologyClass::WslHost);
        assert_eq!(core_belongs_to(Some(TopologyClass::Local), None, false), TopologyClass::Local);
        assert_eq!(core_belongs_to(None, None, false), TopologyClass::Local);
    }

    /// Check 14's skip used to be "see check 1", which on `wsl-host` pointed
    /// at a check that was itself wrong. Each class now names what is missing.
    #[test]
    fn check_14_says_why_it_cannot_run_without_pointing_at_check_1() {
        for class in [TopologyClass::Local, TopologyClass::WslHost, TopologyClass::Remote] {
            let c = check_flash_backend(None, class);
            assert_eq!(c.status, Status::Warn, "{class:?}");
            assert_eq!(c.code, Some("core-not-located"), "{class:?}");
            assert!(!c.detail.contains("check 1"), "{}", c.detail);
        }
        assert!(check_flash_backend(None, TopologyClass::WslHost).detail.contains("sc.exe qc"));
        assert!(check_flash_backend(None, TopologyClass::Remote).detail.contains("another machine"));
    }

    #[test]
    fn a_missing_embarch_api_binary_is_a_reason_not_a_panic() {
        let located = Located {
            path: PathBuf::from("/no/such/embarch-api-xyz"),
            found_by: locate::FoundBy::EnvVar,
            windows_exe_from_wsl2: false,
        };
        let e = api_host_schema_version(Some(&located)).unwrap_err();
        assert!(e.contains("couldn't run"), "{e}");
        assert!(api_host_schema_version(None).unwrap_err().contains("check 1"));
    }

    /// The three failing shapes against a real spawn, not just a parse: an
    /// `embarch-api` that answers, one too old to know the subcommand, and one
    /// this user cannot execute. Unix-only because it fabricates the binaries
    /// as shell scripts and uses unix permission bits.
    #[cfg(unix)]
    #[test]
    fn a_located_binary_is_actually_spawned_and_its_failures_are_reported() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        let fake = |name: &str, body: &str, mode: u32| {
            let p = dir.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            Located { path: p, found_by: locate::FoundBy::EnvVar, windows_exe_from_wsl2: false }
        };

        let answers = fake(
            "answers",
            r#"echo '{"schema_version":1,"success":true,"api_version":"0.1.0","host_type_schema_version":17}'"#,
            0o755,
        );
        assert_eq!(api_host_schema_version(Some(&answers)), Ok(17));

        let too_old = fake("too-old", "echo \"error: unrecognized subcommand\" >&2; exit 2", 0o755);
        let e = api_host_schema_version(Some(&too_old)).unwrap_err();
        assert!(e.contains("no `versions` subcommand"), "{e}");

        // No execute bit for anyone, which `execve` refuses even for root —
        // so this stays deterministic wherever the suite runs.
        let unreadable = fake("unreadable", "echo nope", 0o644);
        let e = api_host_schema_version(Some(&unreadable)).unwrap_err();
        assert!(e.contains("couldn't run"), "{e}");
    }

    // ---- check 10: registered is not the same as working ---------------------

    const SAMPLE_GET: &str = "embarch:\n  \
        Scope: Local (private to you in this project)\n  \
        Status: ✓ Connected\n  \
        Type: stdio\n  \
        Command: /home/u/.local/bin/embarch-api\n  \
        Args: --config /repo/embarch/embarch.toml\n  \
        Environment:\n";

    #[test]
    fn a_registration_entry_yields_the_exact_command_to_spawn() {
        let (cmd, args) = parse_registered_command(SAMPLE_GET).unwrap();
        assert_eq!(cmd, "/home/u/.local/bin/embarch-api");
        assert_eq!(args, vec!["--config".to_string(), "/repo/embarch/embarch.toml".to_string()]);
    }

    #[test]
    fn an_entry_with_no_command_line_is_unreadable_not_a_command() {
        assert!(parse_registered_command("embarch:\n  Scope: Local\n").is_none());
        assert!(parse_registered_command("embarch:\n  Command:\n").is_none());
    }

    #[test]
    fn a_quoted_argument_with_a_space_survives_the_split() {
        assert_eq!(
            split_args("--config \"C:\\Program Files\\embarch\\embarch.toml\" --quiet"),
            vec![
                "--config".to_string(),
                "C:\\Program Files\\embarch\\embarch.toml".to_string(),
                "--quiet".to_string()
            ]
        );
    }

    fn registered() -> McpRegistration {
        McpRegistration::Registered {
            command: "/bin/embarch-api".to_string(),
            args: vec!["--config".to_string(), "/repo/embarch.toml".to_string()],
        }
    }

    /// The regression this check was rebuilt for (decision 23): a registration
    /// entry that exists while the command behind it does not start must read
    /// Fail. The old check reported exactly this state as Pass.
    #[test]
    fn a_registered_but_unstartable_command_fails_rather_than_passing() {
        let c = judge_mcp(
            &registered(),
            Some(&HandshakeOutcome::Failed("couldn't start `/bin/embarch-api`: No such file".to_string())),
            "claude mcp add embarch -- ...",
        );
        assert_eq!(c.status, Status::Fail);
        assert_eq!(c.code, Some("handshake-failed"));
        // The fix must not be "re-register it" — the registration is fine.
        let fix = c.fix.unwrap();
        assert!(fix.contains("re-adding it fixes"), "{fix}");
    }

    #[test]
    fn the_three_handshake_outcomes_stay_distinct_in_json() {
        let codes = [
            HandshakeOutcome::Answered("embarch-api".to_string()),
            HandshakeOutcome::Failed("boom".to_string()),
            HandshakeOutcome::TimedOut,
        ]
        .iter()
        .map(|o| {
            let c = judge_mcp(&registered(), Some(o), "fix");
            let rendered = render_json(std::slice::from_ref(&c), c.status == Status::Fail);
            let v: serde_json::Value = serde_json::from_str(&rendered).unwrap();
            v["checks"][0]["code"].as_str().unwrap().to_string()
        })
        .collect::<Vec<_>>();

        assert_eq!(codes, vec!["handshake-ok", "handshake-failed", "handshake-timeout"]);
    }

    #[test]
    fn an_answered_handshake_is_the_only_pass() {
        assert_eq!(
            judge_mcp(&registered(), Some(&HandshakeOutcome::Answered("x".into())), "fix").status,
            Status::Pass
        );
        assert_eq!(judge_mcp(&registered(), Some(&HandshakeOutcome::TimedOut), "fix").status, Status::Fail);
        assert_eq!(judge_mcp(&McpRegistration::NotRegistered, None, "fix").status, Status::Fail);
        // Neither of the two "can't tell" states may invent a verdict.
        assert_eq!(judge_mcp(&McpRegistration::NoCli, None, "fix").status, Status::Warn);
        let unreadable = judge_mcp(&McpRegistration::UnreadableEntry, None, "fix");
        assert_eq!(unreadable.status, Status::Warn);
        assert_eq!(unreadable.code, Some("unreadable-entry"));
    }

    /// The handshake against a real spawn, in the three shapes decision 23
    /// names. Unix-only for the same reason the check-11 spawn test is: it
    /// fabricates the servers as shell scripts.
    #[cfg(unix)]
    #[test]
    fn a_real_spawn_separates_answering_broken_and_hanging() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        let fake = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p.to_string_lossy().into_owned()
        };

        // Answers the request it is actually sent, after a line of noise that
        // a real server's logging would produce.
        let answers = fake(
            "answers",
            "echo 'starting up' >&2\n\
             read line\n\
             echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\
             \"capabilities\":{},\"serverInfo\":{\"name\":\"embarch-api\",\"version\":\"0.1.0\"}}}'",
        );
        assert_eq!(
            mcp_initialize(&answers, &[], Duration::from_secs(10)),
            HandshakeOutcome::Answered("embarch-api".to_string())
        );

        // Registered but broken — the state the old check called Pass. It
        // never reads stdin, so the `initialize` write races its exit and
        // usually loses with EPIPE: the assertions below are what pin the
        // verdict to its exit and its stderr rather than to who won.
        let broken = fake("broken", "echo 'error: --config: no such file' >&2; exit 1");
        match mcp_initialize(&broken, &[], Duration::from_secs(10)) {
            HandshakeOutcome::Failed(why) => {
                assert!(why.contains("exited without"), "{why}");
                assert!(why.contains("no such file"), "stderr should be reported: {why}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // A command that is not there at all.
        match mcp_initialize(&dir.path().join("absent").to_string_lossy(), &[], Duration::from_secs(10)) {
            HandshakeOutcome::Failed(why) => assert!(why.contains("couldn't start"), "{why}"),
            other => panic!("expected Failed, got {other:?}"),
        }

        // Starts, reads, and never answers. Distinct from Failed.
        let hangs = fake("hangs", "read line\nsleep 30");
        assert_eq!(
            mcp_initialize(&hangs, &[], Duration::from_millis(400)),
            HandshakeOutcome::TimedOut
        );

        // Answers something that is not a response to our request: skipped,
        // then EOF, so it is a failure rather than a false pass.
        let wrong_id = fake(
            "wrong-id",
            "read line\necho '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}'",
        );
        match mcp_initialize(&wrong_id, &[], Duration::from_secs(10)) {
            HandshakeOutcome::Failed(why) => assert!(why.contains("without answering"), "{why}"),
            other => panic!("expected Failed, got {other:?}"),
        }

        // A JSON-RPC error for our id is a failure that quotes it.
        let errors = fake(
            "errors",
            "read line\necho '{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"nope\"}}'",
        );
        match mcp_initialize(&errors, &[], Duration::from_secs(10)) {
            HandshakeOutcome::Failed(why) => assert!(why.contains("nope"), "{why}"),
            other => panic!("expected Failed, got {other:?}"),
        }
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
            build_dir_root: None,
        }
    }

    // ---- check 16 -----------------------------------------------------------
    //
    // Every one of these runs against a temp directory. None of them resolves
    // a real Core data directory, and nothing in check 16 deletes anything —
    // `--prune` is deliberately not built (decision 26's amendment).

    fn zephyr_west_project(name: &str, source: &Path, build_dir_root: Option<&str>) -> ProjectConfig {
        ProjectConfig {
            name: name.to_string(),
            source_path: source.to_path_buf(),
            discovery: config::Discovery::ZephyrWest,
            build_cwd: None,
            build_command: None,
            artifact_path: None,
            chip: None,
            artifact_path_for_core: None,
            west_binary: Some(PathBuf::from("west")),
            build_dir_root: build_dir_root.map(PathBuf::from),
        }
    }

    #[test]
    fn check_16_counts_result_entries_and_their_bytes() {
        let dir = tempdir();
        let results = dir.path().join("study_results");
        for id in ["a", "b"] {
            let streams = results.join(id).join("streams");
            std::fs::create_dir_all(&streams).unwrap();
            std::fs::write(results.join(id).join("events.json"), vec![b'x'; 100]).unwrap();
            std::fs::write(streams.join("tap.bin"), vec![b'y'; 900]).unwrap();
        }
        let c = judge_growth(Some(&results), "", &[]);
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains("2 entries"), "{}", c.detail);
        assert!(c.detail.contains("2.0 KiB"), "{}", c.detail);
        // Core owns the retention, and the reader is told which knob bounds
        // it — and that it bounds the count, not the bytes just reported.
        assert!(c.detail.contains("EMBARCH_STUDY_RESULTS_KEEP"), "{}", c.detail);
    }

    #[test]
    fn check_16_reports_a_machine_that_has_never_run_a_study() {
        let dir = tempdir();
        let c = judge_growth(Some(&dir.path().join("study_results")), "", &[]);
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains("nothing yet"), "{}", c.detail);
    }

    #[test]
    fn check_16_counts_build_directories_per_zephyr_west_project() {
        let dir = tempdir();
        let root = dir.path().join("embarch").join("build");
        for target in ["ref_board-default-none-widget", "ref_board-os_5led-evt1-widget"] {
            std::fs::create_dir_all(root.join(target)).unwrap();
        }
        // A stray file beside them is not a build directory.
        std::fs::write(root.join("notes.txt"), "x").unwrap();
        let project = zephyr_west_project("fw", dir.path(), Some("embarch/build"));
        let c = judge_growth(None, "", std::slice::from_ref(&project));
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains("fw: 2 build directories"), "{}", c.detail);
        assert!(c.detail.contains("nothing prunes these"), "{}", c.detail);
    }

    #[test]
    fn check_16_resolves_a_relative_build_dir_root_under_source_path() {
        let dir = tempdir();
        std::fs::create_dir_all(dir.path().join("embarch/build/a")).unwrap();
        let project = zephyr_west_project("fw", dir.path(), Some("embarch/build"));
        assert_eq!(
            project.resolved_build_dir_root(),
            Some(dir.path().join("embarch").join("build"))
        );
        let c = judge_growth(None, "", std::slice::from_ref(&project));
        assert!(c.detail.contains("fw: 1 build directory"), "{}", c.detail);
    }

    #[test]
    fn check_16_says_a_static_project_has_one_build_directory_by_construction() {
        let c = judge_growth(None, "", &[sample_project("legacy", "nRF54L15")]);
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("by construction"), "{}", c.detail);
    }

    #[test]
    fn check_16_never_fails_the_run_even_with_nothing_to_measure() {
        let c = judge_growth(None, "study_results/ is on the remote Core's machine", &[]);
        assert_eq!(c.status, Status::Warn);
        assert_ne!(c.status, Status::Fail);
        assert!(c.detail.contains("remote Core"), "{}", c.detail);
    }

    #[test]
    fn check_16_names_the_assumption_when_check_3_found_no_winner() {
        let dir = tempdir();
        let results = dir.path().join("study_results");
        std::fs::create_dir_all(results.join("s1")).unwrap();
        let c = judge_growth(Some(&results), "assuming a wsl-host Core — check 3 found no winner to ask", &[]);
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.contains("check 3 found no winner"), "{}", c.detail);
    }

    #[test]
    fn a_remote_core_has_no_local_data_directory_to_measure() {
        // The reason check 16 asks `setup::data_dir_for` rather than
        // `token.rs`: a Remote Core's results are on another machine, and a
        // local directory that happens to exist would be the wrong answer
        // reported confidently.
        assert_eq!(setup::data_dir_for(TopologyClass::Remote, false), None);
        assert_eq!(
            setup::data_dir_for(TopologyClass::WslHost, false),
            Some(PathBuf::from("/mnt/c/ProgramData/embarch"))
        );
    }

    #[test]
    fn dir_bytes_does_not_follow_a_symlink_out_of_the_tree() {
        let dir = tempdir();
        let inner = dir.path().join("study_results").join("s1");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("events.json"), vec![b'x'; 10]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path(), inner.join("loop")).unwrap();
        let usage = measure_results(&dir.path().join("study_results")).unwrap();
        assert_eq!(usage.entries, 1);
        assert_eq!(usage.bytes, 10);
    }

    #[test]
    fn human_bytes_reads_as_a_size_and_not_a_float_at_zero() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 3 / 2), "1.5 MiB");
    }
}
