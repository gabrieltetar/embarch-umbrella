//! `embarch install-core` — install a suite release only after it verifies.
//!
//! Step 4 of `embarch-doc/embarch-release-signing-proposal.md` (EMB-338,
//! embarch-umbrella decision 61). The release is copied into a staging folder
//! only the elevated step can write, checked **there** by
//! [`verify_release`](crate::verify_release), compared against the suite
//! version already installed, and recorded in `installed-release.json`. A
//! failed check writes no record. Registering the service is a later unit.
//!
//! The elevated half, [`install_core_elevated`], takes its folders and a
//! verifier as arguments, so tests run it as an ordinary user in temp dirs
//! with a fake verifier.

use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::install::SUITE_BINARIES;
use crate::locate;
use crate::verify_release::{
    load_trust_root, verify_release_with_root, TrustRootSource, Verified, VerifyError, MANIFEST_FILE,
};

/// The record's file name, directly in the data dir.
pub const RECORD_FILE: &str = "installed-release.json";
/// The folder under the data dir holding verified copies, `<n>` each.
pub const STAGING_DIR: &str = "release-staging";
/// Bumped when the record's shape changes.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// What was verified and installed, as `installed-release.json` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRelease {
    pub schema_version: u32,
    pub suite_version: String,
    /// SHA-256 of the staged `embarch-manifest.json`, lowercase hex.
    pub manifest_sha256: String,
    pub identity: String,
    pub issuer: String,
    pub log_time: Option<String>,
    /// Each suite binary found in the staged release, name to SHA-256.
    pub binaries: std::collections::BTreeMap<String, String>,
    /// `--allow-downgrade` was passed.
    pub allow_downgrade: bool,
    /// This install was older than the one it replaced.
    pub downgraded: bool,
    /// The suite version this replaced, when a record existed.
    pub previous_suite_version: Option<String>,
    /// The staging folder it was verified in, relative to the data dir.
    pub staging: String,
    /// UTC, RFC 3339.
    pub installed_at: String,
}

/// Why an install stopped. Nothing was recorded for any of them.
#[derive(Debug)]
pub enum InstallCoreError {
    Io { what: String, source: std::io::Error },
    /// The release did not verify.
    Verify(VerifyError),
    /// The release's suite version is older than the installed one.
    Downgrade { installed: String, offered: String },
    /// A suite version that is not `major.minor.patch[-pre]`, so no order exists.
    UnorderedVersion { installed: String, offered: String },
    /// The existing record cannot be read.
    BadRecord(String),
    /// The archive could not be unpacked, or holds no manifest.
    Archive(String),
}

impl fmt::Display for InstallCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallCoreError::Io { what, source } => write!(f, "{what}: {source}"),
            InstallCoreError::Verify(e) => write!(f, "release not verified, nothing installed: {e}"),
            InstallCoreError::Downgrade { installed, offered } => write!(
                f,
                "suite {offered} is older than the installed {installed}; \
                 pass --allow-downgrade to install it anyway (the record will say so)"
            ),
            InstallCoreError::UnorderedVersion { installed, offered } => write!(
                f,
                "cannot order suite {offered} against the installed {installed} \
                 (not major.minor.patch); pass --allow-downgrade to install it anyway"
            ),
            InstallCoreError::BadRecord(m) => write!(f, "{RECORD_FILE} is unusable: {m}"),
            InstallCoreError::Archive(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for InstallCoreError {}

fn io<T>(what: impl Into<String>, r: std::io::Result<T>) -> Result<T, InstallCoreError> {
    r.map_err(|source| InstallCoreError::Io { what: what.into(), source })
}

/// What `install-core` would do, printed by `--dry-run` and before a real run.
#[derive(Debug, Clone)]
pub struct Plan {
    pub source: PathBuf,
    pub source_is_archive: bool,
    pub data_dir: PathBuf,
    pub allow_downgrade: bool,
    pub installed: Option<String>,
}

impl Plan {
    /// Reads the existing record, if any; writes nothing.
    pub fn build(source: &Path, data_dir: &Path, allow_downgrade: bool) -> Result<Plan, InstallCoreError> {
        let installed = read_record(data_dir)?.map(|r| r.suite_version);
        Ok(Plan {
            source: source.to_path_buf(),
            source_is_archive: source.is_file(),
            data_dir: data_dir.to_path_buf(),
            allow_downgrade,
            installed,
        })
    }

    pub fn render(&self) -> String {
        let kind = if self.source_is_archive { "archive" } else { "release folder" };
        let mut s = format!("install-core plan\n  source:      {} ({kind})\n", self.source.display());
        s += &format!(
            "  staging:     {} (readable by Administrators or root only)\n",
            self.data_dir.join(STAGING_DIR).join("<n>").display()
        );
        s += "  1. needs elevation: Administrators on Windows, root elsewhere\n";
        s += &format!(
            "  2. copy {} into the staging folder{}\n",
            if self.source_is_archive { "and unpack the archive" } else { "the folder" },
            ""
        );
        s += "  3. verify the manifest signature and every listed file there\n";
        s += &match &self.installed {
            Some(v) => format!(
                "  4. compare with the installed suite {v}; an older one is {}\n",
                if self.allow_downgrade { "allowed (--allow-downgrade) and recorded" } else { "refused" }
            ),
            None => "  4. no installed-release.json: nothing to compare with\n".to_string(),
        };
        s += &format!("  5. write {}\n", self.data_dir.join(RECORD_FILE).display());
        s += "  Not done here: registering the service under its own account.\n";
        s
    }
}

/// The elevated half. Copies `source` into a fresh `<data_dir>/release-staging/<n>/`,
/// runs `verifier` on the staged release, applies the downgrade rule and writes
/// `installed-release.json`. On any failure the staging folder it made is
/// removed and no record is written or changed.
pub fn install_core_elevated(
    source: &Path,
    data_dir: &Path,
    allow_downgrade: bool,
    verifier: &dyn Fn(&Path) -> Result<Verified, VerifyError>,
    now: SystemTime,
) -> Result<InstalledRelease, InstallCoreError> {
    let previous = read_record(data_dir)?;

    let staging_root = data_dir.join(STAGING_DIR);
    io(format!("create {}", staging_root.display()), fs::create_dir_all(&staging_root))?;
    restrict_to_admins(&staging_root)?;
    let n = next_staging_number(&staging_root)?;
    let stage = staging_root.join(n.to_string());
    io(format!("create {}", stage.display()), fs::create_dir(&stage))?;

    let result = stage_and_record(
        source,
        data_dir,
        &stage,
        n,
        previous.as_ref(),
        allow_downgrade,
        verifier,
        now,
    );
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn stage_and_record(
    source: &Path,
    data_dir: &Path,
    stage: &Path,
    n: u64,
    previous: Option<&InstalledRelease>,
    allow_downgrade: bool,
    verifier: &dyn Fn(&Path) -> Result<Verified, VerifyError>,
    now: SystemTime,
) -> Result<InstalledRelease, InstallCoreError> {
    if source.is_dir() {
        copy_dir(source, stage)?;
    } else if source.is_file() {
        unpack_archive(source, stage)?;
    } else {
        return Err(InstallCoreError::Archive(format!(
            "{} is neither a release folder nor an archive",
            source.display()
        )));
    }
    let root = release_root(stage)?;

    let verified = verifier(&root).map_err(InstallCoreError::Verify)?;

    let downgraded = match previous {
        Some(p) => match compare_versions(&verified.suite_version, &p.suite_version) {
            Some(Ordering::Less) => true,
            Some(_) => false,
            None => {
                if !allow_downgrade {
                    return Err(InstallCoreError::UnorderedVersion {
                        installed: p.suite_version.clone(),
                        offered: verified.suite_version.clone(),
                    });
                }
                false
            }
        },
        None => false,
    };
    if downgraded && !allow_downgrade {
        return Err(InstallCoreError::Downgrade {
            installed: previous.map(|p| p.suite_version.clone()).unwrap_or_default(),
            offered: verified.suite_version.clone(),
        });
    }

    let manifest_path = root.join(MANIFEST_FILE);
    let manifest_sha256 = sha256_file(&manifest_path)?;
    let mut binaries = std::collections::BTreeMap::new();
    for stem in SUITE_BINARIES {
        let name = locate::native_name(stem);
        let p = root.join(&name);
        if p.is_file() {
            binaries.insert(name, sha256_file(&p)?);
        }
    }

    let record = InstalledRelease {
        schema_version: RECORD_SCHEMA_VERSION,
        suite_version: verified.suite_version,
        manifest_sha256,
        identity: verified.identity,
        issuer: verified.issuer,
        log_time: verified.log_time,
        binaries,
        allow_downgrade,
        downgraded,
        previous_suite_version: previous.map(|p| p.suite_version.clone()),
        staging: format!("{STAGING_DIR}/{n}"),
        installed_at: rfc3339_utc(now),
    };
    write_record(data_dir, &record)?;
    Ok(record)
}

/// Read `installed-release.json`; `None` when there is none.
pub fn read_record(data_dir: &Path) -> Result<Option<InstalledRelease>, InstallCoreError> {
    let path = data_dir.join(RECORD_FILE);
    match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| InstallCoreError::BadRecord(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(InstallCoreError::Io { what: format!("read {}", path.display()), source }),
    }
}

/// Write the record by temp file and rename, so a reader never sees half of it.
fn write_record(data_dir: &Path, record: &InstalledRelease) -> Result<(), InstallCoreError> {
    let path = data_dir.join(RECORD_FILE);
    let tmp = data_dir.join(format!(".{RECORD_FILE}.new"));
    let json = serde_json::to_string_pretty(record).expect("record serialises");
    io(format!("write {}", tmp.display()), fs::write(&tmp, json + "\n"))?;
    if let Err(source) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(InstallCoreError::Io { what: format!("replace {}", path.display()), source });
    }
    Ok(())
}

fn next_staging_number(root: &Path) -> Result<u64, InstallCoreError> {
    let mut max = 0;
    for entry in io(format!("read {}", root.display()), fs::read_dir(root))? {
        let entry = io("read staging entry", entry)?;
        if let Some(n) = entry.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) {
            max = max.max(n);
        }
    }
    Ok(max + 1)
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), InstallCoreError> {
    for entry in io(format!("read {}", from.display()), fs::read_dir(from))? {
        let entry = io("read release entry", entry)?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let ty = io(format!("stat {}", src.display()), entry.file_type())?;
        if ty.is_dir() {
            io(format!("create {}", dst.display()), fs::create_dir(&dst))?;
            copy_dir(&src, &dst)?;
        } else if ty.is_file() {
            io(format!("copy {}", src.display()), fs::copy(&src, &dst))?;
        }
        // Symlinks and other entries are not copied: the manifest lists
        // regular files, and a link would point outside the staging folder.
    }
    Ok(())
}

/// `tar` unpacks tar.gz everywhere and zip on Windows 10+ (bsdtar), without a
/// new dependency. It runs inside the admin-only staging folder.
fn unpack_archive(archive: &Path, stage: &Path) -> Result<(), InstallCoreError> {
    let out = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(stage)
        .output()
        .map_err(|e| InstallCoreError::Archive(format!("cannot run tar to unpack {}: {e}", archive.display())))?;
    if !out.status.success() {
        return Err(InstallCoreError::Archive(format!(
            "tar could not unpack {}: {}",
            archive.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The folder holding the manifest: the staging folder itself, or its only
/// subfolder (an archive's top-level directory).
fn release_root(stage: &Path) -> Result<PathBuf, InstallCoreError> {
    if stage.join(MANIFEST_FILE).is_file() {
        return Ok(stage.to_path_buf());
    }
    let mut dirs = Vec::new();
    for entry in io(format!("read {}", stage.display()), fs::read_dir(stage))? {
        let p = io("read staged entry", entry)?.path();
        if p.is_dir() {
            dirs.push(p);
        }
    }
    match dirs.as_slice() {
        [only] if only.join(MANIFEST_FILE).is_file() => Ok(only.clone()),
        _ => Err(InstallCoreError::Archive(format!(
            "no {MANIFEST_FILE} at the top of the release or in its single folder"
        ))),
    }
}

fn sha256_file(path: &Path) -> Result<String, InstallCoreError> {
    let bytes = io(format!("read {}", path.display()), fs::read(path))?;
    Ok(Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

/// Owner-only on Unix. On Windows, remove inherited access and grant
/// Administrators and SYSTEM, through `icacls`.
fn restrict_to_admins(dir: &Path) -> Result<(), InstallCoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        io(
            format!("restrict {}", dir.display()),
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)),
        )
    }
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(dir)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])
            .output();
        match out {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(InstallCoreError::Archive(format!(
                "icacls could not restrict {}: {}",
                dir.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            ))),
            Err(e) => Err(InstallCoreError::Archive(format!("cannot run icacls: {e}"))),
        }
    }
}

/// Orders two `major.minor.patch[-pre]` versions; `None` when either is not
/// of that shape. A pre-release sorts before its release; two pre-release
/// tags compare as text.
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    fn parse(v: &str) -> Option<([u64; 3], Option<&str>)> {
        let v = v.strip_prefix('v').unwrap_or(v);
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        let mut it = core.split('.');
        let nums = [it.next()?, it.next()?, it.next()?];
        if it.next().is_some() {
            return None;
        }
        let mut out = [0u64; 3];
        for (o, s) in out.iter_mut().zip(nums) {
            *o = s.parse().ok()?;
        }
        Some((out, pre))
    }
    let (an, ap) = parse(a)?;
    let (bn, bp) = parse(b)?;
    Some(an.cmp(&bn).then_with(|| match (ap, bp) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    }))
}

/// RFC 3339 UTC, whole seconds, from the Unix epoch.
fn rfc3339_utc(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// The verb. Builds the plan, prints it, and with `dry_run` stops there. The
/// elevated half runs in this process, so it needs the privileges to create
/// the staging folder; re-launching itself elevated is a later unit.
pub async fn run(
    source: PathBuf,
    data_dir: Option<PathBuf>,
    allow_downgrade: bool,
    dry_run: bool,
    trusted_root: Option<PathBuf>,
    refresh: bool,
) -> i32 {
    let data_dir = match data_dir
        .or_else(|| crate::setup::data_dir_for(embarch_topology::software::TopologyClass::Local, cfg!(windows)))
    {
        Some(d) => d,
        None => {
            eprintln!("install-core: cannot work out the data folder; pass --data-dir");
            return 1;
        }
    };
    let plan = match Plan::build(&source, &data_dir, allow_downgrade) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("install-core: {e}");
            return 1;
        }
    };
    print!("{}", plan.render());
    if dry_run {
        println!("Dry run: nothing was changed.");
        return 0;
    }
    let trust = match (trusted_root, refresh) {
        (Some(p), _) => TrustRootSource::File(p),
        (None, true) => TrustRootSource::Refresh,
        (None, false) => TrustRootSource::Embedded,
    };
    let root = match load_trust_root(&trust).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("install-core: {e}");
            return 1;
        }
    };
    let label = trust.describe();
    let verifier = |dir: &Path| verify_release_with_root(dir, &root, &label);
    match install_core_elevated(&source, &data_dir, allow_downgrade, &verifier, SystemTime::now()) {
        Ok(r) => {
            println!("INSTALLED suite {} (verified in {})", r.suite_version, r.staging);
            println!("  signed by: {}", r.identity);
            println!("  record:    {}", data_dir.join(RECORD_FILE).display());
            if r.downgraded {
                println!("  note:      older than the previous {}; recorded as a downgrade",
                    r.previous_suite_version.as_deref().unwrap_or("?"));
            }
            0
        }
        Err(e) => {
            eprintln!("install-core: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "embarch-install-core-{name}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn release(version: &str) -> PathBuf {
        let d = tmp("rel");
        fs::write(d.join(MANIFEST_FILE), format!("{{\"suite_version\":\"{version}\"}}")).unwrap();
        fs::write(d.join(locate::native_name("embarch")), b"umbrella").unwrap();
        fs::write(d.join(locate::native_name("embarch-core")), b"core").unwrap();
        d
    }

    fn verified(version: &str) -> Verified {
        Verified {
            suite_version: version.to_string(),
            components: vec![],
            identity: "the-identity".into(),
            issuer: "the-issuer".into(),
            log_time: Some("2026-11-25T00:00:00Z".into()),
            files_checked: 2,
            root: "fake".into(),
        }
    }

    fn ok(version: &'static str) -> impl Fn(&Path) -> Result<Verified, VerifyError> {
        move |dir| {
            assert!(dir.join(MANIFEST_FILE).is_file(), "verifier runs on the staged copy");
            assert!(dir.starts_with(std::env::temp_dir()));
            Ok(verified(version))
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    #[test]
    fn a_passing_release_writes_every_field() {
        let (rel, data) = (release("1.2.0"), tmp("data"));
        let r = install_core_elevated(&rel, &data, false, &ok("1.2.0"), at(1_000_000_000)).unwrap();
        assert_eq!(r.suite_version, "1.2.0");
        assert_eq!(r.identity, "the-identity");
        assert_eq!(r.issuer, "the-issuer");
        assert_eq!(r.log_time.as_deref(), Some("2026-11-25T00:00:00Z"));
        assert_eq!(r.manifest_sha256, sha256_file(&rel.join(MANIFEST_FILE)).unwrap());
        assert_eq!(r.binaries.len(), 2);
        assert_eq!(r.binaries[&locate::native_name("embarch-core")], sha256_file(&rel.join(locate::native_name("embarch-core"))).unwrap());
        assert!(!r.allow_downgrade && !r.downgraded);
        assert_eq!(r.staging, "release-staging/1");
        assert_eq!(r.installed_at, "2001-09-09T01:46:40Z");
        assert!(data.join(STAGING_DIR).join("1").join(MANIFEST_FILE).is_file());
        assert_eq!(read_record(&data).unwrap().unwrap(), r);
    }

    #[test]
    fn a_failing_release_writes_nothing() {
        let (rel, data) = (release("1.2.0"), tmp("data"));
        let bad = |_: &Path| Err(VerifyError::FileMissing("embarch-core".into()));
        let e = install_core_elevated(&rel, &data, false, &bad, at(0)).unwrap_err();
        assert!(matches!(e, InstallCoreError::Verify(_)));
        assert!(!data.join(RECORD_FILE).exists());
        assert_eq!(fs::read_dir(data.join(STAGING_DIR)).unwrap().count(), 0);
    }

    #[test]
    fn a_failure_leaves_an_existing_record_untouched() {
        let (rel, data) = (release("1.2.0"), tmp("data"));
        install_core_elevated(&rel, &data, false, &ok("1.2.0"), at(1)).unwrap();
        let before = fs::read(data.join(RECORD_FILE)).unwrap();
        let bad = |_: &Path| Err(VerifyError::Signature("no".into()));
        assert!(install_core_elevated(&rel, &data, false, &bad, at(2)).is_err());
        assert_eq!(fs::read(data.join(RECORD_FILE)).unwrap(), before);
    }

    #[test]
    fn an_older_suite_is_refused() {
        let data = tmp("data");
        install_core_elevated(&release("1.2.0"), &data, false, &ok("1.2.0"), at(1)).unwrap();
        let before = fs::read(data.join(RECORD_FILE)).unwrap();
        let e = install_core_elevated(&release("1.1.9"), &data, false, &ok("1.1.9"), at(2)).unwrap_err();
        assert!(matches!(e, InstallCoreError::Downgrade { .. }), "{e}");
        assert_eq!(fs::read(data.join(RECORD_FILE)).unwrap(), before);
    }

    #[test]
    fn allow_downgrade_installs_and_records_it() {
        let data = tmp("data");
        install_core_elevated(&release("1.2.0"), &data, false, &ok("1.2.0"), at(1)).unwrap();
        let r = install_core_elevated(&release("1.1.9"), &data, true, &ok("1.1.9"), at(2)).unwrap();
        assert!(r.allow_downgrade && r.downgraded);
        assert_eq!(r.previous_suite_version.as_deref(), Some("1.2.0"));
        assert_eq!(r.staging, "release-staging/2");
        assert_eq!(read_record(&data).unwrap().unwrap().suite_version, "1.1.9");
    }

    #[test]
    fn a_newer_or_equal_suite_is_not_a_downgrade() {
        let data = tmp("data");
        install_core_elevated(&release("1.2.0"), &data, false, &ok("1.2.0"), at(1)).unwrap();
        let r = install_core_elevated(&release("1.2.0"), &data, false, &ok("1.2.0"), at(2)).unwrap();
        assert!(!r.downgraded);
        let r = install_core_elevated(&release("1.10.0"), &data, false, &ok("1.10.0"), at(3)).unwrap();
        assert!(!r.downgraded);
    }

    #[test]
    fn an_unorderable_version_is_refused_without_the_flag() {
        let data = tmp("data");
        install_core_elevated(&release("1.2.0"), &data, false, &ok("1.2.0"), at(1)).unwrap();
        let e = install_core_elevated(&release("weird"), &data, false, &ok("weird"), at(2)).unwrap_err();
        assert!(matches!(e, InstallCoreError::UnorderedVersion { .. }));
        assert!(install_core_elevated(&release("weird"), &data, true, &ok("weird"), at(2)).is_ok());
    }

    #[test]
    fn dry_run_plan_touches_nothing() {
        let (rel, data) = (release("1.2.0"), tmp("data"));
        let plan = Plan::build(&rel, &data, false).unwrap();
        let text = plan.render();
        assert!(text.contains("release-staging") && text.contains("installed-release.json"));
        assert_eq!(fs::read_dir(&data).unwrap().count(), 0);
    }

    #[test]
    fn an_archive_is_unpacked_in_staging() {
        if Command::new("tar").arg("--version").output().is_err() {
            return;
        }
        let rel = release("1.2.0");
        let out = tmp("arch");
        let archive = out.join("suite.tar.gz");
        let st = Command::new("tar")
            .arg("-czf").arg(&archive)
            .arg("-C").arg(rel.parent().unwrap())
            .arg(rel.file_name().unwrap())
            .status().unwrap();
        assert!(st.success());
        let data = tmp("data");
        let r = install_core_elevated(&archive, &data, false, &ok("1.2.0"), at(1)).unwrap();
        assert_eq!(r.binaries.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn staging_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (rel, data) = (release("1.2.0"), tmp("data"));
        install_core_elevated(&rel, &data, false, &ok("1.2.0"), at(1)).unwrap();
        let mode = fs::metadata(data.join(STAGING_DIR)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn version_order() {
        assert_eq!(compare_versions("1.2.0", "1.10.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("1.2.0-rc1", "1.2.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("v2.0.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(compare_versions("x", "1.0.0"), None);
    }

    #[test]
    fn timestamp_formats() {
        assert_eq!(rfc3339_utc(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(at(1_709_164_800)), "2024-02-29T00:00:00Z");
    }
}
