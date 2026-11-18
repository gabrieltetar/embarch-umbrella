//! `embarch verify-release` — is this unpacked suite release exactly what
//! EmbArch's release workflow signed? Offline, by default.
//!
//! Step 3 of `embarch-doc/embarch-release-signing-proposal.md` (EMB-192).
//! The design is the owner's and is not reopened here:
//!
//! 1. `embarch-manifest.json` is verified against its Sigstore bundle under
//!    one exact identity, built from the version the manifest claims, and one
//!    issuer. Never a regular expression, never `any_identity()`.
//! 2. Every file the manifest lists exists with the listed SHA-256.
//! 3. The trust root is the one embedded in the `sigstore-trust-root` crate,
//!    unless `--trusted-root <file>` names one. **Verification never fetches
//!    anything**; only [`TrustRootSource::Refresh`] touches the network, and
//!    it never caches what it got.
//!
//! The check returns a [`Verified`] or a [`VerifyError`] and prints nothing,
//! so the checked elevated install (step 4) can call [`verify_release`].

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_types::Bundle;
use sigstore_verify::{
    Error as SigstoreError, TransparencyLogError, VerificationPolicy, VerificationResult, Verifier,
};

/// The manifest's file name inside a suite release folder.
pub const MANIFEST_FILE: &str = "embarch-manifest.json";
/// Its Sigstore bundle, beside it.
pub const BUNDLE_FILE: &str = "embarch-manifest.json.sigstore.json";

/// The OIDC issuer of a GitHub Actions run.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The identity the suite manifest's certificate must carry: the
/// `assemble-suite.yml` workflow at the tag the manifest names. Exact,
/// because the proposal rules a pattern out.
pub fn suite_identity(suite_version: &str) -> String {
    format!(
        "https://github.com/gabrieltetar/embarch-umbrella/.github/workflows/assemble-suite.yml@refs/tags/suite-v{suite_version}"
    )
}

/// Where the Sigstore trust root comes from.
#[derive(Debug, Clone)]
pub enum TrustRootSource {
    /// The public-good root compiled into this binary. No network.
    Embedded,
    /// An explicit `trusted_root.json`. No network.
    File(PathBuf),
    /// Fetched through TUF for this one run and **never cached**. The only
    /// variant that reaches the network.
    Refresh,
}

impl TrustRootSource {
    /// What the report says about the root, so a reader knows what it rested on.
    pub fn describe(&self) -> String {
        match self {
            TrustRootSource::Embedded => {
                "embedded Sigstore public-good root (compiled in, no network)".to_string()
            }
            TrustRootSource::File(p) => format!("trusted root file {} (no network)", p.display()),
            TrustRootSource::Refresh => {
                "Sigstore root fetched through TUF for this run only (not cached)".to_string()
            }
        }
    }
}

/// A component the manifest names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentInfo {
    pub name: String,
    pub tag: String,
    /// The commit, when the manifest records one (EMB-190's manifest does;
    /// the manifest `doctor` reads today names tags only).
    pub commit: Option<String>,
}

/// What a passing check established.
#[derive(Debug, Clone)]
pub struct Verified {
    pub suite_version: String,
    pub components: Vec<ComponentInfo>,
    /// The certificate identity that signed the manifest.
    pub identity: String,
    pub issuer: String,
    /// The transparency log entry's integrated time, as the crate renders it.
    pub log_time: Option<String>,
    pub files_checked: usize,
    pub root: String,
}

/// Why a check failed. `Display` names what failed.
#[derive(Debug)]
pub enum VerifyError {
    Io { path: PathBuf, source: std::io::Error },
    Manifest(String),
    Bundle(String),
    TrustRoot(String),
    /// The transparency log evidence was not accepted under the trust root in
    /// use. An unknown log key, a key not valid at the entry's time, or a
    /// checkpoint or proof the root cannot vouch for: all what a log shard
    /// newer than the root looks like, so the message names the way out.
    LogNotTrusted { detail: String, root: String },
    /// The signature, identity, issuer, certificate or log evidence failed.
    Signature(String),
    /// The manifest lists a path that is absolute or climbs out of the folder.
    UnsafePath(String),
    FileMissing(String),
    FileMismatch { path: String, expected: String, actual: String },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Io { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            VerifyError::Manifest(m) => write!(f, "{MANIFEST_FILE} is unusable: {m}"),
            VerifyError::Bundle(m) => write!(f, "{BUNDLE_FILE} is unusable: {m}"),
            VerifyError::TrustRoot(m) => write!(f, "trust root unusable: {m}"),
            VerifyError::LogNotTrusted { detail, root } => write!(
                f,
                "the transparency log evidence is not accepted under the trust root in use \
                 ({root}): {detail}. If this release was logged to a newer log shard than \
                 the root knows, its log key is not in it: re-run with --refresh-trust-root \
                 (fetches the root through TUF for that one run, never caches it) or pass \
                 --trusted-root <file>"
            ),
            VerifyError::Signature(m) => {
                write!(f, "the manifest's signature check failed: {m}")
            }
            VerifyError::UnsafePath(p) => write!(
                f,
                "the manifest lists {p:?}, which is not a plain relative path inside the release folder"
            ),
            VerifyError::FileMissing(p) => write!(f, "listed file is missing: {p}"),
            VerifyError::FileMismatch { path, expected, actual } => write!(
                f,
                "{path}: SHA-256 is {actual}, the manifest says {expected}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// A component entry is a bare tag today and an object once the signed
/// manifest records commits.
#[derive(Deserialize)]
#[serde(untagged)]
enum ComponentEntry {
    Tag(String),
    Detail { tag: String, #[serde(default)] commit: Option<String> },
}

#[derive(Deserialize)]
struct SignedManifest {
    suite_version: String,
    #[serde(default)]
    components: BTreeMap<String, ComponentEntry>,
    /// Relative path to SHA-256, lowercase hex.
    #[serde(default)]
    files: BTreeMap<String, String>,
}

/// Load the trust root a [`TrustRootSource`] names. The only call here that
/// can reach the network is the `Refresh` arm.
pub async fn load_trust_root(source: &TrustRootSource) -> Result<TrustedRoot, VerifyError> {
    match source {
        TrustRootSource::Embedded => TrustedRoot::from_embedded(SigstoreInstance::PublicGood)
            .map_err(|e| VerifyError::TrustRoot(e.to_string())),
        TrustRootSource::File(path) => {
            let json = std::fs::read_to_string(path)
                .map_err(|source| VerifyError::Io { path: path.clone(), source })?;
            TrustedRoot::from_json(&json).map_err(|e| VerifyError::TrustRoot(e.to_string()))
        }
        TrustRootSource::Refresh => {
            // `without_cache`: a cached root in a folder the engineer's account
            // can write could be swapped (the proposal's reason).
            let config = sigstore_trust_root::tuf::TufConfig::production().without_cache();
            TrustedRoot::from_tuf(config)
                .await
                .map_err(|e| VerifyError::TrustRoot(format!("TUF refresh failed: {e}")))
        }
    }
}

/// Check the release in `dir`: the manifest's signature, then every listed
/// file's hash. Prints nothing.
pub async fn verify_release(dir: &Path, source: &TrustRootSource) -> Result<Verified, VerifyError> {
    let root = load_trust_root(source).await?;
    verify_release_with_root(dir, &root, &source.describe())
}

/// [`verify_release`] with a root already in hand. Synchronous and offline.
pub fn verify_release_with_root(
    dir: &Path,
    root: &TrustedRoot,
    root_label: &str,
) -> Result<Verified, VerifyError> {
    let manifest_path = dir.join(MANIFEST_FILE);
    let bundle_path = dir.join(BUNDLE_FILE);
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|source| VerifyError::Io { path: manifest_path.clone(), source })?;
    let bundle_json = std::fs::read_to_string(&bundle_path)
        .map_err(|source| VerifyError::Io { path: bundle_path.clone(), source })?;

    // The same bytes are verified and then parsed, so nothing is read twice.
    // The version is read first only to build the identity it must match.
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| VerifyError::Manifest(e.to_string()))?;

    let identity = suite_identity(&manifest.suite_version);
    let result = verify_blob_bundle(
        root,
        root_label,
        manifest_bytes.as_slice(),
        &bundle_json,
        &identity,
        GITHUB_ACTIONS_ISSUER,
    )?;

    let files_checked = check_files(dir, &manifest.files)?;

    Ok(Verified {
        suite_version: manifest.suite_version,
        components: manifest
            .components
            .into_iter()
            .map(|(name, entry)| match entry {
                ComponentEntry::Tag(tag) => ComponentInfo { name, tag, commit: None },
                ComponentEntry::Detail { tag, commit } => ComponentInfo { name, tag, commit },
            })
            .collect(),
        identity: result.identity().map(|i| i.as_str().to_string()).unwrap_or(identity),
        issuer: result.issuer().unwrap_or(GITHUB_ACTIONS_ISSUER).to_string(),
        log_time: result.integrated_time().map(|t| t.to_string()),
        files_checked,
        root: root_label.to_string(),
    })
}

/// Verify an artifact (bytes or a [`Sha256Hash`]) against a bundle under an
/// exact identity and issuer.
fn verify_blob_bundle<'a>(
    root: &TrustedRoot,
    root_label: &str,
    artifact: impl Into<sigstore_types::Artifact<'a>>,
    bundle_json: &str,
    identity: &str,
    issuer: &str,
) -> Result<VerificationResult, VerifyError> {
    let bundle = Bundle::from_json(bundle_json).map_err(|e| VerifyError::Bundle(e.to_string()))?;
    let verifier = Verifier::new(root).map_err(|e| VerifyError::TrustRoot(e.to_string()))?;
    let policy = VerificationPolicy::new(identity, issuer);
    verifier.verify(artifact, &bundle, &policy).map_err(|e| match e {
        SigstoreError::TransparencyLog(
            log @ (TransparencyLogError::UnknownLog { .. }
            | TransparencyLogError::InclusionPromise(_)
            | TransparencyLogError::InclusionProof(_)
            | TransparencyLogError::Checkpoint(_)),
        ) => VerifyError::LogNotTrusted { detail: log.to_string(), root: root_label.to_string() },
        other => VerifyError::Signature(other.to_string()),
    })
}

/// Every listed file exists under `dir` with the listed SHA-256. Returns how
/// many it checked.
fn check_files(dir: &Path, files: &BTreeMap<String, String>) -> Result<usize, VerifyError> {
    for (rel, expected) in files {
        let rel_path = Path::new(rel);
        let plain = !rel.is_empty()
            && rel_path.components().all(|c| matches!(c, Component::Normal(_)));
        if !plain {
            return Err(VerifyError::UnsafePath(rel.clone()));
        }
        let path = dir.join(rel_path);
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VerifyError::FileMissing(rel.clone()));
            }
            Err(source) => return Err(VerifyError::Io { path, source }),
        };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|source| VerifyError::Io { path: path.clone(), source })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hex_lower(&hasher.finalize());
        if !actual.eq_ignore_ascii_case(expected.trim()) {
            return Err(VerifyError::FileMismatch {
                path: rel.clone(),
                expected: expected.clone(),
                actual,
            });
        }
    }
    Ok(files.len())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `verify-release` verb: check `dir`, print the report, return the exit
/// code (0 only when everything checked).
pub async fn run(dir: Option<PathBuf>, trusted_root: Option<PathBuf>, refresh: bool) -> i32 {
    let dir = match dir.or_else(|| std::env::current_exe().ok()?.parent().map(Path::to_path_buf)) {
        Some(d) => d,
        None => {
            eprintln!("verify-release: cannot work out the running binary's folder; pass DIR");
            return 1;
        }
    };
    let source = match (trusted_root, refresh) {
        (Some(path), _) => TrustRootSource::File(path),
        (None, true) => TrustRootSource::Refresh,
        (None, false) => TrustRootSource::Embedded,
    };
    println!("Checking {} with {}", dir.display(), source.describe());
    match verify_release(&dir, &source).await {
        Ok(v) => {
            println!("VERIFIED suite {}", v.suite_version);
            for c in &v.components {
                match &c.commit {
                    Some(commit) => println!("  {}: {} ({commit})", c.name, c.tag),
                    None => println!("  {}: {} (commit not recorded in the manifest)", c.name, c.tag),
                }
            }
            println!("  signed by: {}", v.identity);
            println!("  issuer:    {}", v.issuer);
            println!("  logged at: {}", v.log_time.as_deref().unwrap_or("unknown"));
            println!("  files:     {} checked, all match", v.files_checked);
            println!("  root:      {}", v.root);
            0
        }
        Err(e) => {
            eprintln!("NOT VERIFIED: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::Sha256Hash;

    const COSIGN_BUNDLE: &str = include_str!("../tests/fixtures/cosign-linux-amd64.sigstore.json");
    const COSIGN_DIGEST: &str = "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa";
    const COSIGN_IDENTITY: &str = "keyless@projectsigstore.iam.gserviceaccount.com";
    const COSIGN_ISSUER: &str = "https://accounts.google.com";

    const UV_BUNDLE: &str =
        include_str!("../tests/fixtures/uv-0.13.8-linux-gnu.attestation.sigstore.json");
    const UV_DIGEST: &str = "5acfd9177cfecf0bf87578f059728215ccc884388988f55f7a65041b57387d91";
    const UV_IDENTITY: &str =
        "https://github.com/astral-sh/uv/.github/workflows/release.yml@refs/heads/main";

    const OTHER_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn embedded() -> TrustedRoot {
        TrustedRoot::from_embedded(SigstoreInstance::PublicGood).unwrap()
    }

    fn check(
        bundle: &str,
        digest: &str,
        identity: &str,
        issuer: &str,
    ) -> Result<VerificationResult, VerifyError> {
        verify_blob_bundle(
            &embedded(),
            "test root",
            Sha256Hash::from_hex(digest).unwrap(),
            bundle,
            identity,
            issuer,
        )
    }

    fn assert_signature_error(r: Result<VerificationResult, VerifyError>, needle: &str) {
        match r {
            Err(VerifyError::Signature(m)) => {
                assert!(m.contains(needle), "{m:?} should mention {needle:?}")
            }
            Err(other) => panic!("wrong error kind: {other}"),
            Ok(_) => panic!("verification should have failed"),
        }
    }

    #[test]
    fn cosign_fixture_verifies() {
        let r = check(COSIGN_BUNDLE, COSIGN_DIGEST, COSIGN_IDENTITY, COSIGN_ISSUER).unwrap();
        assert_eq!(r.identity().unwrap().as_str(), COSIGN_IDENTITY);
        assert!(r.integrated_time().is_some());
    }

    #[test]
    fn cosign_fixture_fails_on_wrong_identity_issuer_and_digest() {
        assert_signature_error(
            check(COSIGN_BUNDLE, COSIGN_DIGEST, "someone@example.com", COSIGN_ISSUER),
            "identity mismatch",
        );
        assert_signature_error(
            check(COSIGN_BUNDLE, COSIGN_DIGEST, COSIGN_IDENTITY, GITHUB_ACTIONS_ISSUER),
            "issuer mismatch",
        );
        assert!(check(COSIGN_BUNDLE, OTHER_DIGEST, COSIGN_IDENTITY, COSIGN_ISSUER).is_err());
    }

    #[test]
    fn uv_fixture_verifies() {
        let r = check(UV_BUNDLE, UV_DIGEST, UV_IDENTITY, GITHUB_ACTIONS_ISSUER).unwrap();
        assert_eq!(r.identity().unwrap().as_str(), UV_IDENTITY);
        assert!(r.integrated_time().is_some());
    }

    #[test]
    fn uv_fixture_fails_on_wrong_identity_issuer_and_digest() {
        // Same workflow, a different ref: an exact match must refuse it.
        assert_signature_error(
            check(
                UV_BUNDLE,
                UV_DIGEST,
                "https://github.com/astral-sh/uv/.github/workflows/release.yml@refs/heads/other",
                GITHUB_ACTIONS_ISSUER,
            ),
            "identity mismatch",
        );
        assert_signature_error(
            check(UV_BUNDLE, UV_DIGEST, UV_IDENTITY, COSIGN_ISSUER),
            "issuer mismatch",
        );
        assert!(check(UV_BUNDLE, OTHER_DIGEST, UV_IDENTITY, GITHUB_ACTIONS_ISSUER).is_err());
    }

    #[test]
    fn a_log_key_missing_from_the_root_names_refresh_trust_root() {
        // The embedded root with its transparency-log keys removed: the same
        // situation as a release logged to a shard newer than the root.
        let mut json: serde_json::Value =
            serde_json::from_str(SigstoreInstance::PublicGood.embedded_trusted_root_json()).unwrap();
        json["tlogs"] = serde_json::json!([]);
        let root = TrustedRoot::from_json(&json.to_string()).unwrap();
        let err = verify_blob_bundle(
            &root,
            "root without log keys",
            Sha256Hash::from_hex(COSIGN_DIGEST).unwrap(),
            COSIGN_BUNDLE,
            COSIGN_IDENTITY,
            COSIGN_ISSUER,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::LogNotTrusted { .. }), "{err}");
        assert!(err.to_string().contains("--refresh-trust-root"), "{err}");
    }

    #[test]
    fn log_not_trusted_text_names_the_flag() {
        let text = VerifyError::LogNotTrusted { detail: "unknown transparency log abc".into(), root: "embedded".into() }
            .to_string();
        assert!(text.contains("--refresh-trust-root"));
        assert!(text.contains("--trusted-root"));
        assert!(text.contains("never caches"));
        assert!(text.contains("unknown transparency log abc"));
    }

    #[test]
    fn suite_identity_is_exact() {
        assert_eq!(
            suite_identity("0.2.0"),
            "https://github.com/gabrieltetar/embarch-umbrella/.github/workflows/assemble-suite.yml@refs/tags/suite-v0.2.0"
        );
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("embarch-verify-release-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sha(bytes: &[u8]) -> String {
        hex_lower(&Sha256::digest(bytes))
    }

    #[test]
    fn file_hashes_pass_then_fail_on_missing_and_changed_byte() {
        let dir = tmp("files");
        std::fs::write(dir.join("embarch"), b"binary one").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/fw.bin"), b"firmware").unwrap();
        let mut files = BTreeMap::new();
        files.insert("embarch".to_string(), sha(b"binary one"));
        files.insert("sub/fw.bin".to_string(), sha(b"firmware"));

        assert_eq!(check_files(&dir, &files).unwrap(), 2);

        // A changed byte.
        std::fs::write(dir.join("embarch"), b"binary onE").unwrap();
        match check_files(&dir, &files) {
            Err(VerifyError::FileMismatch { path, .. }) => assert_eq!(path, "embarch"),
            other => panic!("expected a mismatch, got {other:?}"),
        }
        std::fs::write(dir.join("embarch"), b"binary one").unwrap();

        // A missing file.
        std::fs::remove_file(dir.join("sub/fw.bin")).unwrap();
        match check_files(&dir, &files) {
            Err(VerifyError::FileMissing(p)) => assert_eq!(p, "sub/fw.bin"),
            other => panic!("expected a missing file, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_paths_must_stay_inside_the_folder() {
        let dir = tmp("paths");
        for bad in ["../outside", "/etc/passwd", "a/../../b", ""] {
            let mut files = BTreeMap::new();
            files.insert(bad.to_string(), sha(b""));
            assert!(matches!(check_files(&dir, &files), Err(VerifyError::UnsafePath(_))), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_folder_without_a_manifest_fails_by_name() {
        let dir = tmp("empty");
        let err = verify_release_with_root(&dir, &embedded(), "test").unwrap_err();
        assert!(err.to_string().contains(MANIFEST_FILE), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_with_a_bundle_for_another_artifact_is_refused() {
        // The manifest bytes are not what the cosign bundle signed, and the
        // identity is the suite workflow's, so verification must fail before
        // any file is looked at.
        let dir = tmp("wrongbundle");
        std::fs::write(dir.join(MANIFEST_FILE), br#"{"suite_version":"9.9.9","files":{}}"#).unwrap();
        std::fs::write(dir.join(BUNDLE_FILE), COSIGN_BUNDLE).unwrap();
        let err = verify_release_with_root(&dir, &embedded(), "test").unwrap_err();
        assert!(matches!(err, VerifyError::Signature(_)), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn components_accept_a_bare_tag_or_a_tag_with_commit() {
        let m: SignedManifest = serde_json::from_str(
            r#"{"suite_version":"0.2.0","components":{
                "embarch":"v0.2.0",
                "embarch-core":{"tag":"v0.1.4","commit":"72bbd52f"}},
               "files":{}}"#,
        )
        .unwrap();
        assert!(matches!(m.components["embarch"], ComponentEntry::Tag(_)));
        assert!(matches!(&m.components["embarch-core"], ComponentEntry::Detail { commit: Some(c), .. } if c == "72bbd52f"));
    }
}
