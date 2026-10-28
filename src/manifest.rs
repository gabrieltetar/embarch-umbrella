//! Reads the suite manifest a combined release archive carries
//! (`.github/workflows/assemble-suite.yml`), so `doctor`'s check 1 can
//! compare what's actually installed against what the archive said it
//! shipped (decision 14, and decision 24 for why a mismatch is a warning
//! rather than a refusal: "`doctor` warns when the installed
//! component versions don't match the suite manifest").
//!
//! Absent entirely for anyone who didn't install from a suite archive (a
//! per-repo release, or a debug build like the ones this crate's own tests
//! run against) — that's not an error, just nothing to compare against, and
//! check 1 says so rather than treating it as a failure.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub suite_version: String,
    #[serde(default)]
    pub target: String,
    pub components: Components,
}

#[derive(Debug, Deserialize)]
pub struct Components {
    pub embarch: String,
    #[serde(rename = "embarch-core")]
    pub embarch_core: String,
    #[serde(rename = "embarch-api")]
    pub embarch_api: String,
}

/// The manifest sits next to the three binaries in a combined suite
/// archive — the same directory this binary itself runs from, per
/// `locate.rs`'s sibling-lookup convention.
pub fn find_next_to_me() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let candidate = dir.join("embarch-manifest.json");
    candidate.is_file().then_some(candidate)
}

pub fn load(path: &Path) -> Option<Manifest> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Strip a leading `v` from a release tag (`v0.1.0` -> `0.1.0`), so it can be
/// compared against the plain version number `--version` prints.
pub fn normalize_tag(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Pull the version number out of a `--version` line — the field after the
/// binary name: `"embarch-core 0.1.0"` and
/// `"embarch-core 0.1.0 (commit 72bbd52f, dirty)"` both give `"0.1.0"`.
///
/// It read the **last** field until decision 57 put the commit after the
/// version; the first field after the name is the one both shapes share. A
/// line with only one field is taken as the version itself, as the old
/// reading also did.
pub fn version_from_output(output: &str) -> Option<&str> {
    let mut fields = output.split_whitespace();
    let first = fields.next()?;
    Some(fields.next().unwrap_or(first))
}

/// Does an actual `--version` output agree with what the manifest recorded
/// for that component (a release tag)?
pub fn agrees(manifest_tag: &str, actual_version_output: &str) -> bool {
    version_from_output(actual_version_output)
        .map(|actual| actual == normalize_tag(manifest_tag))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_leading_v() {
        assert_eq!(normalize_tag("v0.1.0"), "0.1.0");
        assert_eq!(normalize_tag("0.1.0"), "0.1.0");
    }

    #[test]
    fn version_from_output_takes_the_field_after_the_name() {
        assert_eq!(version_from_output("embarch-core 0.1.0"), Some("0.1.0"));
        assert_eq!(version_from_output("embarch-api 0.1.0\n"), Some("0.1.0"));
    }

    #[test]
    fn version_from_output_reads_past_the_commit_decision_57_added() {
        assert_eq!(version_from_output("embarch-core 0.1.4 (commit 72bbd52f)"), Some("0.1.4"));
        assert_eq!(version_from_output("embarch-api 0.1.0 (commit 744b94be, dirty)\n"), Some("0.1.0"));
        assert_eq!(version_from_output("embarch-core 0.1.4 (commit unknown)"), Some("0.1.4"));
        assert!(agrees("v0.1.4", "embarch-core 0.1.4 (commit 72bbd52f, dirty)"));
    }

    #[test]
    fn version_from_empty_output_is_none() {
        assert_eq!(version_from_output(""), None);
        assert_eq!(version_from_output("   "), None);
    }

    #[test]
    fn agrees_when_versions_match_modulo_the_v_prefix() {
        assert!(agrees("v0.1.0", "embarch-core 0.1.0"));
        assert!(!agrees("v0.2.0", "embarch-core 0.1.0"));
    }

    #[test]
    fn manifest_json_round_trips() {
        let raw = r#"{
            "suite_version": "0.1.0",
            "target": "x86_64-unknown-linux-gnu",
            "components": {
                "embarch": "v0.1.0",
                "embarch-core": "v0.1.0",
                "embarch-api": "v0.1.0"
            }
        }"#;
        let m: Manifest = serde_json::from_str(raw).unwrap();
        assert_eq!(m.suite_version, "0.1.0");
        assert_eq!(m.components.embarch_core, "v0.1.0");
    }
}
