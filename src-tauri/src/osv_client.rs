//! OSV (Open Source Vulnerabilities) client.
//!
//! Queries https://api.osv.dev/v1/query for advisories affecting a specific
//! package + version. This is the real vulnerability source for Strazh: no
//! bundled sample SBOM and no hardcoded CVE. A package is only reported as
//! vulnerable when OSV returns an advisory for the exact version declared in
//! the scanned repository's own manifest.

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// One advisory returned by OSV for a queried package+version.
#[derive(Clone, Debug, Serialize)]
pub struct OsvAdvisory {
    pub id: String,              // e.g. GHSA-xxxx or CVE-YYYY-NNNN
    pub summary: Option<String>,
    pub details: Option<String>, // longer advisory text when OSV supplies it
    pub severity: Option<String>, // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    pub aliases: Vec<String>,     // other ids (e.g. CVE id for a GHSA)
    /// First "fixed" version OSV reports for the queried package, if any.
    /// This is verified advisory evidence — the basis for an upgrade rec.
    pub fixed_version: Option<String>,
}

/// Map a Strazh build system to an OSV ecosystem string.
/// Returns None for build systems OSV does not index by name here.
pub fn ecosystem_for(build_system: &str) -> Option<&'static str> {
    match build_system {
        "cargo" => Some("crates.io"),
        "npm" => Some("npm"),
        "python" => Some("PyPI"),
        "go" => Some("Go"),
        "maven" | "gradle" => Some("Maven"),
        "ruby" => Some("RubyGems"),
        _ => None,
    }
}

/// Normalize a declared version string into a concrete version OSV can match.
/// OSV's `version` query wants an exact version, so we strip common range
/// operators (^, ~, >=, etc.). If nothing concrete remains, returns None and
/// the caller skips the query (we never guess).
pub fn concrete_version(raw: &str) -> Option<String> {
    let v = raw.trim().trim_matches('"').trim();
    if v.is_empty() || v == "*" || v.eq_ignore_ascii_case("latest") {
        return None;
    }
    // Strip a leading range operator and take the first token.
    let cleaned = v
        .trim_start_matches(|c: char| matches!(c, '^' | '~' | '=' | '>' | '<' | ' '))
        .split(|c: char| c == ',' || c == ' ' || c == '|')
        .next()
        .unwrap_or("")
        .trim();
    // Require it to start with a digit so we don't send a range like "x".
    if cleaned.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        Some(cleaned.to_string())
    } else {
        None
    }
}

pub struct OsvClient {
    client: Client,
}

#[derive(Serialize)]
struct Package<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    version: &'a str,
    package: Package<'a>,
}

impl OsvClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder().build()?,
        })
    }

    /// Query OSV for advisories affecting `name`@`version` in `ecosystem`.
    /// Returns an empty vec when OSV reports no vulnerabilities.
    pub async fn query(
        &self,
        name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<OsvAdvisory>> {
        let body = OsvQuery {
            version,
            package: Package { name, ecosystem },
        };

        let resp = self.client.post(OSV_QUERY_URL).json(&body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("OSV query error {}: {}", status, txt));
        }

        let parsed: serde_json::Value = resp.json().await?;
        let mut out = Vec::new();
        if let Some(vulns) = parsed["vulns"].as_array() {
            for v in vulns {
                let id = v["id"].as_str().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let summary = v["summary"].as_str().map(|s| s.to_string());
                let details = v["details"].as_str().map(|s| s.to_string());
                let aliases = v["aliases"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let severity = extract_severity(v);
                let fixed_version = extract_fixed_version(v, name, ecosystem, version);
                out.push(OsvAdvisory {
                    id,
                    summary,
                    details,
                    severity,
                    aliases,
                    fixed_version,
                });
            }
        }
        Ok(out)
    }
}

/// Extract the advisory-reported fixed version that applies to the SCANNED
/// version of the queried package.
///
/// Correctness requirements:
///   - the `affected[]` entry must match the queried package name AND ecosystem;
///   - only ECOSYSTEM-typed ranges are usable (GIT ranges carry commit hashes,
///     not versions, so we ignore them);
///   - a range is a sorted list of events forming intervals
///     [introduced, fixed). The fixed version that applies is the one closing
///     the interval that CONTAINS the scanned version;
///   - version comparison is numeric/segment-based, never lexical;
///   - if the scanned version is already at/after every reported fix (already
///     fixed), or applicability cannot be determined, return None so the UI
///     shows "Fix version not determined" rather than an arbitrary version.
pub fn extract_fixed_version(
    v: &serde_json::Value,
    pkg_name: &str,
    ecosystem: &str,
    scanned_version: &str,
) -> Option<String> {
    let affected = v["affected"].as_array()?;
    let pkg_lower = pkg_name.to_lowercase();

    for a in affected {
        // Package name must match when present.
        if let Some(n) = a["package"]["name"].as_str() {
            if n.to_lowercase() != pkg_lower {
                continue;
            }
        }
        // Ecosystem must match when present.
        if let Some(eco) = a["package"]["ecosystem"].as_str() {
            if !eco.eq_ignore_ascii_case(ecosystem) {
                continue;
            }
        }

        let Some(ranges) = a["ranges"].as_array() else { continue };
        for r in ranges {
            // Only version-typed ranges (SEMVER / ECOSYSTEM). Skip GIT.
            if let Some(t) = r["type"].as_str() {
                if t.eq_ignore_ascii_case("git") {
                    continue;
                }
            }
            let Some(events) = r["events"].as_array() else { continue };

            // Collect ordered (kind, version) events.
            let mut evs: Vec<(&str, String)> = Vec::new();
            for e in events {
                if let Some(x) = e["introduced"].as_str() {
                    evs.push(("introduced", x.to_string()));
                } else if let Some(x) = e["fixed"].as_str() {
                    evs.push(("fixed", x.to_string()));
                } else if e.get("last_affected").is_some() {
                    // last_affected means no fixed version is published for this branch.
                    evs.push(("last_affected", e["last_affected"].as_str().unwrap_or("").to_string()));
                }
            }

            // Walk intervals: an "introduced" opens affected; a "fixed" closes it.
            // The scanned version is affected if introduced <= scanned (introduced
            // "0" means from the beginning) and (no fixed yet OR scanned < fixed).
            let mut open_introduced: Option<String> = None;
            for (kind, ver) in &evs {
                match *kind {
                    "introduced" => {
                        open_introduced = Some(ver.clone());
                    }
                    "fixed" => {
                        if let Some(intro) = &open_introduced {
                            let in_range = version_in_range(scanned_version, intro, Some(ver), ecosystem);
                            match in_range {
                                Some(true) => return Some(ver.trim().to_string()),
                                // scanned not in this interval -> keep scanning
                                Some(false) => {}
                                // comparison undeterminable -> don't guess
                                None => return None,
                            }
                        }
                        open_introduced = None;
                    }
                    _ => {
                        // last_affected: branch has no fix; close interval.
                        open_introduced = None;
                    }
                }
            }
        }
    }
    None
}

/// True if `introduced <= scanned < fixed` (fixed optional). Returns None when
/// any comparison is undeterminable (so callers can refuse to guess).
fn version_in_range(
    scanned: &str,
    introduced: &str,
    fixed: Option<&str>,
    ecosystem: &str,
) -> Option<bool> {
    // "0" / empty introduced means "from the beginning".
    let after_intro = if introduced.trim().is_empty() || introduced.trim() == "0" {
        true
    } else {
        match compare_versions(scanned, introduced, ecosystem) {
            Some(o) => o != std::cmp::Ordering::Less, // scanned >= introduced
            None => return None,
        }
    };
    if !after_intro {
        return Some(false);
    }
    if let Some(f) = fixed {
        match compare_versions(scanned, f, ecosystem) {
            Some(o) => Some(o == std::cmp::Ordering::Less), // scanned < fixed
            None => None,
        }
    } else {
        Some(true)
    }
}

/// Ecosystem-aware version comparison. Numeric/segment based — never lexical.
/// Returns None when the versions cannot be compared reliably (e.g. unexpected
/// epoch/local forms), so callers avoid guessing.
///
/// Handles the common dotted numeric forms used by PyPI, npm, crates.io, Maven,
/// Go, RubyGems, with a conservative pre-release rule (a version carrying a
/// pre-release suffix sorts BEFORE the same core release).
pub fn compare_versions(a: &str, b: &str, _ecosystem: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    let (a_core, a_pre) = split_release_pre(a);
    let (b_core, b_pre) = split_release_pre(b);

    let a_nums = numeric_segments(&a_core)?;
    let b_nums = numeric_segments(&b_core)?;

    let n = a_nums.len().max(b_nums.len());
    for i in 0..n {
        let av = *a_nums.get(i).unwrap_or(&0);
        let bv = *b_nums.get(i).unwrap_or(&0);
        if av != bv {
            return Some(av.cmp(&bv));
        }
    }
    // Cores equal: a release with NO pre-release outranks one WITH a pre-release.
    match (a_pre, b_pre) {
        (false, true) => Some(Ordering::Greater),
        (true, false) => Some(Ordering::Less),
        _ => Some(Ordering::Equal),
    }
}

/// Split "1.2.3rc1" / "1.2.3-alpha" / "1.2.3.dev0" into ("1.2.3", has_prerelease).
fn split_release_pre(v: &str) -> (String, bool) {
    let v = v.trim();
    // Find the first character that is not a digit or '.'; everything from there
    // on (e.g. "-rc1", "a1", ".dev0", "+local") is treated as a pre/meta marker.
    let mut core_end = v.len();
    for (i, c) in v.char_indices() {
        if !(c.is_ascii_digit() || c == '.') {
            core_end = i;
            break;
        }
    }
    let core = &v[..core_end];
    let rest = &v[core_end..];
    // Build metadata is not a pre-release; a leading '+' means only metadata.
    let has_pre = !rest.is_empty() && !rest.starts_with('+');
    (core.trim_end_matches('.').to_string(), has_pre)
}

/// Parse dotted numeric core into u64 segments. None if any segment isn't numeric.
fn numeric_segments(core: &str) -> Option<Vec<u64>> {
    if core.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for seg in core.split('.') {
        if seg.is_empty() {
            continue;
        }
        match seg.parse::<u64>() {
            Ok(n) => out.push(n),
            Err(_) => return None,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Pull a coarse severity label out of an OSV record.
/// Prefers the `database_specific.severity` label (GHSA style), falls back to
/// classifying a CVSS vector/score if present.
fn extract_severity(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v["database_specific"]["severity"].as_str() {
        return Some(s.to_uppercase());
    }
    // severity: [{ type: "CVSS_V3", score: "CVSS:3.1/.../A:H" | "9.8" }]
    if let Some(arr) = v["severity"].as_array() {
        for s in arr {
            if let Some(score) = s["score"].as_str() {
                if let Some(num) = parse_cvss_base(score) {
                    return Some(classify_cvss(num));
                }
                // Not a numeric score; if it's a vector we can't trivially parse,
                // report UNKNOWN rather than guess.
            }
        }
        return Some("UNKNOWN".to_string());
    }
    None
}

fn parse_cvss_base(score: &str) -> Option<f64> {
    // Accept a plain number like "9.8".
    score.trim().parse::<f64>().ok()
}

fn classify_cvss(score: f64) -> String {
    if score >= 9.0 {
        "CRITICAL".into()
    } else if score >= 7.0 {
        "HIGH".into()
    } else if score >= 4.0 {
        "MEDIUM".into()
    } else {
        "LOW".into()
    }
}

// ══════════════════════════════════════════════════════
//  Regression tests for fixed-version matching
// ══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cmp::Ordering;

    // Helper: one advisory with a single affected entry.
    fn advisory(pkg: &str, eco: &str, ranges: serde_json::Value) -> serde_json::Value {
        json!({
            "id": "TEST-0001",
            "affected": [ { "package": { "name": pkg, "ecosystem": eco }, "ranges": ranges } ]
        })
    }

    fn eco_range(events: serde_json::Value) -> serde_json::Value {
        json!([ { "type": "ECOSYSTEM", "events": events } ])
    }

    #[test]
    fn version_comparison_is_numeric_not_lexical() {
        // Lexical sort would put "1.10.0" < "1.9.0"; numeric must not.
        assert_eq!(compare_versions("1.10.0", "1.9.0", "PyPI"), Some(Ordering::Greater));
        assert_eq!(compare_versions("1.2.3", "1.2.3", "npm"), Some(Ordering::Equal));
        assert_eq!(compare_versions("2.0.0", "10.0.0", "crates.io"), Some(Ordering::Less));
        // pre-release sorts before its release
        assert_eq!(compare_versions("1.0.0rc1", "1.0.0", "PyPI"), Some(Ordering::Less));
        assert_eq!(compare_versions("1.0.0", "1.0.0-alpha", "npm"), Some(Ordering::Greater));
        // build metadata is not a pre-release
        assert_eq!(compare_versions("1.0.0+build", "1.0.0", "crates.io"), Some(Ordering::Equal));
        // undeterminable -> None (don't guess)
        assert_eq!(compare_versions("weird", "1.0.0", "PyPI"), None);
    }

    #[test]
    fn matched_package_single_range_returns_fix() {
        let v = advisory("agno", "PyPI", eco_range(json!([
            { "introduced": "0" }, { "fixed": "2.3.24" }
        ])));
        // scanned 1.7.2 is in [0, 2.3.24) -> fixed 2.3.24
        assert_eq!(extract_fixed_version(&v, "agno", "PyPI", "1.7.2"), Some("2.3.24".into()));
    }

    #[test]
    fn mismatched_package_returns_none() {
        let v = advisory("agno", "PyPI", eco_range(json!([
            { "introduced": "0" }, { "fixed": "2.3.24" }
        ])));
        assert_eq!(extract_fixed_version(&v, "other-pkg", "PyPI", "1.7.2"), None);
    }

    #[test]
    fn mismatched_ecosystem_returns_none() {
        let v = advisory("agno", "PyPI", eco_range(json!([
            { "introduced": "0" }, { "fixed": "2.3.24" }
        ])));
        // Same name, wrong ecosystem (npm) -> not applicable.
        assert_eq!(extract_fixed_version(&v, "agno", "npm", "1.7.2"), None);
    }

    #[test]
    fn multiple_ranges_picks_the_branch_containing_scanned_version() {
        // Two release branches: [1.0,1.4.2) fixed 1.4.2, and [2.0,2.1.0) fixed 2.1.0.
        let v = advisory("pkg", "PyPI", eco_range(json!([
            { "introduced": "1.0" }, { "fixed": "1.4.2" },
            { "introduced": "2.0" }, { "fixed": "2.1.0" }
        ])));
        assert_eq!(extract_fixed_version(&v, "pkg", "PyPI", "1.3.0"), Some("1.4.2".into()));
        assert_eq!(extract_fixed_version(&v, "pkg", "PyPI", "2.0.5"), Some("2.1.0".into()));
    }

    #[test]
    fn already_fixed_version_returns_none() {
        // scanned 2.5.0 is at/after the fix 2.3.24 -> not in affected interval.
        let v = advisory("agno", "PyPI", eco_range(json!([
            { "introduced": "0" }, { "fixed": "2.3.24" }
        ])));
        assert_eq!(extract_fixed_version(&v, "agno", "PyPI", "2.5.0"), None);
    }

    #[test]
    fn missing_fixed_event_returns_none() {
        // Range with only an introduced event (no fix published).
        let v = advisory("agno", "PyPI", eco_range(json!([ { "introduced": "0" } ])));
        assert_eq!(extract_fixed_version(&v, "agno", "PyPI", "1.7.2"), None);
    }

    #[test]
    fn last_affected_branch_has_no_fix() {
        let v = advisory("pkg", "PyPI", eco_range(json!([
            { "introduced": "1.0" }, { "last_affected": "1.9.9" }
        ])));
        assert_eq!(extract_fixed_version(&v, "pkg", "PyPI", "1.5.0"), None);
    }

    #[test]
    fn git_ranges_are_ignored() {
        // A GIT range carries commit hashes, not versions; must be skipped.
        let v = advisory("pkg", "PyPI", json!([
            { "type": "GIT", "events": [ { "introduced": "0" }, { "fixed": "abc123def" } ] }
        ]));
        assert_eq!(extract_fixed_version(&v, "pkg", "PyPI", "1.0.0"), None);
    }

    #[test]
    fn undeterminable_version_returns_none_not_guess() {
        // scanned version can't be parsed -> refuse to recommend.
        let v = advisory("pkg", "PyPI", eco_range(json!([
            { "introduced": "0" }, { "fixed": "2.0.0" }
        ])));
        assert_eq!(extract_fixed_version(&v, "pkg", "PyPI", "not-a-version"), None);
    }
}
