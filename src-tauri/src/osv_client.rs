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
    pub severity: Option<String>, // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    pub aliases: Vec<String>,     // other ids (e.g. CVE id for a GHSA)
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
                let aliases = v["aliases"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let severity = extract_severity(v);
                out.push(OsvAdvisory {
                    id,
                    summary,
                    severity,
                    aliases,
                });
            }
        }
        Ok(out)
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
