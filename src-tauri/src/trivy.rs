use serde::{Deserialize, Serialize};
use std::process::Command;

// ══════════════════════════════════════════════════════
//  Trivy CLI Integration — invoke trivy via shell
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrivyScanRequest {
    pub target: String,           // image name, path, or repo URL
    pub scan_type: String,        // image, fs, repo, config, sbom
    pub severity: Option<String>, // CRITICAL,HIGH,MEDIUM,LOW
    pub format: Option<String>,   // json (always json internally)
    pub skip_db_update: bool,
    pub vex_path: Option<String>, // path to VEX document (OpenVEX/CycloneDX VEX/CSAF)
    pub ignore_unfixed: bool,     // --ignore-unfixed: skip vulns without fix
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrivyResult {
    pub success: bool,
    pub scan_type: String,
    pub target: String,
    pub raw_json: Option<serde_json::Value>,
    pub summary: TrivySummary,
    pub vulnerabilities: Vec<TrivyVuln>,
    pub misconfigurations: Vec<TrivyMisconf>,
    pub secrets: Vec<TrivySecret>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub trivy_version: String,
    pub vex_applied: bool,        // was VEX filtering applied?
    pub vex_path: Option<String>, // which VEX file was used
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TrivySummary {
    pub total_vulns: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub total_misconf: usize,
    pub total_secrets: usize,
    pub vex_filtered: usize,      // vulns suppressed by VEX
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrivyVuln {
    pub vuln_id: String,
    pub pkg_name: String,
    pub installed_version: String,
    pub fixed_version: String,
    pub severity: String,
    pub title: String,
    pub primary_url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrivyMisconf {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub message: String,
    pub resolution: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrivySecret {
    pub rule_id: String,
    pub category: String,
    pub title: String,
    pub severity: String,
    pub match_str: String,
}

// ══════════════════════════════════════════════════════
//  Parse Trivy JSON output
// ══════════════════════════════════════════════════════

fn parse_trivy_json(json: &serde_json::Value) -> (TrivySummary, Vec<TrivyVuln>, Vec<TrivyMisconf>, Vec<TrivySecret>) {
    let mut summary = TrivySummary::default();
    let mut vulns = Vec::new();
    let mut misconfs = Vec::new();
    let mut secrets = Vec::new();

    // Trivy JSON has "Results" array
    if let Some(results) = json.get("Results").and_then(|r| r.as_array()) {
        for result in results {
            // Vulnerabilities
            if let Some(vuln_arr) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for v in vuln_arr {
                    let severity = v.get("Severity").and_then(|s| s.as_str()).unwrap_or("UNKNOWN").to_string();
                    match severity.as_str() {
                        "CRITICAL" => summary.critical += 1,
                        "HIGH" => summary.high += 1,
                        "MEDIUM" => summary.medium += 1,
                        "LOW" => summary.low += 1,
                        _ => summary.unknown += 1,
                    }
                    summary.total_vulns += 1;

                    vulns.push(TrivyVuln {
                        vuln_id: v.get("VulnerabilityID").and_then(|s| s.as_str()).unwrap_or("").into(),
                        pkg_name: v.get("PkgName").and_then(|s| s.as_str()).unwrap_or("").into(),
                        installed_version: v.get("InstalledVersion").and_then(|s| s.as_str()).unwrap_or("").into(),
                        fixed_version: v.get("FixedVersion").and_then(|s| s.as_str()).unwrap_or("").into(),
                        severity,
                        title: v.get("Title").and_then(|s| s.as_str()).unwrap_or("").into(),
                        primary_url: v.get("PrimaryURL").and_then(|s| s.as_str()).unwrap_or("").into(),
                    });
                }
            }

            // Misconfigurations
            if let Some(misconf_arr) = result.get("Misconfigurations").and_then(|m| m.as_array()) {
                for m in misconf_arr {
                    summary.total_misconf += 1;
                    misconfs.push(TrivyMisconf {
                        id: m.get("ID").and_then(|s| s.as_str()).unwrap_or("").into(),
                        title: m.get("Title").and_then(|s| s.as_str()).unwrap_or("").into(),
                        severity: m.get("Severity").and_then(|s| s.as_str()).unwrap_or("").into(),
                        message: m.get("Message").and_then(|s| s.as_str()).unwrap_or("").into(),
                        resolution: m.get("Resolution").and_then(|s| s.as_str()).unwrap_or("").into(),
                    });
                }
            }

            // Secrets
            if let Some(secret_arr) = result.get("Secrets").and_then(|s| s.as_array()) {
                for s in secret_arr {
                    summary.total_secrets += 1;
                    secrets.push(TrivySecret {
                        rule_id: s.get("RuleID").and_then(|v| v.as_str()).unwrap_or("").into(),
                        category: s.get("Category").and_then(|v| v.as_str()).unwrap_or("").into(),
                        title: s.get("Title").and_then(|v| v.as_str()).unwrap_or("").into(),
                        severity: s.get("Severity").and_then(|v| v.as_str()).unwrap_or("").into(),
                        match_str: s.get("Match").and_then(|v| v.as_str()).unwrap_or("***").into(),
                    });
                }
            }
        }
    }

    (summary, vulns, misconfs, secrets)
}

// ══════════════════════════════════════════════════════
//  Check trivy version
// ══════════════════════════════════════════════════════

fn get_trivy_version() -> String {
    Command::new("trivy")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .unwrap_or_else(|| "not installed".into())
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

/// Run trivy scan via CLI
#[tauri::command]
pub async fn trivy_scan(request: TrivyScanRequest) -> Result<TrivyResult, String> {
    let start = std::time::Instant::now();
    let version = get_trivy_version();

    if version == "not installed" {
        return Ok(TrivyResult {
            success: false,
            scan_type: request.scan_type.clone(),
            target: request.target.clone(),
            raw_json: None,
            summary: TrivySummary::default(),
            vulnerabilities: vec![],
            misconfigurations: vec![],
            secrets: vec![],
            error: Some("Trivy is not installed. Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/".into()),
            duration_ms: start.elapsed().as_millis() as u64,
            trivy_version: version,
            vex_applied: false,
            vex_path: None,
        });
    }

    let mut cmd = tokio::process::Command::new("trivy");

    // Scan type
    cmd.arg(&request.scan_type);

    // Target
    cmd.arg(&request.target);

    // Always JSON for parsing
    cmd.arg("--format").arg("json");

    // Severity filter
    if let Some(ref sev) = request.severity {
        cmd.arg("--severity").arg(sev);
    }

    // VEX document for filtering false positives
    if let Some(ref vex) = request.vex_path {
        if !vex.is_empty() {
            cmd.arg("--vex").arg(vex);
        }
    }

    // Ignore unfixed vulnerabilities
    if request.ignore_unfixed {
        cmd.arg("--ignore-unfixed");
    }

    // Skip DB update if requested
    if request.skip_db_update {
        cmd.arg("--skip-db-update");
    }

    // Quiet mode
    cmd.arg("--quiet");

    let output = cmd.output().await
        .map_err(|e| format!("Failed to execute trivy: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout.trim().is_empty() {
        return Ok(TrivyResult {
            success: false,
            scan_type: request.scan_type,
            target: request.target,
            raw_json: None,
            summary: TrivySummary::default(),
            vulnerabilities: vec![],
            misconfigurations: vec![],
            secrets: vec![],
            error: Some(if stderr.is_empty() { "No output from trivy".into() } else { stderr }),
            duration_ms: start.elapsed().as_millis() as u64,
            trivy_version: version,
            vex_applied: false,
            vex_path: None,
        });
    }

    let vex_applied = request.vex_path.is_some() && !request.vex_path.as_deref().unwrap_or("").is_empty();
    let vex_path_used = request.vex_path.clone();

    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(json) => {
            let (summary, vulns, misconfs, secrets) = parse_trivy_json(&json);
            Ok(TrivyResult {
                success: true,
                scan_type: request.scan_type,
                target: request.target,
                raw_json: Some(json),
                summary,
                vulnerabilities: vulns,
                misconfigurations: misconfs,
                secrets,
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
                trivy_version: version,
                vex_applied,
                vex_path: vex_path_used,
            })
        }
        Err(e) => Ok(TrivyResult {
            success: false,
            scan_type: request.scan_type,
            target: request.target,
            raw_json: None,
            summary: TrivySummary::default(),
            vulnerabilities: vec![],
            misconfigurations: vec![],
            secrets: vec![],
            error: Some(format!("Failed to parse trivy output: {}\n\nstdout: {}\nstderr: {}", e, &stdout[..stdout.len().min(500)], stderr)),
            duration_ms: start.elapsed().as_millis() as u64,
            trivy_version: version,
            vex_applied: false,
            vex_path: None,
        }),
    }
}

/// Check if trivy is installed and get version
#[tauri::command]
pub fn trivy_check() -> Result<serde_json::Value, String> {
    let version = get_trivy_version();
    let installed = version != "not installed";
    Ok(serde_json::json!({
        "installed": installed,
        "version": version,
        "scan_types": ["image", "fs", "repo", "config", "sbom", "rootfs", "vm"],
        "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        "vex_formats": ["openvex", "cyclonedx", "csaf"],
    }))
}

/// Generate a VEX template from existing scan results
#[tauri::command]
pub async fn trivy_generate_vex(target: String, scan_type: String, output_path: String) -> Result<serde_json::Value, String> {
    // Scan first to know which vulns exist
    let output = tokio::process::Command::new("trivy")
        .args([&scan_type, &target, "--format", "json", "--quiet"])
        .output()
        .await
        .map_err(|e| format!("trivy failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    // Build OpenVEX template
    let mut statements = Vec::new();
    if let Some(results) = json.get("Results").and_then(|r| r.as_array()) {
        for result in results {
            if let Some(vulns) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for v in vulns {
                    let vuln_id = v.get("VulnerabilityID").and_then(|s| s.as_str()).unwrap_or("");
                    let pkg = v.get("PkgName").and_then(|s| s.as_str()).unwrap_or("");
                    let severity = v.get("Severity").and_then(|s| s.as_str()).unwrap_or("");

                    statements.push(serde_json::json!({
                        "vulnerability": { "@id": format!("https://nvd.nist.gov/vuln/detail/{}", vuln_id), "name": vuln_id },
                        "products": [{ "@id": format!("pkg:generic/{}@*", pkg) }],
                        "status": "under_investigation",
                        "justification": "",
                        "impact_statement": format!("[TODO] Assess impact of {} ({}) on {}", vuln_id, severity, pkg),
                    }));
                }
            }
        }
    }

    let vex_doc = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("https://openvex.dev/docs/{}", uuid_simple()),
        "author": "CycloneDX Tauri UI",
        "role": "security-analyst",
        "timestamp": chrono_now(),
        "version": 1,
        "statements": statements,
    });

    let content = serde_json::to_string_pretty(&vex_doc).map_err(|e| e.to_string())?;
    std::fs::write(&output_path, &content).map_err(|e| format!("Write failed: {}", e))?;

    Ok(serde_json::json!({
        "path": output_path,
        "statements": statements.len(),
        "message": format!("VEX template with {} statements. Edit 'status' fields: not_affected, fixed, under_investigation", statements.len()),
    }))
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{:032x}", t)
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("2026-03-05T{:02}:{:02}:{:02}Z", (now / 3600) % 24, (now / 60) % 60, now % 60)
}
