use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ══════════════════════════════════════════════════════
//  Pipeline Stages — inspired by Tracee events_pipeline.go
//  decode → match → process → derive → detect → sink
// ══════════════════════════════════════════════════════

/// Stage execution result
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StageResult {
    pub stage: String,
    pub status: StageStatus,
    pub message: String,
    pub duration_ms: u64,
    pub artifacts_produced: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum StageStatus {
    Success,
    Warning,
    Error,
    Skipped,
}

/// Pipeline run report — all stages
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineReport {
    pub stages: Vec<StageResult>,
    pub total_duration_ms: u64,
    pub overall_status: StageStatus,
}

// ══════════════════════════════════════════════════════
//  Stage 1: Enrichment — add vuln/license/supplier data
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrichmentConfig {
    pub enable_vulns: bool,
    pub enable_licenses: bool,
    pub enable_suppliers: bool,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self { enable_vulns: true, enable_licenses: true, enable_suppliers: true }
    }
}

fn run_enrichment(sbom: &mut serde_json::Value, config: &EnrichmentConfig) -> StageResult {
    let start = std::time::Instant::now();
    let mut artifacts = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if let Some(components) = sbom.get_mut("components").and_then(|c| c.as_array_mut()) {
        let total = components.len();
        let mut enriched = 0usize;

        for comp in components.iter_mut() {
            let name = comp.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let mut was_enriched = false;

            // Add vulnerability metadata (enrichment marker)
            if config.enable_vulns {
                let name_lower = name.to_lowercase();
                let known_vulns = match name_lower.as_str() {
                    "log4j-core" => Some(("CVE-2021-44228", "CRITICAL", 10.0)),
                    "lodash" => Some(("CVE-2021-23337", "HIGH", 7.2)),
                    "openssl" => Some(("CVE-2022-3602", "HIGH", 7.5)),
                    _ => None,
                };
                if let Some((cve, severity, score)) = known_vulns {
                    let vuln_prop = serde_json::json!({
                        "vulnerabilities": [{
                            "id": cve,
                            "severity": severity,
                            "score": score
                        }]
                    });
                    if let Some(props) = comp.get_mut("properties") {
                        if let Some(arr) = props.as_array_mut() {
                            arr.push(serde_json::json!({
                                "name": "enrichment:vulns",
                                "value": serde_json::to_string(&vuln_prop).unwrap_or_default()
                            }));
                        }
                    } else {
                        comp.as_object_mut().map(|o| o.insert("properties".into(),
                            serde_json::json!([{
                                "name": "enrichment:vulns",
                                "value": serde_json::to_string(&vuln_prop).unwrap_or_default()
                            }])
                        ));
                    }
                    was_enriched = true;
                }
            }

            // Add license category
            if config.enable_licenses {
                if let Some(licenses) = comp.get("licenses").and_then(|l| l.as_array()) {
                    if let Some(first) = licenses.first() {
                        let lic_id = first.get("license")
                            .and_then(|l| l.get("id"))
                            .and_then(|id| id.as_str())
                            .or_else(|| first.get("expression").and_then(|e| e.as_str()));

                        if let Some(id) = lic_id {
                            let category = match id {
                                "MIT" | "Apache-2.0" | "BSD-2-Clause" | "BSD-3-Clause" | "ISC" => "permissive",
                                "GPL-2.0-only" | "GPL-3.0-only" | "AGPL-3.0-only" => "copyleft",
                                "LGPL-2.1-only" | "MPL-2.0" => "weak-copyleft",
                                _ => "unknown",
                            };
                            let prop_arr = comp.get_mut("properties")
                                .and_then(|p| p.as_array_mut());
                            if let Some(arr) = prop_arr {
                                arr.push(serde_json::json!({
                                    "name": "enrichment:license_category",
                                    "value": category
                                }));
                            }
                            was_enriched = true;
                        }
                    }
                }
            }

            if was_enriched { enriched += 1; }
        }

        artifacts.push(format!("enriched {}/{} components", enriched, total));
    }

    StageResult {
        stage: "enrichment".into(),
        status: if warnings.is_empty() { StageStatus::Success } else { StageStatus::Warning },
        message: format!("Enrichment complete: {}", artifacts.join(", ")),
        duration_ms: start.elapsed().as_millis() as u64,
        artifacts_produced: artifacts,
    }
}

// ══════════════════════════════════════════════════════
//  Stage 2: Derivation — SBOM → VEX + License Report
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DerivationConfig {
    pub derive_vex: bool,
    pub derive_license_report: bool,
    pub derive_supplier_report: bool,
}

impl Default for DerivationConfig {
    fn default() -> Self {
        Self { derive_vex: true, derive_license_report: true, derive_supplier_report: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DerivedArtifact {
    pub name: String,
    pub artifact_type: String,
    pub content: String,
}

fn run_derivation(sbom: &serde_json::Value, config: &DerivationConfig) -> (StageResult, Vec<DerivedArtifact>) {
    let start = std::time::Instant::now();
    let mut derived = Vec::new();
    let mut artifacts_names = Vec::new();

    let components = sbom.get("components")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    // Derive VEX document
    if config.derive_vex {
        let mut vulns = Vec::new();
        for comp in &components {
            let name = comp.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let version = comp.get("version").and_then(|v| v.as_str()).unwrap_or("");
            // Check for enrichment:vulns property
            if let Some(props) = comp.get("properties").and_then(|p| p.as_array()) {
                for prop in props {
                    if prop.get("name").and_then(|n| n.as_str()) == Some("enrichment:vulns") {
                        if let Some(val) = prop.get("value").and_then(|v| v.as_str()) {
                            vulns.push(serde_json::json!({
                                "component": format!("{}@{}", name, version),
                                "data": val
                            }));
                        }
                    }
                }
            }
        }

        let vex_doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "vulnerabilities": vulns
        });

        derived.push(DerivedArtifact {
            name: "vex-report.json".into(),
            artifact_type: "VEX".into(),
            content: serde_json::to_string_pretty(&vex_doc).unwrap_or_default(),
        });
        artifacts_names.push("VEX report".into());
    }

    // Derive License Report
    if config.derive_license_report {
        let mut license_summary: HashMap<String, usize> = HashMap::new();
        let mut no_license = 0usize;

        for comp in &components {
            let lic_id = comp.get("licenses")
                .and_then(|l| l.as_array())
                .and_then(|arr| arr.first())
                .and_then(|lic| {
                    lic.get("license").and_then(|l| l.get("id")).and_then(|id| id.as_str())
                        .or_else(|| lic.get("expression").and_then(|e| e.as_str()))
                });

            match lic_id {
                Some(id) => *license_summary.entry(id.to_string()).or_default() += 1,
                None => no_license += 1,
            }
        }

        let report = serde_json::json!({
            "total_components": components.len(),
            "with_license": components.len() - no_license,
            "without_license": no_license,
            "coverage_percent": if components.is_empty() { 0.0 } else {
                ((components.len() - no_license) as f64 / components.len() as f64) * 100.0
            },
            "license_distribution": license_summary
        });

        derived.push(DerivedArtifact {
            name: "license-report.json".into(),
            artifact_type: "LicenseReport".into(),
            content: serde_json::to_string_pretty(&report).unwrap_or_default(),
        });
        artifacts_names.push("License report".into());
    }

    // Derive Supplier Report
    if config.derive_supplier_report {
        let mut with_supplier = 0usize;
        let mut supplier_names: HashMap<String, usize> = HashMap::new();

        for comp in &components {
            if let Some(supplier) = comp.get("supplier").and_then(|s| s.get("name")).and_then(|n| n.as_str()) {
                with_supplier += 1;
                *supplier_names.entry(supplier.to_string()).or_default() += 1;
            }
        }

        let report = serde_json::json!({
            "total_components": components.len(),
            "with_supplier": with_supplier,
            "without_supplier": components.len() - with_supplier,
            "coverage_percent": if components.is_empty() { 0.0 } else {
                (with_supplier as f64 / components.len() as f64) * 100.0
            },
            "supplier_distribution": supplier_names
        });

        derived.push(DerivedArtifact {
            name: "supplier-report.json".into(),
            artifact_type: "SupplierReport".into(),
            content: serde_json::to_string_pretty(&report).unwrap_or_default(),
        });
        artifacts_names.push("Supplier report".into());
    }

    let result = StageResult {
        stage: "derivation".into(),
        status: StageStatus::Success,
        message: format!("Derived {} artifacts: {}", derived.len(), artifacts_names.join(", ")),
        duration_ms: start.elapsed().as_millis() as u64,
        artifacts_produced: artifacts_names,
    };

    (result, derived)
}

// ══════════════════════════════════════════════════════
//  Stage 3: MultiSink — save to multiple outputs
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SinkConfig {
    pub save_to_files: bool,
    pub output_dir: String,
}

fn run_multi_sink(
    sbom: &serde_json::Value,
    derived: &[DerivedArtifact],
    config: &SinkConfig,
) -> StageResult {
    let start = std::time::Instant::now();
    let mut saved = Vec::new();

    if config.save_to_files {
        let dir = Path::new(&config.output_dir);
        if let Err(e) = std::fs::create_dir_all(dir) {
            return StageResult {
                stage: "sink".into(),
                status: StageStatus::Error,
                message: format!("Failed to create output dir: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
                artifacts_produced: vec![],
            };
        }

        // Save enriched SBOM
        let sbom_path = dir.join("enriched-sbom.json");
        if let Ok(content) = serde_json::to_string_pretty(sbom) {
            if std::fs::write(&sbom_path, &content).is_ok() {
                saved.push(format!("enriched-sbom.json"));
            }
        }

        // Save derived artifacts
        for artifact in derived {
            let path = dir.join(&artifact.name);
            if std::fs::write(&path, &artifact.content).is_ok() {
                saved.push(artifact.name.clone());
            }
        }
    }

    StageResult {
        stage: "sink".into(),
        status: StageStatus::Success,
        message: format!("Saved {} files to {}", saved.len(), config.output_dir),
        duration_ms: start.elapsed().as_millis() as u64,
        artifacts_produced: saved,
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

/// Run complete multi-stage pipeline: Enrich → Derive → Sink
#[tauri::command]
pub async fn run_pipeline_stages(
    sbom_path: String,
    output_dir: String,
) -> Result<PipelineReport, String> {
    let content = tokio::fs::read_to_string(&sbom_path)
        .await
        .map_err(|e| format!("Failed to read SBOM: {}", e))?;

    let mut sbom: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let total_start = std::time::Instant::now();
    let mut stages = Vec::new();

    // Stage 1: Enrichment
    let enrich_config = EnrichmentConfig::default();
    let enrich_result = run_enrichment(&mut sbom, &enrich_config);
    stages.push(enrich_result);

    // Stage 2: Derivation
    let derive_config = DerivationConfig::default();
    let (derive_result, derived_artifacts) = run_derivation(&sbom, &derive_config);
    stages.push(derive_result);

    // Stage 3: MultiSink
    let sink_config = SinkConfig {
        save_to_files: true,
        output_dir: output_dir.clone(),
    };
    let sink_result = run_multi_sink(&sbom, &derived_artifacts, &sink_config);
    stages.push(sink_result);

    let has_errors = stages.iter().any(|s| matches!(s.status, StageStatus::Error));
    let overall = if has_errors { StageStatus::Error } else { StageStatus::Success };

    Ok(PipelineReport {
        stages,
        total_duration_ms: total_start.elapsed().as_millis() as u64,
        overall_status: overall,
    })
}

/// Get info about available pipeline stages
#[tauri::command]
pub fn list_pipeline_stages() -> Result<Vec<serde_json::Value>, String> {
    Ok(vec![
        serde_json::json!({
            "id": "enrichment",
            "name": "Enrichment Stage",
            "description": "Add vulnerability, license, and supplier data to SBOM components",
            "icon": "🔬",
            "inputs": ["SBOM"],
            "outputs": ["Enriched SBOM"]
        }),
        serde_json::json!({
            "id": "derivation",
            "name": "Derivation Stage",
            "description": "Generate VEX, License Report, and Supplier Report from SBOM",
            "icon": "🔀",
            "inputs": ["SBOM / Enriched SBOM"],
            "outputs": ["VEX", "License Report", "Supplier Report"]
        }),
        serde_json::json!({
            "id": "sink",
            "name": "Multi-Sink Output",
            "description": "Save all artifacts to output directory",
            "icon": "💾",
            "inputs": ["Enriched SBOM", "Derived Artifacts"],
            "outputs": ["Files on disk"]
        }),
    ])
}
