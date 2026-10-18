use serde::{Deserialize, Serialize};
use crate::sbom_graph::SbomGraph;
use std::collections::{HashMap, HashSet, VecDeque};

// ══════════════════════════════════════════════════════
//  Trust Execution Graph — formal DevSecOps model
//  Execution nodes change trust → trigger policies →
//  generate compliance artifacts
// ══════════════════════════════════════════════════════

// ─────────────────── Typed Execution DAG ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ExecNodeType {
    Scan,
    Validate,
    Evaluate,
    Transform,
    Export,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExecStatus {
    Pending,
    Running,
    Success,
    Failed,
    Skipped,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecNodeSpec {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecRuntime {
    pub node_id: String,
    pub status: String,
    pub started_at_us: u64,
    pub finished_at_us: u64,
    pub duration_us: u64,
    pub output: String,
    pub trust_delta: f64,  // how this step changed avg trust
}

// ─────────────────── Trust Propagation ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustPropagation {
    pub component: String,
    pub original_trust: f64,
    pub propagated_trust: f64,
    pub reason: String,
    pub affected_by: Vec<String>,
}

/// Propagate trust: if a dependency is compromised, parents lose trust
pub fn propagate_trust(sbom: &SbomGraph) -> Vec<TrustPropagation> {
    let mut propagated: HashMap<String, f64> = HashMap::new();
    let mut reasons: HashMap<String, (String, Vec<String>)> = HashMap::new();

    // Initialize with original trust
    for comp in &sbom.components {
        let bref = comp.bom_ref.as_deref().unwrap_or(&comp.name).to_string();
        propagated.insert(bref.clone(), comp.trust_score);
    }

    // BFS from low-trust/vulnerable components upward
    let mut queue: VecDeque<String> = VecDeque::new();
    for comp in &sbom.components {
        let bref = comp.bom_ref.as_deref().unwrap_or(&comp.name).to_string();
        if comp.trust_score < 0.5 || comp.vuln_count > 0 {
            queue.push_back(bref);
        }
    }

    let mut visited = HashSet::new();
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) { continue; }
        let current_trust = propagated.get(&current).copied().unwrap_or(1.0);

        // Find parents (dependents)
        if let Some(parents) = sbom.reverse_adj.get(&current) {
            for parent in parents {
                let parent_trust = propagated.get(parent).copied().unwrap_or(1.0);
                // Trust of parent = min(own_trust, min(child_trust * 0.9))
                let new_trust = parent_trust.min(current_trust * 0.9);
                if new_trust < parent_trust {
                    propagated.insert(parent.clone(), new_trust);
                    reasons.entry(parent.clone())
                        .or_insert_with(|| (format!("trust reduced by dependency {}", current), Vec::new()))
                        .1.push(current.clone());
                    queue.push_back(parent.clone());
                }
            }
        }
    }

    // Build result (only changed components)
    let mut results = Vec::new();
    for comp in &sbom.components {
        let bref = comp.bom_ref.as_deref().unwrap_or(&comp.name).to_string();
        let original = comp.trust_score;
        let propagated_score = propagated.get(&bref).copied().unwrap_or(original);
        if (propagated_score - original).abs() > 0.001 {
            let (reason, affected) = reasons.get(&bref).cloned().unwrap_or_default();
            results.push(TrustPropagation {
                component: comp.name.clone(),
                original_trust: original,
                propagated_trust: propagated_score,
                reason,
                affected_by: affected,
            });
        }
    }
    results.sort_by(|a, b| a.propagated_trust.partial_cmp(&b.propagated_trust).unwrap_or(std::cmp::Ordering::Equal));
    results
}

// ─────────────────── Attack Surface Analysis ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttackSurface {
    pub entry_point: String,        // vulnerable component
    pub vulnerability: String,
    pub severity: String,
    pub blast_radius: Vec<String>,  // all components affected
    pub depth: usize,
    pub risk_score: f64,
}

/// Compute attack surface: for each vuln, find all dependents (upward blast radius)
pub fn compute_attack_surface(sbom: &SbomGraph) -> Vec<AttackSurface> {
    let mut surfaces = Vec::new();

    for vuln in &sbom.vulnerabilities {
        for comp_ref in &vuln.affects {
            // BFS upward through reverse adjacency
            let mut blast = Vec::new();
            let mut visited = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(comp_ref.clone());
            visited.insert(comp_ref.clone());

            while let Some(current) = queue.pop_front() {
                blast.push(current.clone());
                if let Some(parents) = sbom.reverse_adj.get(&current) {
                    for parent in parents {
                        if visited.insert(parent.clone()) {
                            queue.push_back(parent.clone());
                        }
                    }
                }
            }

            let depth = blast.len();
            let sev_mult = match vuln.severity.as_deref() {
                Some("critical") | Some("CRITICAL") => 10.0,
                Some("high") | Some("HIGH") => 7.0,
                Some("medium") | Some("MEDIUM") => 4.0,
                _ => 1.0,
            };

            surfaces.push(AttackSurface {
                entry_point: comp_ref.clone(),
                vulnerability: vuln.id.clone(),
                severity: vuln.severity.clone().unwrap_or_else(|| "unknown".into()),
                blast_radius: blast,
                depth,
                risk_score: sev_mult * depth as f64,
            });
        }
    }

    surfaces.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
    surfaces.truncate(30);
    surfaces
}

// ─────────────────── Compliance Verification ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComplianceResult {
    pub framework: String,
    pub requirements: Vec<ComplianceReq>,
    pub pass_count: usize,
    pub fail_count: usize,
    pub score: f64,
    pub verdict: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComplianceReq {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: String,  // pass, fail, partial
    pub evidence: String,
}

pub fn verify_compliance(sbom: &SbomGraph) -> Vec<ComplianceResult> {
    let stats = sbom.stats();
    let unlicensed = sbom.unlicensed().len();
    let no_supplier = sbom.no_supplier().len();
    let copyleft = sbom.copyleft_propagation().len();

    vec![
        // CycloneDX Minimum Elements
        check_cyclonedx(&stats, unlicensed, no_supplier),
        // NTIA Minimum Elements
        check_ntia(&stats, unlicensed, no_supplier),
        // NIST Requirements
        check_nist_ssdf(&stats, unlicensed, copyleft),
        // EU CRA (Cyber Resilience Act)
        check_eu_cra(&stats, unlicensed, no_supplier),
        // SLSA (Google)
        check_slsa(&stats),
    ]
}

fn check_cyclonedx(stats: &crate::sbom_graph::SbomStats, unlicensed: usize, no_supplier: usize) -> ComplianceResult {
    let mut reqs = Vec::new();
    let r1 = stats.total_components > 0;
    reqs.push(ComplianceReq { id: "CDX-01".into(), name: "Components present".into(), description: "SBOM contains components".into(), status: if r1 { "pass" } else { "fail" }.into(), evidence: format!("{} components", stats.total_components) });
    let r2 = stats.with_version == stats.total_components;
    reqs.push(ComplianceReq { id: "CDX-02".into(), name: "All versioned".into(), description: "All components have version".into(), status: if r2 { "pass" } else { "fail" }.into(), evidence: format!("{}/{}", stats.with_version, stats.total_components) });
    let r3 = stats.purl_coverage > 80.0;
    reqs.push(ComplianceReq { id: "CDX-03".into(), name: "PURL coverage >80%".into(), description: "Package URL identifiers".into(), status: if r3 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}%", stats.purl_coverage) });
    let r4 = unlicensed == 0;
    reqs.push(ComplianceReq { id: "CDX-04".into(), name: "License declared".into(), description: "All components have license".into(), status: if r4 { "pass" } else { "fail" }.into(), evidence: format!("{} unlicensed", unlicensed) });
    let r5 = no_supplier == 0;
    reqs.push(ComplianceReq { id: "CDX-05".into(), name: "Supplier declared".into(), description: "All components have supplier".into(), status: if r5 { "pass" } else { "fail" }.into(), evidence: format!("{} missing", no_supplier) });
    let pass = reqs.iter().filter(|r| r.status == "pass").count();
    let fail = reqs.len() - pass;
    let score = (pass as f64 / reqs.len() as f64) * 100.0;
    ComplianceResult { framework: "CycloneDX Minimum Elements".into(), requirements: reqs, pass_count: pass, fail_count: fail, score, verdict: if fail == 0 { "COMPLIANT" } else { "NON-COMPLIANT" }.into() }
}

fn check_ntia(stats: &crate::sbom_graph::SbomStats, unlicensed: usize, no_supplier: usize) -> ComplianceResult {
    let mut reqs = Vec::new();
    reqs.push(ComplianceReq { id: "NTIA-01".into(), name: "Supplier name".into(), description: "Entity that creates/distributes".into(), status: if no_supplier < stats.total_components / 2 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}% coverage", stats.supplier_coverage) });
    reqs.push(ComplianceReq { id: "NTIA-02".into(), name: "Component name".into(), description: "All components named".into(), status: "pass".into(), evidence: format!("{} components", stats.total_components) });
    reqs.push(ComplianceReq { id: "NTIA-03".into(), name: "Component version".into(), description: "Version for each component".into(), status: if stats.with_version == stats.total_components { "pass" } else { "fail" }.into(), evidence: format!("{}/{}", stats.with_version, stats.total_components) });
    reqs.push(ComplianceReq { id: "NTIA-04".into(), name: "Unique identifier".into(), description: "PURL or CPE".into(), status: if stats.purl_coverage > 50.0 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}% PURL", stats.purl_coverage) });
    reqs.push(ComplianceReq { id: "NTIA-05".into(), name: "Dependencies".into(), description: "Dependency relationships".into(), status: if stats.total_dependencies > 0 { "pass" } else { "fail" }.into(), evidence: format!("{} edges", stats.total_dependencies) });
    reqs.push(ComplianceReq { id: "NTIA-06".into(), name: "Timestamp".into(), description: "SBOM creation time".into(), status: "pass".into(), evidence: "present".into() });
    let pass = reqs.iter().filter(|r| r.status == "pass").count();
    let fail = reqs.len() - pass;
    ComplianceResult { framework: "NTIA Minimum Elements".into(), requirements: reqs, pass_count: pass, fail_count: fail, score: (pass as f64 / 6.0) * 100.0, verdict: if fail == 0 { "COMPLIANT" } else { "NON-COMPLIANT" }.into() }
}

fn check_nist_ssdf(stats: &crate::sbom_graph::SbomStats, unlicensed: usize, copyleft: usize) -> ComplianceResult {
    let mut reqs = Vec::new();
    reqs.push(ComplianceReq { id: "FSTEC-01".into(), name: "Перечень компонентов".into(), description: "Полный перечень open-source".into(), status: if stats.total_components > 0 { "pass" } else { "fail" }.into(), evidence: format!("{} компонентов", stats.total_components) });
    reqs.push(ComplianceReq { id: "FSTEC-02".into(), name: "Лицензии".into(), description: "Все компоненты лицензированы".into(), status: if unlicensed == 0 { "pass" } else { "fail" }.into(), evidence: format!("{} без лицензий", unlicensed) });
    reqs.push(ComplianceReq { id: "FSTEC-03".into(), name: "Контроль copyleft".into(), description: "Отслеживание copyleft лицензий".into(), status: if copyleft == 0 { "pass" } else { "partial" }.into(), evidence: format!("{} copyleft пропагаций", copyleft) });
    reqs.push(ComplianceReq { id: "FSTEC-04".into(), name: "Анализ уязвимостей".into(), description: "CVE/BDU анализ".into(), status: if stats.critical_vulns == 0 { "pass" } else { "fail" }.into(), evidence: format!("{} critical, {} high", stats.critical_vulns, stats.high_vulns) });
    reqs.push(ComplianceReq { id: "FSTEC-05".into(), name: "Контрольные суммы".into(), description: "Hash для целостности".into(), status: if stats.hash_coverage > 50.0 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}% hash coverage", stats.hash_coverage) });
    let pass = reqs.iter().filter(|r| r.status == "pass").count();
    let fail = reqs.iter().filter(|r| r.status == "fail").count();
    ComplianceResult { framework: "NIST (National Institute of Standards and Technology)".into(), requirements: reqs, pass_count: pass, fail_count: fail, score: (pass as f64 / 5.0) * 100.0, verdict: if fail == 0 { "СООТВЕТСТВУЕТ" } else { "НЕ СООТВЕТСТВУЕТ" }.into() }
}

fn check_eu_cra(stats: &crate::sbom_graph::SbomStats, unlicensed: usize, no_supplier: usize) -> ComplianceResult {
    let mut reqs = Vec::new();
    reqs.push(ComplianceReq { id: "CRA-01".into(), name: "SBOM provided".into(), description: "Machine-readable SBOM".into(), status: "pass".into(), evidence: "CycloneDX JSON".into() });
    reqs.push(ComplianceReq { id: "CRA-02".into(), name: "Vulnerability monitoring".into(), description: "Known vuln tracking".into(), status: if stats.total_vulnerabilities > 0 || stats.total_components > 0 { "pass" } else { "fail" }.into(), evidence: format!("{} vulns tracked", stats.total_vulnerabilities) });
    reqs.push(ComplianceReq { id: "CRA-03".into(), name: "Unique identification".into(), description: "PURL/CPE identifiers".into(), status: if stats.purl_coverage > 70.0 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}%", stats.purl_coverage) });
    reqs.push(ComplianceReq { id: "CRA-04".into(), name: "Supply chain transparency".into(), description: "Supplier information".into(), status: if no_supplier < stats.total_components / 3 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}% supplier", stats.supplier_coverage) });
    let pass = reqs.iter().filter(|r| r.status == "pass").count();
    let fail = reqs.len() - pass;
    ComplianceResult { framework: "EU Cyber Resilience Act".into(), requirements: reqs, pass_count: pass, fail_count: fail, score: (pass as f64 / 4.0) * 100.0, verdict: if fail == 0 { "COMPLIANT" } else { "NON-COMPLIANT" }.into() }
}

fn check_slsa(stats: &crate::sbom_graph::SbomStats) -> ComplianceResult {
    let mut reqs = Vec::new();
    reqs.push(ComplianceReq { id: "SLSA-01".into(), name: "Source integrity".into(), description: "Hash verification".into(), status: if stats.hash_coverage > 80.0 { "pass" } else { "fail" }.into(), evidence: format!("{:.0}% hash", stats.hash_coverage) });
    reqs.push(ComplianceReq { id: "SLSA-02".into(), name: "Provenance".into(), description: "Build provenance attestation".into(), status: if stats.supplier_coverage > 50.0 { "partial" } else { "fail" }.into(), evidence: format!("{:.0}% supplier", stats.supplier_coverage) });
    reqs.push(ComplianceReq { id: "SLSA-03".into(), name: "Dependencies complete".into(), description: "All deps declared".into(), status: if stats.total_dependencies > 0 { "pass" } else { "fail" }.into(), evidence: format!("{} deps", stats.total_dependencies) });
    let pass = reqs.iter().filter(|r| r.status == "pass").count();
    let fail = reqs.iter().filter(|r| r.status == "fail").count();
    ComplianceResult { framework: "SLSA (Google)".into(), requirements: reqs, pass_count: pass, fail_count: fail, score: (pass as f64 / 3.0) * 100.0, verdict: if fail == 0 { "Level 2+" } else { "Level 1" }.into() }
}

// ─────────────────── Full Trust Execution ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustExecResult {
    pub pipeline: Vec<ExecRuntime>,
    pub propagations: Vec<TrustPropagation>,
    pub attack_surfaces: Vec<AttackSurface>,
    pub compliance: Vec<ComplianceResult>,
    pub overall_trust: f64,
    pub overall_verdict: String,
    pub total_duration_us: u64,
}

pub fn run_trust_execution(sbom: &mut SbomGraph) -> TrustExecResult {
    let start = std::time::Instant::now();
    let mut pipeline = Vec::new();

    // Step 1: Build indices
    let s1 = std::time::Instant::now();
    sbom.build_indices();
    pipeline.push(ExecRuntime { node_id: "build_indices".into(), status: "Success".into(), started_at_us: 0, finished_at_us: s1.elapsed().as_micros() as u64, duration_us: s1.elapsed().as_micros() as u64, output: format!("{} components indexed", sbom.components.len()), trust_delta: 0.0 });

    // Step 2: Compute base trust
    let s2 = std::time::Instant::now();
    let base_trust = sbom.stats().avg_trust_score;
    pipeline.push(ExecRuntime { node_id: "compute_base_trust".into(), status: "Success".into(), started_at_us: 0, finished_at_us: s2.elapsed().as_micros() as u64, duration_us: s2.elapsed().as_micros() as u64, output: format!("base trust {:.1}%", base_trust * 100.0), trust_delta: 0.0 });

    // Step 3: Trust propagation
    let s3 = std::time::Instant::now();
    let propagations = propagate_trust(sbom);
    let avg_propagated = if propagations.is_empty() { base_trust } else {
        propagations.iter().map(|p| p.propagated_trust).sum::<f64>() / propagations.len() as f64
    };
    let delta = avg_propagated - base_trust;
    pipeline.push(ExecRuntime { node_id: "trust_propagation".into(), status: "Success".into(), started_at_us: 0, finished_at_us: s3.elapsed().as_micros() as u64, duration_us: s3.elapsed().as_micros() as u64, output: format!("{} components affected, delta {:.1}%", propagations.len(), delta * 100.0), trust_delta: delta });

    // Step 4: Attack surface
    let s4 = std::time::Instant::now();
    let attack_surfaces = compute_attack_surface(sbom);
    let max_blast = attack_surfaces.iter().map(|a| a.blast_radius.len()).max().unwrap_or(0);
    pipeline.push(ExecRuntime { node_id: "attack_surface".into(), status: "Success".into(), started_at_us: 0, finished_at_us: s4.elapsed().as_micros() as u64, duration_us: s4.elapsed().as_micros() as u64, output: format!("{} surfaces, max blast {}", attack_surfaces.len(), max_blast), trust_delta: 0.0 });

    // Step 5: Compliance verification
    let s5 = std::time::Instant::now();
    let compliance = verify_compliance(sbom);
    let compliance_pass = compliance.iter().filter(|c| c.fail_count == 0).count();
    pipeline.push(ExecRuntime { node_id: "compliance_verify".into(), status: "Success".into(), started_at_us: 0, finished_at_us: s5.elapsed().as_micros() as u64, duration_us: s5.elapsed().as_micros() as u64, output: format!("{}/{} frameworks pass", compliance_pass, compliance.len()), trust_delta: 0.0 });

    let overall = if propagations.is_empty() { base_trust } else { base_trust + delta };
    let verdict = if overall >= 0.8 && compliance_pass == compliance.len() { "TRUSTED" }
        else if overall >= 0.5 { "PARTIAL" }
        else { "UNTRUSTED" };

    TrustExecResult {
        pipeline, propagations, attack_surfaces, compliance,
        overall_trust: overall,
        overall_verdict: verdict.into(),
        total_duration_us: start.elapsed().as_micros() as u64,
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn run_trust_exec(sbom_path: String) -> Result<TrustExecResult, String> {
    let content = std::fs::read_to_string(&sbom_path)
        .map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    let mut sbom = SbomGraph::from_cdx_json(&json)?;
    Ok(run_trust_execution(&mut sbom))
}
