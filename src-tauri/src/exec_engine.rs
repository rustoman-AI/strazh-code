use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::sbom_graph::SbomGraph;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::toposort;

// ══════════════════════════════════════════════════════
//  Execution Engine — petgraph-based typed pipeline DAG
//  LoadSBOM → BuildIndices → TrustScore → VulnScan
//  → LicenseAudit → PolicyCheck → GenerateReport
// ══════════════════════════════════════════════════════

pub type ExecNodeId = String;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecutionGraph {
    pub nodes: Vec<ExecNodeDef>,
    pub edges: Vec<ExecEdge>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecNodeDef {
    pub id: ExecNodeId,
    pub kind: String,
    pub label: String,
    pub description: String,
    pub status: String,          // pending, running, success, failed, skipped
    pub duration_us: u64,
    pub output_summary: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecEdge {
    pub from: ExecNodeId,
    pub to: ExecNodeId,
}

// ─────────────────── Context ───────────────────

#[derive(Clone, Debug)]
pub struct ExecContext {
    pub sbom: Option<SbomGraph>,
    pub violations: Vec<PolicyViolation>,
    pub audit_results: Vec<LicenseAuditItem>,
    pub trust_scores: Vec<(String, f64)>,
    pub report_lines: Vec<String>,
}

impl Default for ExecContext {
    fn default() -> Self {
        Self { sbom: None, violations: Vec::new(), audit_results: Vec::new(), trust_scores: Vec::new(), report_lines: Vec::new() }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyViolation {
    pub rule_id: String,
    pub component: String,
    pub severity: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LicenseAuditItem {
    pub component: String,
    pub license: String,
    pub risk: String,           // copyleft, permissive, unknown, none
    pub propagates_to: Vec<String>,
}

// ─────────────────── Steps ───────────────────

trait ExecStep: Send + Sync {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String>;
}

struct StepLoadSbom { json: serde_json::Value }
impl ExecStep for StepLoadSbom {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        let graph = SbomGraph::from_cdx_json(&self.json)?;
        let count = graph.components.len();
        ctx.sbom = Some(graph);
        Ok(format!("{} components loaded", count))
    }
}

struct StepBuildIndices;
impl ExecStep for StepBuildIndices {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        if let Some(ref mut sbom) = ctx.sbom {
            sbom.build_indices();
            Ok(format!("{} dep edges, {} reverse edges, {} petgraph nodes", sbom.adjacency.len(), sbom.reverse_adj.len(), sbom.pet_graph.node_count()))
        } else {
            Err("No SBOM loaded".into())
        }
    }
}

struct StepComputeTrust;
impl ExecStep for StepComputeTrust {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        if let Some(ref sbom) = ctx.sbom {
            ctx.trust_scores = sbom.components.iter().map(|c| {
                (c.bom_ref.as_deref().unwrap_or(&c.name).to_string(), c.trust_score)
            }).collect();
            let avg = if ctx.trust_scores.is_empty() { 0.0 } else {
                ctx.trust_scores.iter().map(|(_, s)| s).sum::<f64>() / ctx.trust_scores.len() as f64
            };
            Ok(format!("avg trust {:.0}%, {} untrusted (<50%)", avg * 100.0, ctx.trust_scores.iter().filter(|(_, s)| *s < 0.5).count()))
        } else { Err("No SBOM".into()) }
    }
}

struct StepVulnScan;
impl ExecStep for StepVulnScan {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        if let Some(ref sbom) = ctx.sbom {
            let critical = sbom.critical_vulnerable();
            for (comp, vulns) in &critical {
                for vuln in vulns {
                    ctx.violations.push(PolicyViolation {
                        rule_id: "VULN-CRITICAL".into(),
                        component: comp.name.clone(),
                        severity: "critical".into(),
                        message: format!("{} affects {} ({})", vuln.id, comp.name, vuln.severity.as_deref().unwrap_or("?")),
                    });
                }
            }
            Ok(format!("{} vulns, {} critical components", sbom.vulnerabilities.len(), critical.len()))
        } else { Err("No SBOM".into()) }
    }
}

struct StepLicenseAudit;
impl ExecStep for StepLicenseAudit {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        if let Some(ref sbom) = ctx.sbom {
            let copyleft = sbom.copyleft_propagation();
            for (lic, from, to) in &copyleft {
                ctx.audit_results.push(LicenseAuditItem {
                    component: from.clone(), license: lic.clone(), risk: "copyleft".into(), propagates_to: vec![to.clone()],
                });
            }
            let unlicensed = sbom.unlicensed();
            for comp in &unlicensed {
                ctx.audit_results.push(LicenseAuditItem {
                    component: comp.name.clone(), license: "NONE".into(), risk: "unknown".into(), propagates_to: vec![],
                });
                ctx.violations.push(PolicyViolation {
                    rule_id: "LICENSE-MISSING".into(), component: comp.name.clone(),
                    severity: "warning".into(), message: format!("{} has no license declared", comp.name),
                });
            }
            Ok(format!("{} copyleft, {} unlicensed", copyleft.len(), unlicensed.len()))
        } else { Err("No SBOM".into()) }
    }
}

struct StepPolicyCheck;
impl ExecStep for StepPolicyCheck {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        if let Some(ref sbom) = ctx.sbom {
            let no_sup = sbom.no_supplier();
            for comp in &no_sup {
                ctx.violations.push(PolicyViolation {
                    rule_id: "SUPPLIER-MISSING".into(), component: comp.name.clone(),
                    severity: "info".into(), message: format!("{} has no supplier info", comp.name),
                });
            }
            for (name, score) in &ctx.trust_scores {
                if *score < 0.3 {
                    ctx.violations.push(PolicyViolation {
                        rule_id: "TRUST-LOW".into(), component: name.clone(),
                        severity: "warning".into(), message: format!("{} trust score {:.0}% (threshold 30%)", name, score * 100.0),
                    });
                }
            }
            let critical = ctx.violations.iter().filter(|v| v.severity == "critical").count();
            let warnings = ctx.violations.iter().filter(|v| v.severity == "warning").count();
            Ok(format!("{} violations: {} critical, {} warnings", ctx.violations.len(), critical, warnings))
        } else { Err("No SBOM".into()) }
    }
}

struct StepGenerateReport;
impl ExecStep for StepGenerateReport {
    fn execute(&self, ctx: &mut ExecContext) -> Result<String, String> {
        if let Some(ref sbom) = ctx.sbom {
            let stats = sbom.stats();
            ctx.report_lines.push(format!("Components: {}", stats.total_components));
            ctx.report_lines.push(format!("Vulnerabilities: {} ({} critical, {} high)", stats.total_vulnerabilities, stats.critical_vulns, stats.high_vulns));
            ctx.report_lines.push(format!("License coverage: {:.0}%", stats.license_coverage));
            ctx.report_lines.push(format!("Supplier coverage: {:.0}%", stats.supplier_coverage));
            ctx.report_lines.push(format!("Trust score: {:.0}%", stats.avg_trust_score * 100.0));
            ctx.report_lines.push(format!("Policy violations: {}", ctx.violations.len()));
            ctx.report_lines.push(format!("License audit items: {}", ctx.audit_results.len()));
            ctx.report_lines.push(format!("petgraph nodes: {}", sbom.pet_graph.node_count()));
            Ok(format!("{} report lines", ctx.report_lines.len()))
        } else { Err("No SBOM".into()) }
    }
}

// ─────────────────── Engine (petgraph DAG) ───────────────────

pub struct ExecutionEngine {
    /// petgraph DAG for topological step ordering
    dag: DiGraph<ExecNodeId, ()>,
    node_map: HashMap<ExecNodeId, NodeIndex>,
    steps: HashMap<ExecNodeId, Box<dyn ExecStep>>,
}

impl ExecutionEngine {
    pub fn devsecops_pipeline(json: serde_json::Value) -> Self {
        let step_defs: Vec<(ExecNodeId, Box<dyn ExecStep>)> = vec![
            ("load_sbom".into(), Box::new(StepLoadSbom { json })),
            ("build_indices".into(), Box::new(StepBuildIndices)),
            ("compute_trust".into(), Box::new(StepComputeTrust)),
            ("vuln_scan".into(), Box::new(StepVulnScan)),
            ("license_audit".into(), Box::new(StepLicenseAudit)),
            ("policy_check".into(), Box::new(StepPolicyCheck)),
            ("generate_report".into(), Box::new(StepGenerateReport)),
        ];

        let mut dag = DiGraph::with_capacity(step_defs.len(), step_defs.len());
        let mut node_map = HashMap::new();
        let mut steps = HashMap::new();

        // Add nodes
        for (id, step) in step_defs {
            let nx = dag.add_node(id.clone());
            node_map.insert(id.clone(), nx);
            steps.insert(id, step);
        }

        // Linear chain edges (can be extended for parallel branches)
        let order = ["load_sbom", "build_indices", "compute_trust", "vuln_scan", "license_audit", "policy_check", "generate_report"];
        for w in order.windows(2) {
            let from = node_map[w[0]];
            let to = node_map[w[1]];
            dag.add_edge(from, to, ());
        }

        Self { dag, node_map, steps }
    }

    pub fn run(&self) -> PipelineResult {
        let start = std::time::Instant::now();
        let mut ctx = ExecContext::default();
        let mut result_nodes = Vec::new();
        let mut result_edges = Vec::new();

        // Topological sort via petgraph
        let topo_order = match toposort(&self.dag, None) {
            Ok(order) => order,
            Err(_) => {
                return PipelineResult {
                    graph: ExecutionGraph { nodes: vec![], edges: vec![] },
                    violations: vec![], audit_results: vec![], trust_scores: vec![],
                    report: vec!["DAG cycle detected".to_string()],
                    total_duration_us: 0, verdict: "FAILED".into(),
                };
            }
        };

        let labels: HashMap<&str, (&str, &str)> = [
            ("load_sbom", ("① Load SBOM", "Parse CycloneDX JSON → typed SbomGraph")),
            ("build_indices", ("② Build Indices", "Adjacency maps, petgraph, component stats")),
            ("compute_trust", ("③ Trust Score", "Compute per-component trust 0-100%")),
            ("vuln_scan", ("④ Vulnerability Scan", "Identify critical/high vulnerability paths")),
            ("license_audit", ("⑤ License Audit", "Copyleft propagation, unlicensed detection")),
            ("policy_check", ("⑥ Policy Check", "Supplier, trust threshold, compliance rules")),
            ("generate_report", ("⑦ Generate Report", "Aggregate stats and findings")),
        ].into_iter().collect();

        let mut prev_id: Option<String> = None;

        for nx in &topo_order {
            let id = &self.dag[*nx];
            let step = match self.steps.get(id) {
                Some(s) => s,
                None => continue,
            };
            let (label, desc) = labels.get(id.as_str()).copied().unwrap_or(("?", "?"));

            if let Some(ref prev) = prev_id {
                result_edges.push(ExecEdge { from: prev.clone(), to: id.clone() });
            }
            prev_id = Some(id.clone());

            let step_start = std::time::Instant::now();
            match step.execute(&mut ctx) {
                Ok(summary) => {
                    result_nodes.push(ExecNodeDef {
                        id: id.clone(), kind: id.clone(), label: label.into(), description: desc.into(),
                        status: "success".into(), duration_us: step_start.elapsed().as_micros() as u64, output_summary: summary,
                    });
                }
                Err(e) => {
                    result_nodes.push(ExecNodeDef {
                        id: id.clone(), kind: id.clone(), label: label.into(), description: desc.into(),
                        status: "failed".into(), duration_us: step_start.elapsed().as_micros() as u64, output_summary: e.clone(),
                    });
                    return PipelineResult {
                        graph: ExecutionGraph { nodes: result_nodes, edges: result_edges },
                        violations: ctx.violations,
                        audit_results: ctx.audit_results,
                        trust_scores: ctx.trust_scores.into_iter().map(|(n, s)| TrustEntry { component: n, score: s }).collect(),
                        report: ctx.report_lines,
                        total_duration_us: start.elapsed().as_micros() as u64,
                        verdict: "FAILED".into(),
                    };
                }
            }
        }

        let critical = ctx.violations.iter().any(|v| v.severity == "critical");
        let verdict = if critical { "FAIL" } else { "PASS" };

        PipelineResult {
            graph: ExecutionGraph { nodes: result_nodes, edges: result_edges },
            violations: ctx.violations,
            audit_results: ctx.audit_results,
            trust_scores: ctx.trust_scores.into_iter().map(|(n, s)| TrustEntry { component: n, score: s }).collect(),
            report: ctx.report_lines,
            total_duration_us: start.elapsed().as_micros() as u64,
            verdict: verdict.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustEntry {
    pub component: String,
    pub score: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineResult {
    pub graph: ExecutionGraph,
    pub violations: Vec<PolicyViolation>,
    pub audit_results: Vec<LicenseAuditItem>,
    pub trust_scores: Vec<TrustEntry>,
    pub report: Vec<String>,
    pub total_duration_us: u64,
    pub verdict: String,
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn run_devsecops_pipeline(sbom_path: String) -> Result<PipelineResult, String> {
    let content = std::fs::read_to_string(&sbom_path)
        .map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    let engine = ExecutionEngine::devsecops_pipeline(json);
    Ok(engine.run())
}
