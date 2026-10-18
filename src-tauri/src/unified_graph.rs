use serde::{Deserialize, Serialize};
use crate::sbom_graph::{SbomGraph, SbomStats};
use std::collections::HashMap;

// ══════════════════════════════════════════════════════
//  Unified System Graph — connects 4 sub-graphs
//  ExecutionGraph + SBOMGraph + RuleGraph + ArtifactGraph
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemGraph {
    pub sbom: Option<SbomGraph>,
    pub execution_nodes: Vec<ExecNode>,
    pub rules: Vec<RuleNode>,
    pub artifacts: Vec<ArtifactNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecNode {
    pub id: String,
    pub name: String,
    pub node_type: String,  // scan, validate, transform, evaluate, export
    pub status: String,     // pending, running, success, failed
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RuleNode {
    pub id: String,
    pub name: String,
    pub field: String,
    pub operator: String,
    pub severity: String,
    pub result: Option<bool>,
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArtifactNode {
    pub id: String,
    pub name: String,
    pub artifact_type: String, // sbom, sarif, vex, license_report, diagnostics
    pub path: Option<String>,
    pub size_bytes: Option<u64>,
    pub produced_by: Option<String>, // exec node id
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,  // produces, represents, evaluates, uses, triggers, depends_on
    pub label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphSummary {
    pub total_nodes: usize,
    pub exec_nodes: usize,
    pub sbom_components: usize,
    pub rule_nodes: usize,
    pub artifact_nodes: usize,
    pub total_edges: usize,
    pub sbom_stats: Option<SbomStats>,
    pub trust_verdict: String,        // TRUSTED, PARTIAL, UNTRUSTED
    pub compliance_score: f64,
}

impl SystemGraph {
    /// Build unified graph from SBOM JSON + pipeline config
    pub fn from_sbom_json(json: &serde_json::Value) -> Result<Self, String> {
        let sbom = SbomGraph::from_cdx_json(json)?;

        // Auto-generate execution nodes
        let execution_nodes = vec![
            ExecNode { id: "exec-scan".into(), name: "① Generate SBOM".into(), node_type: "scan".into(), status: "success".into(), inputs: vec!["source-code".into()], outputs: vec!["sbom.json".into()] },
            ExecNode { id: "exec-validate".into(), name: "② Validate".into(), node_type: "validate".into(), status: "success".into(), inputs: vec!["sbom.json".into()], outputs: vec!["validation-report".into()] },
            ExecNode { id: "exec-rules".into(), name: "③ Evaluate Rules".into(), node_type: "evaluate".into(), status: "success".into(), inputs: vec!["sbom.json".into()], outputs: vec!["rule-results".into()] },
            ExecNode { id: "exec-scan-vulns".into(), name: "④ Scan Vulns".into(), node_type: "scan".into(), status: "success".into(), inputs: vec!["sbom.json".into()], outputs: vec!["trivy-scan.json".into()] },
            ExecNode { id: "exec-export".into(), name: "⑤ Export".into(), node_type: "export".into(), status: "success".into(), inputs: vec!["sbom.json".into(), "rule-results".into()], outputs: vec!["report.json".into(), "report.sarif".into()] },
        ];

        // Auto-generate rule nodes from built-in profiles
        let profiles = crate::policies::all_builtin_profiles_pub();
        let rules: Vec<RuleNode> = profiles.iter().flat_map(|p| {
            p.rules.iter().map(|r| {
                let result = crate::policies::evaluate_rules_against(&[r.clone()], json);
                RuleNode {
                    id: r.id.clone(),
                    name: format!("{} ({})", r.id, p.id),
                    field: r.field.clone(),
                    operator: r.operator.clone(),
                    severity: r.severity.clone(),
                    result: Some(result.1 == 0),
                    message: None,
                }
            }).collect::<Vec<_>>()
        }).collect();

        // Auto-generate artifact nodes
        let artifacts = vec![
            ArtifactNode { id: "art-sbom".into(), name: "sbom.json".into(), artifact_type: "sbom".into(), path: None, size_bytes: None, produced_by: Some("exec-scan".into()) },
            ArtifactNode { id: "art-sarif".into(), name: "report.sarif".into(), artifact_type: "sarif".into(), path: None, size_bytes: None, produced_by: Some("exec-export".into()) },
            ArtifactNode { id: "art-vex".into(), name: "vex.json".into(), artifact_type: "vex".into(), path: None, size_bytes: None, produced_by: Some("exec-scan-vulns".into()) },
        ];

        // Build cross-graph edges
        let mut edges = Vec::new();

        // ExecutionNode → produces → Artifact
        edges.push(GraphEdge { from: "exec-scan".into(), to: "art-sbom".into(), edge_type: "produces".into(), label: Some("SBOM generation".into()) });
        edges.push(GraphEdge { from: "exec-export".into(), to: "art-sarif".into(), edge_type: "produces".into(), label: Some("SARIF export".into()) });
        edges.push(GraphEdge { from: "exec-scan-vulns".into(), to: "art-vex".into(), edge_type: "produces".into(), label: Some("VEX template".into()) });

        // Artifact → represents → SBOMGraph
        edges.push(GraphEdge { from: "art-sbom".into(), to: "sbom-graph".into(), edge_type: "represents".into(), label: Some("CycloneDX model".into()) });

        // Rule → evaluates → SBOM Component
        for rule in &rules {
            edges.push(GraphEdge { from: rule.id.clone(), to: "sbom-graph".into(), edge_type: "evaluates".into(), label: Some(rule.field.clone()) });
        }

        // ExecutionNode → triggers → RuleEvaluation
        edges.push(GraphEdge { from: "exec-rules".into(), to: rules.first().map(|r| r.id.clone()).unwrap_or_default(), edge_type: "triggers".into(), label: Some("policy eval".into()) });

        // Execution pipeline edges
        edges.push(GraphEdge { from: "exec-scan".into(), to: "exec-validate".into(), edge_type: "depends_on".into(), label: None });
        edges.push(GraphEdge { from: "exec-validate".into(), to: "exec-rules".into(), edge_type: "depends_on".into(), label: None });
        edges.push(GraphEdge { from: "exec-rules".into(), to: "exec-scan-vulns".into(), edge_type: "depends_on".into(), label: None });
        edges.push(GraphEdge { from: "exec-scan-vulns".into(), to: "exec-export".into(), edge_type: "depends_on".into(), label: None });

        let stats = sbom.stats();
        let trust = if stats.avg_trust_score >= 0.8 { "TRUSTED" } else if stats.avg_trust_score >= 0.5 { "PARTIAL" } else { "UNTRUSTED" };
        let compliance = stats.license_coverage * 0.3 + stats.supplier_coverage * 0.3 + stats.purl_coverage * 0.2 + stats.hash_coverage * 0.2;

        Ok(SystemGraph {
            sbom: Some(sbom),
            execution_nodes,
            rules,
            artifacts,
            edges,
        })
    }

    pub fn summary(&self) -> GraphSummary {
        let sbom_stats = self.sbom.as_ref().map(|s| s.stats());
        let avg_trust = sbom_stats.as_ref().map(|s| s.avg_trust_score).unwrap_or(0.0);
        let trust = if avg_trust >= 0.8 { "TRUSTED" } else if avg_trust >= 0.5 { "PARTIAL" } else { "UNTRUSTED" };
        let compliance = sbom_stats.as_ref().map(|s| s.license_coverage * 0.3 + s.supplier_coverage * 0.3 + s.purl_coverage * 0.2 + s.hash_coverage * 0.2).unwrap_or(0.0);
        GraphSummary {
            total_nodes: self.execution_nodes.len() + self.sbom.as_ref().map(|s| s.components.len()).unwrap_or(0) + self.rules.len() + self.artifacts.len(),
            exec_nodes: self.execution_nodes.len(),
            sbom_components: self.sbom.as_ref().map(|s| s.components.len()).unwrap_or(0),
            rule_nodes: self.rules.len(),
            artifact_nodes: self.artifacts.len(),
            total_edges: self.edges.len(),
            sbom_stats,
            trust_verdict: trust.into(),
            compliance_score: compliance,
        }
    }
}

// ══════════════════════════════════════════════════════
//  SBOM Query Engine — DSL for graph queries
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SbomQuery {
    pub target: String,               // "components", "vulnerabilities", "dependencies"
    pub filters: Vec<QueryFilter>,
    pub sort_by: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueryFilter {
    pub field: String,
    pub op: String,           // eq, ne, contains, gt, lt, exists, not_exists, in
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueryResult {
    pub query: String,
    pub total: usize,
    pub items: Vec<serde_json::Value>,
    pub duration_us: u64,
}

pub fn execute_query(graph: &SbomGraph, query: &SbomQuery) -> QueryResult {
    let start = std::time::Instant::now();
    let description = format!("{} where {:?}", query.target, query.filters.iter().map(|f| format!("{} {} {}", f.field, f.op, f.value)).collect::<Vec<_>>().join(" AND "));

    let items: Vec<serde_json::Value> = match query.target.as_str() {
        "components" => {
            let mut results: Vec<&crate::sbom_graph::Component> = graph.components.iter().collect();
            // Apply filters
            for filter in &query.filters {
                results.retain(|c| match_component(c, filter));
            }
            // Sort
            if let Some(ref sort) = query.sort_by {
                match sort.as_str() {
                    "name" => results.sort_by(|a, b| a.name.cmp(&b.name)),
                    "trust_score" => results.sort_by(|a, b| b.trust_score.partial_cmp(&a.trust_score).unwrap_or(std::cmp::Ordering::Equal)),
                    "vuln_count" => results.sort_by(|a, b| b.vuln_count.cmp(&a.vuln_count)),
                    _ => {}
                }
            }
            // Limit
            if let Some(limit) = query.limit { results.truncate(limit); }
            results.into_iter().map(|c| serde_json::json!({
                "name": c.name, "version": c.version, "type": c.component_type,
                "purl": c.purl, "group": c.group,
                "licenses": c.licenses.iter().map(|l| l.id.as_deref().or(l.name.as_deref()).unwrap_or("")).collect::<Vec<_>>(),
                "supplier": c.supplier.as_ref().and_then(|s| s.name.as_deref()),
                "vuln_count": c.vuln_count, "dep_count": c.dep_count,
                "trust_score": format!("{:.1}%", c.trust_score * 100.0),
            })).collect()
        }
        "vulnerabilities" => {
            let mut results: Vec<&crate::sbom_graph::Vulnerability> = graph.vulnerabilities.iter().collect();
            for filter in &query.filters {
                results.retain(|v| match_vulnerability(v, filter));
            }
            if let Some(limit) = query.limit { results.truncate(limit); }
            results.into_iter().map(|v| serde_json::json!({
                "id": v.id, "severity": v.severity, "cvss": v.cvss_score,
                "affects": v.affects.len(), "source": v.source, "description": v.description,
            })).collect()
        }
        "unlicensed" => {
            graph.unlicensed().into_iter().take(query.limit.unwrap_or(100)).map(|c| serde_json::json!({
                "name": c.name, "version": c.version, "purl": c.purl, "supplier": c.supplier.as_ref().and_then(|s| s.name.as_deref()),
            })).collect()
        }
        "no_supplier" => {
            graph.no_supplier().into_iter().take(query.limit.unwrap_or(100)).map(|c| serde_json::json!({
                "name": c.name, "version": c.version, "purl": c.purl, "licenses": c.licenses.first().and_then(|l| l.id.as_deref()),
            })).collect()
        }
        "copyleft" => {
            graph.copyleft_propagation().into_iter().take(query.limit.unwrap_or(100)).map(|(lic, from, to)| serde_json::json!({
                "license": lic, "source_component": from, "propagates_to": to,
            })).collect()
        }
        "critical" => {
            graph.critical_vulnerable().into_iter().take(query.limit.unwrap_or(100)).map(|(c, vulns)| serde_json::json!({
                "name": c.name, "version": c.version,
                "vulns": vulns.iter().map(|v| serde_json::json!({ "id": v.id, "severity": v.severity, "cvss": v.cvss_score })).collect::<Vec<_>>(),
            })).collect()
        }
        _ => vec![],
    };

    QueryResult {
        query: description,
        total: items.len(),
        items,
        duration_us: start.elapsed().as_micros() as u64,
    }
}

fn match_component(c: &crate::sbom_graph::Component, f: &QueryFilter) -> bool {
    let field_val = match f.field.as_str() {
        "name" => c.name.clone(),
        "version" => c.version.clone().unwrap_or_default(),
        "type" => c.component_type.clone(),
        "group" => c.group.clone().unwrap_or_default(),
        "purl" => c.purl.clone().unwrap_or_default(),
        "license" => c.licenses.first().and_then(|l| l.id.clone().or_else(|| l.name.clone())).unwrap_or_default(),
        "supplier" => c.supplier.as_ref().and_then(|s| s.name.clone()).unwrap_or_default(),
        "scope" => c.scope.clone().unwrap_or_default(),
        _ => String::new(),
    };
    match f.op.as_str() {
        "eq" => field_val == f.value,
        "ne" => field_val != f.value,
        "contains" => field_val.to_lowercase().contains(&f.value.to_lowercase()),
        "exists" => !field_val.is_empty(),
        "not_exists" => field_val.is_empty(),
        _ => true,
    }
}

fn match_vulnerability(v: &crate::sbom_graph::Vulnerability, f: &QueryFilter) -> bool {
    let field_val = match f.field.as_str() {
        "id" => v.id.clone(),
        "severity" => v.severity.clone().unwrap_or_default(),
        "source" => v.source.clone().unwrap_or_default(),
        _ => String::new(),
    };
    match f.op.as_str() {
        "eq" => field_val.to_lowercase() == f.value.to_lowercase(),
        "contains" => field_val.to_lowercase().contains(&f.value.to_lowercase()),
        _ => true,
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn build_system_graph(sbom_path: String) -> Result<GraphSummary, String> {
    let content = std::fs::read_to_string(&sbom_path)
        .map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    let sys = SystemGraph::from_sbom_json(&json)?;
    Ok(sys.summary())
}

#[tauri::command]
pub fn query_sbom_graph(sbom_path: String, query: SbomQuery) -> Result<QueryResult, String> {
    let content = std::fs::read_to_string(&sbom_path)
        .map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    let graph = SbomGraph::from_cdx_json(&json)?;
    Ok(execute_query(&graph, &query))
}

#[tauri::command]
pub fn get_graph_edges(sbom_path: String) -> Result<SystemGraph, String> {
    let content = std::fs::read_to_string(&sbom_path)
        .map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    SystemGraph::from_sbom_json(&json)
}
