use serde::{Deserialize, Serialize};
use crate::sbom_graph::SbomGraph;
use std::collections::{HashMap, HashSet};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

// ══════════════════════════════════════════════════════
//  Trust Graph — petgraph-based security reasoning layer
//  SbomGraph → TrustGraph → Attack Surface Graph
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustGraph {
    pub nodes: Vec<TrustNode>,
    pub edges: Vec<TrustEdge>,
    pub attack_paths: Vec<AttackPath>,
    pub risk_summary: RiskSummary,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustNode {
    pub id: String,
    pub name: String,
    pub node_type: String,    // component, vulnerability, license, supplier
    pub trust_score: f64,
    pub risk_level: String,   // critical, high, medium, low, none
    pub details: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,    // depends_on, has_vuln, licensed_by, supplied_by, propagates_to
    pub weight: f64,          // risk weight 0-1
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttackPath {
    pub path: Vec<String>,         // node ids root → ... → vuln
    pub vulnerability_id: String,
    pub severity: String,
    pub depth: usize,
    pub risk_score: f64,           // higher = more critical
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RiskSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub attack_paths: usize,
    pub critical_paths: usize,
    pub avg_trust: f64,
    pub min_trust: f64,
    pub max_depth: usize,
    pub exposed_components: usize,  // components reachable from a vulnerability
    pub supply_chain_risk: String,  // CRITICAL, HIGH, MEDIUM, LOW
    pub copyleft_risk: usize,
    pub untrusted_suppliers: usize,
}

/// Edge kind for petgraph TrustGraph
#[derive(Clone, Copy, Debug, PartialEq)]
enum TrustEdgeKind {
    DependsOn,
    HasVuln,
    LicensedBy,
    SuppliedBy,
    PropagatesTo,
}

impl TrustGraph {
    pub fn from_sbom(sbom: &SbomGraph) -> Self {
        // ── petgraph construction ──
        let mut pg: DiGraph<String, TrustEdgeKind> = DiGraph::with_capacity(
            sbom.components.len() + sbom.vulnerabilities.len() + 64,
            sbom.dependencies.len() * 4,
        );
        let mut id_map: HashMap<String, NodeIndex> = HashMap::new();

        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Helper: ensure node in petgraph
        let mut ensure = |pg: &mut DiGraph<String, TrustEdgeKind>, id: &str, map: &mut HashMap<String, NodeIndex>| -> NodeIndex {
            if let Some(&nx) = map.get(id) { return nx; }
            let nx = pg.add_node(id.to_string());
            map.insert(id.to_string(), nx);
            nx
        };

        // Component nodes
        for comp in &sbom.components {
            let id = comp.bom_ref.as_deref().unwrap_or(&comp.name).to_string();
            let risk = if comp.vuln_count > 0 && comp.trust_score < 0.5 { "critical" }
                else if comp.vuln_count > 0 { "high" }
                else if comp.trust_score < 0.3 { "medium" }
                else if comp.trust_score < 0.7 { "low" }
                else { "none" };

            let mut details = HashMap::new();
            details.insert("version".into(), comp.version.clone().unwrap_or_default());
            details.insert("type".into(), comp.component_type.clone());
            if let Some(ref p) = comp.purl { details.insert("purl".into(), p.clone()); }
            details.insert("deps".into(), format!("{}", comp.dep_count));
            details.insert("dependents".into(), format!("{}", comp.dependents_count));
            details.insert("vulns".into(), format!("{}", comp.vuln_count));

            ensure(&mut pg, &id, &mut id_map);
            nodes.push(TrustNode { id: id.clone(), name: comp.name.clone(), node_type: "component".into(), trust_score: comp.trust_score, risk_level: risk.into(), details });
        }

        // Vulnerability nodes
        for vuln in &sbom.vulnerabilities {
            let risk = match vuln.severity.as_deref() {
                Some("critical") | Some("CRITICAL") => "critical",
                Some("high") | Some("HIGH") => "high",
                Some("medium") | Some("MEDIUM") => "medium",
                _ => "low",
            };
            let mut details = HashMap::new();
            if let Some(ref s) = vuln.source { details.insert("source".into(), s.clone()); }
            if let Some(c) = vuln.cvss_score { details.insert("cvss".into(), format!("{:.1}", c)); }
            if let Some(ref d) = vuln.description { details.insert("description".into(), d.chars().take(120).collect()); }

            ensure(&mut pg, &vuln.id, &mut id_map);
            nodes.push(TrustNode { id: vuln.id.clone(), name: vuln.id.clone(), node_type: "vulnerability".into(), trust_score: 0.0, risk_level: risk.into(), details });
        }

        // Supplier nodes (deduplicated)
        let mut supplier_set = HashSet::new();
        for comp in &sbom.components {
            if let Some(ref sup) = comp.supplier {
                let sname = sup.name.as_deref().unwrap_or("unknown");
                if supplier_set.insert(sname.to_string()) {
                    let sid = format!("supplier:{}", sname);
                    ensure(&mut pg, &sid, &mut id_map);
                    nodes.push(TrustNode { id: sid.clone(), name: sname.into(), node_type: "supplier".into(), trust_score: 1.0, risk_level: "none".into(), details: HashMap::new() });
                }
            }
        }

        // License nodes (deduplicated)
        let mut license_set = HashSet::new();
        for comp in &sbom.components {
            for lic in &comp.licenses {
                let lid = lic.id.as_deref().or(lic.name.as_deref()).unwrap_or("unknown");
                if license_set.insert(lid.to_string()) {
                    let copyleft = ["GPL", "LGPL", "AGPL", "MPL", "EUPL", "CDDL", "EPL"];
                    let risk = if copyleft.iter().any(|c| lid.to_uppercase().contains(c)) { "medium" } else { "none" };
                    let nid = format!("license:{}", lid);
                    ensure(&mut pg, &nid, &mut id_map);
                    nodes.push(TrustNode { id: nid.clone(), name: lid.into(), node_type: "license".into(), trust_score: if risk == "none" { 1.0 } else { 0.5 }, risk_level: risk.into(), details: HashMap::new() });
                }
            }
        }

        // ── petgraph edges ──

        // Dependency edges
        for dep in &sbom.dependencies {
            let from_nx = ensure(&mut pg, &dep.from_ref, &mut id_map);
            for to in &dep.to_refs {
                let to_nx = ensure(&mut pg, to, &mut id_map);
                pg.add_edge(from_nx, to_nx, TrustEdgeKind::DependsOn);
                edges.push(TrustEdge { from: dep.from_ref.clone(), to: to.clone(), edge_type: "depends_on".into(), weight: 0.3 });
            }
        }

        // Vulnerability edges
        for vuln in &sbom.vulnerabilities {
            let vuln_nx = ensure(&mut pg, &vuln.id, &mut id_map);
            for comp_ref in &vuln.affects {
                if id_map.contains_key(comp_ref) {
                    let comp_nx = id_map[comp_ref];
                    pg.add_edge(comp_nx, vuln_nx, TrustEdgeKind::HasVuln);
                    let w = match vuln.severity.as_deref() { Some("critical") | Some("CRITICAL") => 1.0, Some("high") | Some("HIGH") => 0.8, Some("medium") | Some("MEDIUM") => 0.5, _ => 0.2 };
                    edges.push(TrustEdge { from: comp_ref.clone(), to: vuln.id.clone(), edge_type: "has_vuln".into(), weight: w });
                }
            }
        }

        // Supplier edges
        for comp in &sbom.components {
            if let Some(ref sup) = comp.supplier {
                let sid = format!("supplier:{}", sup.name.as_deref().unwrap_or("unknown"));
                let cid = comp.bom_ref.as_deref().unwrap_or(&comp.name);
                let comp_nx = ensure(&mut pg, cid, &mut id_map);
                let sup_nx = ensure(&mut pg, &sid, &mut id_map);
                pg.add_edge(comp_nx, sup_nx, TrustEdgeKind::SuppliedBy);
                edges.push(TrustEdge { from: cid.into(), to: sid, edge_type: "supplied_by".into(), weight: 0.1 });
            }
        }

        // License edges
        for comp in &sbom.components {
            for lic in &comp.licenses {
                let lid = format!("license:{}", lic.id.as_deref().or(lic.name.as_deref()).unwrap_or("unknown"));
                let cid = comp.bom_ref.as_deref().unwrap_or(&comp.name);
                let comp_nx = ensure(&mut pg, cid, &mut id_map);
                let lic_nx = ensure(&mut pg, &lid, &mut id_map);
                pg.add_edge(comp_nx, lic_nx, TrustEdgeKind::LicensedBy);
                edges.push(TrustEdge { from: cid.into(), to: lid, edge_type: "licensed_by".into(), weight: 0.1 });
            }
        }

        // Copyleft propagation edges
        for (lic, from, to) in sbom.copyleft_propagation() {
            let from_nx = ensure(&mut pg, &from, &mut id_map);
            let to_nx = ensure(&mut pg, &to, &mut id_map);
            pg.add_edge(from_nx, to_nx, TrustEdgeKind::PropagatesTo);
            edges.push(TrustEdge { from, to, edge_type: "propagates_to".into(), weight: 0.6 });
        }

        // ── Attack paths via petgraph BFS ──
        let attack_paths = compute_attack_paths_petgraph(&pg, &id_map, sbom);

        // Risk summary
        let avg_trust = if nodes.is_empty() { 0.0 } else { nodes.iter().filter(|n| n.node_type == "component").map(|n| n.trust_score).sum::<f64>() / nodes.iter().filter(|n| n.node_type == "component").count().max(1) as f64 };
        let min_trust = nodes.iter().filter(|n| n.node_type == "component").map(|n| n.trust_score).fold(1.0_f64, f64::min);
        let critical_paths = attack_paths.iter().filter(|p| p.severity == "critical" || p.severity == "CRITICAL").count();
        let max_depth = attack_paths.iter().map(|p| p.depth).max().unwrap_or(0);
        let exposed = nodes.iter().filter(|n| n.node_type == "component" && (n.risk_level == "critical" || n.risk_level == "high")).count();
        let supply_risk = if critical_paths > 5 { "CRITICAL" } else if critical_paths > 0 { "HIGH" } else if avg_trust < 0.5 { "MEDIUM" } else { "LOW" };

        let risk_summary = RiskSummary {
            total_nodes: nodes.len(), total_edges: edges.len(),
            attack_paths: attack_paths.len(), critical_paths, avg_trust, min_trust, max_depth,
            exposed_components: exposed,
            supply_chain_risk: supply_risk.into(),
            copyleft_risk: sbom.copyleft_propagation().len(),
            untrusted_suppliers: 0,
        };

        TrustGraph { nodes, edges, attack_paths, risk_summary }
    }
}

/// Compute attack paths using petgraph BFS reverse traversal
fn compute_attack_paths_petgraph(
    pg: &DiGraph<String, TrustEdgeKind>,
    id_map: &HashMap<String, NodeIndex>,
    sbom: &SbomGraph,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();
    for vuln in &sbom.vulnerabilities {
        for comp_ref in &vuln.affects {
            let Some(&start) = id_map.get(comp_ref) else { continue };
            // BFS reverse via DependsOn edges to find root path
            let mut path_ids = vec![comp_ref.clone()];
            let mut visited = vec![false; pg.node_count()];
            visited[start.index()] = true;
            let mut current = start;
            loop {
                let parent = pg.edges_directed(current, Direction::Incoming)
                    .find(|e| *e.weight() == TrustEdgeKind::DependsOn && !visited[e.source().index()])
                    .map(|e| e.source());
                if let Some(p) = parent {
                    visited[p.index()] = true;
                    path_ids.push(pg[p].clone());
                    current = p;
                } else {
                    break;
                }
            }
            path_ids.reverse();
            path_ids.push(vuln.id.clone());
            let depth = path_ids.len();
            let risk = match vuln.severity.as_deref() {
                Some("critical") | Some("CRITICAL") => 10.0 * depth as f64,
                Some("high") | Some("HIGH") => 7.0 * depth as f64,
                Some("medium") | Some("MEDIUM") => 4.0 * depth as f64,
                _ => 1.0 * depth as f64,
            };
            paths.push(AttackPath {
                path: path_ids,
                vulnerability_id: vuln.id.clone(),
                severity: vuln.severity.clone().unwrap_or_else(|| "unknown".into()),
                depth, risk_score: risk,
                description: format!("{} → {} (depth {})", comp_ref, vuln.id, depth),
            });
        }
    }
    paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
    paths.truncate(50);
    paths
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn build_trust_graph(sbom_path: String) -> Result<TrustGraph, String> {
    let content = std::fs::read_to_string(&sbom_path)
        .map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;
    let sbom = SbomGraph::from_cdx_json(&json)?;
    Ok(TrustGraph::from_sbom(&sbom))
}
