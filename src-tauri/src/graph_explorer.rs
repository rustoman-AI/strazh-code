use serde::{Deserialize, Serialize};
use crate::sbom_graph::SbomGraph;
use std::collections::{HashMap, HashSet, VecDeque};

// ══════════════════════════════════════════════════════
//  Graph Explorer — interactive node expansion
//  Supports: components, vulnerabilities, licenses,
//  suppliers, dependencies, pipeline stages
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GNode {
    pub id: String,
    pub label: String,
    pub kind: String,       // component, vulnerability, license, supplier, pipeline, artifact
    pub color: String,
    pub icon: String,
    pub size: f64,          // node radius
    pub details: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GEdge {
    pub from: String,
    pub to: String,
    pub kind: String,       // depends_on, has_vuln, licensed_by, supplied_by, produces, contains
    pub label: String,
    pub color: String,
    pub dashed: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphSubgraph {
    pub center: String,
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FullGraphView {
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
    pub stats: GraphViewStats,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphViewStats {
    pub total_nodes: usize,
    pub component_nodes: usize,
    pub vuln_nodes: usize,
    pub license_nodes: usize,
    pub supplier_nodes: usize,
    pub pipeline_nodes: usize,
    pub total_edges: usize,
}

// ─────────────────── Build full graph ───────────────────

fn build_full_graph(sbom: &SbomGraph) -> (Vec<GNode>, Vec<GEdge>) {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen_licenses = HashSet::new();
    let mut seen_suppliers = HashSet::new();

    // Components
    for comp in &sbom.components {
        let id = comp.bom_ref.as_deref().unwrap_or(&comp.name).to_string();
        let risk = if comp.vuln_count > 0 { "high" } else if comp.trust_score < 0.5 { "medium" } else { "ok" };
        let color = match risk { "high" => "#ff4d4f", "medium" => "#fa8c16", _ => "#1890ff" };
        let mut det = HashMap::new();
        det.insert("version".into(), comp.version.clone().unwrap_or_default());
        det.insert("type".into(), comp.component_type.clone());
        det.insert("trust".into(), format!("{:.0}%", comp.trust_score * 100.0));
        det.insert("vulns".into(), format!("{}", comp.vuln_count));
        det.insert("deps".into(), format!("{}", comp.dep_count));
        if let Some(ref p) = comp.purl { det.insert("purl".into(), p.clone()); }

        let short_name = comp.name.split('/').last().unwrap_or(&comp.name);
        nodes.push(GNode { id: id.clone(), label: short_name.to_string(), kind: "component".into(), color: color.into(), icon: "📦".into(), size: 20.0 + (comp.dependents_count as f64).min(15.0), details: det });
    }

    // Vulnerabilities
    for vuln in &sbom.vulnerabilities {
        let color = match vuln.severity.as_deref() {
            Some("critical") | Some("CRITICAL") => "#ff4d4f",
            Some("high") | Some("HIGH") => "#fa8c16",
            Some("medium") | Some("MEDIUM") => "#fadb14",
            _ => "#52c41a",
        };
        let mut det = HashMap::new();
        if let Some(ref s) = vuln.source { det.insert("source".into(), s.clone()); }
        if let Some(c) = vuln.cvss_score { det.insert("cvss".into(), format!("{:.1}", c)); }
        det.insert("severity".into(), vuln.severity.clone().unwrap_or_default());

        nodes.push(GNode { id: vuln.id.clone(), label: vuln.id.clone(), kind: "vulnerability".into(), color: color.into(), icon: "🔴".into(), size: 18.0, details: det });

        for comp_ref in &vuln.affects {
            edges.push(GEdge { from: comp_ref.clone(), to: vuln.id.clone(), kind: "has_vuln".into(), label: "vuln".into(), color: color.into(), dashed: false });
        }
    }

    // Dependencies
    for dep in &sbom.dependencies {
        for to in &dep.to_refs {
            edges.push(GEdge { from: dep.from_ref.clone(), to: to.clone(), kind: "depends_on".into(), label: "dep".into(), color: "#555".into(), dashed: false });
        }
    }

    // Licenses (deduplicated)
    for comp in &sbom.components {
        let comp_id = comp.bom_ref.as_deref().unwrap_or(&comp.name);
        for lic in &comp.licenses {
            let lid = lic.id.as_deref().or(lic.name.as_deref()).unwrap_or("unknown");
            let nid = format!("lic:{}", lid);
            if seen_licenses.insert(nid.clone()) {
                let copyleft = ["GPL", "LGPL", "AGPL", "MPL"];
                let color = if copyleft.iter().any(|c| lid.to_uppercase().contains(c)) { "#fa8c16" } else { "#52c41a" };
                nodes.push(GNode { id: nid.clone(), label: lid.into(), kind: "license".into(), color: color.into(), icon: "📜".into(), size: 14.0, details: HashMap::new() });
            }
            edges.push(GEdge { from: comp_id.into(), to: nid, kind: "licensed_by".into(), label: "license".into(), color: "#52c41a33".into(), dashed: true });
        }
    }

    // Suppliers (deduplicated)
    for comp in &sbom.components {
        let comp_id = comp.bom_ref.as_deref().unwrap_or(&comp.name);
        if let Some(ref sup) = comp.supplier {
            let sname = sup.name.as_deref().unwrap_or("unknown");
            let nid = format!("sup:{}", sname);
            if seen_suppliers.insert(nid.clone()) {
                nodes.push(GNode { id: nid.clone(), label: sname.into(), kind: "supplier".into(), color: "#722ed1".into(), icon: "🏢".into(), size: 16.0, details: HashMap::new() });
            }
            edges.push(GEdge { from: comp_id.into(), to: nid, kind: "supplied_by".into(), label: "supplier".into(), color: "#722ed133".into(), dashed: true });
        }
    }

    // Pipeline stages (static)
    let stages = [
        ("pipe:scan", "① Scan", "pipeline", "#1890ff"),
        ("pipe:validate", "② Validate", "pipeline", "#52c41a"),
        ("pipe:rules", "③ Rules", "pipeline", "#fa8c16"),
        ("pipe:vuln", "④ Vuln Scan", "pipeline", "#ff4d4f"),
        ("pipe:export", "⑤ Export", "pipeline", "#722ed1"),
    ];
    for (id, label, kind, color) in &stages {
        nodes.push(GNode { id: id.to_string(), label: label.to_string(), kind: kind.to_string(), color: color.to_string(), icon: "⚙️".into(), size: 22.0, details: HashMap::new() });
    }
    // Pipeline edges
    edges.push(GEdge { from: "pipe:scan".into(), to: "pipe:validate".into(), kind: "pipeline".into(), label: "→".into(), color: "#1890ff".into(), dashed: false });
    edges.push(GEdge { from: "pipe:validate".into(), to: "pipe:rules".into(), kind: "pipeline".into(), label: "→".into(), color: "#52c41a".into(), dashed: false });
    edges.push(GEdge { from: "pipe:rules".into(), to: "pipe:vuln".into(), kind: "pipeline".into(), label: "→".into(), color: "#fa8c16".into(), dashed: false });
    edges.push(GEdge { from: "pipe:vuln".into(), to: "pipe:export".into(), kind: "pipeline".into(), label: "→".into(), color: "#ff4d4f".into(), dashed: false });

    // Artifact nodes
    let artifacts = [("art:sbom", "sbom.json", "📄"), ("art:sarif", "report.sarif", "📋"), ("art:vex", "vex.json", "🛡️")];
    for (id, label, icon) in &artifacts {
        nodes.push(GNode { id: id.to_string(), label: label.to_string(), kind: "artifact".into(), color: "#13c2c2".into(), icon: icon.to_string(), size: 15.0, details: HashMap::new() });
    }
    edges.push(GEdge { from: "pipe:scan".into(), to: "art:sbom".into(), kind: "produces".into(), label: "produces".into(), color: "#13c2c2".into(), dashed: true });
    edges.push(GEdge { from: "pipe:export".into(), to: "art:sarif".into(), kind: "produces".into(), label: "produces".into(), color: "#13c2c2".into(), dashed: true });
    edges.push(GEdge { from: "pipe:vuln".into(), to: "art:vex".into(), kind: "produces".into(), label: "produces".into(), color: "#13c2c2".into(), dashed: true });

    (nodes, edges)
}

// ─────────────────── Expand node ───────────────────

fn expand_from_graph(node_id: &str, all_nodes: &[GNode], all_edges: &[GEdge]) -> GraphSubgraph {
    let mut sub_nodes = Vec::new();
    let mut sub_edges = Vec::new();
    let mut included = HashSet::new();

    // Add center node
    if let Some(center) = all_nodes.iter().find(|n| n.id == node_id) {
        sub_nodes.push(center.clone());
        included.insert(node_id.to_string());
    }

    // Add all direct neighbors (1 hop)
    for edge in all_edges {
        if edge.from == node_id {
            sub_edges.push(edge.clone());
            if included.insert(edge.to.clone()) {
                if let Some(n) = all_nodes.iter().find(|n| n.id == edge.to) {
                    sub_nodes.push(n.clone());
                }
            }
        }
        if edge.to == node_id {
            sub_edges.push(edge.clone());
            if included.insert(edge.from.clone()) {
                if let Some(n) = all_nodes.iter().find(|n| n.id == edge.from) {
                    sub_nodes.push(n.clone());
                }
            }
        }
    }

    GraphSubgraph { center: node_id.into(), nodes: sub_nodes, edges: sub_edges }
}

// ─────────────────── Graph traversal ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TraversalQuery {
    pub start_kind: String,       // "component", "vulnerability"
    pub filter_field: Option<String>,
    pub filter_op: Option<String>,
    pub filter_value: Option<String>,
    pub expand_kinds: Vec<String>, // e.g., ["depends_on", "has_vuln"]
    pub depth: usize,
    pub limit: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TraversalResult {
    pub query_desc: String,
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
    pub paths: Vec<Vec<String>>,
    pub duration_us: u64,
}

fn run_traversal(query: &TraversalQuery, all_nodes: &[GNode], all_edges: &[GEdge]) -> TraversalResult {
    let start = std::time::Instant::now();

    // Find start nodes
    let mut start_nodes: Vec<&GNode> = all_nodes.iter().filter(|n| n.kind == query.start_kind).collect();

    // Apply filter
    if let (Some(ref field), Some(ref op), Some(ref value)) = (&query.filter_field, &query.filter_op, &query.filter_value) {
        start_nodes.retain(|n| {
            let fv = n.details.get(field.as_str()).map(|s| s.as_str()).unwrap_or("");
            match op.as_str() {
                "eq" => fv == value,
                "ne" => fv != value,
                "contains" => fv.to_lowercase().contains(&value.to_lowercase()),
                "gt" => fv.parse::<f64>().unwrap_or(0.0) > value.parse::<f64>().unwrap_or(0.0),
                "lt" => fv.parse::<f64>().unwrap_or(0.0) < value.parse::<f64>().unwrap_or(0.0),
                _ => true,
            }
        });
    }

    let mut result_nodes = HashSet::new();
    let mut result_edges = Vec::new();
    let mut paths = Vec::new();

    for snode in start_nodes.iter().take(query.limit) {
        result_nodes.insert(snode.id.clone());

        // BFS expand along specified edge kinds
        let mut queue = VecDeque::new();
        queue.push_back((snode.id.clone(), vec![snode.id.clone()], 0usize));
        let mut visited = HashSet::new();
        visited.insert(snode.id.clone());

        while let Some((current, path, depth)) = queue.pop_front() {
            if depth >= query.depth { continue; }

            for edge in all_edges {
                let neighbor = if edge.from == current && query.expand_kinds.contains(&edge.kind) {
                    Some(edge.to.clone())
                } else if edge.to == current && query.expand_kinds.contains(&edge.kind) {
                    Some(edge.from.clone())
                } else {
                    None
                };

                if let Some(nb) = neighbor {
                    if visited.insert(nb.clone()) {
                        result_nodes.insert(nb.clone());
                        result_edges.push(edge.clone());
                        let mut new_path = path.clone();
                        new_path.push(nb.clone());
                        queue.push_back((nb, new_path.clone(), depth + 1));
                        if depth + 1 == query.depth {
                            paths.push(new_path);
                        }
                    }
                }
            }
        }
    }

    let nodes: Vec<GNode> = all_nodes.iter().filter(|n| result_nodes.contains(&n.id)).cloned().collect();

    TraversalResult {
        query_desc: format!("MATCH {} {} EXPAND {:?} DEPTH {} LIMIT {}",
            query.start_kind,
            query.filter_field.as_deref().map(|f| format!("WHERE {} {} {}", f, query.filter_op.as_deref().unwrap_or("?"), query.filter_value.as_deref().unwrap_or("?"))).unwrap_or_default(),
            query.expand_kinds, query.depth, query.limit),
        nodes, edges: result_edges, paths,
        duration_us: start.elapsed().as_micros() as u64,
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn get_full_graph(sbom_path: String) -> Result<FullGraphView, String> {
    let content = std::fs::read_to_string(&sbom_path).map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
    let sbom = SbomGraph::from_cdx_json(&json)?;
    let (nodes, edges) = build_full_graph(&sbom);
    let stats = GraphViewStats {
        total_nodes: nodes.len(),
        component_nodes: nodes.iter().filter(|n| n.kind == "component").count(),
        vuln_nodes: nodes.iter().filter(|n| n.kind == "vulnerability").count(),
        license_nodes: nodes.iter().filter(|n| n.kind == "license").count(),
        supplier_nodes: nodes.iter().filter(|n| n.kind == "supplier").count(),
        pipeline_nodes: nodes.iter().filter(|n| n.kind == "pipeline" || n.kind == "artifact").count(),
        total_edges: edges.len(),
    };
    Ok(FullGraphView { nodes, edges, stats })
}

#[tauri::command]
pub fn expand_graph_node(sbom_path: String, node_id: String) -> Result<GraphSubgraph, String> {
    let content = std::fs::read_to_string(&sbom_path).map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
    let sbom = SbomGraph::from_cdx_json(&json)?;
    let (nodes, edges) = build_full_graph(&sbom);
    Ok(expand_from_graph(&node_id, &nodes, &edges))
}

#[tauri::command]
pub fn traverse_graph(sbom_path: String, query: TraversalQuery) -> Result<TraversalResult, String> {
    let content = std::fs::read_to_string(&sbom_path).map_err(|e| format!("Cannot read: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
    let sbom = SbomGraph::from_cdx_json(&json)?;
    let (nodes, edges) = build_full_graph(&sbom);
    Ok(run_traversal(&query, &nodes, &edges))
}
