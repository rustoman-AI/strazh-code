use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::Direction;

use crate::sbom_graph::SbomGraph;
use crate::supply_chain::AstGraph;

// ══════════════════════════════════════════════════════
//  MetaGraph — petgraph-based Multi-Layer Security
//  Reasoning Engine (in-memory DiGraph)
// ══════════════════════════════════════════════════════

// ─────────────────── Node / Edge Payloads ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MetaNodeKind {
    File,
    Module,
    Component,
    Vulnerability,
    BuildTarget,
    Artifact,
    PipelineStep,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetaNode {
    pub id: String,
    pub kind: MetaNodeKind,
    pub label: String,
    pub properties: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Copy)]
pub enum MetaEdgeKind {
    Imports,
    DependsOn,
    UsesComponent,
    HasVuln,
    Builds,
    Produces,
    Contains,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetaEdge {
    pub source: String,
    pub target: String,
    pub kind: MetaEdgeKind,
    pub label: String,
    pub weight: f64,
}

// ─────────────────── petgraph core ───────────────────

pub struct PetMetaGraph {
    pub graph: DiGraph<MetaNode, MetaEdgeKind>,
    id_map: HashMap<String, NodeIndex>,
}

impl PetMetaGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::with_capacity(4096, 8192),
            id_map: HashMap::with_capacity(4096),
        }
    }

    #[inline]
    fn ensure_node(&mut self, node: MetaNode) -> NodeIndex {
        if let Some(&idx) = self.id_map.get(&node.id) {
            return idx;
        }
        let id = node.id.clone();
        let idx = self.graph.add_node(node);
        self.id_map.insert(id, idx);
        idx
    }

    #[inline]
    fn add_edge_by_id(&mut self, from_id: &str, to_id: &str, kind: MetaEdgeKind) {
        if let (Some(&a), Some(&b)) = (self.id_map.get(from_id), self.id_map.get(to_id)) {
            self.graph.add_edge(a, b, kind);
        }
    }

    // ─── Construction ───

    pub fn from_ast_and_sbom(ast: &AstGraph, sbom: Option<&SbomGraph>) -> Self {
        let mut mg = PetMetaGraph::new();

        // 1. AST file nodes
        for src in &ast.source_nodes {
            let mut props = HashMap::new();
            props.insert("language".into(), src.language.clone());
            props.insert("lines".into(), src.lines.to_string());
            props.insert("imports".into(), src.imports.to_string());
            props.insert("size_bytes".into(), src.size_bytes.to_string());
            props.insert("is_entry".into(), src.is_entry.to_string());
            mg.ensure_node(MetaNode {
                id: format!("file:{}", src.path),
                kind: MetaNodeKind::File,
                label: src.path.split('/').last().unwrap_or(&src.path).to_string(),
                properties: props,
            });
        }

        // 2. Import edges
        for imp in &ast.import_edges {
            if imp.import_type == "internal" {
                let mod_path = imp.to_module.replace("::", "/").replace('.', "/");
                if let Some(target) = ast.source_nodes.iter().find(|n| {
                    n.path != imp.from_file
                        && (n.path.contains(&mod_path)
                            || n.path.replace(&['.'][..], "").ends_with(&mod_path))
                }) {
                    let from_id = format!("file:{}", imp.from_file);
                    let to_id = format!("file:{}", target.path);
                    mg.add_edge_by_id(&from_id, &to_id, MetaEdgeKind::Imports);
                }
            } else {
                let mod_root = imp
                    .to_module
                    .split("::")
                    .next()
                    .unwrap_or(&imp.to_module)
                    .split('/')
                    .next()
                    .unwrap_or(&imp.to_module)
                    .to_string();
                let mod_id = format!("module:{}", mod_root);
                mg.ensure_node(MetaNode {
                    id: mod_id.clone(),
                    kind: MetaNodeKind::Module,
                    label: mod_root.clone(),
                    properties: HashMap::from([("type".into(), imp.import_type.clone())]),
                });
                let from_id = format!("file:{}", imp.from_file);
                mg.add_edge_by_id(&from_id, &mod_id, MetaEdgeKind::Imports);
            }
        }

        // 3. SBOM layer
        if let Some(sbom) = sbom {
            // Components
            for comp in &sbom.components {
                let mut props = HashMap::new();
                if let Some(ref v) = comp.version {
                    props.insert("version".into(), v.clone());
                }
                if let Some(ref p) = comp.purl {
                    props.insert("purl".into(), p.clone());
                }
                if !comp.licenses.is_empty() {
                    let names: Vec<String> = comp
                        .licenses
                        .iter()
                        .filter_map(|l| l.id.clone().or(l.name.clone()))
                        .collect();
                    props.insert("license".into(), names.join(", "));
                }
                if let Some(ref s) = comp.supplier {
                    if let Some(ref sn) = s.name {
                        props.insert("supplier".into(), sn.clone());
                    }
                }
                let comp_name = comp.name.clone();
                let comp_id =
                    format!("component:{}", comp.bom_ref.as_deref().unwrap_or(&comp_name));
                mg.ensure_node(MetaNode {
                    id: comp_id,
                    kind: MetaNodeKind::Component,
                    label: comp_name,
                    properties: props,
                });
            }

            // Dependency edges
            for dep in &sbom.dependencies {
                let from_id = format!("component:{}", dep.from_ref);
                for to_ref in &dep.to_refs {
                    let to_id = format!("component:{}", to_ref);
                    mg.add_edge_by_id(&from_id, &to_id, MetaEdgeKind::DependsOn);
                }
            }

            // Vulnerabilities
            for vuln in &sbom.vulnerabilities {
                let mut props = HashMap::new();
                props.insert(
                    "severity".into(),
                    vuln.severity.clone().unwrap_or_default(),
                );
                props.insert(
                    "score".into(),
                    vuln.cvss_score.map(|s| s.to_string()).unwrap_or_default(),
                );
                props.insert(
                    "description".into(),
                    vuln.description.clone().unwrap_or_default(),
                );
                let vuln_id = format!("vuln:{}", vuln.id);
                mg.ensure_node(MetaNode {
                    id: vuln_id.clone(),
                    kind: MetaNodeKind::Vulnerability,
                    label: vuln.id.clone(),
                    properties: props,
                });
                for comp_ref in &vuln.affects {
                    let comp_id = format!("component:{}", comp_ref);
                    mg.add_edge_by_id(&comp_id, &vuln_id, MetaEdgeKind::HasVuln);
                }
            }

            // 4. AST → SBOM bridge
            Self::bridge_ast_to_sbom(&mut mg, ast, sbom);
        }

        mg
    }

    fn bridge_ast_to_sbom(mg: &mut PetMetaGraph, ast: &AstGraph, sbom: &SbomGraph) {
        let comp_lookup: HashMap<String, String> = sbom
            .components
            .iter()
            .map(|c| {
                (
                    c.name.to_lowercase(),
                    format!("component:{}", c.bom_ref.as_deref().unwrap_or(&c.name)),
                )
            })
            .collect();

        for bf in &ast.build_files {
            for dep in &bf.declared_deps {
                let dep_lower = dep.name.to_lowercase();
                let comp_id = comp_lookup.get(&dep_lower).or_else(|| {
                    comp_lookup
                        .iter()
                        .find(|(k, _)| k.contains(&dep_lower) || dep_lower.contains(k.as_str()))
                        .map(|(_, v)| v)
                });

                if let Some(comp_id) = comp_id {
                    let mod_id = format!("module:{}", dep.name);
                    mg.ensure_node(MetaNode {
                        id: mod_id.clone(),
                        kind: MetaNodeKind::Module,
                        label: dep.name.clone(),
                        properties: HashMap::from([
                            ("version".into(), dep.version.clone()),
                            ("dep_type".into(), dep.dep_type.clone()),
                        ]),
                    });
                    mg.add_edge_by_id(&mod_id, comp_id, MetaEdgeKind::UsesComponent);

                    for imp in &ast.import_edges {
                        if imp.import_type == "external" {
                            let root = imp
                                .to_module
                                .split("::")
                                .next()
                                .unwrap_or("")
                                .split('/')
                                .next()
                                .unwrap_or("");
                            if root.to_lowercase() == dep_lower {
                                let file_id = format!("file:{}", imp.from_file);
                                mg.add_edge_by_id(&file_id, comp_id, MetaEdgeKind::UsesComponent);
                            }
                        }
                    }
                }
            }
        }
    }

    // ─── petgraph-accelerated queries ───

    /// BFS forward traversal following edges of `kind` from `start_id`
    fn bfs_forward(&self, start_id: &str, kind: MetaEdgeKind) -> Vec<NodeIndex> {
        let Some(&start) = self.id_map.get(start_id) else {
            return vec![];
        };
        let mut visited = vec![false; self.graph.node_count()];
        visited[start.index()] = true;
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start);
        let mut result = Vec::new();
        while let Some(cur) = queue.pop_front() {
            for edge in self.graph.edges_directed(cur, Direction::Outgoing) {
                if *edge.weight() == kind && !visited[edge.target().index()] {
                    visited[edge.target().index()] = true;
                    result.push(edge.target());
                    queue.push_back(edge.target());
                }
            }
        }
        result
    }

    /// BFS reverse traversal following incoming edges of `kind`
    fn bfs_reverse(&self, start_id: &str, kind: MetaEdgeKind) -> Vec<NodeIndex> {
        let Some(&start) = self.id_map.get(start_id) else {
            return vec![];
        };
        let mut visited = vec![false; self.graph.node_count()];
        visited[start.index()] = true;
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start);
        let mut result = Vec::new();
        while let Some(cur) = queue.pop_front() {
            for edge in self.graph.edges_directed(cur, Direction::Incoming) {
                if *edge.weight() == kind && !visited[edge.source().index()] {
                    visited[edge.source().index()] = true;
                    result.push(edge.source());
                    queue.push_back(edge.source());
                }
            }
        }
        result
    }

    /// petgraph BFS: all reachable nodes from `start` (any edge type)
    fn bfs_all_reachable(&self, start: NodeIndex) -> Vec<NodeIndex> {
        let mut bfs = Bfs::new(&self.graph, start);
        let mut result = Vec::new();
        while let Some(nx) = bfs.next(&self.graph) {
            if nx != start {
                result.push(nx);
            }
        }
        result
    }

    // ─── Query Engine ───

    pub fn cve_impact(&self, cve_id: &str) -> CveImpactResult {
        let vuln_id = format!("vuln:{}", cve_id);
        let mut affected_components = Vec::new();
        let mut affected_files = Vec::new();
        let mut entry_points = Vec::new();

        let Some(&vuln_nx) = self.id_map.get(&vuln_id) else {
            return CveImpactResult {
                cve_id: cve_id.to_string(),
                severity: String::new(),
                score: 0.0,
                affected_components: vec![],
                affected_files: vec![],
                entry_points: vec![],
                blast_radius: 0,
            };
        };

        // Components → vuln (incoming HasVuln edges to vuln node)
        for edge in self.graph.edges_directed(vuln_nx, Direction::Incoming) {
            if *edge.weight() == MetaEdgeKind::HasVuln {
                let comp = &self.graph[edge.source()];
                affected_components.push(comp.clone());

                // Files → component (incoming UsesComponent)
                for e2 in self.graph.edges_directed(edge.source(), Direction::Incoming) {
                    if *e2.weight() == MetaEdgeKind::UsesComponent {
                        let node = &self.graph[e2.source()];
                        if node.kind == MetaNodeKind::File {
                            affected_files.push(node.clone());
                            if node
                                .properties
                                .get("is_entry")
                                .map(|v| v == "true")
                                .unwrap_or(false)
                            {
                                entry_points.push(node.clone());
                            }
                        }
                    }
                }
            }
        }

        // Transitive: BFS reverse via Imports to find reachable entry points
        let affected_ids: Vec<String> = affected_files.iter().map(|n| n.id.clone()).collect();
        for fid in &affected_ids {
            for nx in self.bfs_reverse(fid, MetaEdgeKind::Imports) {
                let node = &self.graph[nx];
                if node
                    .properties
                    .get("is_entry")
                    .map(|v| v == "true")
                    .unwrap_or(false)
                {
                    if !entry_points.iter().any(|ep| ep.id == node.id) {
                        entry_points.push(node.clone());
                    }
                }
            }
        }

        let vuln_node = &self.graph[vuln_nx];
        let blast = affected_files.len() + entry_points.len();
        CveImpactResult {
            cve_id: cve_id.to_string(),
            severity: vuln_node
                .properties
                .get("severity")
                .cloned()
                .unwrap_or_default(),
            score: vuln_node
                .properties
                .get("score")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0),
            affected_components,
            affected_files,
            entry_points,
            blast_radius: blast,
        }
    }

    pub fn supply_chain_trace(&self, package_name: &str) -> SupplyChainTrace {
        let mod_id = format!("module:{}", package_name);
        let mut importing_files = Vec::new();
        let mut sbom_component = None;
        let mut transitive_deps = Vec::new();
        let mut vulnerabilities = Vec::new();

        // Files importing this module (incoming Imports edges)
        if let Some(&mod_nx) = self.id_map.get(&mod_id) {
            for edge in self.graph.edges_directed(mod_nx, Direction::Incoming) {
                if *edge.weight() == MetaEdgeKind::Imports {
                    importing_files.push(self.graph[edge.source()].clone());
                }
            }
            // Module → Component (outgoing UsesComponent)
            for edge in self.graph.edges_directed(mod_nx, Direction::Outgoing) {
                if *edge.weight() == MetaEdgeKind::UsesComponent {
                    sbom_component = Some(self.graph[edge.target()].clone());
                    let comp_id = &self.graph[edge.target()].id;
                    // Transitive deps via BFS DependsOn
                    for nx in self.bfs_forward(comp_id, MetaEdgeKind::DependsOn) {
                        transitive_deps.push(self.graph[nx].clone());
                    }
                    // Vulns on component + transitive
                    let mut check = vec![edge.target()];
                    check.extend(self.bfs_forward(comp_id, MetaEdgeKind::DependsOn));
                    for cnx in check {
                        for ve in self.graph.edges_directed(cnx, Direction::Outgoing) {
                            if *ve.weight() == MetaEdgeKind::HasVuln {
                                vulnerabilities.push(self.graph[ve.target()].clone());
                            }
                        }
                    }
                    break;
                }
            }
        }

        SupplyChainTrace {
            package_name: package_name.to_string(),
            importing_files,
            sbom_component,
            transitive_deps,
            vulnerabilities,
        }
    }

    pub fn attack_surface(&self) -> AttackSurface {
        // Collect all components that have HasVuln edges
        let mut vuln_comp_set: HashSet<NodeIndex> = HashSet::new();
        for edge in self.graph.edge_indices() {
            if let Some((src, _tgt)) = self.graph.edge_endpoints(edge) {
                if *self.graph.edge_weight(edge).unwrap() == MetaEdgeKind::HasVuln {
                    vuln_comp_set.insert(src);
                }
            }
        }

        let mut exposed_entries = Vec::new();
        let mut risk_paths = Vec::new();
        let mut seen_entries: HashSet<String> = HashSet::new();

        for &comp_nx in &vuln_comp_set {
            let comp_id = self.graph[comp_nx].id.clone();
            // Files using this component
            for edge in self.graph.edges_directed(comp_nx, Direction::Incoming) {
                if *edge.weight() == MetaEdgeKind::UsesComponent {
                    let file_node = &self.graph[edge.source()];
                    if file_node.kind != MetaNodeKind::File {
                        continue;
                    }
                    // BFS reverse via Imports to entry points
                    let reachable = self.bfs_reverse(&file_node.id, MetaEdgeKind::Imports);
                    let mut path_nodes = vec![file_node.id.clone()];
                    for nx in &reachable {
                        let node = &self.graph[*nx];
                        if node
                            .properties
                            .get("is_entry")
                            .map(|v| v == "true")
                            .unwrap_or(false)
                        {
                            if seen_entries.insert(node.id.clone()) {
                                exposed_entries.push(node.clone());
                            }
                            path_nodes.push(node.id.clone());
                        }
                    }
                    if path_nodes.len() > 1 {
                        risk_paths.push(RiskPath {
                            from_vuln_component: comp_id.clone(),
                            nodes: path_nodes,
                        });
                    }
                }
            }
        }

        AttackSurface {
            vuln_component_count: vuln_comp_set.len(),
            exposed_entry_count: exposed_entries.len(),
            exposed_entries,
            risk_paths,
        }
    }

    pub fn graph_stats(&self) -> MetaGraphStats {
        let nodes = self.graph.node_indices();
        let mut file_nodes = 0usize;
        let mut module_nodes = 0usize;
        let mut component_nodes = 0usize;
        let mut vuln_nodes = 0usize;
        for nx in nodes {
            match self.graph[nx].kind {
                MetaNodeKind::File => file_nodes += 1,
                MetaNodeKind::Module => module_nodes += 1,
                MetaNodeKind::Component => component_nodes += 1,
                MetaNodeKind::Vulnerability => vuln_nodes += 1,
                _ => {}
            }
        }
        let mut import_edges = 0usize;
        let mut depends_edges = 0usize;
        let mut uses_component_edges = 0usize;
        let mut has_vuln_edges = 0usize;
        for edge in self.graph.edge_indices() {
            match self.graph.edge_weight(edge).unwrap() {
                MetaEdgeKind::Imports => import_edges += 1,
                MetaEdgeKind::DependsOn => depends_edges += 1,
                MetaEdgeKind::UsesComponent => uses_component_edges += 1,
                MetaEdgeKind::HasVuln => has_vuln_edges += 1,
                _ => {}
            }
        }
        MetaGraphStats {
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
            file_nodes,
            module_nodes,
            component_nodes,
            vuln_nodes,
            import_edges,
            depends_edges,
            uses_component_edges,
            has_vuln_edges,
            ast_to_sbom_bridges: uses_component_edges,
        }
    }

    /// Serialize to MetaGraphView for frontend
    pub fn to_view(&self) -> MetaGraphView {
        let nodes: Vec<MetaNode> = self.graph.node_indices().map(|nx| self.graph[nx].clone()).collect();
        let edges: Vec<MetaEdge> = self
            .graph
            .edge_indices()
            .map(|ei| {
                let (src, tgt) = self.graph.edge_endpoints(ei).unwrap();
                let kind = *self.graph.edge_weight(ei).unwrap();
                MetaEdge {
                    source: self.graph[src].id.clone(),
                    target: self.graph[tgt].id.clone(),
                    kind,
                    label: match kind {
                        MetaEdgeKind::Imports => "imports",
                        MetaEdgeKind::DependsOn => "depends_on",
                        MetaEdgeKind::UsesComponent => "uses",
                        MetaEdgeKind::HasVuln => "has_vuln",
                        MetaEdgeKind::Builds => "builds",
                        MetaEdgeKind::Produces => "produces",
                        MetaEdgeKind::Contains => "contains",
                    }
                    .to_string(),
                    weight: 1.0,
                }
            })
            .collect();
        let stats = self.graph_stats();
        MetaGraphView {
            nodes,
            edges,
            stats,
        }
    }
}

// ─────────────────── Query Result Types ───────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CveImpactResult {
    pub cve_id: String,
    pub severity: String,
    pub score: f64,
    pub affected_components: Vec<MetaNode>,
    pub affected_files: Vec<MetaNode>,
    pub entry_points: Vec<MetaNode>,
    pub blast_radius: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SupplyChainTrace {
    pub package_name: String,
    pub importing_files: Vec<MetaNode>,
    pub sbom_component: Option<MetaNode>,
    pub transitive_deps: Vec<MetaNode>,
    pub vulnerabilities: Vec<MetaNode>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttackSurface {
    pub vuln_component_count: usize,
    pub exposed_entry_count: usize,
    pub exposed_entries: Vec<MetaNode>,
    pub risk_paths: Vec<RiskPath>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RiskPath {
    pub from_vuln_component: String,
    pub nodes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetaGraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub file_nodes: usize,
    pub module_nodes: usize,
    pub component_nodes: usize,
    pub vuln_nodes: usize,
    pub import_edges: usize,
    pub depends_edges: usize,
    pub uses_component_edges: usize,
    pub has_vuln_edges: usize,
    pub ast_to_sbom_bridges: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetaGraphView {
    pub nodes: Vec<MetaNode>,
    pub edges: Vec<MetaEdge>,
    pub stats: MetaGraphStats,
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn build_meta_graph(
    root_dir: String,
    sbom_path: Option<String>,
) -> Result<MetaGraphView, String> {
    let ast = crate::supply_chain::scan_ast(&root_dir);
    let sbom = if let Some(ref sp) = sbom_path {
        let content =
            std::fs::read_to_string(sp).map_err(|e| format!("Cannot read SBOM: {}", e))?;
        let json: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
        Some(SbomGraph::from_cdx_json(&json)?)
    } else {
        None
    };
    let mg = PetMetaGraph::from_ast_and_sbom(&ast, sbom.as_ref());
    Ok(mg.to_view())
}

#[tauri::command]
pub fn query_cve_impact(
    root_dir: String,
    sbom_path: String,
    cve_id: String,
) -> Result<CveImpactResult, String> {
    let ast = crate::supply_chain::scan_ast(&root_dir);
    let content = std::fs::read_to_string(&sbom_path).map_err(|e| format!("{}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("{}", e))?;
    let sbom = SbomGraph::from_cdx_json(&json)?;
    let mg = PetMetaGraph::from_ast_and_sbom(&ast, Some(&sbom));
    Ok(mg.cve_impact(&cve_id))
}

#[tauri::command]
pub fn query_supply_chain_trace(
    root_dir: String,
    sbom_path: Option<String>,
    package_name: String,
) -> Result<SupplyChainTrace, String> {
    let ast = crate::supply_chain::scan_ast(&root_dir);
    let sbom = if let Some(ref sp) = sbom_path {
        let content = std::fs::read_to_string(sp).map_err(|e| format!("{}", e))?;
        let json: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| format!("{}", e))?;
        Some(SbomGraph::from_cdx_json(&json)?)
    } else {
        None
    };
    let mg = PetMetaGraph::from_ast_and_sbom(&ast, sbom.as_ref());
    Ok(mg.supply_chain_trace(&package_name))
}

#[tauri::command]
pub fn query_attack_surface(
    root_dir: String,
    sbom_path: String,
) -> Result<AttackSurface, String> {
    let ast = crate::supply_chain::scan_ast(&root_dir);
    let content = std::fs::read_to_string(&sbom_path).map_err(|e| format!("{}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("{}", e))?;
    let sbom = SbomGraph::from_cdx_json(&json)?;
    let mg = PetMetaGraph::from_ast_and_sbom(&ast, Some(&sbom));
    Ok(mg.attack_surface())
}

// ═══ Cross-Graph Path Tracing ═══

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PathNode {
    pub id: String,
    pub label: String,
    pub kind: String,   // File, Module, Component, Vulnerability, etc.
    pub layer: String,  // ast, sbom, build, trust
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphPathResult {
    pub found: bool,
    pub from: String,
    pub to: String,
    pub path: Vec<PathNode>,
    pub edge_types: Vec<String>,
    pub depth: usize,
    pub query_duration_us: u64,
}

#[tauri::command]
pub fn trace_graph_path(
    root_dir: String,
    sbom_path: Option<String>,
    from_query: String,
    to_query: String,
) -> Result<GraphPathResult, String> {
    let start = std::time::Instant::now();
    let ast = crate::supply_chain::scan_ast(&root_dir);
    let sbom = if let Some(ref sp) = sbom_path {
        let content = std::fs::read_to_string(sp).map_err(|e| format!("{}", e))?;
        let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| format!("{}", e))?;
        Some(SbomGraph::from_cdx_json(&json)?)
    } else { None };
    let mg = PetMetaGraph::from_ast_and_sbom(&ast, sbom.as_ref());

    let from_q = from_query.to_lowercase();
    let to_q = to_query.to_lowercase();

    // Find start node
    let start_nx = mg.graph.node_indices().find(|&nx| {
        let n = &mg.graph[nx];
        n.id.to_lowercase().contains(&from_q) || n.label.to_lowercase().contains(&from_q)
    });
    // Find target node
    let target_nx = mg.graph.node_indices().find(|&nx| {
        let n = &mg.graph[nx];
        n.id.to_lowercase().contains(&to_q) || n.label.to_lowercase().contains(&to_q)
    });

    let (Some(snx), Some(tnx)) = (start_nx, target_nx) else {
        return Ok(GraphPathResult {
            found: false, from: from_query, to: to_query,
            path: vec![], edge_types: vec![], depth: 0,
            query_duration_us: start.elapsed().as_micros() as u64,
        });
    };

    // BFS shortest path
    use std::collections::VecDeque;
    let mut queue: VecDeque<(NodeIndex, Vec<NodeIndex>)> = VecDeque::new();
    let mut visited = HashSet::new();
    queue.push_back((snx, vec![snx]));
    visited.insert(snx);

    let mut result_path: Option<Vec<NodeIndex>> = None;
    while let Some((current, path)) = queue.pop_front() {
        if current == tnx {
            result_path = Some(path);
            break;
        }
        for edge in mg.graph.edges(current) {
            let next = edge.target();
            if visited.insert(next) {
                let mut new_path = path.clone();
                new_path.push(next);
                queue.push_back((next, new_path));
            }
        }
        // Also check incoming edges (reverse traversal for full reachability)
        for edge in mg.graph.edges_directed(current, Direction::Incoming) {
            let next = edge.source();
            if visited.insert(next) {
                let mut new_path = path.clone();
                new_path.push(next);
                queue.push_back((next, new_path));
            }
        }
    }

    match result_path {
        Some(path) => {
            let path_nodes: Vec<PathNode> = path.iter().map(|&nx| {
                let n = &mg.graph[nx];
                let layer = match n.kind {
                    MetaNodeKind::File | MetaNodeKind::Module => "ast",
                    MetaNodeKind::Component | MetaNodeKind::Vulnerability => "sbom",
                    MetaNodeKind::BuildTarget | MetaNodeKind::Artifact => "build",
                    MetaNodeKind::PipelineStep => "exec",
                };
                PathNode { id: n.id.clone(), label: n.label.clone(), kind: format!("{:?}", n.kind), layer: layer.into() }
            }).collect();

            let mut edge_types = Vec::new();
            for i in 0..path.len().saturating_sub(1) {
                let from = path[i]; let to = path[i + 1];
                let etype = mg.graph.edges(from).find(|e| e.target() == to)
                    .or_else(|| mg.graph.edges_directed(to, Direction::Incoming).find(|e| e.source() == from))
                    .map(|e| format!("{:?}", e.weight()))
                    .unwrap_or_else(|| "unknown".into());
                edge_types.push(etype);
            }

            Ok(GraphPathResult {
                found: true, from: from_query, to: to_query,
                depth: path_nodes.len(),
                path: path_nodes, edge_types,
                query_duration_us: start.elapsed().as_micros() as u64,
            })
        }
        None => Ok(GraphPathResult {
            found: false, from: from_query, to: to_query,
            path: vec![], edge_types: vec![], depth: 0,
            query_duration_us: start.elapsed().as_micros() as u64,
        }),
    }
}
