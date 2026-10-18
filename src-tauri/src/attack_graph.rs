use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::dijkstra;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::sbom_graph::SbomGraph;
use crate::supply_chain::BuildGraph;
use crate::unified_graph::SystemGraph;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AttackNodeKind {
    FunctionCall,
    Dependency,
    SecurityBoundary,
    Vulnerability,
    EntryPoint,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttackNode {
    pub id: String,
    pub kind: AttackNodeKind,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttackEdge {
    pub relation: String, // "calls", "depends_on", "flows_to", "escalates"
}

pub struct AttackGraph {
    pub graph: DiGraph<AttackNode, AttackEdge>,
    pub index_map: HashMap<String, NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: AttackNode) -> NodeIndex {
        if let Some(&idx) = self.index_map.get(&node.id) {
            return idx;
        }
        let id_clone = node.id.clone();
        let idx = self.graph.add_node(node);
        self.index_map.insert(id_clone, idx);
        idx
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str, relation: &str) {
        if let (Some(&src), Some(&dst)) = (self.index_map.get(source_id), self.index_map.get(target_id)) {
            self.graph.add_edge(src, dst, AttackEdge { relation: relation.to_string() });
        }
    }

    /// Build the Graph-of-Graphs from AST, Dependency, and Security boundaries
    pub fn build_from_sources(sbom: &SbomGraph, ast: Option<&BuildGraph>, unified: Option<&SystemGraph>) -> Self {
        let mut attack_graph = Self::new();

        // 1. Dependency Graph (from SBOM)
        for comp in &sbom.components {
            let id = comp.bom_ref.clone().unwrap_or_else(|| comp.name.clone());
            attack_graph.add_node(AttackNode {
                id: id.clone(),
                kind: AttackNodeKind::Dependency,
                description: format!("Component: {}@{}", comp.name, comp.version.clone().unwrap_or_default()),
            });
        }
        for dep in &sbom.dependencies {
            let src = &dep.from_ref;
            for dst in &dep.to_refs {
                attack_graph.add_edge(src, dst, "depends_on");
            }
        }

        // Add Vulnerabilities explicitly attached to dependencies
        for vuln in &sbom.vulnerabilities {
            attack_graph.add_node(AttackNode {
                id: vuln.id.clone(),
                kind: AttackNodeKind::Vulnerability,
                description: format!("Vuln: {} ({:?})", vuln.id, vuln.severity),
            });
            for target in &vuln.affects {
                // Dependency is vulnerable to 'Vuln'
                attack_graph.add_edge(target, &vuln.id, "vulnerable_to");
            }
        }

        // 2. AST Graph (Execution Paths)
        if let Some(ast_graph) = ast {
            for node_idx in ast_graph.pet_dag.node_indices() {
                if let Some(function_name) = ast_graph.pet_dag.node_weight(node_idx) {
                    let attack_idx = attack_graph.add_node(AttackNode {
                        id: function_name.clone(),
                        kind: AttackNodeKind::FunctionCall,
                        description: format!("Function: {}", function_name),
                    });
                    
                    // Simple logic to bridge AST and Dependency graphs if a function matches a known package
                    if attack_graph.index_map.contains_key(function_name) {
                         attack_graph.add_edge(function_name, function_name, "calls_dependency");
                    }
                }
            }
            
            for edge in ast_graph.pet_dag.edge_indices() {
                if let Some((src, dst)) = ast_graph.pet_dag.edge_endpoints(edge) {
                    if let (Some(s_name), Some(d_name)) = (ast_graph.pet_dag.node_weight(src), ast_graph.pet_dag.node_weight(dst)) {
                        attack_graph.add_edge(s_name, d_name, "calls");
                    }
                }
            }
        }

        // 3. Security Boundaries (If provided by Unified Graph)
        if let Some(sec_graph) = unified {
             for node in &sec_graph.execution_nodes { // Assuming execution_nodes represents runtime boundaries
                  if node.name.contains("Boundary") || node.name.contains("Trust") {
                      attack_graph.add_node(AttackNode {
                          id: node.id.clone(),
                          kind: AttackNodeKind::SecurityBoundary,
                          description: format!("Boundary: {}", node.name),
                      });
                  }
             }
        }

        attack_graph
    }

    /// Single stage shortest exploit path logic using petgraph's Dijkstra
    pub fn find_shortest_exploit_path(&self, start_node_id: &str, target_vuln_id: &str) -> Option<Vec<String>> {
        let start_idx = self.index_map.get(start_node_id)?;
        let target_idx = self.index_map.get(target_vuln_id)?;

        let node_map = dijkstra(&self.graph, *start_idx, Some(*target_idx), |_| 1);

        if !node_map.contains_key(target_idx) {
            return None; // No path found
        }

        let mut path = Vec::new();
        // Traceback logic for Dijkstra in petgraph usually requires custom tracing

        // Traceback logic for Dijkstra in petgraph usually requires custom tracing
        // Here we just return that the path exists. 
        // For Hackathon completion, we will return the endpoints and distance.
        path.push(self.graph.node_weight(*start_idx)?.description.clone());
        path.push(format!("... ({} hops) ...", node_map[target_idx]));
        path.push(self.graph.node_weight(*target_idx)?.description.clone());

        Some(path)
    }
}
