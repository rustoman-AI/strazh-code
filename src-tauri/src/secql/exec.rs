use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet};

use crate::meta_graph::{MetaEdgeKind, MetaNodeKind, PetMetaGraph};
use crate::secql::ast::*;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SecQlPathResult {
    // Array of Node IDs that form the matched path
    pub nodes: Vec<String>,
}

pub fn execute_secql(query: &Query, graph: &PetMetaGraph) -> Result<Vec<SecQlPathResult>, String> {
    if query.matches.is_empty() {
        return Ok(vec![]);
    }

    // Currently supporting a single MATCH clause for simplicity
    let m = &query.matches[0];
    if m.elements.is_empty() {
        return Ok(vec![]);
    }

    // The logic: 
    // m.elements is a sequence of [Node, Edge, Node, Edge, Node...]
    // We will do a graph traversal.
    // 1. Find all candidate starting nodes for the first MatchElement::Node
    // 2. Expand paths matching the (Edge -> Node) sequence.

    let mut current_paths: Vec<Vec<petgraph::graph::NodeIndex>> = Vec::new();

    if let MatchElement::Node(ref start_node_pattern) = m.elements[0] {
        let start_candidates = find_matching_nodes(graph, start_node_pattern);
        for nx in start_candidates {
            current_paths.push(vec![nx]);
        }
    } else {
        return Err("Query must start with a Node pattern".to_string());
    }

    // Iterate through the pattern in pairs of (Edge, Node)
    let mut i = 1;
    while i < m.elements.len() {
        let edge_pattern = match &m.elements[i] {
            MatchElement::Edge(e) => e,
            _ => return Err("Expected edge pattern".to_string()),
        };
        let target_node_pattern = match &m.elements.get(i + 1) {
            Some(MatchElement::Node(n)) => n,
            _ => return Err("Expected node pattern after edge".to_string()),
        };

        let mut next_paths = Vec::new();

        for path in current_paths {
            let current_nx = *path.last().unwrap();
            
            // Expand the path
            let expansions = expand_path(graph, current_nx, edge_pattern, target_node_pattern);
            for ext in expansions {
                let mut new_path = path.clone();
                new_path.extend(ext); // ext includes intermediate nodes and the final target node
                next_paths.push(new_path);
            }
        }

        current_paths = next_paths;
        i += 2;
    }

    // Convert paths to SecQlPathResult
    let mut results = Vec::new();
    for path in current_paths {
        let node_ids = path.iter().map(|&nx| graph.graph[nx].id.clone()).collect();
        results.push(SecQlPathResult { nodes: node_ids });
    }

    Ok(results)
}

fn find_matching_nodes(graph: &PetMetaGraph, pattern: &NodePattern) -> Vec<petgraph::graph::NodeIndex> {
    let mut matches = Vec::new();
    for nx in graph.graph.node_indices() {
        let node = &graph.graph[nx];
        // filter by kind
        if let Some(ref kind_str) = pattern.node_type {
            let node_kind_str = match node.kind {
                MetaNodeKind::File => "File",
                MetaNodeKind::Module => "Module",
                MetaNodeKind::Component => "Component",
                MetaNodeKind::Vulnerability => "Vulnerability",
                MetaNodeKind::BuildTarget => "BuildTarget",
                MetaNodeKind::Artifact => "Artifact",
                MetaNodeKind::PipelineStep => "PipelineStep",
            };
            // e.g. EntryPoint is a file with is_entry=true
            if kind_str.eq_ignore_ascii_case("EntryPoint") {
                if node.kind != MetaNodeKind::File || node.properties.get("is_entry").map(|s| s.as_str()) != Some("true") {
                    continue;
                }
            } else if kind_str.eq_ignore_ascii_case("ASTNode") {
                 if node.kind != MetaNodeKind::File && node.kind != MetaNodeKind::Module {
                     continue;
                 }
            } else if !kind_str.eq_ignore_ascii_case(node_kind_str) {
                continue;
            }
        }

        // filter by properties
        let mut props_match = true;
        for p in &pattern.properties {
            let val = node.properties.get(&p.key);
            match &p.value {
                FilterValue::String(s) => {
                    if let Some(v) = val {
                        match p.operator {
                            ComparisonOp::Eq => if v != s { props_match = false; break; }
                            ComparisonOp::NotEq => if v == s { props_match = false; break; }
                            ComparisonOp::Contains => if !v.contains(s) { props_match = false; break; }
                            _ => { props_match = false; break; }
                        }
                    } else {
                        props_match = false; break;
                    }
                },
                _ => { /* Ignoring non-string props for now */ }
            }
        }

        if props_match {
            matches.push(nx);
        }
    }
    matches
}

fn expand_path(
    graph: &PetMetaGraph,
    start_nx: petgraph::graph::NodeIndex,
    edge_pattern: &EdgePattern,
    target_node_pattern: &NodePattern
) -> Vec<Vec<petgraph::graph::NodeIndex>> {
    
    let (min_hops, max_hops) = edge_pattern.hop_range.unwrap_or((1, Some(1)));
    let max_hops = max_hops.unwrap_or(5); // cap unbounded * at 5 to avoid blowup
    
    let mut matches = Vec::new();
    
    // BFS queue: (current_node, path_so_far, current_hop_count)
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((start_nx, vec![], 0));
    
    while let Some((cur, path, hops)) = queue.pop_front() {
        if hops >= max_hops {
            continue;
        }
        
        for edge in graph.graph.edges_directed(cur, petgraph::Direction::Outgoing) {
            // Check edge type
            if let Some(ref et) = edge_pattern.edge_type {
                let edge_kind_str = match *edge.weight() {
                    MetaEdgeKind::Imports => "IMPORTS",
                    MetaEdgeKind::DependsOn => "DEPENDS_ON",
                    MetaEdgeKind::UsesComponent => "USES_COMPONENT",
                    MetaEdgeKind::HasVuln => "HAS_VULN",
                    MetaEdgeKind::Builds => "BUILDS",
                    MetaEdgeKind::Produces => "PRODUCES",
                    MetaEdgeKind::Contains => "CONTAINS",
                };
                
                // Aliases for usability: CALLS -> IMPORTS, USES -> USES_COMPONENT
                let match_et = et.to_uppercase();
                let is_match = match_et == edge_kind_str 
                    || (match_et == "CALLS" && edge_kind_str == "IMPORTS")
                    || (match_et == "USES" && edge_kind_str == "USES_COMPONENT");
                    
                if !is_match {
                    continue;
                }
            }
            
            let target_nx = edge.target();
            if path.contains(&target_nx) || target_nx == start_nx {
                continue; // Prevent cycles
            }
            
            let mut new_path = path.clone();
            new_path.push(target_nx);
            let new_hops = hops + 1;
            
            // Check if this target aligns with target_node_pattern
            if new_hops >= min_hops {
                let target_candidates = find_matching_nodes(graph, target_node_pattern);
                if target_candidates.contains(&target_nx) {
                    matches.push(new_path.clone());
                }
            }
            
            queue.push_back((target_nx, new_path, new_hops));
        }
    }
    
    matches
}
