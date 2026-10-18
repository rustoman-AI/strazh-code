use crate::engine::artifact::ArtifactRef;
use crate::engine::nodes::{ExecutableNode, ExecutionError};
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

pub type NodeBox = Box<dyn ExecutableNode>;

pub struct ExecutionGraph {
    pub graph: DiGraph<NodeBox, ()>,
    node_map: HashMap<String, NodeIndex>,
    artifact_producers: HashMap<String, NodeIndex>,
}

impl ExecutionGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            artifact_producers: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: NodeBox) -> NodeIndex {
        let id = node.id().to_string();
        let idx = self.graph.add_node(node);
        let outputs = self.graph[idx].outputs();
        for output in &outputs {
            self.artifact_producers.insert(output.id.clone(), idx);
        }
        self.node_map.insert(id, idx);
        idx
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex) {
        self.graph.add_edge(from, to, ());
    }

    pub fn auto_wire(&mut self) -> Result<(), ExecutionError> {
        let indices: Vec<NodeIndex> = self.graph.node_indices().collect();
        let mut errors: Vec<String> = Vec::new();

        for &ci in &indices {
            let inputs = self.graph[ci].inputs();
            for input in &inputs {
                if let Some(&pi) = self.artifact_producers.get(&input.id) {
                    if pi != ci {
                        let po = self.graph[pi].outputs();
                        if let Some(p) = po.iter().find(|o| o.id == input.id) {
                            if !p.kind.is_compatible_with(&input.kind) {
                                errors.push(format!(
                                    "Type mismatch on artifact '{}': node '{}' produces {}, but node '{}' expects {}",
                                    input.id,
                                    self.graph[pi].id(),
                                    p.kind,
                                    self.graph[ci].id(),
                                    input.kind,
                                ));
                                continue;
                            }
                        }
                        self.graph.add_edge(pi, ci, ());
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExecutionError::MultipleErrors(errors.join("\n")))
        }
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        toposort(&self.graph, None).map_err(|_| ExecutionError::CycleDetected)?;
        Ok(())
    }

    pub fn execution_order(&self) -> Result<Vec<NodeIndex>, ExecutionError> {
        toposort(&self.graph, None).map_err(|_| ExecutionError::CycleDetected)
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }
}
