use crate::engine::graph::ExecutionGraph;
use crate::engine::nodes::RunStatus;
use anyhow::Result;
use std::fs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

pub const SNAPSHOT_FILENAME: &str = "GRAPH_SNAPSHOT.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotNode {
    pub id: String,
    pub status: RunStatus,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub error: Option<String>,
    pub requires_approval: bool,
    pub relevance_score: f64, // phase 22: decay score
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotGraph {
    pub nodes: Vec<SnapshotNode>,
    pub edges: Vec<SnapshotEdge>,
}

/// Export the active Graph into a JSON Time-Travel snapshot
pub fn export_graph_snapshot(
    workspace_dir: &Path, 
    graph: &SnapshotGraph,
) -> Result<PathBuf> {
    let snapshot_path = workspace_dir.join(SNAPSHOT_FILENAME);
    let serialized = serde_json::to_string_pretty(graph)?;
    fs::write(&snapshot_path, serialized)?;
    println!("📸 Graph Checkpoint exported: {}", snapshot_path.display());
    Ok(snapshot_path)
}

/// Import the Graph from a Time-Travel snapshot
pub fn restore_graph_snapshot(workspace_dir: &Path) -> Result<SnapshotGraph> {
    let snapshot_path = workspace_dir.join(SNAPSHOT_FILENAME);
    if !snapshot_path.exists() {
        return Err(anyhow::anyhow!("No graph snapshot found to restore."));
    }
    
    let content = fs::read_to_string(&snapshot_path)?;
    let graph: SnapshotGraph = serde_json::from_str(&content)?;
    
    println!("🧬 Graph Checkpoint restored from {}", snapshot_path.display());
    Ok(graph)
}
