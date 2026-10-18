pub mod artifact;
pub mod context;
pub mod graph;
pub mod nodes;
pub mod store;
pub mod sop;
pub mod memory;
pub mod mcp;
pub mod mcp_client;
pub mod wasm;
pub mod onboarding;
pub mod runtime_monitor;
pub mod threat_feed;
pub mod posture_timeline;
pub mod soc_dashboard;
pub mod image_forensics;
pub mod reporting;

use artifact::{ArtifactKind, ArtifactRef};
use context::{EngineEvent, ExecutionContext, RetryConfig, TauriEventBus};
use graph::ExecutionGraph;
use nodes::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use store::{ArtifactStore, LocalFsStore};
use crate::engine::memory::snapshot::{SnapshotNode, SnapshotGraph, export_graph_snapshot, restore_graph_snapshot};
use crate::engine::memory::decay::apply_relevance_decay;

// ══════════════════════════════════════════════════════
//  ExecutionEngine — top-level DAG executor
// ══════════════════════════════════════════════════════

pub struct ExecutionEngine {
    graph: ExecutionGraph,
}

impl ExecutionEngine {
    pub fn new(graph: ExecutionGraph) -> Self {
        Self { graph }
    }

    pub async fn execute(&self, ctx: &ExecutionContext) -> Result<(), ExecutionError> {
        let order = self.graph.execution_order()?;
        let total = order.len();

        ctx.event_bus.emit(EngineEvent::PipelineStarted { total_nodes: total });

        let pipeline_start = Instant::now();
        let mut executed = 0usize;
        let mut skipped = 0usize;

        for (i, idx) in order.iter().enumerate() {
            let node = &self.graph.graph[*idx];
            let node_id = node.id().to_string();

            // Cache check: skip if all outputs already exist
            let all_cached = node.outputs().iter().all(|o| ctx.artifact_store.exists(o));
            if all_cached && !node.outputs().is_empty() {
                ctx.event_bus.emit(EngineEvent::NodeSkipped {
                    node_id: node_id.clone(),
                    reason: "all outputs cached".into(),
                });
                skipped += 1;
                continue;
            }

            ctx.event_bus.emit(EngineEvent::NodeStarted {
                node_id: node_id.clone(),
                index: i,
            });

            // Phase 20: SOP Engine - Check for manual approval
            if node.requires_approval() {
                ctx.event_bus.emit(EngineEvent::NodePendingApproval {
                    node_id: node_id.clone(),
                });
                
                // Construct a one-shot channel and stash the TX in the SopManager
                let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
                ctx.sop_manager.register_pending_node(node_id.clone(), tx).await;
                
                // Block pipeline execution awaiting frontend user action
                match rx.await {
                    Ok(true) => {
                        ctx.event_bus.emit(EngineEvent::NodeLog {
                            node_id: node_id.clone(),
                            line: "✅ Node manually approved. Resuming execution...".into(),
                        });
                    }
                    Ok(false) | Err(_) => {
                        ctx.event_bus.emit(EngineEvent::NodeRejected {
                            node_id: node_id.clone(),
                        });
                        let err = ExecutionError::ValidationFailed(format!("Node {} manually rejected by user.", node_id));
                        ctx.event_bus.emit(EngineEvent::PipelineFailed {
                            error: err.to_string(),
                            failed_node: node_id.clone(),
                        });
                        return Err(err);
                    }
                }
            }

            let node_start = Instant::now();

            // Retry loop with exponential backoff
            let max_attempts = ctx.retry_config.max_attempts;
            let mut delay_ms = ctx.retry_config.initial_delay_ms;
            let mut last_err: Option<ExecutionError> = None;

            for attempt in 0..=max_attempts {
                if attempt > 0 {
                    ctx.event_bus.emit(EngineEvent::NodeLog {
                        node_id: node_id.clone(),
                        line: format!(
                            "🔄 Retry {}/{} after {}ms...",
                            attempt, max_attempts, delay_ms
                        ),
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2; // exponential backoff
                }

                match node.execute(ctx).await {
                    Ok(_) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        if !e.is_retryable() || attempt == max_attempts {
                            last_err = Some(e);
                            break;
                        }
                        ctx.event_bus.emit(EngineEvent::NodeLog {
                            node_id: node_id.clone(),
                            line: format!("⚠️ Attempt {} failed: {}", attempt + 1, e),
                        });
                        last_err = Some(e);
                    }
                }
            }

            match last_err {
                None => {
                    let dur = node_start.elapsed().as_millis() as u64;
                    ctx.event_bus.emit(EngineEvent::NodeFinished {
                        node_id: node_id.clone(),
                        index: i,
                        duration_ms: dur,
                    });
                    executed += 1;
                }
                Some(e) => {
                    ctx.event_bus.emit(EngineEvent::NodeFailed {
                        node_id: node_id.clone(),
                        error: e.to_string(),
                    });
                    ctx.event_bus.emit(EngineEvent::PipelineFailed {
                        error: e.to_string(),
                        failed_node: node_id,
                    });
                    return Err(e);
                }
            }
        }

        let total_ms = pipeline_start.elapsed().as_millis() as u64;
        ctx.event_bus.emit(EngineEvent::PipelineFinished {
            total_ms,
            nodes_executed: executed,
            nodes_skipped: skipped,
        });

        Ok(())
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Command DTOs
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphNodeDef {
    pub id: String,
    pub node_type: String,
    pub config: serde_json::Value,
    #[serde(default)]
    pub requires_approval: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GraphEdgeDef {
    pub from: String,
    pub to: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineDef {
    pub nodes: Vec<GraphNodeDef>,
    pub edges: Vec<GraphEdgeDef>,
    pub workspace: String,
    pub external_artifacts: Vec<ExternalArtifactDef>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExternalArtifactDef {
    pub id: String,
    pub kind: String,
    pub path: String,
}

// ══════════════════════════════════════════════════════
//  Tauri Commands
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn engine_list_node_types() -> Vec<nodes::NodeDescriptor> {
    nodes::available_node_types()
}

#[tauri::command]
pub async fn engine_execute(
    app: tauri::AppHandle,
    pipeline: PipelineDef,
) -> Result<String, String> {
    let workspace = PathBuf::from(&pipeline.workspace);

    // Create artifact store
    let store = Arc::new(
        LocalFsStore::new(&workspace).map_err(|e| e.to_string())?
    );

    // Register external artifacts
    for ext in &pipeline.external_artifacts {
        let kind = parse_artifact_kind(&ext.kind);
        let aref = ArtifactRef::new(&ext.id, kind);
        let path = PathBuf::from(&ext.path);
        store.put(&aref, &path).map_err(|e| e.to_string())?;
    }

    // Build graph
    let mut graph = ExecutionGraph::new();

    for ndef in &pipeline.nodes {
        let node = build_node(ndef).map_err(|e| e.to_string())?;
        graph.add_node(node);
    }

    // Auto-wire based on artifact ids
    graph.auto_wire().map_err(|e| e.to_string())?;
    graph.validate().map_err(|e| e.to_string())?;

    // Create context
    let event_bus = Arc::new(TauriEventBus::new(app));
    let ctx = ExecutionContext {
        workspace,
        artifact_store: store,
        event_bus,
        sop_manager: Arc::new(crate::engine::sop::SopManager::default()), // Assuming SopManager has a default constructor
        retry_config: RetryConfig::default(),
    };

    // Execute
    let engine = ExecutionEngine::new(graph);
    engine.execute(&ctx).await.map_err(|e| e.to_string())?;

    Ok("Pipeline completed successfully".into())
}

#[tauri::command]
pub async fn engine_approve_node(
    app: tauri::AppHandle,
    node_id: String,
    approved: bool,
) -> Result<(), String> {
    use tauri::Manager;
    let sop_manager = app.state::<Arc<crate::engine::sop::SopManager>>();
    if !sop_manager.resolve_node(&node_id, approved).await {
        Err(format!("Node {} not found in pending state.", node_id))
    } else {
        Ok(())
    }
}

// ══════════════════════════════════════════════════════
//  Memory Architecture (Phase 22): Snapshots & Decay
// ══════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════
//  MCP Architecture (Phase 23): Extensibility
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_register_mcp_server(
    app: tauri::AppHandle,
    name: String,
    command: String,
    args: Vec<String>,
) -> Result<Vec<crate::engine::mcp::protocol::McpToolDef>, String> {
    use tauri::Manager;
    let registry = app.state::<crate::engine::mcp::McpRegistry>();
    let res: anyhow::Result<Vec<crate::engine::mcp::protocol::McpToolDef>> = registry.register(&name, &command, &args).await;
    res.map_err(|e: anyhow::Error| e.to_string())
}

#[tauri::command]
pub async fn engine_list_mcp_tools(
    app: tauri::AppHandle,
    server_name: String,
) -> Result<Vec<crate::engine::mcp::protocol::McpToolDef>, String> {
    use tauri::Manager;
    let registry = app.state::<crate::engine::mcp::McpRegistry>();
    let res: anyhow::Result<Vec<crate::engine::mcp::protocol::McpToolDef>> = registry.list_tools(&server_name).await;
    res.map_err(|e: anyhow::Error| e.to_string())
}

// ══════════════════════════════════════════════════════
//  Zero-Trust WASM Plugins (Phase 24)
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_run_wasm_plugin(
    plugin_path: String,
    name: String,
    description: String,
    args: serde_json::Value,
) -> Result<String, String> {
    let _ = plugin_path;
    let _ = description;
    let _ = args;
    let res = crate::engine::wasm::WasmEngine::execute_policy(&name, "mock_node").await;
    Ok(serde_json::to_string(&res).unwrap_or_else(|_| "success".into()))
}


// ══════════════════════════════════════════════════════
//  Vector RAG & Cortex Memory (Phase 25)
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_vector_search(
    query: String,
    limit: usize,
) -> Result<Vec<crate::engine::memory::vector::ScoredResult>, String> {
    // In a full implementation, we would use the embeddings provider to embed the query 
    // and then cosine_similarity against an index. For demo purposes, we will return 
    // mock semantic results reflecting the query intent via keyword match.
    // ZeroClaw's implementation uses the embedding pool, here we simulate the interface.
    
    let mut results = Vec::new();
    let lower = query.to_lowercase();
    
    if lower.contains("password") || lower.contains("auth") {
        results.push(crate::engine::memory::vector::ScoredResult {
            id: "auth_service.rs:14".to_string(),
            vector_score: Some(0.92),
            keyword_score: Some(0.85),
            final_score: 0.90,
        });
        results.push(crate::engine::memory::vector::ScoredResult {
            id: "src/db/user_repo.rs:88".to_string(),
            vector_score: Some(0.88),
            keyword_score: Some(0.40),
            final_score: 0.74,
        });
    } else if lower.contains("sql") || lower.contains("query") {
        results.push(crate::engine::memory::vector::ScoredResult {
            id: "mock_vulnerable_service.rs:34".to_string(),
            vector_score: Some(0.95),
            keyword_score: Some(0.99),
            final_score: 0.96,
        });
    } else {
        results.push(crate::engine::memory::vector::ScoredResult {
            id: "src/main.rs:1".to_string(),
            vector_score: Some(0.40),
            keyword_score: Some(0.10),
            final_score: 0.35,
        });
    }
    
    Ok(results)
}


#[tauri::command]
pub fn engine_export_snapshot(
    workspace: String,
    nodes: Vec<SnapshotNode>,
) -> Result<String, String> {
    let ws = PathBuf::from(&workspace);
    let graph = SnapshotGraph {
        nodes,
        edges: vec![], // DAG structure handled implicitly by Config inputs/outputs in React
    };
    export_graph_snapshot(&ws, &graph)
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn engine_restore_snapshot(
    workspace: String,
) -> Result<Vec<SnapshotNode>, String> {
    let ws = PathBuf::from(&workspace);
    let graph = restore_graph_snapshot(&ws).map_err(|e| e.to_string())?;
    Ok(graph.nodes)
}

#[tauri::command]
pub fn engine_apply_decay(
    mut nodes: Vec<SnapshotNode>,
) -> Vec<SnapshotNode> {
    // Just wrap it over our memory/decay logic
    apply_relevance_decay(&mut nodes, 14.0);
    nodes
}

// ══════════════════════════════════════════════════════
//  Helper: build node from definition
// ══════════════════════════════════════════════════════

fn parse_artifact_kind(s: &str) -> ArtifactKind {
    match s {
        "source-dir" => ArtifactKind::SourceDir,
        "sbom" => ArtifactKind::SBOM,
        "validated-sbom" => ArtifactKind::ValidatedSBOM,
        "merged-sbom" => ArtifactKind::MergedSBOM,
        "signed-sbom" => ArtifactKind::SignedSBOM,
        "compliance-report" => ArtifactKind::ComplianceReport,
        "diff-report" => ArtifactKind::DiffReport,
        "sarif-report" => ArtifactKind::SarifReport,
        _ => ArtifactKind::Generic,
    }
}

fn build_node(def: &GraphNodeDef) -> Result<graph::NodeBox, ExecutionError> {
    let cfg = &def.config;
    match def.node_type.as_str() {
        "validate" => {
            let input_id = cfg["input"].as_str().unwrap_or("input.sbom");
            let output_id = cfg["output"].as_str().unwrap_or("validated.sbom");
            Ok(Box::new(CycloneDxValidateNode {
                id: def.id.clone(),
                input: ArtifactRef::sbom(input_id),
                output: ArtifactRef::validated(output_id),
                expects_approval: def.requires_approval,
            }))
        }
        "merge" => {
            let inputs: Vec<ArtifactRef> = cfg["inputs"].as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|v| ArtifactRef::sbom(v.as_str().unwrap_or("?")))
                .collect();
            let output_id = cfg["output"].as_str().unwrap_or("merged.sbom");
            Ok(Box::new(CycloneDxMergeNode {
                id: def.id.clone(),
                inputs,
                output: ArtifactRef::merged(output_id),
                expects_approval: def.requires_approval,
            }))
        }
        "cdxgen_scan" => {
            let input_id = cfg["input"].as_str().unwrap_or("source");
            let output_id = cfg["output"].as_str().unwrap_or("scanned.sbom");
            let cdxgen = cfg["cdxgen_path"].as_str().unwrap_or("cdxgen").to_string();
            Ok(Box::new(CdxgenScanNode {
                id: def.id.clone(),
                input: ArtifactRef::source_dir(input_id),
                output: ArtifactRef::sbom(output_id),
                cdxgen_path: cdxgen,
                expects_approval: def.requires_approval,
            }))
        }
        "nist_ssdf" => {
            let input_id = cfg["input"].as_str().unwrap_or("input.sbom");
            let output_id = cfg["output"].as_str().unwrap_or("nist_ssdf.report");
            let fail_on_violation = cfg["fail_on_violation"].as_bool().unwrap_or(false);
            Ok(Box::new(FstecComplianceNode {
                id: def.id.clone(),
                input: ArtifactRef::sbom(input_id),
                output: ArtifactRef::compliance(output_id),
                fail_on_violation,
                expects_approval: def.requires_approval,
            }))
        }
        "diff" => {
            let a = cfg["input_a"].as_str().unwrap_or("a.sbom");
            let b = cfg["input_b"].as_str().unwrap_or("b.sbom");
            let out = cfg["output"].as_str().unwrap_or("diff.report");
            Ok(Box::new(DiffNode {
                id: def.id.clone(),
                input_a: ArtifactRef::sbom(a),
                input_b: ArtifactRef::sbom(b),
                output: ArtifactRef::diff(out),
                expects_approval: def.requires_approval,
            }))
        }
        "sign" => {
            let input_id = cfg["input"].as_str().unwrap_or("validated.sbom");
            let output_id = cfg["output"].as_str().unwrap_or("signed.sbom");
            Ok(Box::new(SignNode {
                id: def.id.clone(),
                input: ArtifactRef::validated(input_id),
                output: ArtifactRef::new(output_id, ArtifactKind::SignedSBOM),
                expects_approval: def.requires_approval,
            }))
        }
        "sarif_export" => {
            let input_id = cfg["input"].as_str().unwrap_or("nist_ssdf.report");
            let output_id = cfg["output"].as_str().unwrap_or("sarif.report");
            Ok(Box::new(SarifExportNode {
                id: def.id.clone(),
                input: ArtifactRef::compliance(input_id),
                output: ArtifactRef::sarif(output_id),
                expects_approval: def.requires_approval,
            }))
        }
        other => Err(ExecutionError::ValidationFailed(
            format!("Unknown node type: {}", other)
        )),
    }
}

// ══════════════════════════════════════════════════════
//  Tauri Command: on-demand SARIF export
// ══════════════════════════════════════════════════════

#[tauri::command]
pub async fn engine_export_sarif(input_path: String, output_path: String) -> Result<String, String> {
    let content = tokio::fs::read_to_string(&input_path)
        .await
        .map_err(|e| format!("Failed to read compliance report: {}", e))?;

    let report: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let sarif = nodes::compliance_to_sarif(&report);
    let sarif_str = serde_json::to_string_pretty(&sarif)
        .map_err(|e| format!("Failed to serialize SARIF: {}", e))?;

    tokio::fs::write(&output_path, &sarif_str)
        .await
        .map_err(|e| format!("Failed to write SARIF: {}", e))?;

    Ok(sarif_str)
}
