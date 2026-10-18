use crate::engine::store::ArtifactStore;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

// ══════════════════════════════════════════════════════
//  RetryConfig — configurable retry with exponential backoff
// ══════════════════════════════════════════════════════

pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_attempts: u32,
    /// Initial delay in milliseconds (doubles each retry)
    pub initial_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 2000, // 2s → 4s → 8s
        }
    }
}

// ══════════════════════════════════════════════════════
//  ExecutionContext — shared state for pipeline execution
// ══════════════════════════════════════════════════════

pub struct ExecutionContext {
    /// Working directory for the pipeline
    pub workspace: PathBuf,
    /// Artifact storage backend
    pub artifact_store: Arc<dyn ArtifactStore>,
    /// Event streaming channel
    pub event_bus: Arc<dyn EventBus>,
    /// SOP Manager for pausing execution and awaiting manual approval
    pub sop_manager: Arc<crate::engine::sop::SopManager>,
    /// Retry configuration for node execution
    pub retry_config: RetryConfig,
}

// ══════════════════════════════════════════════════════
//  EventBus — abstraction for pipeline event streaming
// ══════════════════════════════════════════════════════

pub trait EventBus: Send + Sync {
    fn emit(&self, event: EngineEvent);
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum EngineEvent {
    /// Pipeline execution started
    PipelineStarted { total_nodes: usize },
    /// A specific node started executing
    NodeStarted { node_id: String, index: usize },
    /// Node completed successfully
    NodeFinished { node_id: String, index: usize, duration_ms: u64 },
    /// Node was skipped (cache hit)
    NodeSkipped { node_id: String, reason: String },
    /// Node failed
    NodeFailed { node_id: String, error: String },
    /// Pipeline completed
    PipelineFinished { total_ms: u64, nodes_executed: usize, nodes_skipped: usize },
    /// Pipeline failed
    PipelineFailed { error: String, failed_node: String },
    /// Artifact stored
    ArtifactStored { artifact_id: String, path: String, hash: Option<String> },
    /// Log message from a node
    NodeLog { node_id: String, line: String },
    /// Phase 20: SOP Engine - Node requires manual human approval to proceed
    NodePendingApproval { node_id: String },
    /// Phase 20: SOP Engine - Human rejected the node
    NodeRejected { node_id: String },
}

// ══════════════════════════════════════════════════════
//  TauriEventBus — emits events via Tauri's event system
// ══════════════════════════════════════════════════════

pub struct TauriEventBus {
    app: tauri::AppHandle,
}

impl TauriEventBus {
    pub fn new(app: tauri::AppHandle) -> Self {
        Self { app }
    }
}

impl EventBus for TauriEventBus {
    fn emit(&self, event: EngineEvent) {
        use tauri::Emitter;
        let _ = self.app.emit("engine-event", &event);
    }
}

// ══════════════════════════════════════════════════════
//  NoopEventBus — for testing / headless execution
// ══════════════════════════════════════════════════════

pub struct NoopEventBus;

impl EventBus for NoopEventBus {
    fn emit(&self, _event: EngineEvent) {
        // intentionally empty
    }
}
