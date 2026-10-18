use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};

/// The SOP (Standard Operating Procedure) Manager handles paused execution states.
/// It holds the `tx` half of a oneshot channel, allowing the Tauri frontend
/// to asynchronously approve or reject a paused DAG node.
#[derive(Default, Clone)]
pub struct SopManager {
    channels: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
}

impl SopManager {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Stores the transmission channel for a node that is currently awaiting approval.
    pub async fn register_pending_node(&self, node_id: String, tx: oneshot::Sender<bool>) {
        let mut map = self.channels.lock().await;
        map.insert(node_id, tx);
    }

    /// Resolves the pending state by sending a boolean signal back to the ExecutionEngine.
    /// Returns true if the node was found and the signal was sent.
    pub async fn resolve_node(&self, node_id: &str, approved: bool) -> bool {
        let mut map = self.channels.lock().await;
        if let Some(tx) = map.remove(node_id) {
            let _ = tx.send(approved);
            true
        } else {
            false
        }
    }
}
