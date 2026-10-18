use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tauri::AppHandle;
use tauri::Emitter;
use uuid::Uuid;

// ══════════════════════════════════════════════════════
//  The Reactive Core: Event-Driven AST Actor System
//  Inspired by A2A Actor Engine (Erlang/OTP GenServer model)
// ══════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeState {
    Unparsed,
    Parsed,
    Tested,
    Vulnerable,
    Quarantined,
    Healed, // Added as per the provided snippet's NodeState
}

impl std::fmt::Display for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The messages that can be sent to an AstNodeActor
#[derive(Debug)]
pub enum ActorMsg {
    /// A source file was modified on disk
    SourceChanged,
    /// An upstream dependency (import) has changed its state/hash
    DependencyChanged {
        from_node: String,
        new_hash: String,
    },
    /// A vulnerability was detected by Nova Shield or SBOM scan
    VulnerabilityDetected {
        vuln_id: String,
        severity: String,
    },
    /// Subscribe to updates from this actor
    Subscribe {
        subscriber_id: String,
        tx: mpsc::Sender<ActorMsg>,
    },
    /// Get the current state of the actor
    GetState {
        reply_to: tokio::sync::oneshot::Sender<NodeState>,
    },
}

/// The internal state of an individual AST Node Actor
pub struct AstNodeActor {
    pub node_id: String,
    pub state: NodeState,
    pub hash: String,
    
    // Who we depend on (we listen to them)
    pub dependencies: HashSet<String>,
    
    // Who depends on us (we broadcast to them)
    pub subscribers: HashMap<String, mpsc::Sender<ActorMsg>>,
    
    // Inbox
    pub receiver: mpsc::Receiver<ActorMsg>,
    
    // Global Actor Registry access to find other actors
    pub registry: Arc<ActorRegistry>,
    
    // Optional UI hook
    pub app_handle: Option<AppHandle>,
}

impl AstNodeActor {
    pub fn new(
        node_id: String, 
        receiver: mpsc::Receiver<ActorMsg>, 
        registry: Arc<ActorRegistry>,
        app_handle: Option<AppHandle>
    ) -> Self {
        Self {
            node_id,
            state: NodeState::Unparsed,
            hash: String::new(),
            dependencies: HashSet::new(),
            subscribers: HashMap::new(),
            receiver,
            registry,
            app_handle,
        }
    }

    /// The main run loop (GenServer loop)
    pub async fn run(mut self) {
        println!("🚀 Actor [{}] Spawned", self.node_id);
        
        while let Some(msg) = self.receiver.recv().await {
            // Emit MESSAGE_RECEIVED event
            if let Some(app) = &self.app_handle {
                let _ = app.emit("pulse-event", serde_json::json!({
                    "action": "MESSAGE_RECEIVED",
                    "node_id": &self.node_id,
                    "msg_type": format!("{:?}", msg), // Use debug format for message type
                    "from": "unknown" // Can't easily determine sender for all msg types here
                }));
            }
            self.handle_cast(msg).await;
        }
        
        println!("🛑 Actor [{}] Shutting down", self.node_id);
    }

    async fn handle_cast(&mut self, msg: ActorMsg) {
        match msg {
            ActorMsg::SourceChanged => {
                println!("🔄 Actor [{}]: Source code changed. Re-parsing...", self.node_id);
                // Simulate parse/hash generation
                self.update_state(NodeState::Parsed).await;
                self.hash = format!("hash_{}", uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>());

                // Broadcast to dependents
                self.broadcast_change().await;
            }
            ActorMsg::DependencyChanged { from_node, new_hash } => {
                println!("⚠️ Actor [{}]: Dependency [{}] updated (hash: {}). Invaliding state...", 
                         self.node_id, from_node, new_hash);
                
                // If a dependency changes, we need to be re-evaluated
                self.update_state(NodeState::Unparsed).await;
                
                // Cascade the invalidation
                self.broadcast_change().await;
            }
            ActorMsg::VulnerabilityDetected { vuln_id, severity } => {
                println!("🚨 Actor [{}]: Vulnerability DETECTED: {} ({})", self.node_id, vuln_id, severity);
                self.update_state(NodeState::Quarantined).await;
                
                // Here we spawn a PR Agent / Patch Generator!
                println!("🤖 Actor [{}]: Self-Healing Triggered. Spawning PatchAgentActor...", self.node_id);
                
                let node_id_clone = self.node_id.clone();
                let vuln_id_clone = vuln_id.clone();
                let app = self.app_handle.clone();
                
                tokio::spawn(async move {
                    if let Ok(res) = crate::patch_generator::PatchGenerator::heal_node(
                        app.as_ref(),
                        &node_id_clone,
                        &vuln_id_clone,
                        "// Simulated AST Source Node"
                    ).await {
                        println!("✨ Actor [{}]: SUCCESSFULLY HEALED! Generated Rule: {}", node_id_clone, res.extracted_rule_pattern);
                        // After healing, update state to Healed
                        if let Some(app_handle) = app {
                            let _ = app_handle.emit("pulse-event", serde_json::json!({
                                "action": "STATE_TRANSITION",
                                "node_id": &node_id_clone,
                                "old_state": NodeState::Quarantined.to_string(), // Assuming it was quarantined
                                "new_state": NodeState::Healed.to_string()
                            }));
                        }
                    } else {
                        println!("❌ Actor [{}]: Failed to heal node.", node_id_clone);
                    }
                });
                
                // Broadcast that we are no longer safe
                self.broadcast_change().await;
            }
            ActorMsg::Subscribe { subscriber_id, tx } => {
                self.subscribers.insert(subscriber_id, tx);
            }
            ActorMsg::GetState { reply_to } => {
                let _ = reply_to.send(self.state.clone());
            }
        }
    }

    async fn update_state(&mut self, new_state: NodeState) {
        let old_state = self.state.clone();
        if self.state != new_state {
            println!("[Actor {}] Transition: {:?} -> {:?}", self.node_id, self.state, new_state);
            self.state = new_state.clone();
            
            if let Some(app) = &self.app_handle {
                let _ = app.emit("pulse-event", serde_json::json!({
                    "action": "STATE_TRANSITION",
                    "node_id": &self.node_id,
                    "old_state": old_state.to_string(),
                    "new_state": new_state.to_string()
                }));
            }
        }
    }
    
    async fn broadcast_change(&self) {
        for (sub_id, tx) in &self.subscribers {
            let msg = ActorMsg::DependencyChanged {
                from_node: self.node_id.clone(),
                new_hash: self.hash.clone(),
            };
            // Emit MESSAGE_SENT event
            if let Some(app) = &self.app_handle {
                let _ = app.emit("pulse-event", serde_json::json!({
                    "action": "MESSAGE_SENT",
                    "from": &self.node_id,
                    "to": sub_id,
                    "msg_type": "DependencyChanged"
                }));
            }
            if let Err(e) = tx.send(msg).await {
                eprintln!("Failed to notify subscriber [{}] from [{}]: {}", sub_id, self.node_id, e);
            }
        }
    }
}

// ══════════════════════════════════════════════════════
//  Actor Registry (Supervisor / Registry)
// ══════════════════════════════════════════════════════

pub struct ActorRegistry {
    pub actors: RwLock<HashMap<String, mpsc::Sender<ActorMsg>>>,
}

impl ActorRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            actors: RwLock::new(HashMap::new()),
        })
    }

    /// Register a new actor and spawn its run loop
    pub async fn spawn_actor(self: &Arc<Self>, node_id: String, app_handle: Option<AppHandle>) -> mpsc::Sender<ActorMsg> {
        let (tx, rx) = mpsc::channel(100);
        let actor = AstNodeActor::new(node_id.clone(), rx, self.clone(), app_handle.clone()); // Clone app_handle for actor

        self.actors.write().await.insert(node_id.clone(), tx.clone());
        
        // Emit Pulse Event for NODE_SPAWNED
        if let Some(app) = &app_handle {
            let _ = app.emit("pulse-event", serde_json::json!({
                "action": "NODE_SPAWNED",
                "node_id": &node_id,
                "initial_state": NodeState::Unparsed.to_string()
            }));
        }

        tokio::spawn(async move {
            actor.run().await;
        });
        
        tx
    }
    
    pub async fn get_actor(&self, node_id: &str) -> Option<mpsc::Sender<ActorMsg>> {
        self.actors.read().await.get(node_id).cloned()
    }
}

// ══════════════════════════════════════════════════════
//  Tests demonstrating Event-Driven AST Cascade
// ══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ast_actor_quarantine_cascade() {
        let registry = ActorRegistry::new();

        // 1. Spawn three actors representing an AST import chain: App -> Auth -> Crypto
        let _app_tx = registry.spawn_actor("App".into(), None).await;
        let auth_tx = registry.spawn_actor("Auth".into(), None).await;
        let crypto_tx = registry.spawn_actor("Crypto".into(), None).await;

        // 2. Wire up the dependencies (Subscribe)
        // Auth depends on Crypto (so Auth subscribes to Crypto)
        crypto_tx.send(ActorMsg::Subscribe {
            subscriber_id: "Auth".into(),
            tx: auth_tx.clone(),
        }).await.unwrap();

        // 3. Crypto parses successfully
        crypto_tx.send(ActorMsg::SourceChanged).await.unwrap();
        
        // Let actors process messages
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. Nova Shield detects a vulnerability in Crypto!
        crypto_tx.send(ActorMsg::VulnerabilityDetected {
            vuln_id: "CVE-2026-9999".into(),
            severity: "CRITICAL".into(),
        }).await.unwrap();

        // Let the cascade propagate: Crypto (Quarantined) -> Auth (Invaliated due to Dep Change)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 5. Verify the states
        let (tx, rx) = tokio::sync::oneshot::channel();
        crypto_tx.send(ActorMsg::GetState { reply_to: tx }).await.unwrap();
        assert_eq!(rx.await.unwrap(), NodeState::Quarantined);

        let (tx2, rx2) = tokio::sync::oneshot::channel();
        auth_tx.send(ActorMsg::GetState { reply_to: tx2 }).await.unwrap();
        // Auth goes back to Unparsed waiting for a safe Crypto dependency
        assert_eq!(rx2.await.unwrap(), NodeState::Unparsed);
    }
}
