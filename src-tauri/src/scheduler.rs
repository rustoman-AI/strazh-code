use std::path::Path;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::ast_actor::{ActorRegistry, ActorMsg};
use tauri::AppHandle;

/// The Reactive Graph Scheduler loops infinitely to watch the filesystem and feed
/// the Actor Engine with state transitions.
pub struct GraphScheduler {
    pub registry: Arc<ActorRegistry>,
    pub watch_path: String,
    pub app_handle: Option<AppHandle>,
}

impl GraphScheduler {
    pub fn new(registry: Arc<ActorRegistry>, watch_path: String, app_handle: Option<AppHandle>) -> Self {
        Self {
            registry,
            watch_path,
            app_handle,
        }
    }

    /// Spawns the filesystem watcher loop into a background Tokio task.
    pub async fn run(self) -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel(100);

        // Map the synchronous notify loop to an asynchronous tokio channel
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                // Ignore metadata/access events, only care about actual content changes
                if matches!(event.kind, EventKind::Modify(_)) {
                    let _ = tx.blocking_send(event);
                }
            }
        })?;

        // Start watching the target directory
        watcher.watch(Path::new(&self.watch_path), RecursiveMode::Recursive)?;
        
        println!("👁️  Graph Scheduler is watching {} for reactive transitions...", self.watch_path);

        // Process FS events and bridge them into the A2A Actor System
        // By moving `self` into the loop, the background task holds the registry.
        while let Some(event) = rx.recv().await {
            for path in event.paths {
                if let Some(path_str) = path.to_str() {
                    // Primitive Mapping: In a real AST parser, we would map the file path 
                    // to the exact Node IDs (like "Crypto", "App", "HttpHandler") that live in this file.
                    // For the hackathon, if *any* .rs or .js file changes, we trigger the root or mock node.
                    if path_str.ends_with(".rs") || path_str.ends_with(".js") || path_str.ends_with(".ts") {
                        println!("⚡ Scheduler detected change in {}. Routing to AST Node...", path_str);
                        
                        // We simulate finding the corresponding AST Actor. 
                        // For the hackathon, let's target the "Crypto" node we use in our demonstrations.
                        // Or we can dynamically spawn if not exist. Let's try to fetch it first.
                        if let Some(actor_tx) = self.registry.get_actor("Crypto").await {
                            let _ = actor_tx.send(ActorMsg::SourceChanged).await;
                        } else {
                            // If the node doesn't exist yet, we can spawn it on the fly!
                            // This proves it's a True Synthetic Runtime.
                            println!("🌱 Scheduler: Actor [Crypto] not found. Spawning dynamically based on filesystem event!");
                            let actor_tx = self.registry.spawn_actor("Crypto".into(), self.app_handle.clone()).await;
                            
                            // Let it parse
                            let _ = actor_tx.send(ActorMsg::SourceChanged).await;
                            
                            // Wait a tiny bit then simulate that Nova Shield immediately scans it
                            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                            
                            // Trigger the self-healing loop for the demo!
                            let _ = actor_tx.send(ActorMsg::VulnerabilityDetected {
                                vuln_id: "CVE-2026-9999".into(),
                                severity: "HIGH".into(),
                            }).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
