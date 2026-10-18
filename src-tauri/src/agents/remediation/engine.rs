use std::sync::Arc;
use crate::actor_registry::{SwarmBus, SwarmEvent};
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

pub struct RemediationEngine {
    bus: Arc<SwarmBus>,
}

impl RemediationEngine {
    pub fn new(bus: Arc<SwarmBus>) -> Self {
        Self { bus }
    }

    pub async fn run(&self) {
        let mut rx = self.bus.subscribe();

        self.bus.publish(SwarmEvent::Log {
            agent: "AutoRemediation".into(),
            message: "Auto-remediation engine started. Waiting for approved patches...".into(),
        });

        while let Ok(event) = rx.recv().await {
            if let SwarmEvent::ReviewResult { node_id, vuln_id, approved, feedback: _, proposed_patch } = event {
                // If a patch was approved by the reviewer agent, auto-apply it.
                if approved {
                    self.bus.publish(SwarmEvent::Log {
                        agent: "AutoRemediation".into(),
                        message: format!("Patch for Node {} approved. Attempting to apply recursively...", node_id),
                    });

                    // In a real scenario, we would map node_id or vuln_id to actual files.
                    // For the demo / MVP, we log the attempt.
                    match self.apply_patch(&node_id, &proposed_patch).await {
                        Ok(file_path) => {
                             self.bus.publish(SwarmEvent::Log {
                                agent: "AutoRemediation".into(),
                                message: format!("✅ Patch successfully applied to {:?}", file_path),
                            });
                             self.bus.publish(SwarmEvent::FilePatched {
                                 node_id: node_id.clone(),
                                 vuln_id: vuln_id.clone(),
                                 file_path: file_path.to_string_lossy().to_string(),
                             });
                             self.bus.publish(SwarmEvent::TestFailed {
                                 // Let the test agent re-run
                                 node_id,
                                 vuln_id,
                                 test_type: "Remediation Check".into(),
                                 error: "Re-evaluating post remediation".into()
                             });
                        },
                        Err(e) => {
                             self.bus.publish(SwarmEvent::Log {
                                agent: "AutoRemediation".into(),
                                message: format!("Failed to apply patch: {}", e),
                            });
                        }
                    }
                } else {
                     self.bus.publish(SwarmEvent::Log {
                        agent: "AutoRemediation".into(),
                        message: format!("Patch for Node {} was REJECTED by ReviewerAgent. Skipping remediation.", node_id),
                    });
                }
            }
        }
    }

    async fn apply_patch(&self, node_id: &str, patch_content: &str) -> Result<PathBuf, String> {
        // Stub: Determine file to patch based on node_id.
        // For demonstration, we create a patched file in a temp directory.
        let temp_dir = std::env::temp_dir().join("cyclonedx_remediations");
        fs::create_dir_all(&temp_dir).await.map_err(|e| e.to_string())?;

        let file_name = format!("patched_{}_{}.rs", node_id, Uuid::new_v4().as_simple());
        let file_path = temp_dir.join(file_name);

        fs::write(&file_path, patch_content).await.map_err(|e| e.to_string())?;
        
        // Return the path the patch was applied to
        Ok(file_path)
    }
}
