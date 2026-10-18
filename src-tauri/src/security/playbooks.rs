use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use uuid::Uuid;
use crate::actor_registry::{SwarmBus, SwarmEvent};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlaybookStep {
    pub id: String,
    pub description: String,
    pub action_type: String, // e.g., "isolate_pod", "revoke_token", "patch_code"
    pub target: String,
    pub automated: bool,
    pub status: String, // "pending", "running", "success", "failed"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Playbook {
    pub id: String,
    pub vulnerability_id: String,
    pub title: String,
    pub description: String,
    pub steps: Vec<PlaybookStep>,
    pub status: String, // "draft", "active", "completed"
    pub created_at: String,
}

pub struct PlaybookManager {
    bus: Arc<SwarmBus>,
    playbooks: Arc<Mutex<HashMap<String, Playbook>>>,
}

impl PlaybookManager {
    pub fn new(bus: Arc<SwarmBus>) -> Self {
        Self {
            bus,
            playbooks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generates a mocked playbook based on a vulnerability ID
    pub async fn generate_playbook(&self, vuln_id: String) -> Result<Playbook, String> {
        let pb_id = Uuid::new_v4().to_string();
        
        let steps = vec![
            PlaybookStep {
                id: format!("{}-step-1", pb_id),
                description: "Isolate affected microservices from external traffic".to_string(),
                action_type: "isolate_network".to_string(),
                target: "*.payment_gateway".to_string(),
                automated: true,
                status: "pending".to_string(),
            },
            PlaybookStep {
                id: format!("{}-step-2", pb_id),
                description: "Rotate compromised JWT signing keys".to_string(),
                action_type: "revoke_token".to_string(),
                target: "auth-server".to_string(),
                automated: true,
                status: "pending".to_string(),
            },
            PlaybookStep {
                id: format!("{}-step-3", pb_id),
                description: "Apply LLM-generated hotfix to source code".to_string(),
                action_type: "patch_code".to_string(),
                target: "src/api/auth.rs".to_string(),
                automated: true,
                status: "pending".to_string(),
            },
        ];

        let playbook = Playbook {
            id: pb_id.clone(),
            vulnerability_id: vuln_id.clone(),
            title: format!("Incident Response: {}", vuln_id),
            description: "AI-generated mitigation strategy to contain and remediate the vulnerability.".to_string(),
            steps,
            status: "draft".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        self.playbooks.lock().await.insert(pb_id.clone(), playbook.clone());
        self.bus.publish(SwarmEvent::Log {
            agent: "PlaybookManager".into(),
            message: format!("[INFO] Generated playbook {} for vulnerability {}", pb_id, vuln_id),
        });

        Ok(playbook)
    }

    /// Executes the steps in a playbook sequentially
    pub async fn execute_playbook(&self, pb_id: String) -> Result<(), String> {
        let mut playbooks = self.playbooks.lock().await;
        
        if let Some(playbook) = playbooks.get_mut(&pb_id) {
            playbook.status = "active".to_string();
            self.bus.publish(SwarmEvent::Log {
                agent: "PlaybookManager".into(),
                message: format!("[WARN] Starting execution of playbook {}", pb_id),
            });

            // For demo purposes, we execute them instantly instead of truly async
            // To be realistic in the UI, we could let the UI poll, but here we emit events.
            for step in &mut playbook.steps {
                step.status = "running".to_string();
                
                self.bus.publish(SwarmEvent::PlaybookStepExecuted {
                    playbook_id: pb_id.clone(),
                    step_id: step.id.clone(),
                    action_type: step.action_type.clone(),
                    status: "running".to_string(),
                });

                // Simulate execution delay
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                step.status = "success".to_string();

                self.bus.publish(SwarmEvent::PlaybookStepExecuted {
                    playbook_id: pb_id.clone(),
                    step_id: step.id.clone(),
                    action_type: step.action_type.clone(),
                    status: "success".to_string(),
                });
            }

            playbook.status = "completed".to_string();
            self.bus.publish(SwarmEvent::Log {
                agent: "PlaybookManager".into(),
                message: format!("[SUCCESS] ✅ Playbook {} completed successfully", pb_id),
            });

            Ok(())
        } else {
            Err(format!("Playbook {} not found", pb_id))
        }
    }
    
    pub async fn get_playbooks(&self) -> Vec<Playbook> {
        let pbs = self.playbooks.lock().await;
        pbs.values().cloned().collect()
    }
}
