use std::sync::Arc;
use crate::actor_registry::{SwarmBus, SwarmEvent};
use crate::nebius_client::NebiusClient;

pub struct ReviewerAgent {
    bus: Arc<SwarmBus>,
}

impl ReviewerAgent {
    pub fn new(bus: Arc<SwarmBus>) -> Self {
        Self { bus }
    }

    pub async fn run(&self) {
        let mut rx = self.bus.subscribe();

        self.bus.publish(SwarmEvent::Log {
            agent: "NovaShield".into(),
            message: "Security Gate Active. Awaiting patches for review...".into(),
        });

        while let Ok(event) = rx.recv().await {
            if let SwarmEvent::ReviewRequested { node_id, vuln_id, original_code, proposed_patch } = event {
                self.bus.publish(SwarmEvent::Log {
                    agent: "NovaShield".into(),
                    message: format!("Reviewing patch from PatchAgent for {}...", node_id),
                });

                if let Ok(client) = NebiusClient::new().await {
                    match client.review_code(&original_code, &proposed_patch).await {
                        Ok(res) => {
                            let approved = res.status == "APPROVED";
                            self.bus.publish(SwarmEvent::ReviewResult {
                                node_id,
                                vuln_id,
                                approved,
                                feedback: res.feedback,
                                proposed_patch,
                            });
                        }
                        Err(e) => {
                            self.bus.publish(SwarmEvent::Log {
                                agent: "StrazhShield".into(),
                                message: format!("❌ Error calling Nemotron for review: {}", e),
                            });
                        }
                    }
                }
            }
        }
    }
}
