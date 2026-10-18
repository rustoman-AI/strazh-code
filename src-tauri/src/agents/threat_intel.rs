use std::sync::Arc;
use tokio::time::{sleep, Duration};
use crate::actor_registry::{SwarmBus, SwarmEvent};

pub struct ThreatIntelAgent {
    bus: Arc<SwarmBus>,
}

impl ThreatIntelAgent {
    pub fn new(bus: Arc<SwarmBus>) -> Self {
        Self { bus }
    }

    pub async fn run(&self) {
        self.bus.publish(SwarmEvent::Log {
            agent: "ThreatIntel".into(),
            message: "Starting surveillance on the AST/SBOM graph...".into(),
        });

        // Simulate taking time to scan
        sleep(Duration::from_secs(2)).await;

        self.bus.publish(SwarmEvent::Log {
            agent: "ThreatIntel".into(),
            message: "⚠️ Critical vulnerability detected in dependency!".into(),
        });

        // Emit the simulated threat
        self.bus.publish(SwarmEvent::ThreatDetected {
            node_id: "api_server.rs".into(),
            vuln_id: "CVE-2026-0002".into(),
            description: "Missing input validation allowing SQL Injection.".into(),
        });
    }
}
