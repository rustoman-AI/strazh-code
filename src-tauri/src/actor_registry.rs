use std::sync::Arc;
use tokio::sync::broadcast;
use serde::{Deserialize, Serialize};

/// All events that can flow through the Swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmEvent {
    /// Step 1: Threat Intel found a vulnerability
    ThreatDetected {
        node_id: String,
        vuln_id: String,
        description: String,
    },
    /// Step 2: Patch Agent sends code for review
    ReviewRequested {
        node_id: String,
        vuln_id: String,
        original_code: String,
        proposed_patch: String,
    },
    /// Step 3: Nova Shield (Reviewer) approves or rejects the patch
    ReviewResult {
        node_id: String,
        vuln_id: String,
        approved: bool,
        feedback: String,
        proposed_patch: String,
    },
    /// Info event for logging
    Log {
        agent: String,
        message: String,
    },
    /// Step 4: Patch has been written to disk
    FilePatched {
        node_id: String,
        vuln_id: String,
        file_path: String,
    },
    /// Step 5: Git commit created
    GitCommitCreated {
        node_id: String,
        vuln_id: String,
        commit_hash: String,
        branch: String,
    },
    /// Step 5: Compliance audit result
    ComplianceResult {
        node_id: String,
        vuln_id: String,
        passed: bool,
        score: u32,
        details: String,
    },
    /// Step 6: Rollback was performed after failed verification
    RollbackPerformed {
        node_id: String,
        vuln_id: String,
        commit_id: String,
        reason: String,
    },
    /// Step 7: Test Agent verified the patch
    TestPassed {
        node_id: String,
        vuln_id: String,
        test_type: String,
        passed: bool,
        details: String,
    },
    /// Step 8: Fuzz Agent found or confirmed no issues
    FuzzResult {
        node_id: String,
        vuln_id: String,
        mutations: u32,
        crashes: u32,
        coverage_pct: f64,
    },
    /// Multi-stage exploit chain detected by Attack-Path AI Engine
    ExploitChainDetected {
        chain_id: String,
        stages: Vec<String>,
        severity: String,
        entry_point: String,
        target: String,
    },
    // --- Graph-Scheduled Events (any agent can react) ---
    /// Test Agent detected a failing test after patch
    TestFailed {
        node_id: String,
        vuln_id: String,
        test_type: String,
        error: String,
    },
    /// Dependency Agent found a risky dependency update
    DependencyRisk {
        node_id: String,
        package: String,
        current_version: String,
        risk_level: String,
        description: String,
    },
    /// Compliance Agent detected a policy violation
    PolicyViolation {
        node_id: String,
        framework: String,
        rule: String,
        severity: String,
        remediation: String,
    },
    /// Exploit Simulation Engine — Red Team vs Blue Team moves
    ExploitSimulation {
        sim_id: String,
        phase: String,          // "recon", "exploit", "escalate", "exfiltrate", "defense"
        attacker_action: String,
        defender_response: String,
        success: bool,          // did the attacker succeed at this step?
        severity_score: f64,    // 0.0 - 10.0
        node_path: Vec<String>, // graph nodes traversed
    },
    /// Phase 18: Team Orchestration - IPC Message between Leader and Subagents
    TeamOrchestration {
        payload: crate::agents::ipc_bus::IPCMessage,
    },
    /// Phase 19: Agent State Machine tracker
    AgentStateChanged {
        agent_id: String,
        state: crate::agents::loop_state::AgentState,
        details: String,
    },
    /// Phase 30: Incident Playbook Engine
    PlaybookStepExecuted {
        playbook_id: String,
        step_id: String,
        action_type: String,
        status: String,
    },
    /// Phase 32: Swarm Chat
    UserChatMessage {
        text: String,
    },
    AgentReply {
        agent: String,
        message: String,
    },
}

/// The central nervous system uniting all agents
pub struct SwarmBus {
    pub tx: broadcast::Sender<SwarmEvent>,
}

impl SwarmBus {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(Self { tx })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SwarmEvent> {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: SwarmEvent) {
        let _ = self.tx.send(event);
    }
}
