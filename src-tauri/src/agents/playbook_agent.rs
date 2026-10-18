use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlaybookStep {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String, // "pending", "running", "completed", "failed"
    pub executor: String, // "k8s_api", "aws_iam", "github_mcp", "slack"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IncidentPlaybook {
    pub incident_id: String,
    pub severity: String,
    pub scenario_name: String,
    pub description: String,
    pub steps: Vec<PlaybookStep>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StepExecutionResult {
    pub step_id: String,
    pub success: bool,
    pub logs: Vec<String>,
}

pub struct PlaybookAgent;

impl PlaybookAgent {
    pub fn get_active_playbooks() -> Vec<IncidentPlaybook> {
        vec![
            IncidentPlaybook {
                incident_id: "INC-9941".to_string(),
                severity: "CRITICAL".to_string(),
                scenario_name: "CVE-2021-44228 (Log4Shell) Active Exploit Detected".to_string(),
                description: "Deep packet inspection identified JNDI lookup attempts bypassing WAF rules. Immediate orchestration required to isolate Kubernetes application pods and rotate corresponding AWS IAM roles.".to_string(),
                steps: vec![
                    PlaybookStep {
                        id: "step-1".to_string(),
                        title: "Isolate Kubernetes Pods".to_string(),
                        description: "Inject NetworkPolicy to block all egress traffic from namespace 'payment-gateway' to prevent LDAP callback beaconing.".to_string(),
                        status: "pending".to_string(),
                        executor: "k8s_api".to_string(),
                    },
                    PlaybookStep {
                        id: "step-2".to_string(),
                        title: "Revoke Overprivileged IAM Role".to_string(),
                        description: "Force detachment of STS policies from the compromised EKS worker node instance profile.".to_string(),
                        status: "pending".to_string(),
                        executor: "aws_iam".to_string(),
                    },
                    PlaybookStep {
                        id: "step-3".to_string(),
                        title: "Generate and Deploy Log4j AST Patch".to_string(),
                        description: "Trigger GitOps Patch Agent to upgrade log4j-core to 2.17.1 across tracking PurLs.".to_string(),
                        status: "pending".to_string(),
                        executor: "github_mcp".to_string(),
                    },
                    PlaybookStep {
                        id: "step-4".to_string(),
                        title: "Notify Major Incident Channel".to_string(),
                        description: "Broadcast containment status to #sec-ops-incidents via Slack webhook.".to_string(),
                        status: "pending".to_string(),
                        executor: "slack".to_string(),
                    }
                ],
            },
            IncidentPlaybook {
                incident_id: "INC-8802".to_string(),
                severity: "HIGH".to_string(),
                scenario_name: "Compromised Developer Credential (NPM Registry)".to_string(),
                description: "Leaked Personal Access Token identified on GitHub public spaces matching internal core-maintainer regex.".to_string(),
                steps: vec![
                    PlaybookStep {
                        id: "step-1".to_string(),
                        title: "Revoke NPM Published Token".to_string(),
                        description: "Call NPM Enterprise APIs to invalidate token.".to_string(),
                        status: "pending".to_string(),
                        executor: "npm_api".to_string(),
                    },
                    PlaybookStep {
                        id: "step-2".to_string(),
                        title: "Enforce 2FA & Password Reset".to_string(),
                        description: "Trigger Okta session invalidation and force multi-factor authentication enrollment.".to_string(),
                        status: "pending".to_string(),
                        executor: "okta".to_string(),
                    }
                ],
            }
        ]
    }

    pub async fn execute_step(incident_id: &str, step_id: &str, executor: &str) -> StepExecutionResult {
        // Simulate real-world API latency
        let execution_time = rand::random::<u64>() % 1500 + 500;
        tokio::time::sleep(tokio::time::Duration::from_millis(execution_time)).await;
        
        let mut logs = Vec::new();
        logs.push(format!("[SOAR] Authenticating to {} Integration...", executor.to_uppercase()));
        
        match executor {
            "k8s_api" => {
                logs.push("[K8S] Context: arn:aws:eks:us-east-1:123456789012:cluster/prod".to_string());
                logs.push("[K8S] -> Applying net-isolate-policy.yaml to namespace".to_string());
                logs.push("[K8S] Status: Networking objects mutated successfully. Egress blocked.".to_string());
            },
            "aws_iam" => {
                logs.push("[AWS IAM] -> Calling DetachRolePolicy on role 'eks-node-group-role'".to_string());
                logs.push("[AWS IAM] Context: Purging active AccessKeys and rotating KMS aliases...".to_string());
                logs.push("[AWS IAM] Status: Permissions successfully stripped.".to_string());
            },
            "github_mcp" => {
                logs.push("[MCP HUB] -> Bridging to autonomous execution matrix.".to_string());
                logs.push("[MCP HUB] Constructing AST differences... Opening PR #448912".to_string());
                logs.push("[MCP HUB] Status: Pull Request successfully merged into staging.".to_string());
            },
            "slack" => {
                logs.push("[SLACK] Target Channel: #sec-ops-incidents".to_string());
                logs.push("[SLACK] Dispatching adaptive block payload notification...".to_string());
                logs.push("[SLACK] Status: HTTP 200 OK Message Delivered.".to_string());
            },
            _ => {
                logs.push(format!("[{}] Executing generic API protocol...", executor.to_uppercase()));
                logs.push(format!("[{}] Expected state convergence achieved.", executor.to_uppercase()));
            }
        }
        
        logs.push(format!("[SOAR] Incident {} Phase [{}] Orchestration Complete in {}ms.", incident_id, step_id, execution_time));
        
        StepExecutionResult {
            step_id: step_id.to_string(),
            success: true,
            logs,
        }
    }
}
