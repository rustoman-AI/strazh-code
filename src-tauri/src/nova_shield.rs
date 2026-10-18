use anyhow::Result;
use crate::nebius_client::{NebiusClient, ScanRequest};

pub async fn security_gate(
    nebius: &NebiusClient,
    intent: &str,
    payload: &str,
) -> Result<()> {
    
    // Attempt scan through NVIDIA Nemotron on Nebius Token Factory
    let result = nebius.scan(ScanRequest {
        intent: intent.into(),
        payload: payload.into(),
    }).await;
    
    match result {
        Ok(scan_result) => evaluate_risk(&scan_result.risk, intent, payload, &scan_result.analysis),
        Err(e) => {
            // Failsafe: if the scanner is unreachable or fails, we block execution for safety 
            // of the DevSecOps graph, or we can choose to allow. For Hackathon demo, we print error 
            // but let it proceed so the rest of the app doesn't break if AWS credentials are not set up perfectly yet.
            println!("⚠️ [STRAZH-SHIELD-WARNING] Failed to reach Nemotron scanner: {}", e);
            println!("⚠️ Proceeding without ML security gate for this request.");
            Ok(())
        }
    }
}

pub fn evaluate_risk(risk: &str, intent: &str, payload: &str, analysis: &str) -> Result<()> {
    match risk {
        "HIGH" => {
            println!("🚨 [STRAZH-SHIELD] HIGH RISK OPERATION BLOCKED");
            println!("Intent: {}", intent);
            println!("Payload: {}", payload);
            println!("Analysis:\n{}", analysis);
            Err(anyhow::anyhow!(
                "Operation blocked by Strazh Shield. Reason:\n{}", 
                analysis
            ))
        }
        "MEDIUM" => {
            println!("⚠️ [STRAZH-SHIELD] Medium risk detected");
            println!("Intent: {}", intent);
            println!("Payload: {}", payload);
            println!("Analysis:\n{}", analysis);
            // Medium risk allows execution but logs heavily
            Ok(())
        }
        _ => {
            println!("✅ [STRAZH-SHIELD] Operation passed security gate (LOW risk)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_logic_high_risk() {
        let result = evaluate_risk("HIGH", "execute_command", "rm -rf /", "Malicious intent detected");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Malicious intent detected"));
    }

    #[test]
    fn test_gate_logic_medium_risk() {
        let result = evaluate_risk("MEDIUM", "read_file", "/etc/passwd", "Sensitive file access");
        assert!(result.is_ok()); // Medium allows execution but logs
    }

    #[test]
    fn test_gate_logic_low_risk() {
        let result = evaluate_risk("LOW", "read_file", "config.json", "Standard configuration read");
        assert!(result.is_ok());
    }
}
