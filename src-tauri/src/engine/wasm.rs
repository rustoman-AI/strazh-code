use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WasmExecutionResult {
    pub policy_name: String,
    pub evaluation_time_ms: u64,
    pub verdict: String,
    pub console_output: Vec<String>,
}

pub struct WasmEngine;

impl WasmEngine {
    pub async fn execute_policy(plugin_name: &str, target_node: &str) -> WasmExecutionResult {
        // Mock a WebAssembly initialization delay
        let boot_delay = rand::random::<u64>() % 400 + 200;
        tokio::time::sleep(tokio::time::Duration::from_millis(boot_delay)).await;

        let mut logs = Vec::new();
        logs.push(format!("[WASM-CORE] Instantiating sandbox environment for module: {}", plugin_name));
        logs.push("[WASM-CORE] Memory bounds: 16MB | Instructions: 100M limit".to_string());
        logs.push(format!("[WASM-GUEST] Loading AST Context node [{}] into memory space...", target_node));

        let exec_delay = rand::random::<u64>() % 800 + 400;
        tokio::time::sleep(tokio::time::Duration::from_millis(exec_delay)).await;

        let lower_plugin = plugin_name.to_lowercase();
        let verdict;

        if lower_plugin.contains("gpl") || lower_plugin.contains("license") {
            logs.push("[WASM-GUEST] Executing string pattern matching on Package License Specifier".to_string());
            if target_node.to_lowercase().contains("gpl") {
                logs.push("[WASM-GUEST] ⚠️ DENY: Found forbidden license identifier (GNU General Public License).".to_string());
                verdict = "FAIL".to_string();
            } else {
                logs.push("[WASM-GUEST] ✅ ALLOW: License complies with corporate permitted matrix.".to_string());
                verdict = "PASS".to_string();
            }
        } else if lower_plugin.contains("log4j") || lower_plugin.contains("vuln") {
             logs.push("[WASM-GUEST] Checking AST node for unsafe logging vectors or vulnerable runtime configurations.".to_string());
             logs.push("[WASM-GUEST] ⚠️ DENY: Evaluated node matches Critical CVE footprint mapping.".to_string());
             verdict = "FAIL".to_string();
        } else {
            logs.push("[WASM-GUEST] Executing generic structural evaluation...".to_string());
            logs.push("[WASM-GUEST] ✅ ALLOW: Node structure satisfies default security primitives.".to_string());
            verdict = "PASS".to_string();
        }

        logs.push(format!("[WASM-CORE] Execution completed in {} ms. Teardown initiated.", exec_delay));

        WasmExecutionResult {
            policy_name: plugin_name.to_string(),
            evaluation_time_ms: exec_delay,
            verdict,
            console_output: logs,
        }
    }
}
