use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PatchPayload {
    pub cve_id: String,
    pub target_file: String,
    pub unified_diff: String,
    pub explanation: String,
    pub patch_status: String,
}

pub struct PatchAgent;

impl PatchAgent {
    pub async fn generate_ast_patch(cve_id: &str, _component_id: &str) -> PatchPayload {
        // Synthesize an LLM thought process delay
        let delay_ms = rand::random::<u64>() % 1500 + 1000;
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

        let lower_cve = cve_id.to_lowercase();

        if lower_cve.contains("cve-2021-44228") || lower_cve.contains("log4j") {
            PatchPayload {
                cve_id: "CVE-2021-44228".to_string(),
                target_file: "pom.xml".to_string(),
                unified_diff: r#"--- pom.xml
+++ pom.xml
@@ -42,7 +42,7 @@
     <dependency>
         <groupId>org.apache.logging.log4j</groupId>
         <artifactId>log4j-core</artifactId>
-        <version>2.14.1</version>
+        <version>2.17.1</version>
     </dependency>
     <dependency>
         <groupId>org.springframework.boot</groupId>
"#.to_string(),
                explanation: "The patch upgrades Log4j to version 2.17.1, which completely disables JDNI lookups by default, remediating the Remote Code Execution vulnerability.".to_string(),
                patch_status: "Synthesized".to_string(),
            }
        } else if lower_cve.contains("cve-2023-4863") || lower_cve.contains("libwebp") {
            PatchPayload {
                cve_id: "CVE-2023-4863".to_string(),
                target_file: "package.json".to_string(),
                unified_diff: r#"--- package.json
+++ package.json
@@ -15,7 +15,7 @@
   "dependencies": {
     "react": "^18.2.0",
     "react-dom": "^18.2.0",
-    "libwebp": "1.3.1"
+    "libwebp": "^1.3.2"
   },
   "devDependencies": {
     "typescript": "^5.0.0"
"#.to_string(),
                explanation: "Upgraded libwebp dependency to 1.3.2, patching the heap buffer overflow vulnerability in WebP rendering.".to_string(),
                patch_status: "Synthesized".to_string(),
            }
        } else if lower_cve.contains("cve-2024") || lower_cve.contains("xss") {
             PatchPayload {
                cve_id: cve_id.to_string(),
                target_file: "src/utils/sanitize.ts".to_string(),
                unified_diff: r#"--- src/utils/sanitize.ts
+++ src/utils/sanitize.ts
@@ -12,7 +12,7 @@
 export function renderUserInput(input: string): string {
     // Legacy unsafe rendering
-    return `<div>${input}</div>`;
+    const DOMPurify = require('dompurify');
+    return `<div>${DOMPurify.sanitize(input)}</div>`;
 }
"#.to_string(),
                explanation: "Injected DOMPurify to sanitize raw user input to prevent Cross-Site Scripting (XSS) payload execution in the DOM renderer.".to_string(),
                patch_status: "Synthesized".to_string(),
            }
        } else {
            // Generic Fallback Patch
            PatchPayload {
                cve_id: cve_id.to_string(),
                target_file: "config/security.yaml".to_string(),
                unified_diff: format!(r#"--- config/security.yaml
+++ config/security.yaml
@@ -8,3 +8,5 @@
   allow_telemetry: true
   # Auto-Remediated Block
+  enforce_strict_parsing: true
+  blocked_cves: ["{}"]
"#, cve_id),
                explanation: format!("Applied generic strict parsing flags for {} to mitigate unknown payload structures.", cve_id),
                patch_status: "Synthesized".to_string(),
            }
        }
    }
}
