//! Nebius Token Factory client — NVIDIA Nemotron inference.
//!
//! Replaces the previous Amazon Nova client. All model calls go to
//! Nebius Token Factory's OpenAI-compatible endpoint:
//!   https://api.tokenfactory.nebius.com/v1
//! using an NVIDIA Nemotron model.
//!
//! The API key is read from the `NEBIUS_API_KEY` environment variable ONLY.
//! It is never hardcoded, logged, printed, or echoed anywhere in this crate.

use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};

/// Default Nebius Token Factory base URL (OpenAI-compatible).
const DEFAULT_BASE_URL: &str = "https://api.tokenfactory.nebius.com/v1";

/// Default NVIDIA Nemotron model served on Nebius Token Factory.
/// Override with the `NEBIUS_MODEL` environment variable if your account
/// exposes a different Nemotron id (run `cargo run --bin nebius_test` to
/// confirm, or list models at `{base_url}/models`).
const DEFAULT_MODEL: &str = "nvidia/Nemotron-3_5-Lightning";

#[derive(Serialize)]
pub struct ScanRequest {
    pub intent: String,
    pub payload: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ScanResponse {
    pub risk: String,
    pub analysis: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ReviewResponse {
    pub status: String,
    pub feedback: String,
}

/// Client for NVIDIA Nemotron models hosted on Nebius Token Factory.
pub struct NebiusClient {
    client: Client,
    endpoint: String,
    model: String,
}

impl NebiusClient {
    /// Build a client from the environment.
    ///
    /// Required: `NEBIUS_API_KEY`.
    /// Optional: `NEBIUS_BASE_URL` (defaults to the public Token Factory URL),
    ///           `NEBIUS_MODEL`    (defaults to an NVIDIA Nemotron model).
    ///
    /// Returns an error when `NEBIUS_API_KEY` is missing so callers can decide
    /// how to degrade. The key value itself is never included in any error.
    pub async fn new() -> Result<Self> {
        let api_key = std::env::var("NEBIUS_API_KEY")
            .map_err(|_| anyhow::anyhow!("NEBIUS_API_KEY is not set in the environment"))?;

        if api_key.trim().is_empty() {
            return Err(anyhow::anyhow!("NEBIUS_API_KEY is set but empty"));
        }

        let base_url =
            std::env::var("NEBIUS_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        let model = std::env::var("NEBIUS_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth_val = format!("Bearer {}", api_key);
        let mut auth_header = HeaderValue::from_str(&auth_val)
            .map_err(|_| anyhow::anyhow!("NEBIUS_API_KEY contains invalid characters"))?;
        // Mark the credential as sensitive so reqwest/tracing never logs it.
        auth_header.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_header);

        let client = Client::builder().default_headers(headers).build()?;

        let endpoint = format!("{}/chat/completions", base_url.trim_end_matches('/'));

        Ok(Self {
            client,
            endpoint,
            model,
        })
    }

    /// The model id in use (safe to display — contains no secrets).
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Low-level chat completion against Nemotron. Returns assistant text.
    async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user", "content": user_prompt }
            ],
            "temperature": 0.1
        });

        let response = self.client.post(&self.endpoint).json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Nebius Token Factory API error {}: {}",
                status,
                err_text
            ));
        }

        let parsed: serde_json::Value = response.json().await?;
        let content = parsed["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Unexpected response shape from Nebius Token Factory"))?
            .to_string();

        Ok(content)
    }

    /// List model ids available to this account (GET {base}/models).
    /// Useful to discover the exact Nemotron id if the default is rejected.
    pub async fn list_models(&self) -> Result<Vec<String>> {
        let url = self.endpoint.replace("/chat/completions", "/models");
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("models list error {}: {}", status, body));
        }
        let parsed: serde_json::Value = resp.json().await?;
        let ids = parsed["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(ids)
    }

    /// Classify the security risk of an intent/payload using Nemotron.
    pub async fn scan(&self, req: ScanRequest) -> Result<ScanResponse> {
        let system_prompt = "You are an expert cybersecurity analyst acting as a security gate \
            for a software supply-chain scanner. Evaluate the given intent and payload for \
            security risk. Your response MUST contain one of 'Risk Level: HIGH', \
            'Risk Level: MEDIUM', or 'Risk Level: LOW'. Provide a detailed analysis including \
            the likely attack path and what the payload attempts to do.";

        let user_prompt = format!(
            "Intent: {}\nPayload:\n{}\n\nClassify the risk (LOW | MEDIUM | HIGH) and explain the \
             specific reasoning, potential attack paths, and the impact.",
            req.intent, req.payload
        );

        let analysis_text = self.complete(system_prompt, &user_prompt).await?;

        Ok(ScanResponse {
            risk: extract_risk(&analysis_text),
            analysis: analysis_text,
        })
    }

    /// Ask Nemotron to review a proposed patch against the original code.
    pub async fn review_code(
        &self,
        original_code: &str,
        patched_code: &str,
    ) -> Result<ReviewResponse> {
        let system_prompt = "You are an elite security auditor and code reviewer. Rigorously \
            review patches produced by another model. Find any flaws, logic bombs, or \
            regressions. Begin your response with either APPROVED or REJECTED.";

        let user_prompt = format!(
            "Compare the original code and the patched code.\n\nOriginal Code:\n{}\n\nPatched \
             Code:\n{}\n\nDoes the patched code introduce any secondary vulnerabilities or fail \
             to fix the original issue? Respond with 'APPROVED' if it is correct, or 'REJECTED' \
             with an explanation if it is flawed.",
            original_code, patched_code
        );

        let feedback_text = self.complete(system_prompt, &user_prompt).await?;
        let feedback_text = feedback_text.trim().to_string();

        let status = if feedback_text.to_uppercase().contains("REJECTED") {
            "REJECTED".to_string()
        } else {
            "APPROVED".to_string()
        };

        Ok(ReviewResponse {
            status,
            feedback: feedback_text,
        })
    }

    /// Generate a concrete fix for a detected attack path.
    ///
    /// Returns the raw Nemotron text (expected to contain a code fix plus a
    /// short explanation). Parsing is left to the caller.
    pub async fn generate_fix(
        &self,
        vuln_id: &str,
        entry_point: &str,
        target_component: &str,
        proof_chain: &[String],
        source_excerpt: &str,
    ) -> Result<String> {
        let system_prompt = "You are a senior application-security engineer. Given a concrete \
            attack path discovered by a supply-chain scanner, write a minimal, correct fix. \
            Respond in Markdown with two sections: '## Root cause' (2-3 sentences) and \
            '## Fix' (a fenced code block containing only the patched code). Keep it concise.";

        let chain = if proof_chain.is_empty() {
            "(no intermediate hops reported)".to_string()
        } else {
            proof_chain.join("  ->  ")
        };

        let user_prompt = format!(
            "Vulnerability: {vuln}\nEntry point: {entry}\nTarget component: {target}\nAttack path: \
             {chain}\n\nRelevant source context:\n{src}\n\nWrite the fix.",
            vuln = vuln_id,
            entry = entry_point,
            target = target_component,
            chain = chain,
            src = if source_excerpt.is_empty() {
                "(source not available; reason from the attack path and component)"
            } else {
                source_excerpt
            },
        );

        self.complete(system_prompt, &user_prompt).await
    }
}

fn extract_risk(text: &str) -> String {
    let upper = text.to_uppercase();
    if upper.contains("RISK LEVEL: HIGH") || upper.contains("HIGH") {
        "HIGH".into()
    } else if upper.contains("RISK LEVEL: MEDIUM") || upper.contains("MEDIUM") {
        "MEDIUM".into()
    } else {
        "LOW".into()
    }
}
