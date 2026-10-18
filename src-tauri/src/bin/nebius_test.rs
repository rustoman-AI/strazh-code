//! Live proof that Strazh talks to NVIDIA Nemotron on Nebius Token Factory.
//!
//! Run with:
//!   NEBIUS_API_KEY=... cargo run --bin nebius_test
//!
//! The API key is read from the environment only. It is never printed.

use cyclonedx_tauri_ui_lib::nebius_client::{NebiusClient, ScanRequest};
use dotenvy::dotenv;

#[tokio::main]
async fn main() {
    dotenv().ok(); // Load .env if present (NEBIUS_API_KEY lives there, gitignored).

    println!("Strazh -> Nebius Token Factory (NVIDIA Nemotron) live check");
    // Report only whether the key is present. Never print the value.
    match std::env::var("NEBIUS_API_KEY") {
        Ok(k) if !k.trim().is_empty() => println!("NEBIUS_API_KEY: present"),
        _ => {
            eprintln!("NEBIUS_API_KEY: missing — set it in the environment and retry.");
            std::process::exit(1);
        }
    }

    let client = match NebiusClient::new().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to build Nebius client: {}", e);
            std::process::exit(1);
        }
    };

    println!("Model: {}", client.model());
    println!("Sending a test security-scan prompt to Nemotron...\n");

    let req = ScanRequest {
        intent: "terminal_command".to_string(),
        payload: "rm -rf / --no-preserve-root".to_string(),
    };

    match client.scan(req).await {
        Ok(resp) => {
            println!("✅ SUCCESS: Nemotron responded via Nebius Token Factory.");
            println!("Risk: {}", resp.risk);
            println!("--- analysis ---\n{}", resp.analysis);
        }
        Err(e) => {
            eprintln!("❌ FAILED: {}", e);
            // If the model id was rejected, help the user find a valid one.
            if let Ok(models) = client.list_models().await {
                let nemotron: Vec<_> = models
                    .iter()
                    .filter(|m| m.to_lowercase().contains("nemotron"))
                    .collect();
                if !nemotron.is_empty() {
                    eprintln!("\nAvailable NVIDIA Nemotron models on your account:");
                    for m in nemotron {
                        eprintln!("  {}", m);
                    }
                    eprintln!("\nSet NEBIUS_MODEL=<one of the above> and retry.");
                }
            }
            std::process::exit(1);
        }
    }
}
