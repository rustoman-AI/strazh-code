use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SocOverview {
    pub threat_level: String,
    pub threat_score: f64,
    pub active_alerts: u32,
    pub critical_alerts: u32,
    pub high_alerts: u32,
    pub medium_alerts: u32,
    pub low_alerts: u32,
    pub pipeline_health: f64,
    pub sbom_coverage: f64,
    pub compliance_score: f64,
    pub container_events_sec: u32,
    pub cves_total: u32,
    pub cves_critical: u32,
    pub kev_matches: u32,
    pub mttr_hours: f64,
    pub swarm_bots_active: u32,
    pub recent_alerts: Vec<SocAlert>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SocAlert {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub source: String,
    pub message: String,
}

pub struct SocDashboard;

impl SocDashboard {
    pub fn get_overview() -> SocOverview {
        let critical = rand::random::<u32>() % 4 + 2;
        let high = rand::random::<u32>() % 8 + 4;
        let medium = rand::random::<u32>() % 10 + 10;
        let low = rand::random::<u32>() % 10 + 5;
        let total = critical + high + medium + low;

        let threat_score: f64 = if critical >= 4 { rand::random::<f64>() * 20.0 + 75.0 }
            else if critical >= 2 { rand::random::<f64>() * 20.0 + 55.0 }
            else { rand::random::<f64>() * 30.0 + 25.0 };

        let threat_level = if threat_score >= 75.0 { "CRITICAL" }
            else if threat_score >= 55.0 { "HIGH" }
            else if threat_score >= 35.0 { "MEDIUM" }
            else { "LOW" }.to_string();

        let alert_messages = vec![
            ("CRITICAL", "RUNTIME", "ptrace(PTRACE_ATTACH) syscall intercepted in container auth-svc-9d1e"),
            ("HIGH", "THREAT_INTEL", "CVE-2024-3094 (XZ Utils) matched in SBOM component xz-utils:5.6.0"),
            ("CRITICAL", "RUNTIME", "Data exfiltration: 14MB uploaded to external S3 bucket from api-gateway"),
            ("HIGH", "POSTURE", "Compliance score dropped below 85% threshold"),
            ("MEDIUM", "RUNTIME", "DNS query to suspicious domain crypto-miner-pool.xyz from worker-queue"),
            ("HIGH", "THREAT_INTEL", "CISA KEV alert: CVE-2024-27198 actively exploited in TeamCity"),
            ("CRITICAL", "PIPELINE", "Build provenance attestation failed for artifact sha256:a3b8d1"),
            ("MEDIUM", "SBOM", "3 new transitive dependencies detected without license metadata"),
            ("LOW", "POSTURE", "SBOM completeness decreased from 94% to 91%"),
            ("HIGH", "RUNTIME", "Privilege escalation detected: setuid(0) called by non-root in frontend-web"),
        ];

        let mut recent_alerts = Vec::new();
        for (i, (sev, src, msg)) in alert_messages.iter().enumerate() {
            let offset_sec = rand::random::<u32>() % 60;
            recent_alerts.push(SocAlert {
                id: format!("alert-{:03}", i + 1),
                timestamp: format!("2024-12-09T{:02}:{:02}:{:02}Z",
                    21 - (i / 6), 59 - (i * 5) % 60, offset_sec),
                severity: sev.to_string(),
                source: src.to_string(),
                message: msg.to_string(),
            });
        }

        SocOverview {
            threat_level,
            threat_score: (threat_score * 10.0).round() / 10.0,
            active_alerts: total,
            critical_alerts: critical,
            high_alerts: high,
            medium_alerts: medium,
            low_alerts: low,
            pipeline_health: ((rand::random::<f64>() * 11.0 + 88.0) * 10.0).round() / 10.0,
            sbom_coverage: ((rand::random::<f64>() * 8.0 + 89.0) * 10.0).round() / 10.0,
            compliance_score: ((rand::random::<f64>() * 14.0 + 82.0) * 10.0).round() / 10.0,
            container_events_sec: rand::random::<u32>() % 27 + 8,
            cves_total: rand::random::<u32>() % 22 + 18,
            cves_critical: critical,
            kev_matches: rand::random::<u32>() % 5 + 3,
            mttr_hours: ((rand::random::<f64>() * 45.0 + 20.0) * 10.0).round() / 10.0,
            swarm_bots_active: rand::random::<u32>() % 10 + 10,
            recent_alerts,
        }
    }
}
