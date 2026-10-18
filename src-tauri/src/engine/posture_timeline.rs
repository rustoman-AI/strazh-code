use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostureSnapshot {
    pub date: String,
    pub total_cves: u32,
    pub critical_cves: u32,
    pub compliance_score: f64,
    pub sbom_completeness: f64,
    pub mttr_hours: f64,
    pub active_threats: u32,
}

pub struct PostureTimeline;

impl PostureTimeline {
    pub fn get_snapshots() -> Vec<PostureSnapshot> {
        let mut snapshots = Vec::new();

        let mut cves: f64 = 45.0;
        let mut critical: f64 = 12.0;
        let mut compliance: f64 = 62.0;
        let mut sbom: f64 = 71.0;
        let mut mttr: f64 = 96.0;
        let mut threats: f64 = 18.0;

        for day in 0..30 {
            let date = format!("2024-{:02}-{:02}",
                if day < 20 { 11 } else { 12 },
                if day < 20 { day + 10 } else { day - 19 }
            );

            cves += (rand::random::<f64>() * 5.0) - 3.0; // [-3.0, 2.0]
            cves = cves.max(8.0).min(55.0);

            critical += (rand::random::<f64>() * 3.0) - 2.0; // [-2.0, 1.0]
            critical = critical.max(1.0).min(cves * 0.4);

            compliance += (rand::random::<f64>() * 4.0) - 1.0; // [-1.0, 3.0]
            compliance = compliance.max(50.0).min(98.0);

            sbom += (rand::random::<f64>() * 3.0) - 0.5; // [-0.5, 2.5]
            sbom = sbom.max(60.0).min(99.0);

            mttr += (rand::random::<f64>() * 6.0) - 4.0; // [-4.0, 2.0]
            mttr = mttr.max(12.0).min(120.0);

            threats += (rand::random::<f64>() * 5.5) - 3.0; // [-3.0, 2.5]
            threats = threats.max(2.0).min(25.0);

            snapshots.push(PostureSnapshot {
                date,
                total_cves: cves as u32,
                critical_cves: critical as u32,
                compliance_score: (compliance * 10.0).round() / 10.0,
                sbom_completeness: (sbom * 10.0).round() / 10.0,
                mttr_hours: (mttr * 10.0).round() / 10.0,
                active_threats: threats as u32,
            });
        }

        snapshots
    }
}
