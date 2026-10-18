use crate::engine::memory::snapshot::SnapshotNode;
use chrono::{DateTime, Utc};

/// Default half-life in days for time-decay scoring.
const DEFAULT_HALF_LIFE_DAYS: f64 = 14.0;

/// Apply exponential time decay to a graph's node relevance scores.
///
/// Nodes with `requires_approval = true` (SOP Nodes) or `Agent`-triggered overrides
/// can be treated as 'Core' (evergreen) and exempt from decay if needed, but for now 
/// we decay all nodes based on their last `end_time`.
pub fn apply_relevance_decay(nodes: &mut Vec<SnapshotNode>, half_life_days: f64) {
    let half_life = if half_life_days <= 0.0 {
        DEFAULT_HALF_LIFE_DAYS
    } else {
        half_life_days
    };

    let now = Utc::now();

    for state in nodes.iter_mut() {
        if let Some(end_time_ms) = state.end_time {
            // Convert epoch ms to DateTime
            if let Some(ts) = DateTime::from_timestamp(end_time_ms as i64 / 1000, 0) {
                let ts = ts.with_timezone(&Utc);
                let age_days = now.signed_duration_since(ts).num_seconds().max(0) as f64 / 86_400.0;
                let decay_factor = (-age_days / half_life * std::f64::consts::LN_2).exp();
                
                // Exempt evergreen nodes (SOP config nodes manually approved) 
                if !state.requires_approval {
                    state.relevance_score *= decay_factor;
                }
            }
        }
    }
}
