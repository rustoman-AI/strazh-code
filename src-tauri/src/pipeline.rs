use crate::db::DbState;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

// ══════════════════════════════════════════════════════
//  Types
// ══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineRun {
    pub id: String,
    pub name: String,
    pub status: String,
    pub config: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub step_count: i32,
    pub steps_done: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineStep {
    pub id: String,
    pub run_id: String,
    pub step_name: String,
    pub status: String,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineArtifact {
    pub id: String,
    pub run_id: String,
    pub step_id: Option<String>,
    pub file_path: String,
    pub file_type: Option<String>,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineRunDetail {
    pub run: PipelineRun,
    pub steps: Vec<PipelineStep>,
    pub artifacts: Vec<PipelineArtifact>,
}

fn now_iso() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple ISO-like format without chrono dependency
    format!("{}", now)
}

// ══════════════════════════════════════════════════════
//  1. Create pipeline run
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn pipeline_create(
    db: State<'_, DbState>,
    name: String,
    config: Option<String>,
) -> Result<String, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    let id = Uuid::new_v4().to_string();
    let ts = now_iso();

    conn.execute(
        "INSERT INTO pipeline_runs (id, name, status, config, created_at, updated_at) VALUES (?1, ?2, 'running', ?3, ?4, ?5)",
        params![id, name, config, ts, ts],
    ).map_err(|e| e.to_string())?;

    Ok(id)
}

// ══════════════════════════════════════════════════════
//  2. Update pipeline step
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn pipeline_update_step(
    db: State<'_, DbState>,
    run_id: String,
    step_name: String,
    status: String,
    command: Option<String>,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
) -> Result<String, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    let ts = now_iso();

    // Check if step exists
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM pipeline_steps WHERE run_id = ?1 AND step_name = ?2",
            params![run_id, step_name],
            |row| row.get(0),
        )
        .ok();

    let step_id = if let Some(sid) = existing {
        // Update existing step
        conn.execute(
            "UPDATE pipeline_steps SET status = ?1, command = COALESCE(?2, command), exit_code = ?3, stdout = ?4, stderr = ?5, finished_at = CASE WHEN ?1 IN ('done','failed','skipped') THEN ?6 ELSE finished_at END WHERE id = ?7",
            params![status, command, exit_code, stdout, stderr, ts, sid],
        ).map_err(|e| e.to_string())?;
        sid
    } else {
        // Create new step
        let sid = Uuid::new_v4().to_string();
        let started = if status == "running" { Some(&ts) } else { None };
        let finished = if status == "done" || status == "failed" || status == "skipped" {
            Some(&ts)
        } else {
            None
        };
        conn.execute(
            "INSERT INTO pipeline_steps (id, run_id, step_name, status, command, exit_code, stdout, stderr, started_at, finished_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![sid, run_id, step_name, status, command, exit_code, stdout, stderr, started, finished],
        ).map_err(|e| e.to_string())?;
        sid
    };

    // Update run's updated_at and status
    let all_done: bool = conn
        .query_row(
            "SELECT COUNT(*) = 0 FROM pipeline_steps WHERE run_id = ?1 AND status NOT IN ('done','skipped')",
            params![run_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);

    let any_failed: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM pipeline_steps WHERE run_id = ?1 AND status = 'failed'",
            params![run_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);

    let run_status = if any_failed {
        "failed"
    } else if all_done {
        "done"
    } else {
        "running"
    };

    conn.execute(
        "UPDATE pipeline_runs SET status = ?1, updated_at = ?2 WHERE id = ?3",
        params![run_status, ts, run_id],
    )
    .map_err(|e| e.to_string())?;

    Ok(step_id)
}

// ══════════════════════════════════════════════════════
//  3. Add artifact
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn pipeline_add_artifact(
    db: State<'_, DbState>,
    run_id: String,
    step_id: Option<String>,
    file_path: String,
    file_type: Option<String>,
) -> Result<String, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    let id = Uuid::new_v4().to_string();
    let ts = now_iso();

    conn.execute(
        "INSERT INTO pipeline_artifacts (id, run_id, step_id, file_path, file_type, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, run_id, step_id, file_path, file_type, ts],
    ).map_err(|e| e.to_string())?;

    Ok(id)
}

// ══════════════════════════════════════════════════════
//  4. List all runs
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn pipeline_list(db: State<'_, DbState>) -> Result<Vec<PipelineRun>, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT r.id, r.name, r.status, r.config, r.created_at, r.updated_at,
                    (SELECT COUNT(*) FROM pipeline_steps WHERE run_id = r.id) as step_count,
                    (SELECT COUNT(*) FROM pipeline_steps WHERE run_id = r.id AND status IN ('done','skipped')) as steps_done
             FROM pipeline_runs r ORDER BY r.created_at DESC LIMIT 100",
        )
        .map_err(|e| e.to_string())?;

    let runs = stmt
        .query_map([], |row| {
            Ok(PipelineRun {
                id: row.get(0)?,
                name: row.get(1)?,
                status: row.get(2)?,
                config: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                step_count: row.get(6)?,
                steps_done: row.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(runs)
}

// ══════════════════════════════════════════════════════
//  5. Get single run with details
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn pipeline_get(db: State<'_, DbState>, run_id: String) -> Result<PipelineRunDetail, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;

    // Get run
    let run = conn
        .query_row(
            "SELECT r.id, r.name, r.status, r.config, r.created_at, r.updated_at,
                    (SELECT COUNT(*) FROM pipeline_steps WHERE run_id = r.id),
                    (SELECT COUNT(*) FROM pipeline_steps WHERE run_id = r.id AND status IN ('done','skipped'))
             FROM pipeline_runs r WHERE r.id = ?1",
            params![run_id],
            |row| {
                Ok(PipelineRun {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    status: row.get(2)?,
                    config: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    step_count: row.get(6)?,
                    steps_done: row.get(7)?,
                })
            },
        )
        .map_err(|e| e.to_string())?;

    // Get steps
    let mut stmt = conn
        .prepare("SELECT id, run_id, step_name, status, command, exit_code, stdout, stderr, started_at, finished_at FROM pipeline_steps WHERE run_id = ?1 ORDER BY started_at ASC")
        .map_err(|e| e.to_string())?;

    let steps = stmt
        .query_map(params![run_id], |row| {
            Ok(PipelineStep {
                id: row.get(0)?,
                run_id: row.get(1)?,
                step_name: row.get(2)?,
                status: row.get(3)?,
                command: row.get(4)?,
                exit_code: row.get(5)?,
                stdout: row.get(6)?,
                stderr: row.get(7)?,
                started_at: row.get(8)?,
                finished_at: row.get(9)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    // Get artifacts
    let mut stmt = conn
        .prepare("SELECT id, run_id, step_id, file_path, file_type, created_at FROM pipeline_artifacts WHERE run_id = ?1 ORDER BY created_at ASC")
        .map_err(|e| e.to_string())?;

    let artifacts = stmt
        .query_map(params![run_id], |row| {
            Ok(PipelineArtifact {
                id: row.get(0)?,
                run_id: row.get(1)?,
                step_id: row.get(2)?,
                file_path: row.get(3)?,
                file_type: row.get(4)?,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(PipelineRunDetail {
        run,
        steps,
        artifacts,
    })
}

// ══════════════════════════════════════════════════════
//  6. Delete run (cascade deletes steps + artifacts)
// ══════════════════════════════════════════════════════

#[tauri::command]
pub fn pipeline_delete(db: State<'_, DbState>, run_id: String) -> Result<(), String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;

    // Manual cascade since SQLite FK cascade might not fire with execute
    conn.execute("DELETE FROM pipeline_artifacts WHERE run_id = ?1", params![run_id])
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM pipeline_steps WHERE run_id = ?1", params![run_id])
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM pipeline_runs WHERE id = ?1", params![run_id])
        .map_err(|e| e.to_string())?;

    Ok(())
}
