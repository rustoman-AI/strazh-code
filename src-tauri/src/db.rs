use rusqlite::{Connection, Result as SqlResult};
use std::path::PathBuf;
use std::sync::Mutex;

/// Wrapper around SQLite connection for Tauri state management
pub struct DbState(pub Mutex<Connection>);

/// Initialize the database: create file, run migrations
pub fn init_db(app_data_dir: PathBuf) -> SqlResult<DbState> {
    std::fs::create_dir_all(&app_data_dir).ok();
    let db_path = app_data_dir.join("pipeline.db");
    let conn = Connection::open(db_path)?;

    // Enable WAL mode for better concurrency
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS pipeline_runs (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            config      TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pipeline_steps (
            id          TEXT PRIMARY KEY,
            run_id      TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
            step_name   TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            command     TEXT,
            exit_code   INTEGER,
            stdout      TEXT,
            stderr      TEXT,
            started_at  TEXT,
            finished_at TEXT
        );

        CREATE TABLE IF NOT EXISTS pipeline_artifacts (
            id          TEXT PRIMARY KEY,
            run_id      TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
            step_id     TEXT REFERENCES pipeline_steps(id) ON DELETE SET NULL,
            file_path   TEXT NOT NULL,
            file_type   TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_steps_run_id ON pipeline_steps(run_id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON pipeline_artifacts(run_id);
        ",
    )?;

    // Enable foreign keys
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    Ok(DbState(Mutex::new(conn)))
}
