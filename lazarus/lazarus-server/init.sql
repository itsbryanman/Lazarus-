PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os_info TEXT,
    last_seen INTEGER,
    status TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    agent_id TEXT,
    repository_path TEXT NOT NULL,
    source_paths TEXT NOT NULL,
    parameters TEXT NOT NULL,
    scheduled_time INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    status TEXT NOT NULL,
    error_message TEXT,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    schedule_cron TEXT,
    last_run INTEGER,
    next_run INTEGER,
    state TEXT,
    FOREIGN KEY(agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS job_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT,
    start_time INTEGER,
    end_time INTEGER,
    status TEXT,
    logs TEXT,
    FOREIGN KEY(job_id) REFERENCES jobs(id)
);
