use chrono::{DateTime, TimeZone, Utc};
use cron::Schedule;
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::task;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

const INIT_SQL: &str = include_str!("../init.sql");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobType {
    Backup,
    Restore,
    Verify,
    Prune,
}

impl JobType {
    fn as_str(&self) -> &'static str {
        match self {
            JobType::Backup => "Backup",
            JobType::Restore => "Restore",
            JobType::Verify => "Verify",
            JobType::Prune => "Prune",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "Backup" => Some(JobType::Backup),
            "Restore" => Some(JobType::Restore),
            "Verify" => Some(JobType::Verify),
            "Prune" => Some(JobType::Prune),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Assigned,
    InProgress,
    Completed,
    Failed,
}

impl JobStatus {
    fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Pending => "Pending",
            JobStatus::Assigned => "Assigned",
            JobStatus::InProgress => "InProgress",
            JobStatus::Completed => "Completed",
            JobStatus::Failed => "Failed",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "Pending" => Some(JobStatus::Pending),
            "Assigned" => Some(JobStatus::Assigned),
            "InProgress" => Some(JobStatus::InProgress),
            "Completed" => Some(JobStatus::Completed),
            "Failed" => Some(JobStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub job_type: JobType,
    pub agent_id: Option<String>,
    pub repository_path: String,
    pub source_paths: Vec<String>,
    pub parameters: HashMap<String, String>,
    pub scheduled_time: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: JobStatus,
    pub error_message: Option<String>,
    pub progress_percent: i32,
}

#[derive(Clone)]
pub struct JobScheduler {
    db_path: Arc<PathBuf>,
}

impl JobScheduler {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, JobSchedulerError> {
        let path = db_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&path)?;
        Self::configure_connection(&conn)?;
        conn.execute_batch(INIT_SQL)?;

        Ok(Self {
            db_path: Arc::new(path),
        })
    }

    fn configure_connection(conn: &Connection) -> rusqlite::Result<()> {
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        conn.pragma_update(None, "synchronous", &"NORMAL")?;
        Ok(())
    }

    fn open_connection(path: &Path) -> rusqlite::Result<Connection> {
        let conn = Connection::open(path)?;
        Self::configure_connection(&conn)?;
        Ok(conn)
    }

    #[allow(dead_code)]
    pub async fn schedule_job(
        &self,
        job_type: JobType,
        repository_path: String,
        source_paths: Vec<String>,
        parameters: HashMap<String, String>,
        scheduled_time: DateTime<Utc>,
    ) -> Result<String, String> {
        let db_path = self.db_path.clone();
        let job = Job {
            job_id: Uuid::new_v4().to_string(),
            job_type,
            agent_id: None,
            repository_path,
            source_paths,
            parameters,
            scheduled_time,
            started_at: None,
            completed_at: None,
            status: JobStatus::Pending,
            error_message: None,
            progress_percent: 0,
        };

        task::spawn_blocking(move || {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            Self::insert_job(&conn, &job).map_err(|e| e.to_string())?;
            Ok(job.job_id.clone())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    fn insert_job(conn: &Connection, job: &Job) -> rusqlite::Result<()> {
        let source_paths_json = serde_json::to_string(&job.source_paths)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        let parameters_json = serde_json::to_string(&job.parameters)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;

        conn.execute(
            "INSERT INTO jobs (
                id,
                type,
                agent_id,
                repository_path,
                source_paths,
                parameters,
                scheduled_time,
                started_at,
                completed_at,
                status,
                error_message,
                progress_percent
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                job.job_id,
                job.job_type.as_str(),
                job.agent_id.as_deref(),
                job.repository_path,
                source_paths_json,
                parameters_json,
                job.scheduled_time.timestamp(),
                job.started_at.map(|ts| ts.timestamp()),
                job.completed_at.map(|ts| ts.timestamp()),
                job.status.as_str(),
                job.error_message.as_deref(),
                job.progress_percent,
            ],
        )?;

        Ok(())
    }

    pub async fn get_pending_jobs_for_agent(&self, agent_id: &str) -> Vec<Job> {
        let agent = agent_id.to_string();
        let db_path = self.db_path.clone();

        match task::spawn_blocking(move || {
            let mut conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let now = Utc::now().timestamp();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| e.to_string())?;

            let mut jobs = Vec::new();
            {
                let mut stmt = tx
                    .prepare(
                        "SELECT id, type, agent_id, repository_path, source_paths, parameters, scheduled_time, \
                         started_at, completed_at, status, error_message, progress_percent FROM jobs \
                         WHERE status = ?1 AND scheduled_time <= ?2 ORDER BY scheduled_time ASC",
                    )
                    .map_err(|e| e.to_string())?;

                let mut rows = stmt
                    .query(params![JobStatus::Pending.as_str(), now])
                    .map_err(|e| e.to_string())?;

                loop {
                    match rows.next().map_err(|e| e.to_string())? {
                        Some(row) => {
                            let mut job = Self::job_from_row(&row).map_err(|e| e.to_string())?;
                            let updated = tx
                                .execute(
                                    "UPDATE jobs SET status = ?, agent_id = ? WHERE id = ? AND status = ?",
                                    params![
                                        JobStatus::Assigned.as_str(),
                                        agent.as_str(),
                                        job.job_id.as_str(),
                                        JobStatus::Pending.as_str()
                                    ],
                                )
                                .map_err(|e| e.to_string())?;

                            if updated == 1 {
                                job.status = JobStatus::Assigned;
                                job.agent_id = Some(agent.clone());
                                jobs.push(job);
                            }
                        }
                        None => break,
                    }
                }
            }
            tx.commit().map_err(|e| e.to_string())?;
            Ok::<Vec<Job>, String>(jobs)
        })
        .await
        {
            Ok(Ok(jobs)) => jobs,
            Ok(Err(err)) => {
                error!("Failed to fetch pending jobs: {}", err);
                Vec::new()
            }
            Err(err) => {
                error!("Failed to join pending job task: {}", err);
                Vec::new()
            }
        }
    }

    pub async fn start_job(&self, job_id: &str, agent_id: &str) -> Result<(), String> {
        let job_id_owned = job_id.to_string();
        let agent_owned = agent_id.to_string();
        let db_path = self.db_path.clone();

        task::spawn_blocking(move || {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let rows = conn
                .execute(
                    "UPDATE jobs SET status = ?, started_at = ?, agent_id = ? WHERE id = ? AND agent_id = ?",
                    params![
                        JobStatus::InProgress.as_str(),
                        Utc::now().timestamp(),
                        agent_owned.as_str(),
                        job_id_owned.as_str(),
                        agent_owned.as_str()
                    ],
                )
                .map_err(|e| e.to_string())?;

            if rows == 1 {
                Ok(())
            } else {
                Err("Job not assigned to this agent".to_string())
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn update_progress(&self, job_id: &str, progress_percent: i32) -> Result<(), String> {
        let job_id_owned = job_id.to_string();
        let db_path = self.db_path.clone();

        task::spawn_blocking(move || {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let rows = conn
                .execute(
                    "UPDATE jobs SET progress_percent = ?1 WHERE id = ?2",
                    params![progress_percent, job_id_owned.as_str()],
                )
                .map_err(|e| e.to_string())?;

            if rows == 1 {
                Ok(())
            } else {
                Err(format!("Job {} not found", job_id_owned))
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn complete_job(
        &self,
        job_id: &str,
        success: bool,
        error_message: Option<String>,
    ) -> Result<(), String> {
        let job_id_owned = job_id.to_string();
        let error_copy = error_message.clone();
        let db_path = self.db_path.clone();

        task::spawn_blocking(move || {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let status = if success {
                JobStatus::Completed
            } else {
                JobStatus::Failed
            };

            let rows = conn
                .execute(
                    "UPDATE jobs SET status = ?, completed_at = ?, error_message = ? WHERE id = ?",
                    params![
                        status.as_str(),
                        Utc::now().timestamp(),
                        error_copy.as_deref(),
                        job_id_owned.as_str()
                    ],
                )
                .map_err(|e| e.to_string())?;

            if rows == 1 {
                Ok(())
            } else {
                Err(format!("Job {} not found", job_id_owned))
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    #[allow(dead_code)]
    pub async fn get_job(&self, job_id: &str) -> Option<Job> {
        let job_id_owned = job_id.to_string();
        let job_id_for_log = job_id_owned.clone();
        let db_path = self.db_path.clone();

        match task::spawn_blocking(move || -> Result<Option<Job>, String> {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare("SELECT id, type, agent_id, repository_path, source_paths, parameters, scheduled_time, started_at, completed_at, status, error_message, progress_percent FROM jobs WHERE id = ?1")
                .map_err(|e| e.to_string())?;

            let job = stmt
                .query_row(params![job_id_owned.as_str()], |row| Self::job_from_row(row))
                .optional()
                .map_err(|e| e.to_string())?;

            Ok(job)
        })
        .await
        {
            Ok(Ok(job)) => job,
            Ok(Err(err)) => {
                error!("Failed to get job {}: {}", job_id_for_log, err);
                None
            }
            Err(err) => {
                error!("Failed to join job lookup task: {}", err);
                None
            }
        }
    }

    #[allow(dead_code)]
    pub async fn list_jobs(&self) -> Vec<Job> {
        let db_path = self.db_path.clone();

        match task::spawn_blocking(move || -> Result<Vec<Job>, String> {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare("SELECT id, type, agent_id, repository_path, source_paths, parameters, scheduled_time, started_at, completed_at, status, error_message, progress_percent FROM jobs")
                .map_err(|e| e.to_string())?;
            let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
            let mut jobs = Vec::new();

            loop {
                match rows.next().map_err(|e| e.to_string())? {
                    Some(row) => jobs.push(Self::job_from_row(&row).map_err(|e| e.to_string())?),
                    None => break,
                }
            }

            Ok::<Vec<Job>, String>(jobs)
        })
        .await
        {
            Ok(Ok(jobs)) => jobs,
            Ok(Err(err)) => {
                error!("Failed to list jobs: {}", err);
                Vec::new()
            }
            Err(err) => {
                error!("Failed to join job list task: {}", err);
                Vec::new()
            }
        }
    }

    /// Run the scheduler loop
    pub async fn run(&self) {
        info!("Job scheduler started");
        let mut ticker = interval(Duration::from_secs(30));

        loop {
            ticker.tick().await;
            self.check_stale_jobs().await;
            self.run_cron_schedules().await;
        }
    }

    async fn run_cron_schedules(&self) {
        let db_path = self.db_path.clone();
        match task::spawn_blocking(move || {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let now = Utc::now().timestamp();
            let mut stmt = conn
                .prepare(
                    "SELECT id, type, agent_id, repository_path, source_paths, parameters, scheduled_time, \
                     started_at, completed_at, status, error_message, progress_percent, schedule_cron, last_run, next_run \
                     FROM jobs WHERE schedule_cron IS NOT NULL",
                )
                .map_err(|e| e.to_string())?;
            let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
            let mut created = 0;

            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let job = Self::job_from_row(&row).map_err(|e| e.to_string())?;
                let cron_expr: Option<String> = row
                    .get::<_, Option<String>>("schedule_cron")
                    .map_err(|e| e.to_string())?;
                let next_run_value: Option<i64> = row
                    .get::<_, Option<i64>>("next_run")
                    .map_err(|e| e.to_string())?;
                let job_id: String = row.get("id").map_err(|e| e.to_string())?;

                let cron_expr = match cron_expr {
                    Some(expr) => expr,
                    None => continue,
                };

                let schedule = match Schedule::from_str(&cron_expr) {
                    Ok(s) => s,
                    Err(err) => {
                        warn!("Invalid cron expression for job {}: {}", job_id, err);
                        continue;
                    }
                };

                let next_run_ts = next_run_value.unwrap_or_else(|| {
                    schedule
                        .upcoming(Utc)
                        .next()
                        .map(|dt| dt.timestamp())
                        .unwrap_or_else(|| now + 60)
                });

                if next_run_value.is_none() {
                    conn.execute(
                        "UPDATE jobs SET next_run = ? WHERE id = ?",
                        params![next_run_ts, job_id],
                    )
                    .map_err(|e| e.to_string())?;
                }

                if now >= next_run_ts {
                    let next_after = schedule
                        .upcoming(Utc)
                        .skip_while(|dt| dt.timestamp() <= next_run_ts)
                        .next()
                        .map(|dt| dt.timestamp())
                        .unwrap_or(next_run_ts + 60);

                    let new_job_id = Uuid::new_v4().to_string();
                    let parameters_json = serde_json::to_string(&job.parameters)
                        .map_err(|e| e.to_string())?;
                    let source_paths_json = serde_json::to_string(&job.source_paths)
                        .map_err(|e| e.to_string())?;

                    conn.execute(
                        "INSERT INTO jobs (id, type, repository_path, source_paths, parameters, scheduled_time, status, progress_percent) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                        params![
                            new_job_id,
                            job.job_type.as_str(),
                            job.repository_path,
                            source_paths_json,
                            parameters_json,
                            now,
                            JobStatus::Pending.as_str(),
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    created += 1;

                    conn.execute(
                        "UPDATE jobs SET last_run = ?, next_run = ? WHERE id = ?",
                        params![now, next_after, job_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }

            if created > 0 {
                info!("Scheduled {} job(s) based on cron triggers", created);
            }

            Ok::<(), String>(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("Cron scheduling failed: {}", err),
            Err(join_err) => error!("Cron scheduling task join error: {}", join_err),
        }
    }

    async fn check_stale_jobs(&self) {
        let db_path = self.db_path.clone();
        match task::spawn_blocking(move || {
            let conn = Self::open_connection(db_path.as_ref()).map_err(|e| e.to_string())?;
            let cutoff = (Utc::now() - chrono::Duration::hours(24)).timestamp();
            let now = Utc::now().timestamp();

            let affected = conn
                .execute(
                    "UPDATE jobs SET status = ?, error_message = ?, completed_at = ? WHERE status = ? AND started_at IS NOT NULL AND started_at <= ?",
                    params![
                        JobStatus::Failed.as_str(),
                        "Job timed out",
                        now,
                        JobStatus::InProgress.as_str(),
                        cutoff
                    ],
                )
                .map_err(|e| e.to_string())?;

            if affected > 0 {
                warn!("Marked {} jobs as timed out", affected);
            }

            Ok::<(), String>(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => error!("Failed to mark stale jobs: {}", msg),
            Err(join_err) => error!("Failed to join stale job task: {}", join_err),
        }
    }

    fn job_from_row(row: &Row<'_>) -> rusqlite::Result<Job> {
        let job_id: String = row.get("id")?;
        let job_type_raw: String = row.get("type")?;
        let job_type = JobType::from_str(&job_type_raw).ok_or_else(|| {
            Self::conversion_error(row, "type", format!("unknown job type: {}", job_type_raw))
        })?;
        let agent_id: Option<String> = row.get("agent_id")?;
        let repository_path: String = row.get("repository_path")?;

        let source_paths_json: String = row.get("source_paths")?;
        let source_paths: Vec<String> = serde_json::from_str(&source_paths_json)
            .map_err(|err| Self::conversion_error(row, "source_paths", err.to_string()))?;

        let parameters_json: String = row.get("parameters")?;
        let parameters: HashMap<String, String> = serde_json::from_str(&parameters_json)
            .map_err(|err| Self::conversion_error(row, "parameters", err.to_string()))?;

        let scheduled_time: i64 = row.get("scheduled_time")?;
        let started_at: Option<i64> = row.get("started_at")?;
        let completed_at: Option<i64> = row.get("completed_at")?;
        let status_raw: String = row.get("status")?;
        let status = JobStatus::from_str(&status_raw).ok_or_else(|| {
            Self::conversion_error(row, "status", format!("unknown status: {}", status_raw))
        })?;
        let error_message: Option<String> = row.get("error_message")?;
        let progress_percent: i32 = row.get("progress_percent")?;

        Ok(Job {
            job_id,
            job_type,
            agent_id,
            repository_path,
            source_paths,
            parameters,
            scheduled_time: Self::timestamp_to_datetime(scheduled_time),
            started_at: Self::timestamp_to_option(started_at),
            completed_at: Self::timestamp_to_option(completed_at),
            status,
            error_message,
            progress_percent,
        })
    }

    fn timestamp_to_datetime(ts: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(ts, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap())
    }

    fn timestamp_to_option(value: Option<i64>) -> Option<DateTime<Utc>> {
        value.and_then(|ts| Utc.timestamp_opt(ts, 0).single())
    }

    fn conversion_error(row: &Row<'_>, column: &str, message: String) -> rusqlite::Error {
        let idx = row.as_ref().column_index(column).unwrap_or(0);
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, message)),
        )
    }
}

#[derive(Debug)]
pub enum JobSchedulerError {
    Io(io::Error),
    Database(rusqlite::Error),
}

impl fmt::Display for JobSchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobSchedulerError::Io(err) => write!(f, "IO error: {}", err),
            JobSchedulerError::Database(err) => write!(f, "Database error: {}", err),
        }
    }
}

impl std::error::Error for JobSchedulerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JobSchedulerError::Io(err) => Some(err),
            JobSchedulerError::Database(err) => Some(err),
        }
    }
}

impl From<io::Error> for JobSchedulerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for JobSchedulerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}
