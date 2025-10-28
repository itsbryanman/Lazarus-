use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobType {
    Backup,
    Restore,
    Verify,
    Prune,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Assigned,
    InProgress,
    Completed,
    Failed,
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
    jobs: Arc<RwLock<HashMap<String, Job>>>,
}

impl JobScheduler {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn schedule_job(
        &self,
        job_type: JobType,
        repository_path: String,
        source_paths: Vec<String>,
        parameters: HashMap<String, String>,
        scheduled_time: DateTime<Utc>,
    ) -> String {
        let mut jobs = self.jobs.write().await;

        let job_id = Uuid::new_v4().to_string();
        let job = Job {
            job_id: job_id.clone(),
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

        jobs.insert(job_id.clone(), job);
        job_id
    }

    pub async fn get_pending_jobs_for_agent(&self, agent_id: &str) -> Vec<Job> {
        let mut jobs = self.jobs.write().await;
        let now = Utc::now();

        let mut pending_jobs = Vec::new();

        for job in jobs.values_mut() {
            if job.status == JobStatus::Pending && job.scheduled_time <= now {
                job.status = JobStatus::Assigned;
                job.agent_id = Some(agent_id.to_string());
                pending_jobs.push(job.clone());
            }
        }

        pending_jobs
    }

    pub async fn start_job(&self, job_id: &str, agent_id: &str) -> Result<(), String> {
        let mut jobs = self.jobs.write().await;

        if let Some(job) = jobs.get_mut(job_id) {
            if job.agent_id.as_ref() == Some(&agent_id.to_string()) {
                job.status = JobStatus::InProgress;
                job.started_at = Some(Utc::now());
                Ok(())
            } else {
                Err("Job not assigned to this agent".to_string())
            }
        } else {
            Err(format!("Job {} not found", job_id))
        }
    }

    pub async fn update_progress(&self, job_id: &str, progress_percent: i32) -> Result<(), String> {
        let mut jobs = self.jobs.write().await;

        if let Some(job) = jobs.get_mut(job_id) {
            job.progress_percent = progress_percent;
            Ok(())
        } else {
            Err(format!("Job {} not found", job_id))
        }
    }

    pub async fn complete_job(
        &self,
        job_id: &str,
        success: bool,
        error_message: Option<String>,
    ) -> Result<(), String> {
        let mut jobs = self.jobs.write().await;

        if let Some(job) = jobs.get_mut(job_id) {
            job.status = if success { JobStatus::Completed } else { JobStatus::Failed };
            job.completed_at = Some(Utc::now());
            job.error_message = error_message;
            Ok(())
        } else {
            Err(format!("Job {} not found", job_id))
        }
    }

    pub async fn get_job(&self, job_id: &str) -> Option<Job> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).cloned()
    }

    pub async fn list_jobs(&self) -> Vec<Job> {
        let jobs = self.jobs.read().await;
        jobs.values().cloned().collect()
    }

    /// Run the scheduler loop
    pub async fn run(&self) {
        info!("Job scheduler started");
        let mut ticker = interval(Duration::from_secs(30));

        loop {
            ticker.tick().await;
            self.check_stale_jobs().await;
        }
    }

    async fn check_stale_jobs(&self) {
        let mut jobs = self.jobs.write().await;
        let now = Utc::now();
        let timeout = chrono::Duration::hours(24);

        for job in jobs.values_mut() {
            if job.status == JobStatus::InProgress {
                if let Some(started_at) = job.started_at {
                    if now.signed_duration_since(started_at) > timeout {
                        warn!("Job {} timed out after 24 hours", job.job_id);
                        job.status = JobStatus::Failed;
                        job.error_message = Some("Job timed out".to_string());
                        job.completed_at = Some(now);
                    }
                }
            }
        }
    }
}
