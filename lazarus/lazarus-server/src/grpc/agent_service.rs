use crate::agent_manager::{AgentManager, AgentStatus};
use crate::job_scheduler::{JobScheduler, JobType};
use lazarus_common::lazarus::agent::*;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct AgentServiceImpl {
    agent_manager: AgentManager,
    job_scheduler: JobScheduler,
}

impl AgentServiceImpl {
    pub fn new(agent_manager: AgentManager, job_scheduler: JobScheduler) -> Self {
        Self {
            agent_manager,
            job_scheduler,
        }
    }
}

#[tonic::async_trait]
impl agent_service_server::AgentService for AgentServiceImpl {
    async fn register_agent(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        info!("Registering agent: {} ({})", req.agent_id, req.hostname);

        let result = self
            .agent_manager
            .register_agent(
                req.agent_id,
                req.hostname,
                req.os_type,
                req.os_version,
                req.agent_version,
                req.metadata,
            )
            .await;

        match result {
            Ok(_) => Ok(Response::new(RegisterResponse {
                success: true,
                message: "Agent registered successfully".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
            })),
            Err(e) => Ok(Response::new(RegisterResponse {
                success: false,
                message: format!("Failed to register agent: {}", e),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
            })),
        }
    }

    async fn get_jobs(
        &self,
        request: Request<GetJobsRequest>,
    ) -> Result<Response<GetJobsResponse>, Status> {
        let req = request.into_inner();

        let jobs = self
            .job_scheduler
            .get_pending_jobs_for_agent(&req.agent_id)
            .await;

        let proto_jobs: Vec<Job> = jobs
            .into_iter()
            .map(|j| {
                let job_type = match j.job_type {
                    crate::job_scheduler::JobType::Backup => JobType::Backup as i32,
                    crate::job_scheduler::JobType::Restore => JobType::Restore as i32,
                    crate::job_scheduler::JobType::Verify => JobType::Verify as i32,
                    crate::job_scheduler::JobType::Prune => JobType::Prune as i32,
                };

                Job {
                    job_id: j.job_id,
                    job_type,
                    repository_path: j.repository_path,
                    source_paths: j.source_paths,
                    parameters: j.parameters,
                    scheduled_time: j.scheduled_time.timestamp(),
                }
            })
            .collect();

        Ok(Response::new(GetJobsResponse { jobs: proto_jobs }))
    }

    async fn start_job(
        &self,
        request: Request<JobStartRequest>,
    ) -> Result<Response<JobStartResponse>, Status> {
        let req = request.into_inner();

        info!("Starting job: {} for agent: {}", req.job_id, req.agent_id);

        let result = self
            .job_scheduler
            .start_job(&req.job_id, &req.agent_id)
            .await;

        match result {
            Ok(_) => {
                let _ = self
                    .agent_manager
                    .update_agent_status(&req.agent_id, AgentStatus::Busy)
                    .await;

                Ok(Response::new(JobStartResponse { acknowledged: true }))
            }
            Err(e) => {
                warn!("Failed to start job {}: {}", req.job_id, e);
                Err(Status::internal(format!("Failed to start job: {}", e)))
            }
        }
    }

    async fn report_progress(
        &self,
        request: Request<tonic::Streaming<ProgressUpdate>>,
    ) -> Result<Response<ProgressAck>, Status> {
        let mut stream = request.into_inner();

        while let Some(update) = stream.message().await? {
            let _ = self
                .job_scheduler
                .update_progress(&update.job_id, update.progress_percent)
                .await;
        }

        Ok(Response::new(ProgressAck { received: true }))
    }

    async fn complete_job(
        &self,
        request: Request<JobCompletionRequest>,
    ) -> Result<Response<JobCompletionResponse>, Status> {
        let req = request.into_inner();

        info!("Completing job: {} (success: {})", req.job_id, req.success);

        let error_message = if req.error_message.is_empty() {
            None
        } else {
            Some(req.error_message)
        };

        let result = self
            .job_scheduler
            .complete_job(&req.job_id, req.success, error_message)
            .await;

        match result {
            Ok(_) => {
                let _ = self
                    .agent_manager
                    .update_agent_status(&req.agent_id, AgentStatus::Online)
                    .await;

                Ok(Response::new(JobCompletionResponse { acknowledged: true }))
            }
            Err(e) => {
                warn!("Failed to complete job {}: {}", req.job_id, e);
                Err(Status::internal(format!("Failed to complete job: {}", e)))
            }
        }
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();

        let _ = self.agent_manager.update_heartbeat(&req.agent_id).await;

        Ok(Response::new(HeartbeatResponse {
            alive: true,
            server_time: chrono::Utc::now().timestamp(),
        }))
    }
}
