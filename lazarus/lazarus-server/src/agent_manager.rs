use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub agent_id: String,
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
    pub metadata: HashMap<String, String>,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Online,
    Offline,
    Busy,
}

#[derive(Clone)]
pub struct AgentManager {
    agents: Arc<RwLock<HashMap<String, Agent>>>,
}

impl Default for AgentManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentManager {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_agent(
        &self,
        agent_id: String,
        hostname: String,
        os_type: String,
        os_version: String,
        agent_version: String,
        metadata: HashMap<String, String>,
    ) -> Result<(), String> {
        let mut agents = self.agents.write().await;

        let agent = Agent {
            agent_id: agent_id.clone(),
            hostname,
            os_type,
            os_version,
            agent_version,
            metadata,
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: AgentStatus::Online,
        };

        agents.insert(agent_id, agent);
        Ok(())
    }

    pub async fn update_heartbeat(&self, agent_id: &str) -> Result<(), String> {
        let mut agents = self.agents.write().await;

        if let Some(agent) = agents.get_mut(agent_id) {
            agent.last_heartbeat = Utc::now();
            agent.status = AgentStatus::Online;
            Ok(())
        } else {
            Err(format!("Agent {} not found", agent_id))
        }
    }

    #[allow(dead_code)]
    pub async fn get_agent(&self, agent_id: &str) -> Option<Agent> {
        let agents = self.agents.read().await;
        agents.get(agent_id).cloned()
    }

    #[allow(dead_code)]
    pub async fn list_agents(&self) -> Vec<Agent> {
        let agents = self.agents.read().await;
        agents.values().cloned().collect()
    }

    pub async fn update_agent_status(
        &self,
        agent_id: &str,
        status: AgentStatus,
    ) -> Result<(), String> {
        let mut agents = self.agents.write().await;

        if let Some(agent) = agents.get_mut(agent_id) {
            agent.status = status;
            Ok(())
        } else {
            Err(format!("Agent {} not found", agent_id))
        }
    }

    #[allow(dead_code)]
    pub async fn check_stale_agents(&self) {
        let mut agents = self.agents.write().await;
        let now = Utc::now();
        let timeout = chrono::Duration::minutes(5);

        for agent in agents.values_mut() {
            if now.signed_duration_since(agent.last_heartbeat) > timeout {
                agent.status = AgentStatus::Offline;
            }
        }
    }
}
