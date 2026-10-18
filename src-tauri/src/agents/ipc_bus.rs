use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolMode {
    A2aLite,
    Transcript,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2ALiteMessage {
    pub source: String,
    pub destination: String,
    pub summary: String,
    pub next_action: String,
    pub artifacts: Vec<String>,
    pub needs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IPCMessage {
    pub id: String,
    pub payload: A2ALiteMessage,
    #[serde(default = "default_timestamp")]
    pub timestamp: u64,
}

pub fn default_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Simulated IPC Broker for Demo purposes
pub struct IPCBroker;

impl IPCBroker {
    pub fn dispatch(msg: IPCMessage) {
        // In a real system, this routes message to destination actor's channel
        println!("IPC Message routed from {} to {}: {}", msg.payload.source, msg.payload.destination, msg.payload.summary);
    }
}
