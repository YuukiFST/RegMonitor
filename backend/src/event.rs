use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
  pub timestamp: String,
  pub change_type: String,
  pub key_path: String,
  pub value_name: String,
  pub data_type: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub old_value: Option<serde_json::Value>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub new_value: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct Batch {
  pub events: Vec<Event>,
}

pub const CHANGE_TYPE_NEW: &str = "NEW";
pub const CHANGE_TYPE_MODIFIED: &str = "MODIFIED";
pub const CHANGE_TYPE_DELETED: &str = "DELETED";
