use serde::Deserialize;
use std::fs;
use std::time::Duration;
use tracing::{info, warn};

const DEFAULT_ZMQ_ENDPOINT: &str = "tcp://127.0.0.1:5555";
const DEFAULT_BATCH_INTERVAL_MS: u64 = 50;
const DEFAULT_BATCH_SIZE: usize = 100;
const DEFAULT_MAX_SCAN_DEPTH: usize = 5;
const DEFAULT_EVENT_CHANNEL_SIZE: usize = 8192;
const CONFIG_FILE_PATH: &str = "config.json";

#[derive(Debug, Deserialize)]
pub struct Config {
  #[serde(default = "default_zmq_endpoint")]
  pub zmq_endpoint: String,

  #[serde(default = "default_batch_interval_ms")]
  pub batch_interval_ms: u64,

  #[serde(default = "default_batch_size")]
  pub batch_size: usize,

  #[serde(default = "default_max_scan_depth")]
  pub max_scan_depth: usize,

  #[serde(default)]
  pub excluded_paths: Vec<String>,
}

fn default_zmq_endpoint() -> String {
  DEFAULT_ZMQ_ENDPOINT.to_string()
}
fn default_batch_interval_ms() -> u64 {
  DEFAULT_BATCH_INTERVAL_MS
}
fn default_batch_size() -> usize {
  DEFAULT_BATCH_SIZE
}
fn default_max_scan_depth() -> usize {
  DEFAULT_MAX_SCAN_DEPTH
}

impl Config {
  pub fn batch_interval(&self) -> Duration {
    Duration::from_millis(self.batch_interval_ms)
  }

  pub fn event_channel_size(&self) -> usize {
    DEFAULT_EVENT_CHANNEL_SIZE
  }
}

impl Default for Config {
  fn default() -> Self {
    Self {
      zmq_endpoint: DEFAULT_ZMQ_ENDPOINT.to_string(),
      batch_interval_ms: DEFAULT_BATCH_INTERVAL_MS,
      batch_size: DEFAULT_BATCH_SIZE,
      max_scan_depth: DEFAULT_MAX_SCAN_DEPTH,
      excluded_paths: Vec::new(),
    }
  }
}

pub fn load_config() -> Config {
  let data = match fs::read_to_string(CONFIG_FILE_PATH) {
    Ok(data) => data,
    Err(err) => {
      warn!(?err, path = CONFIG_FILE_PATH, "config file not found, using defaults");
      return Config::default();
    }
  };

  let mut cfg: Config = match serde_json::from_str(&data) {
    Ok(cfg) => cfg,
    Err(err) => {
      warn!(?err, "failed to parse config, using defaults");
      return Config::default();
    }
  };

  if cfg.zmq_endpoint.is_empty() {
    cfg.zmq_endpoint = DEFAULT_ZMQ_ENDPOINT.to_string();
  }
  if cfg.batch_interval_ms == 0 {
    cfg.batch_interval_ms = DEFAULT_BATCH_INTERVAL_MS;
  }
  if cfg.batch_size == 0 {
    cfg.batch_size = DEFAULT_BATCH_SIZE;
  }
  if cfg.max_scan_depth == 0 {
    cfg.max_scan_depth = DEFAULT_MAX_SCAN_DEPTH;
  }

  info!(
    endpoint = %cfg.zmq_endpoint,
    batch_size = cfg.batch_size,
    filters = cfg.excluded_paths.len(),
    "config loaded"
  );

  cfg
}
