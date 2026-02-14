mod config;
mod event;
mod monitor;

use config::load_config;
use event::Batch;
use tokio::sync::{mpsc, watch};
use tracing::{error, info};
use zeromq::{PubSocket, Socket, SocketSend};

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt()
    .with_target(false)
    .with_timer(tracing_subscriber::fmt::time::uptime())
    .init();

  let cfg = load_config();
  let batch_interval = cfg.batch_interval();
  let batch_size = cfg.batch_size;
  let channel_size = cfg.event_channel_size();
  let endpoint = cfg.zmq_endpoint.clone();
  let filters: Vec<String> = cfg.excluded_paths.clone();
  let max_depth = cfg.max_scan_depth;

  let (tx, rx) = mpsc::channel(channel_size);
  let (shutdown_tx, shutdown_rx) = watch::channel(false);

  let mut pub_socket = PubSocket::new();
  if let Err(err) = pub_socket.bind(&endpoint).await {
    error!(?err, %endpoint, "failed to bind ZMQ socket");
    return;
  }
  info!(%endpoint, "backend started");

  let batcher_handle = tokio::spawn(run_batcher(rx, pub_socket, batch_size, batch_interval));

  let tx_hkcu = tx.clone();
  let filters_hkcu = filters.clone();
  let shutdown_hkcu = shutdown_rx.clone();
  let hkcu_handle = tokio::task::spawn_blocking(move || {
    monitor::monitor_key("HKEY_CURRENT_USER".to_string(), max_depth, tx_hkcu, filters_hkcu, shutdown_hkcu);
  });

  let tx_hklm = tx.clone();
  let filters_hklm = filters.clone();
  let shutdown_hklm = shutdown_rx.clone();
  let hklm_handle = tokio::task::spawn_blocking(move || {
    monitor::monitor_key("HKEY_LOCAL_MACHINE\\SOFTWARE".to_string(), max_depth, tx_hklm, filters_hklm, shutdown_hklm);
  });

  drop(tx);

  tokio::signal::ctrl_c().await.ok();
  info!("shutdown signal received, stopping monitors...");
  let _ = shutdown_tx.send(true);

  let _ = hkcu_handle.await;
  let _ = hklm_handle.await;
  let _ = batcher_handle.await;

  info!("backend stopped cleanly");
}

async fn run_batcher(
  mut rx: mpsc::Receiver<event::Event>,
  mut pub_socket: PubSocket,
  batch_size: usize,
  interval: std::time::Duration,
) {
  let mut current_batch: Vec<event::Event> = Vec::with_capacity(batch_size);
  let mut ticker = tokio::time::interval(interval);
  ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

  loop {
    tokio::select! {
      maybe_event = rx.recv() => {
        let Some(evt) = maybe_event else {
          if !current_batch.is_empty() {
            send_batch(&mut pub_socket, &mut current_batch).await;
          }
          info!("batcher stopped");
          return;
        };

        current_batch.push(evt);
        if current_batch.len() >= batch_size {
          send_batch(&mut pub_socket, &mut current_batch).await;
        }
      }
      _ = ticker.tick() => {
        if !current_batch.is_empty() {
          send_batch(&mut pub_socket, &mut current_batch).await;
        }
      }
    }
  }
}

async fn send_batch(pub_socket: &mut PubSocket, batch: &mut Vec<event::Event>) {
  let b = Batch {
    events: std::mem::take(batch),
  };

  let data = match serde_json::to_vec(&b) {
    Ok(d) => d,
    Err(err) => {
      error!(?err, "failed to marshal batch");
      return;
    }
  };

  if let Err(err) = pub_socket.send(data.into()).await {
    error!(?err, count = b.events.len(), "failed to send batch");
  }
}
