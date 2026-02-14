use crate::event::{Event, CHANGE_TYPE_DELETED, CHANGE_TYPE_MODIFIED, CHANGE_TYPE_NEW};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Registry::*;
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

const UNSUPPORTED_VALUE: &str = "[Binary/Other]";
const WAIT_TIMEOUT_MS: u32 = 250;

type ValueMap = HashMap<String, (serde_json::Value, &'static str)>;
type CacheMap = HashMap<String, ValueMap>;

fn reg_type_name(val_type: REG_VALUE_TYPE) -> &'static str {
  match val_type {
    REG_DWORD => "REG_DWORD",
    REG_QWORD => "REG_QWORD",
    REG_SZ | REG_EXPAND_SZ => "REG_SZ",
    _ => "REG_BINARY",
  }
}



fn read_value(key: HKEY, name: &str) -> Option<(serde_json::Value, &'static str)> {
  let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
  let pcwstr = windows::core::PCWSTR(name_wide.as_ptr());
  let mut val_type = REG_VALUE_TYPE(0);
  let mut size: u32 = 0;

  let status = unsafe {
    RegQueryValueExW(key, pcwstr, None, Some(&mut val_type), None, Some(&mut size))
  };
  if status.is_err() {
    return None;
  }

  let type_name = reg_type_name(val_type);

  match val_type {
    REG_DWORD => {
      let mut data: u32 = 0;
      let ptr = std::ptr::addr_of_mut!(data) as *mut u8;
      let status = unsafe {
        RegQueryValueExW(key, pcwstr, None, None, Some(ptr), Some(&mut size))
      };
      if status.is_err() {
        return None;
      }
      Some((serde_json::Value::Number(data.into()), type_name))
    }
    REG_QWORD => {
      let mut data: u64 = 0;
      let ptr = std::ptr::addr_of_mut!(data) as *mut u8;
      let status = unsafe {
        RegQueryValueExW(key, pcwstr, None, None, Some(ptr), Some(&mut size))
      };
      if status.is_err() {
        return None;
      }
      Some((serde_json::Value::Number(data.into()), type_name))
    }
    REG_SZ | REG_EXPAND_SZ => {
      let mut buf = vec![0u8; size as usize];
      let status = unsafe {
        RegQueryValueExW(key, pcwstr, None, None, Some(buf.as_mut_ptr()), Some(&mut size))
      };
      if status.is_err() {
        return None;
      }
      let wchars: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
      let s = String::from_utf16_lossy(&wchars).trim_end_matches('\0').to_string();
      Some((serde_json::Value::String(s), type_name))
    }
    _ => Some((serde_json::Value::String(UNSUPPORTED_VALUE.to_string()), type_name)),
  }
}

fn enumerate_values(key: HKEY) -> Vec<String> {
  let mut names = Vec::new();
  let mut index: u32 = 0;
  let mut name_buf = vec![0u16; 16384];

  loop {
    let mut name_len = name_buf.len() as u32;
    let status = unsafe {
      RegEnumValueW(
        key,
        index,
        Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
        &mut name_len,
        None,
        None,
        None,
        None,
      )
    };

    if status.is_err() {
      break;
    }

    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    names.push(name);
    index += 1;
  }

  names
}

fn enumerate_subkeys(key: HKEY) -> Vec<String> {
  let mut names = Vec::new();
  let mut index: u32 = 0;
  let mut name_buf = vec![0u16; 256];

  loop {
    let mut name_len = name_buf.len() as u32;
    let status = unsafe {
      RegEnumKeyExW(
        key,
        index,
        Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
        &mut name_len,
        None,
        None,
        None,
        None,
      )
    };

    if status.is_err() {
      break;
    }

    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    names.push(name);
    index += 1;
  }

  names
}

fn scan_into_cache(key: HKEY, path: &str, cache: &mut CacheMap, depth: usize, max_depth: usize) {
  if depth > max_depth {
    return;
  }

  let mut values = ValueMap::new();
  for name in enumerate_values(key) {
    if let Some((val, type_name)) = read_value(key, &name) {
      values.insert(name, (val, type_name));
    }
  }
  cache.insert(path.to_string(), values);

  for sub_name in enumerate_subkeys(key) {
    let sub_path = format!("{}\\{}", path, sub_name);
    let sub_wide: Vec<u16> = sub_name.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sub_key = HKEY::default();
    let status = unsafe {
      RegOpenKeyExW(key, windows::core::PCWSTR(sub_wide.as_ptr()), Some(0), KEY_READ, &mut sub_key)
    };

    if status.is_err() {
      continue;
    }

    scan_into_cache(sub_key, &sub_path, cache, depth + 1, max_depth);
    let _ = unsafe { RegCloseKey(sub_key) };
  }
}

fn diff_caches(
  old_cache: &CacheMap,
  new_cache: &CacheMap,
  timestamp: &str,
  tx: &mpsc::Sender<Event>,
  filters: &[String],
) {
  for (path, new_values) in new_cache {
    if is_filtered(path, filters) {
      continue;
    }

    match old_cache.get(path) {
      None => emit_new_key_events(path, new_values, timestamp, tx),
      Some(old_values) => emit_modified_events(path, old_values, new_values, timestamp, tx),
    }
  }

  for (path, old_values) in old_cache {
    if is_filtered(path, filters) || new_cache.contains_key(path) {
      continue;
    }
    emit_deleted_key_events(path, old_values, timestamp, tx);
  }
}

fn emit_new_key_events(path: &str, values: &ValueMap, timestamp: &str, tx: &mpsc::Sender<Event>) {
  for (name, (val, type_name)) in values {
    let _ = tx.try_send(Event {
      timestamp: timestamp.to_string(),
      change_type: CHANGE_TYPE_NEW.to_string(),
      key_path: path.to_string(),
      value_name: name.clone(),
      data_type: type_name.to_string(),
      old_value: None,
      new_value: Some(val.clone()),
    });
  }
}

fn emit_modified_events(
  path: &str,
  old_values: &ValueMap,
  new_values: &ValueMap,
  timestamp: &str,
  tx: &mpsc::Sender<Event>,
) {
  for (name, (new_val, new_type)) in new_values {
    match old_values.get(name) {
      None => {
        let _ = tx.try_send(Event {
          timestamp: timestamp.to_string(),
          change_type: CHANGE_TYPE_NEW.to_string(),
          key_path: path.to_string(),
          value_name: name.clone(),
          data_type: new_type.to_string(),
          old_value: None,
          new_value: Some(new_val.clone()),
        });
      }
      Some((old_val, _)) if old_val != new_val => {
        let _ = tx.try_send(Event {
          timestamp: timestamp.to_string(),
          change_type: CHANGE_TYPE_MODIFIED.to_string(),
          key_path: path.to_string(),
          value_name: name.clone(),
          data_type: new_type.to_string(),
          old_value: Some(old_val.clone()),
          new_value: Some(new_val.clone()),
        });
      }
      _ => {}
    }
  }

  for (name, (old_val, old_type)) in old_values {
    if new_values.contains_key(name) {
      continue;
    }
    let _ = tx.try_send(Event {
      timestamp: timestamp.to_string(),
      change_type: CHANGE_TYPE_DELETED.to_string(),
      key_path: path.to_string(),
      value_name: name.clone(),
      data_type: old_type.to_string(),
      old_value: Some(old_val.clone()),
      new_value: None,
    });
  }
}

fn emit_deleted_key_events(path: &str, values: &ValueMap, timestamp: &str, tx: &mpsc::Sender<Event>) {
  for (name, (val, type_name)) in values {
    let _ = tx.try_send(Event {
      timestamp: timestamp.to_string(),
      change_type: CHANGE_TYPE_DELETED.to_string(),
      key_path: path.to_string(),
      value_name: name.clone(),
      data_type: type_name.to_string(),
      old_value: Some(val.clone()),
      new_value: None,
    });
  }
}

fn is_filtered(path: &str, filters: &[String]) -> bool {
  let path_lower = path.to_lowercase();
  filters.iter().any(|f| {
    let f_lower = f.to_lowercase();
    path_lower == f_lower || path_lower.starts_with(&format!("{}\\", f_lower))
  })
}

fn root_hkey(name: &str) -> HKEY {
  match name {
    "HKEY_CURRENT_USER" | "HKCU" => HKEY_CURRENT_USER,
    "HKEY_LOCAL_MACHINE" | "HKLM" => HKEY_LOCAL_MACHINE,
    "HKEY_CLASSES_ROOT" | "HKCR" => HKEY_CLASSES_ROOT,
    _ => HKEY_CURRENT_USER,
  }
}

fn open_monitor_key(root: HKEY, root_name: &str) -> Option<(HKEY, bool)> {
  let parts: Vec<&str> = root_name.splitn(2, '\\').collect();
  if parts.len() < 2 {
    return Some((root, false));
  }

  let sub_path = parts[1];
  let sub_wide: Vec<u16> = sub_path.encode_utf16().chain(std::iter::once(0)).collect();
  let mut opened = HKEY::default();
  let status = unsafe {
    RegOpenKeyExW(root, windows::core::PCWSTR(sub_wide.as_ptr()), Some(0), KEY_READ | KEY_NOTIFY, &mut opened)
  };

  if status.is_err() {
    error!(root = root_name, "failed to open subkey for monitoring");
    return None;
  }

  Some((opened, true))
}

pub fn monitor_key(
  root_name: String,
  max_depth: usize,
  tx: mpsc::Sender<Event>,
  filters: Vec<String>,
  shutdown: tokio::sync::watch::Receiver<bool>,
) {
  let root = root_hkey(&root_name);

  let (monitor_key_handle, should_close) = match open_monitor_key(root, &root_name) {
    Some(pair) => pair,
    None => return,
  };

  let event_handle: HANDLE = unsafe { CreateEventW(None, false, false, None).unwrap() };

  let mut cache: CacheMap = HashMap::new();
  scan_into_cache(monitor_key_handle, &root_name, &mut cache, 0, max_depth);
  info!(root = %root_name, keys = cache.len(), "initial snapshot complete");

  loop {
    if *shutdown.borrow() {
      debug!(root = %root_name, "monitor stopping");
      break;
    }

    let notify_flags = REG_NOTIFY_CHANGE_NAME
      | REG_NOTIFY_CHANGE_ATTRIBUTES
      | REG_NOTIFY_CHANGE_LAST_SET
      | REG_NOTIFY_CHANGE_SECURITY;

    let status = unsafe {
      RegNotifyChangeKeyValue(monitor_key_handle, true, notify_flags, Some(event_handle), true)
    };

    if status.is_err() {
      error!(root = %root_name, "failed to setup registry notification");
      break;
    }

    let wait_result = unsafe { WaitForSingleObject(event_handle, WAIT_TIMEOUT_MS) };

    if wait_result == WAIT_OBJECT_0 {
      let mut new_cache: CacheMap = HashMap::new();
      scan_into_cache(monitor_key_handle, &root_name, &mut new_cache, 0, max_depth);

      let now = chrono_now();
      diff_caches(&cache, &new_cache, &now, &tx, &filters);
      cache = new_cache;
    }
  }

  unsafe {
    let _ = windows::Win32::Foundation::CloseHandle(event_handle);
    if should_close {
      let _ = RegCloseKey(monitor_key_handle);
    }
  }
}

fn chrono_now() -> String {
  use std::time::SystemTime;
  let now = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap_or_default();
  let secs = now.as_secs();
  let nanos = now.subsec_nanos();

  let ts = secs as i64;
  let days = ts / 86400;
  let rem = ts % 86400;
  let hours = rem / 3600;
  let minutes = (rem % 3600) / 60;
  let seconds = rem % 60;

  let mut y = 1970i64;
  let mut d = days;
  loop {
    let days_in_year = if is_leap(y) { 366 } else { 365 };
    if d < days_in_year {
      break;
    }
    d -= days_in_year;
    y += 1;
  }

  let month_days: [i64; 12] = if is_leap(y) {
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  } else {
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  };

  let mut m = 0usize;
  for (i, &md) in month_days.iter().enumerate() {
    if d < md {
      m = i;
      break;
    }
    d -= md;
  }

  format!(
    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
    y,
    m + 1,
    d + 1,
    hours,
    minutes,
    seconds,
    nanos
  )
}

fn is_leap(y: i64) -> bool {
  (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
