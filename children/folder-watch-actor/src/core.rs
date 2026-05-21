use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub const DEFAULT_STREAM: &str = "watch.folder";
pub const DEFAULT_WATCH_PATH: &str = "/input";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConfig {
    pub watch_path: String,
    pub stream_name: String,
    pub recursive: bool,
    pub include_hidden: bool,
    pub emit_existing_on_start: bool,
    pub extensions: Vec<String>,
}

impl Default for StoredConfig {
    fn default() -> Self {
        Self {
            watch_path: DEFAULT_WATCH_PATH.to_string(),
            stream_name: DEFAULT_STREAM.to_string(),
            recursive: true,
            include_hidden: false,
            emit_existing_on_start: false,
            extensions: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredStats {
    pub ticks: u64,
    pub scans: u64,
    pub files_seen_total: u64,
    pub changes_detected_total: u64,
    pub events_emitted_total: u64,
    pub last_scan_at: Option<String>,
    pub last_error: Option<String>,
    pub last_scan_duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFingerprint {
    pub size_bytes: u64,
    pub modified_unix_ms: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct ObservedFile {
    pub absolute_path: String,
    pub relative_path: String,
    pub fingerprint: StoredFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone)]
pub struct ObservedChange {
    pub watcher: String,
    pub stream_name: String,
    pub change_kind: ObservedChangeKind,
    pub absolute_path: String,
    pub relative_path: String,
    pub size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
    pub sha256: Option<String>,
    pub detected_at: String,
}

pub fn observed_change_to_json(change: &ObservedChange) -> serde_json::Value {
    let change_kind = match change.change_kind {
        ObservedChangeKind::Created => "created",
        ObservedChangeKind::Modified => "modified",
        ObservedChangeKind::Deleted => "deleted",
    };

    serde_json::json!({
        "watcher": change.watcher,
        "stream": change.stream_name,
        "change_kind": change_kind,
        "absolute_path": change.absolute_path,
        "relative_path": change.relative_path,
        "size_bytes": change.size_bytes,
        "modified_unix_ms": change.modified_unix_ms,
        "sha256": change.sha256,
        "detected_at": change.detected_at,
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn has_hidden_component(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|part| part.starts_with('.'))
            .unwrap_or(false)
    })
}

pub fn should_include_file(path: &Path, config: &StoredConfig) -> bool {
    if !config.include_hidden && has_hidden_component(path) {
        return false;
    }

    if config.extensions.is_empty() {
        return true;
    }

    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };

    let ext = ext.to_ascii_lowercase();
    config
        .extensions
        .iter()
        .map(|item| item.trim().trim_start_matches('.').to_ascii_lowercase())
        .any(|allowed| !allowed.is_empty() && allowed == ext)
}

pub fn fingerprint_for(path: &Path) -> Result<StoredFingerprint, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("failed to stat '{}': {}", path.display(), e))?;
    let bytes =
        std::fs::read(path).map_err(|e| format!("failed to read '{}': {}", path.display(), e))?;

    let modified_unix_ms = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|dur| dur.as_millis() as u64)
        .unwrap_or(0);

    Ok(StoredFingerprint {
        size_bytes: metadata.len(),
        modified_unix_ms,
        sha256: sha256_hex(&bytes),
    })
}

pub fn derive_changes(
    stream: &str,
    previous: &HashMap<String, StoredFingerprint>,
    current: &HashMap<String, ObservedFile>,
    emit_existing_on_start: bool,
) -> Vec<ObservedChange> {
    let mut events = Vec::new();
    let now = Utc::now().to_rfc3339();
    let previous_empty = previous.is_empty();

    let mut current_keys = current.keys().cloned().collect::<Vec<_>>();
    current_keys.sort();

    for key in current_keys {
        let observed = current.get(&key).expect("existing key");
        match previous.get(&key) {
            None => {
                if !previous_empty || emit_existing_on_start {
                    events.push(ObservedChange {
                        watcher: "folder-watch-actor".to_string(),
                        stream_name: stream.to_string(),
                        change_kind: ObservedChangeKind::Created,
                        absolute_path: observed.absolute_path.clone(),
                        relative_path: observed.relative_path.clone(),
                        size_bytes: Some(observed.fingerprint.size_bytes),
                        modified_unix_ms: Some(observed.fingerprint.modified_unix_ms),
                        sha256: Some(observed.fingerprint.sha256.clone()),
                        detected_at: now.clone(),
                    });
                }
            }
            Some(old) => {
                if old.sha256 != observed.fingerprint.sha256
                    || old.size_bytes != observed.fingerprint.size_bytes
                    || old.modified_unix_ms != observed.fingerprint.modified_unix_ms
                {
                    events.push(ObservedChange {
                        watcher: "folder-watch-actor".to_string(),
                        stream_name: stream.to_string(),
                        change_kind: ObservedChangeKind::Modified,
                        absolute_path: observed.absolute_path.clone(),
                        relative_path: observed.relative_path.clone(),
                        size_bytes: Some(observed.fingerprint.size_bytes),
                        modified_unix_ms: Some(observed.fingerprint.modified_unix_ms),
                        sha256: Some(observed.fingerprint.sha256.clone()),
                        detected_at: now.clone(),
                    });
                }
            }
        }
    }

    let mut old_keys = previous.keys().cloned().collect::<Vec<_>>();
    old_keys.sort();

    for key in old_keys {
        if current.contains_key(&key) {
            continue;
        }

        let relative_path = Path::new(&key)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&key)
            .to_string();

        events.push(ObservedChange {
            watcher: "folder-watch-actor".to_string(),
            stream_name: stream.to_string(),
            change_kind: ObservedChangeKind::Deleted,
            absolute_path: key,
            relative_path,
            size_bytes: None,
            modified_unix_ms: None,
            sha256: None,
            detected_at: now.clone(),
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fingerprint(hash: &str) -> StoredFingerprint {
        StoredFingerprint {
            size_bytes: 10,
            modified_unix_ms: 20,
            sha256: hash.to_string(),
        }
    }

    fn observed(path: &str, hash: &str) -> ObservedFile {
        ObservedFile {
            absolute_path: path.to_string(),
            relative_path: Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            fingerprint: fingerprint(hash),
        }
    }

    #[test]
    fn hidden_files_are_excluded_by_default() {
        let config = StoredConfig::default();
        assert!(!should_include_file(Path::new("/input/.secret"), &config));
        assert!(!should_include_file(
            Path::new("/input/.dir/file.txt"),
            &config
        ));
        assert!(should_include_file(
            Path::new("/input/visible.txt"),
            &config
        ));
    }

    #[test]
    fn extension_filter_is_case_insensitive_and_trims_dots() {
        let config = StoredConfig {
            extensions: vec![" .RS ".to_string(), "toml".to_string()],
            ..StoredConfig::default()
        };
        assert!(should_include_file(Path::new("/input/main.rs"), &config));
        assert!(should_include_file(Path::new("/input/Cargo.TOML"), &config));
        assert!(!should_include_file(Path::new("/input/readme.md"), &config));
    }

    #[test]
    fn first_scan_suppresses_existing_files_unless_configured() {
        let previous = HashMap::new();
        let current = HashMap::from([("/input/a.txt".to_string(), observed("/input/a.txt", "a"))]);

        assert!(derive_changes("watch.folder", &previous, &current, false).is_empty());

        let changes = derive_changes("watch.folder", &previous, &current, true);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_kind, ObservedChangeKind::Created);
    }

    #[test]
    fn changed_fingerprint_emits_modified_event() {
        let previous = HashMap::from([("/input/a.txt".to_string(), fingerprint("old"))]);
        let current =
            HashMap::from([("/input/a.txt".to_string(), observed("/input/a.txt", "new"))]);

        let changes = derive_changes("watch.folder", &previous, &current, false);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_kind, ObservedChangeKind::Modified);
    }

    #[test]
    fn missing_current_file_emits_deleted_event() {
        let previous = HashMap::from([("/input/a.txt".to_string(), fingerprint("old"))]);
        let current = HashMap::new();

        let changes = derive_changes("watch.folder", &previous, &current, false);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_kind, ObservedChangeKind::Deleted);
        assert_eq!(changes[0].relative_path, "a.txt");
    }

    #[test]
    fn observed_change_json_preserves_payload_shape() {
        let change = ObservedChange {
            watcher: "folder-watch-actor".to_string(),
            stream_name: "watch.folder".to_string(),
            change_kind: ObservedChangeKind::Created,
            absolute_path: "/input/a.txt".to_string(),
            relative_path: "a.txt".to_string(),
            size_bytes: Some(10),
            modified_unix_ms: Some(20),
            sha256: Some("abc".to_string()),
            detected_at: "now".to_string(),
        };

        let json = observed_change_to_json(&change);
        assert_eq!(json["watcher"], "folder-watch-actor");
        assert_eq!(json["stream"], "watch.folder");
        assert_eq!(json["change_kind"], "created");
        assert_eq!(json["absolute_path"], "/input/a.txt");
        assert_eq!(json["relative_path"], "a.txt");
        assert_eq!(json["size_bytes"], 10);
        assert_eq!(json["modified_unix_ms"], 20);
        assert_eq!(json["sha256"], "abc");
        assert_eq!(json["detected_at"], "now");
    }

    #[test]
    fn fingerprint_reads_file_content_hash() {
        let dir = tempfile_dir();
        let file = dir.join("sample.txt");
        std::fs::write(&file, b"hello").unwrap();

        let fp = fingerprint_for(&file).unwrap();
        assert_eq!(fp.size_bytes, 5);
        assert_eq!(fp.sha256, sha256_hex(b"hello"));
    }

    fn tempfile_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "folder-watch-core-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
