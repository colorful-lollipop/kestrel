//! Configuration Hot Reload
//!
//! Provides runtime configuration updates without restarting the engine.
//! Supports file watching and signal-based reloading.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Configuration reload error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigReloadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Reload already in progress")]
    AlreadyInProgress,

    #[error("Configuration unchanged")]
    Unchanged,
}

/// Result type for config reload operations
pub type Result<T> = std::result::Result<T, ConfigReloadError>;

/// Configuration change event
#[derive(Debug, Clone)]
pub enum ConfigChange {
    /// Full configuration reload
    FullReload,
    /// Partial configuration update
    PartialUpdate(Vec<String>),
    /// Rules directory changed
    RulesChanged,
    /// Alert output configuration changed
    AlertOutputChanged,
}

/// Configuration version tracking
#[derive(Debug, Clone)]
pub struct ConfigVersion {
    /// Version number (incremented on each reload)
    pub version: u64,
    /// Timestamp of last reload
    pub timestamp: std::time::SystemTime,
    /// Configuration hash for detecting changes
    pub hash: String,
}

impl ConfigVersion {
    pub fn new(version: u64, hash: String) -> Self {
        Self {
            version,
            timestamp: std::time::SystemTime::now(),
            hash,
        }
    }
}

/// Hot-reloadable configuration manager
pub struct ConfigManager {
    /// Current configuration version
    version: Arc<RwLock<ConfigVersion>>,
    /// Broadcast channel for config change notifications
    change_tx: broadcast::Sender<ConfigChange>,
    /// Supported reloadable fields
    reloadable_fields: Vec<String>,
    /// Configuration file path
    config_path: Option<std::path::PathBuf>,
    /// File watcher handle
    _watcher_handle: Option<tokio::task::JoinHandle<()>>,
    /// Last configuration hash for change detection
    last_hash: Arc<RwLock<String>>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Self {
        let (change_tx, _) = broadcast::channel(16);
        
        Self {
            version: Arc::new(RwLock::new(ConfigVersion::new(0, "init".to_string()))),
            change_tx,
            reloadable_fields: Self::default_reloadable_fields(),
            config_path: None,
            _watcher_handle: None,
            last_hash: Arc::new(RwLock::new("init".to_string())),
        }
    }

    /// Create with configuration file path
    pub fn with_config_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.config_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Start file watcher for hot reload
    pub fn start_file_watcher(&mut self) -> Result<()> {
        if self.config_path.is_none() {
            return Err(ConfigReloadError::Validation(
                "Config path not set".to_string()
            ));
        }

        let path = self.config_path.clone().unwrap();
        let change_tx = self.change_tx.clone();
        let last_hash = self.last_hash.clone();
        let version = self.version.clone();

        let handle = tokio::spawn(async move {
            info!(path = %path.display(), "Starting config file watcher");
            
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                // Check if file has changed
                match Self::check_file_changed(&path, &last_hash).await {
                    Ok(true) => {
                        info!("Configuration file changed, triggering reload");
                        
                        // Update version
                        let new_version = {
                            let mut v = version.write().await;
                            v.version += 1;
                            v.timestamp = std::time::SystemTime::now();
                            v.version
                        };
                        
                        // Notify subscribers
                        let _ = change_tx.send(ConfigChange::FullReload);
                        
                        info!(version = new_version, "Configuration reload triggered");
                    }
                    Ok(false) => {
                        debug!("Configuration file unchanged");
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to check config file");
                    }
                }
            }
        });

        self._watcher_handle = Some(handle);
        Ok(())
    }

    /// Check if configuration file has changed
    async fn check_file_changed(
        path: &Path,
        last_hash: &Arc<RwLock<String>>,
    ) -> Result<bool> {
        let content = tokio::fs::read_to_string(path).await?;
        let hash = Self::compute_hash(&content);
        
        let last = last_hash.read().await;
        Ok(*last != hash)
    }

    /// Compute hash of configuration content
    fn compute_hash(content: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Subscribe to configuration change notifications
    pub fn subscribe(&self) -> broadcast::Receiver<ConfigChange> {
        self.change_tx.subscribe()
    }

    /// Get current configuration version
    pub async fn current_version(&self) -> ConfigVersion {
        self.version.read().await.clone()
    }

    /// Trigger manual configuration reload
    pub async fn reload(&self) -> Result<()> {
        info!("Manual configuration reload requested");
        
        // Check if config has actually changed
        if let Some(ref path) = self.config_path {
            match Self::check_file_changed(path, &self.last_hash).await? {
                true => {
                    // Update version
                    let new_version = {
                        let mut v = self.version.write().await;
                        v.version += 1;
                        v.timestamp = std::time::SystemTime::now();
                        v.version
                    };
                    
                    // Notify subscribers
                    let _ = self.change_tx.send(ConfigChange::FullReload);
                    
                    info!(version = new_version, "Configuration reloaded successfully");
                    Ok(())
                }
                false => {
                    warn!("Configuration unchanged, skipping reload");
                    Err(ConfigReloadError::Unchanged)
                }
            }
        } else {
            // No file path, just increment version
            let new_version = {
                let mut v = self.version.write().await;
                v.version += 1;
                v.timestamp = std::time::SystemTime::now();
                v.version
            };
            
            let _ = self.change_tx.send(ConfigChange::FullReload);
            info!(version = new_version, "Configuration reloaded (no file)");
            Ok(())
        }
    }

    /// Update configuration hash after successful reload
    pub async fn mark_reloaded(&self, content: &str) {
        let hash = Self::compute_hash(content);
        let mut last = self.last_hash.write().await;
        *last = hash;
    }

    /// Get list of reloadable fields
    pub fn reloadable_fields(&self) -> &[String] {
        &self.reloadable_fields
    }

    /// Check if a field is reloadable
    pub fn is_reloadable(&self, field: &str) -> bool {
        self.reloadable_fields.iter().any(|f| f == field)
    }

    /// Default reloadable configuration fields
    fn default_reloadable_fields() -> Vec<String> {
        vec![
            "rules.directory".to_string(),
            "rules.watch_enabled".to_string(),
            "alert.output".to_string(),
            "metrics.enabled".to_string(),
            "metrics.interval".to_string(),
            "log.level".to_string(),
            "pool.size".to_string(),
            "pool.max_wait_ms".to_string(),
            "backpressure.queue_depth".to_string(),
            "backpressure.timeout_ms".to_string(),
        ]
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration snapshot for atomic updates
#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub version: u64,
    pub values: HashMap<String, String>,
}

impl ConfigSnapshot {
    pub fn new(version: u64) -> Self {
        Self {
            version,
            values: HashMap::new(),
        }
    }

    pub fn with_values(mut self, values: HashMap<String, String>) -> Self {
        self.values = values;
        self
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.values.get(key)
    }

    pub fn set(&mut self, key: String, value: String) {
        self.values.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_version() {
        let version = ConfigVersion::new(1, "abc123".to_string());
        assert_eq!(version.version, 1);
        assert_eq!(version.hash, "abc123");
    }

    #[test]
    fn test_config_manager_new() {
        let manager = ConfigManager::new();
        assert!(!manager.reloadable_fields().is_empty());
    }

    #[test]
    fn test_is_reloadable() {
        let manager = ConfigManager::new();
        assert!(manager.is_reloadable("log.level"));
        assert!(!manager.is_reloadable("nonexistent.field"));
    }

    #[test]
    fn test_config_snapshot() {
        let mut snapshot = ConfigSnapshot::new(1);
        snapshot.set("key1".to_string(), "value1".to_string());
        snapshot.set("key2".to_string(), "value2".to_string());

        assert_eq!(snapshot.get("key1"), Some(&"value1".to_string()));
        assert_eq!(snapshot.version, 1);
    }

    #[tokio::test]
    async fn test_config_reload_manual() {
        let manager = ConfigManager::new();
        
        // Subscribe to changes
        let mut rx = manager.subscribe();
        
        // Trigger reload (without file, should always succeed)
        let result = manager.reload().await;
        assert!(result.is_ok());
        
        // Verify version incremented
        let version = manager.current_version().await;
        assert_eq!(version.version, 1);
        
        // Verify notification sent
        let change = rx.try_recv();
        assert!(change.is_ok());
        match change.unwrap() {
            ConfigChange::FullReload => {},
            _ => panic!("Expected FullReload"),
        }
    }

    #[test]
    fn test_compute_hash() {
        let hash1 = ConfigManager::compute_hash("test content");
        let hash2 = ConfigManager::compute_hash("test content");
        let hash3 = ConfigManager::compute_hash("different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
