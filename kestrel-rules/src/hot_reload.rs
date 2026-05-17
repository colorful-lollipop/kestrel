//! Hot reload support for rule management
//!
//! Watches the filesystem for rule changes and triggers reloads
//! with debouncing to avoid excessive reloads during rapid changes.

use crate::RuleManager;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Events emitted by the hot reload watcher
#[derive(Debug, Clone)]
pub enum HotReloadEvent {
    /// Filesystem changes detected
    RulesChanged,
    /// Rules were reloaded (contains count or error)
    RulesReloaded(Result<usize, String>),
    /// Rule validation failed
    ValidationFailed(String),
}

/// Manages hot reloading of rules from filesystem
///
/// Creates a filesystem watcher that monitors the rules directory
/// for changes. When changes are detected, it debounces rapid
/// successive changes and triggers a rule reload.
pub struct RuleHotReloader {
    _watcher: RecommendedWatcher,
    event_rx: mpsc::Receiver<HotReloadEvent>,
}

impl RuleHotReloader {
    /// Create a new hot reloader
    ///
    /// # Arguments
    /// * `rule_manager` - The rule manager to reload
    /// * `rules_dir` - Directory to watch for changes
    /// * `debounce_ms` - Milliseconds to wait for changes to settle before reloading
    pub fn new(
        rule_manager: Arc<RuleManager>,
        rules_dir: &Path,
        debounce_ms: u64,
    ) -> Result<Self, notify::Error> {
        let (event_tx, event_rx) = mpsc::channel::<HotReloadEvent>(100);
        let (notify_tx, mut notify_rx) = mpsc::channel::<Event>(100);

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        let is_relevant = matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        );
                        if is_relevant {
                            let _ = notify_tx.blocking_send(event);
                        }
                    }
                    Err(e) => {
                        error!("Watch error: {}", e);
                    }
                }
            },
            Config::default(),
        )?;

        watcher.watch(rules_dir, RecursiveMode::Recursive)?;
        info!("Watching {} for rule changes", rules_dir.display());

        let manager = rule_manager.clone();
        let debounce_duration = std::time::Duration::from_millis(debounce_ms);

        tokio::spawn(async move {
            loop {
                // Wait for first event
                if notify_rx.recv().await.is_none() {
                    break;
                }

                // Debounce: reset timer on each new event during debounce period
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(debounce_duration) => {
                            break;
                        }
                        Some(_) = notify_rx.recv() => {
                            continue;
                        }
                        else => break,
                    }
                }

                // Drain any remaining events that arrived during final sleep
                while notify_rx.try_recv().is_ok() {}

                // Perform reload
                match manager.reload_all().await {
                    Ok(stats) => {
                        info!(
                            "Hot reload successful: {} rules loaded (added: {}, removed: {})",
                            stats.loaded, stats.added, stats.removed
                        );
                        let _ = event_tx
                            .send(HotReloadEvent::RulesReloaded(Ok(stats.loaded)))
                            .await;
                    }
                    Err(e) => {
                        let err_str = format!("{}", e);
                        error!("Hot reload failed: {}", err_str);
                        let _ = event_tx
                            .send(HotReloadEvent::RulesReloaded(Err(err_str)))
                            .await;
                    }
                }
            }
        });

        Ok(Self {
            _watcher: watcher,
            event_rx,
        })
    }

    /// Wait for the next hot reload event
    pub async fn next_event(&mut self) -> Option<HotReloadEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuleManager, RuleManagerConfig};
    use std::time::Duration;

    #[tokio::test]
    async fn test_hot_reloader_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let manager = Arc::new(RuleManager::new(config));

        let reloader = RuleHotReloader::new(manager, temp_dir.path(), 100);
        assert!(reloader.is_ok());
    }

    #[tokio::test]
    async fn test_hot_reloader_file_change_triggers_reload() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create initial rule
        let rule_file = temp_dir.path().join("test.json");
        std::fs::write(
            &rule_file,
            r#"{"id":"test-001","name":"Test","version":"1.0.0","severity":"High","tags":[]}"#,
        )
        .unwrap();

        let config = RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let manager = Arc::new(RuleManager::new(config));
        manager.load_all().await.unwrap();

        let mut reloader = RuleHotReloader::new(manager, temp_dir.path(), 50).unwrap();

        // Give watcher time to initialize
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Modify the rule file
        std::fs::write(
            &rule_file,
            r#"{"id":"test-002","name":"Test 2","version":"1.0.0","severity":"Medium","tags":[]}"#,
        )
        .unwrap();

        // Wait for reload event with timeout
        // Use longer timeout on macOS due to FSEvents latency
        #[cfg(target_os = "macos")]
        let timeout = Duration::from_secs(10);
        #[cfg(not(target_os = "macos"))]
        let timeout = Duration::from_secs(3);

        let event = tokio::time::timeout(timeout, reloader.next_event()).await;
        assert!(event.is_ok(), "Expected reload event within timeout");

        let event = event.unwrap();
        assert!(event.is_some());

        match event.unwrap() {
            HotReloadEvent::RulesReloaded(Ok(count)) => {
                assert_eq!(count, 1);
            }
            other => panic!("Expected RulesReloaded(Ok(1)), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hot_reloader_invalid_rule_does_not_break_existing() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create initial valid rule
        let rule_file = temp_dir.path().join("valid.json");
        std::fs::write(
            &rule_file,
            r#"{"id":"valid-001","name":"Valid","version":"1.0.0","severity":"High","tags":[]}"#,
        )
        .unwrap();

        let config = RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let manager = Arc::new(RuleManager::new(config));
        manager.load_all().await.unwrap();

        let mut reloader = RuleHotReloader::new(manager.clone(), temp_dir.path(), 50).unwrap();

        // Give watcher time to initialize
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create an invalid rule file
        let invalid_file = temp_dir.path().join("invalid.json");
        std::fs::write(&invalid_file, "this is not valid json").unwrap();

        // Wait for reload event
        #[cfg(target_os = "macos")]
        let timeout = Duration::from_secs(10);
        #[cfg(not(target_os = "macos"))]
        let timeout = Duration::from_secs(3);

        let event = tokio::time::timeout(timeout, reloader.next_event()).await;
        assert!(event.is_ok());

        let event = event.unwrap();
        assert!(event.is_some());

        // Should report successful reload - valid rule stays, invalid is skipped
        match event.unwrap() {
            HotReloadEvent::RulesReloaded(Ok(count)) => {
                assert!(count >= 1, "Should have at least the valid rule");
            }
            other => {
                panic!("Expected RulesReloaded(Ok(_)), got {:?}", other);
            }
        }

        // Ensure manager still has the valid rule
        assert!(
            manager.get_rule("valid-001").await.is_some(),
            "Valid rule should still exist after invalid rule was added"
        );
    }

    #[tokio::test]
    async fn test_hot_reloader_debounce() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let manager = Arc::new(RuleManager::new(config));

        let mut reloader = RuleHotReloader::new(manager, temp_dir.path(), 100).unwrap();

        // Give watcher time to initialize
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create multiple files rapidly
        for i in 0..5 {
            let file = temp_dir.path().join(format!("rule{}.json", i));
            std::fs::write(
                &file,
                format!(
                    r#"{{"id":"debounce-{:03}","name":"Rule {}","version":"1.0.0","severity":"High","tags":[]}}"#,
                    i, i
                ),
            )
            .unwrap();
        }

        // Should get exactly one reload event due to debouncing
        #[cfg(target_os = "macos")]
        let timeout = Duration::from_secs(10);
        #[cfg(not(target_os = "macos"))]
        let timeout = Duration::from_secs(3);

        let event = tokio::time::timeout(timeout, reloader.next_event()).await;
        assert!(event.is_ok());
        assert!(event.unwrap().is_some());

        // Should not get another event immediately (debounced into single reload)
        let second_event =
            tokio::time::timeout(Duration::from_millis(500), reloader.next_event()).await;
        assert!(
            second_event.is_err() || second_event.unwrap().is_none(),
            "Expected no second event due to debouncing"
        );
    }
}
