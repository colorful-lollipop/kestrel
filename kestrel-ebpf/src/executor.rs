//! eBPF Enforcement Executor
//!
//! This module implements the enforcement decision engine for real-time blocking.
//! It transforms NFA detection results into Action decisions and executes them
//! through eBPF maps and LSM hooks with low latency.
//!
//! ## Key Features
//!
//! - **Decision Engine**: Converts SequenceAlert to ActionDecision based on severity
//! - **Decision Cache**: LRU cache with TTL to prevent duplicate decisions
//! - **Rate Limiting**: Per-entity rate limiting to prevent decision storms
//! - **Audit Trail**: All enforcement decisions logged for forensics
//! - **Metrics Collection**: Detailed performance and decision metrics

use kestrel_core::{
    ActionCapabilities, ActionDecision, ActionError, ActionEvidence, ActionExecutor, ActionPolicy,
    ActionResult, ActionTarget, ActionType, Alert, Severity,
};
use kestrel_event::Event;
use kestrel_nfa::SequenceAlert;
use lru::LruCache;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{EbpfCollector, EnforcementAction, EnforcementDecision};

/// Executor configuration
#[derive(Debug, Clone)]
pub struct EbpfExecutorConfig {
    pub policy: ActionPolicy,
    pub decision_cache_size: usize,
    pub decision_ttl_ms: u64,
    pub enable_rate_limiting: bool,
    pub max_decisions_per_second: u32,
    pub enable_audit: bool,
    pub audit_channel_size: usize,
}

impl Default for EbpfExecutorConfig {
    fn default() -> Self {
        Self {
            policy: ActionPolicy::Inline,
            decision_cache_size: 1024,
            decision_ttl_ms: 60000,
            enable_rate_limiting: true,
            max_decisions_per_second: 100,
            enable_audit: true,
            audit_channel_size: 1000,
        }
    }
}

/// Executor errors
#[derive(Debug, Error)]
pub enum EbpfExecutorError {
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Action execution error: {0}")]
    ActionError(String),

    #[error("Invalid decision: {0}")]
    InvalidDecision(String),
}

/// Cached decision entry
#[derive(Debug, Clone)]
pub struct DecisionCacheEntry {
    pub decision: ActionDecision,
    pub expires_at_ns: u64,
    pub hit_count: u32,
}

/// Rate limiter for decisions
#[derive(Debug)]
pub struct RateLimiter {
    max_per_second: u32,
    current_second: AtomicU64,
    current_count: AtomicU32,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            current_second: AtomicU64::new(now_sec()),
            current_count: AtomicU32::new(0),
        }
    }

    pub fn check(&self) -> Result<(), EbpfExecutorError> {
        let now = now_sec();
        let prev_second = self.current_second.load(Ordering::Relaxed);

        if now != prev_second {
            self.current_second.store(now, Ordering::Relaxed);
            self.current_count.store(0, Ordering::Relaxed);
        }

        let count = self.current_count.load(Ordering::Relaxed);
        if count >= self.max_per_second {
            return Err(EbpfExecutorError::RateLimitExceeded(format!(
                "Exceeded {} decisions per second",
                self.max_per_second
            )));
        }

        self.current_count.store(count + 1, Ordering::Relaxed);
        Ok(())
    }
}

/// Audit record for enforcement decisions
#[derive(Debug, Clone)]
pub struct EnforcementAuditRecord {
    pub timestamp_ns: u64,
    pub decision_id: String,
    pub rule_id: String,
    pub action_type: ActionType,
    pub entity_key: u128,
    pub target: ActionTarget,
    pub severity: Severity,
    pub cached: bool,
    pub rate_limited: bool,
    pub latency_us: u64,
}

/// Executor metrics
#[derive(Debug, Default)]
pub struct EbpfExecutorMetrics {
    pub decisions_total: AtomicU64,
    pub decisions_blocked: AtomicU64,
    pub decisions_allowed: AtomicU64,
    pub decisions_cached: AtomicU64,
    pub decisions_rate_limited: AtomicU64,
    pub decisions_audited: AtomicU64,
    pub decision_latency_us: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub action_executions: AtomicU64,
    pub action_failures: AtomicU64,
}

impl EbpfExecutorMetrics {
    pub fn record_decision(&self, action_type: ActionType, cached: bool) {
        self.decisions_total.fetch_add(1, Ordering::Relaxed);
        match action_type {
            ActionType::Block | ActionType::Kill => {
                self.decisions_blocked.fetch_add(1, Ordering::Relaxed);
            }
            ActionType::Allow | ActionType::Alert => {
                self.decisions_allowed.fetch_add(1, Ordering::Relaxed);
            }
            ActionType::Quarantine => {
                self.decisions_blocked.fetch_add(1, Ordering::Relaxed);
            }
        }
        if cached {
            self.decisions_cached.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_rate_limited(&self) {
        self.decisions_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_audited(&self) {
        self.decisions_audited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency(&self, latency_us: u64) {
        let old = self.decision_latency_us.load(Ordering::Relaxed);
        let avg = if old == 0 {
            latency_us
        } else {
            (old + latency_us) / 2
        };
        self.decision_latency_us.store(avg, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_action_execution(&self, success: bool) {
        self.action_executions.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.action_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// eBPF Enforcement Executor
///
/// This executor transforms detection results into enforcement decisions
/// and executes them through eBPF maps with low latency.
#[derive(Clone)]
pub struct EbpfExecutor {
    action_executor: Arc<dyn ActionExecutor>,
    config: EbpfExecutorConfig,
    decision_cache: Arc<RwLock<LruCache<u128, DecisionCacheEntry>>>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<RwLock<EbpfExecutorMetrics>>,
    audit_tx: Option<mpsc::Sender<EnforcementAuditRecord>>,
    ebpf_collector: Option<Arc<EbpfCollector>>,
}

impl EbpfExecutor {
    /// Create a new eBPF executor
    pub fn new(action_executor: Arc<dyn ActionExecutor>, config: EbpfExecutorConfig) -> Self {
        let enable_audit = config.enable_audit;
        let audit_channel_size = config.audit_channel_size;
        let decision_cache_size = config.decision_cache_size;
        let max_decisions_per_second = config.max_decisions_per_second;
        let policy = config.policy;

        let audit_tx = if enable_audit {
            let (tx, _) = mpsc::channel(audit_channel_size);
            Some(tx)
        } else {
            None
        };

        Self {
            action_executor,
            config,
            decision_cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(decision_cache_size).unwrap(),
            ))),
            rate_limiter: Arc::new(RateLimiter::new(max_decisions_per_second)),
            metrics: Arc::new(RwLock::new(EbpfExecutorMetrics::default())),
            audit_tx,
            ebpf_collector: None,
        }
    }

    /// Create with eBPF collector
    pub fn with_collector(
        action_executor: Arc<dyn ActionExecutor>,
        config: EbpfExecutorConfig,
        ebpf_collector: Arc<EbpfCollector>,
    ) -> Self {
        let mut executor = Self::new(action_executor, config);
        executor.ebpf_collector = Some(ebpf_collector);
        executor
    }

    /// Set eBPF collector after construction
    pub fn set_collector(&mut self, collector: Arc<EbpfCollector>) {
        self.ebpf_collector = Some(collector);
    }

    /// Get metrics snapshot
    pub fn metrics(&self) -> EbpfExecutorMetricsSnapshot {
        let metrics = self.metrics.read().unwrap();
        EbpfExecutorMetricsSnapshot {
            decisions_total: metrics.decisions_total.load(Ordering::Relaxed),
            decisions_blocked: metrics.decisions_blocked.load(Ordering::Relaxed),
            decisions_allowed: metrics.decisions_allowed.load(Ordering::Relaxed),
            decisions_cached: metrics.decisions_cached.load(Ordering::Relaxed),
            decisions_rate_limited: metrics.decisions_rate_limited.load(Ordering::Relaxed),
            cache_hits: metrics.cache_hits.load(Ordering::Relaxed),
            cache_misses: metrics.cache_misses.load(Ordering::Relaxed),
            avg_latency_us: metrics.decision_latency_us.load(Ordering::Relaxed),
        }
    }

    /// Process a detection alert and return enforcement decisions
    pub async fn process_detection(
        &mut self,
        alert: &SequenceAlert,
    ) -> Result<Vec<ActionDecision>, EbpfExecutorError> {
        let start = std::time::Instant::now();
        let mut decisions = Vec::new();

        let entity_key = alert.entity_key;

        if self.config.enable_rate_limiting {
            if let Err(e) = self.rate_limiter.check() {
                self.metrics.write().unwrap().record_rate_limited();
                self.record_audit(entity_key, None, true, false, 0);
                return Err(e);
            }
        }

        if let Some(cached) = self.check_cache(entity_key) {
            let latency_us = start.elapsed().as_micros() as u64;
            self.metrics
                .write()
                .unwrap()
                .record_decision(cached.action, true);
            self.record_audit(entity_key, Some(&cached), false, false, latency_us);
            return Ok(vec![cached.clone()]);
        }

        let decision = self.make_decision_from_alert(alert, entity_key)?;

        self.cache_decision(entity_key, &decision);

        let latency_us = start.elapsed().as_micros() as u64;
        self.metrics
            .write()
            .unwrap()
            .record_decision(decision.action, false);
        self.record_audit(entity_key, Some(&decision), false, false, latency_us);

        decisions.push(decision);

        Ok(decisions)
    }

    /// Process an alert from the detection engine
    pub async fn process_alert(
        &mut self,
        alert: &Alert,
    ) -> Result<Vec<ActionDecision>, EbpfExecutorError> {
        let start = std::time::Instant::now();
        let mut decisions = Vec::new();

        let entity_key = alert.extract_entity_key();
        let action_type = self.determine_action_from_severity(alert.severity);

        if self.config.enable_rate_limiting {
            if let Err(e) = self.rate_limiter.check() {
                self.metrics.write().unwrap().record_rate_limited();
                self.record_audit(entity_key, None, true, false, 0);
                return Err(e);
            }
        }

        if let Some(cached) = self.check_cache(entity_key) {
            let latency_us = start.elapsed().as_micros() as u64;
            self.metrics
                .write()
                .unwrap()
                .record_decision(cached.action, true);
            self.record_audit(entity_key, Some(&cached), false, false, latency_us);
            return Ok(vec![cached.clone()]);
        }

        let target = self.extract_target_from_alert(alert);
        let decision = ActionDecision::new(
            alert.rule_id.clone(),
            action_type,
            self.config.policy,
            target,
            format!(
                "Alert: {} - {}",
                alert.title,
                alert.description.clone().unwrap_or_default()
            ),
            vec![],
        );

        self.cache_decision(entity_key, &decision);

        let latency_us = start.elapsed().as_micros() as u64;
        self.metrics
            .write()
            .unwrap()
            .record_decision(decision.action, false);
        self.record_audit(entity_key, Some(&decision), false, false, latency_us);

        decisions.push(decision);

        Ok(decisions)
    }

    /// Make enforcement decision for a single event with matched rules
    pub async fn make_decision(
        &mut self,
        event: &Event,
        matched_rules: &[(&str, Severity)],
    ) -> Result<Option<ActionDecision>, EbpfExecutorError> {
        if matched_rules.is_empty() {
            return Ok(None);
        }

        let entity_key = event.entity_key;

        if self.config.enable_rate_limiting {
            self.rate_limiter.check()?;
        }

        if let Some(cached) = self.check_cache(entity_key) {
            self.metrics.write().unwrap().record_cache_hit();
            return Ok(Some(cached.clone()));
        }

        self.metrics.write().unwrap().record_cache_miss();

        let highest_severity =
            matched_rules.iter().fold(
                Severity::Low,
                |acc, (_, severity)| {
                    if *severity > acc {
                        *severity
                    } else {
                        acc
                    }
                },
            );

        let action_type = self.determine_action_from_severity(highest_severity);
        let top_rule = matched_rules
            .iter()
            .fold(("unknown", Severity::Low), |acc, (rule_id, severity)| {
                if *severity > acc.1 {
                    (rule_id, *severity)
                } else {
                    acc
                }
            })
            .0
            .clone();

        let target = self.extract_target_from_event(event);
        let decision = ActionDecision::new(
            top_rule.to_string(),
            action_type,
            self.config.policy,
            target,
            format!("Matched {} rules", matched_rules.len()),
            vec![],
        );

        self.cache_decision(entity_key, &decision);

        Ok(Some(decision))
    }

    /// Check if an entity should be blocked (fast path for LSM hooks)
    pub fn should_block(&self, entity_key: u128) -> bool {
        if let Some(cached) = self.check_cache(entity_key) {
            matches!(
                cached.action,
                ActionType::Block | ActionType::Kill | ActionType::Quarantine
            )
        } else {
            false
        }
    }

    /// Get the current block status for an entity
    pub fn get_block_status(&self, entity_key: u128) -> BlockStatus {
        if let Some(entry) = self.get_cache_entry(entity_key) {
            BlockStatus::Blocked {
                action: entry.decision.action,
                reason: entry.decision.reason.clone(),
                expires_at: entry.expires_at_ns,
            }
        } else {
            BlockStatus::NotBlocked
        }
    }

    /// Force a block decision for an entity
    pub fn force_block(
        &mut self,
        entity_key: u128,
        action_type: ActionType,
        reason: String,
        ttl_ms: u64,
    ) -> Result<ActionDecision, EbpfExecutorError> {
        let current_time_ns = now_ns();
        let decision = ActionDecision::new(
            "manual".to_string(),
            action_type,
            self.config.policy,
            ActionTarget::ProcessExec {
                pid: (entity_key & 0xFFFFFFFF) as u32,
                executable: format!("entity_{}", entity_key),
            },
            reason,
            vec![],
        );

        self.cache_decision_with_ttl(entity_key, &decision, ttl_ms);

        Ok(decision)
    }

    /// Remove a block decision for an entity
    pub fn unblock(&mut self, entity_key: u128) -> bool {
        let mut cache = self.decision_cache.write().unwrap();
        cache.pop(&entity_key).is_some()
    }

    /// Clear all cached decisions
    pub fn clear_cache(&mut self) {
        let mut cache = self.decision_cache.write().unwrap();
        cache.clear();
    }

    fn check_cache(&self, entity_key: u128) -> Option<ActionDecision> {
        let cache = self.decision_cache.read().unwrap();
        if let Some(entry) = cache.peek(&entity_key) {
            if entry.expires_at_ns > now_ns() {
                return Some(entry.decision.clone());
            }
        }
        None
    }

    fn get_cache_entry(&self, entity_key: u128) -> Option<DecisionCacheEntry> {
        let cache = self.decision_cache.read().unwrap();
        cache
            .peek(&entity_key)
            .filter(|e| e.expires_at_ns > now_ns())
            .cloned()
    }

    fn cache_decision(&mut self, entity_key: u128, decision: &ActionDecision) {
        self.cache_decision_with_ttl(entity_key, decision, self.config.decision_ttl_ms);
    }

    fn cache_decision_with_ttl(
        &mut self,
        entity_key: u128,
        decision: &ActionDecision,
        ttl_ms: u64,
    ) {
        let ttl_ns = ttl_ms * 1_000_000;
        let entry = DecisionCacheEntry {
            decision: decision.clone(),
            expires_at_ns: now_ns() + ttl_ns,
            hit_count: 0,
        };
        let mut cache = self.decision_cache.write().unwrap();
        cache.push(entity_key, entry);
    }

    fn make_decision_from_alert(
        &self,
        alert: &SequenceAlert,
        entity_key: u128,
    ) -> Result<ActionDecision, EbpfExecutorError> {
        let action_type = self.determine_action_from_severity(Severity::High);
        let target = self.extract_target_from_events(&alert.events);

        let decision = ActionDecision::new(
            alert.rule_id.clone(),
            action_type,
            self.config.policy,
            target,
            format!(
                "Sequence {} matched for entity {}",
                alert.sequence_id, entity_key
            ),
            vec![],
        );

        Ok(decision)
    }

    fn determine_action_from_severity(&self, severity: Severity) -> ActionType {
        match severity {
            Severity::Critical => ActionType::Kill,
            Severity::High => ActionType::Block,
            Severity::Medium => ActionType::Alert,
            Severity::Low => ActionType::Alert,
            Severity::Informational => ActionType::Allow,
        }
    }

    fn extract_target_from_alert(&self, alert: &Alert) -> ActionTarget {
        let pid = (alert.extract_entity_key() & 0xFFFFFFFF) as u32;
        ActionTarget::ProcessExec {
            pid,
            executable: format!("alert_{}", alert.id),
        }
    }

    fn extract_target_from_event(&self, event: &Event) -> ActionTarget {
        let pid = (event.entity_key & 0xFFFFFFFF) as u32;
        ActionTarget::ProcessExec {
            pid,
            executable: format!("entity_{}", event.entity_key),
        }
    }

    fn extract_target_from_events(&self, events: &[Event]) -> ActionTarget {
        if let Some(first) = events.first() {
            self.extract_target_from_event(first)
        } else {
            let now_ns = now_ns();
            ActionTarget::ProcessExec {
                pid: 0,
                executable: "unknown".to_string(),
            }
        }
    }

    fn record_audit(
        &self,
        entity_key: u128,
        decision: Option<&ActionDecision>,
        rate_limited: bool,
        _cached: bool,
        latency_us: u64,
    ) {
        if !self.config.enable_audit {
            return;
        }

        if let Some(ref tx) = self.audit_tx {
            let record = EnforcementAuditRecord {
                timestamp_ns: now_ns(),
                decision_id: decision.map(|d| d.id.clone()).unwrap_or_default(),
                rule_id: decision.map(|d| d.rule_id.clone()).unwrap_or_default(),
                action_type: decision.map(|d| d.action).unwrap_or(ActionType::Allow),
                entity_key,
                target: decision
                    .as_ref()
                    .map(|d| d.target.clone())
                    .unwrap_or_else(|| ActionTarget::ProcessExec {
                        pid: 0,
                        executable: "unknown".to_string(),
                    }),
                severity: Severity::High,
                cached: false,
                rate_limited,
                latency_us,
            };

            let _ = tx.try_send(record);
        }

        self.metrics.write().unwrap().record_audited();
    }
}

impl ActionExecutor for EbpfExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        debug!(
            decision_id = %decision.id,
            action = ?decision.action,
            target = ?decision.target,
            "Executing action via eBPF executor"
        );

        let ebpf_result = if let Some(ref collector) = self.ebpf_collector {
            let pid = match decision.target {
                ActionTarget::ProcessExec { pid, .. } => pid,
                ActionTarget::FileOp { pid, .. } => pid,
                ActionTarget::NetworkOp { pid, .. } => pid,
                ActionTarget::MemoryOp { pid } => pid,
            };

            let enforcement_action = match decision.action {
                ActionType::Block => EnforcementAction::Block,
                ActionType::Kill => EnforcementAction::Kill,
                ActionType::Alert => EnforcementAction::Allow,
                ActionType::Quarantine => EnforcementAction::Block,
                ActionType::Allow => EnforcementAction::Allow,
            };

            let ttl_ns = if decision.action == ActionType::Block {
                60_000_000_000
            } else {
                0
            };

            let ebpf_decision = EnforcementDecision::new(pid, enforcement_action, ttl_ns);
            collector.set_enforcement(&ebpf_decision)
        } else {
            Ok(())
        };

        let start = std::time::Instant::now();
        let result = self.action_executor.execute(decision);
        let latency_us = start.elapsed().as_micros();

        match &result {
            Ok(_) => {
                self.metrics.write().unwrap().record_action_execution(true);
                debug!(
                    decision_id = %decision.id,
                    latency_us = latency_us,
                    "Action executed successfully"
                );
            }
            Err(e) => {
                self.metrics.write().unwrap().record_action_execution(false);
                error!(
                    decision_id = %decision.id,
                    error = %e,
                    "Action execution failed"
                );
            }
        }

        if let Err(e) = ebpf_result {
            warn!(
                decision_id = %decision.id,
                ebpf_error = %e,
                "eBPF enforcement update failed"
            );
        }

        result
    }

    fn capabilities(&self) -> ActionCapabilities {
        self.action_executor.capabilities()
    }

    fn policy(&self) -> ActionPolicy {
        self.config.policy
    }
}

/// Block status for an entity
#[derive(Debug, Clone)]
pub enum BlockStatus {
    NotBlocked,
    Blocked {
        action: ActionType,
        reason: String,
        expires_at: u64,
    },
}

/// Metrics snapshot
#[derive(Debug, Clone)]
pub struct EbpfExecutorMetricsSnapshot {
    pub decisions_total: u64,
    pub decisions_blocked: u64,
    pub decisions_allowed: u64,
    pub decisions_cached: u64,
    pub decisions_rate_limited: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_latency_us: u64,
}

use std::num::NonZeroUsize;

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

trait EntityKeyExtractor {
    fn extract_entity_key(&self) -> u128;
}

impl EntityKeyExtractor for Alert {
    fn extract_entity_key(&self) -> u128 {
        self.context
            .get("entity_key")
            .and_then(|v| v.as_u64())
            .map(|v| v as u128)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_core::{ActionPolicy, NoOpExecutor};

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        assert_eq!(executor.config.policy, ActionPolicy::Inline);
        assert!(executor.config.decision_cache_size > 0);
    }

    #[tokio::test]
    async fn test_make_decision_no_rules() {
        let mut executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        let result = executor.make_decision(&event, &[]).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_make_decision_with_rules() {
        let mut executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        let rules = vec![("test-rule", Severity::High)];
        let result = executor.make_decision(&event, &rules).await.unwrap();

        assert!(result.is_some());
        let decision = result.unwrap();
        assert_eq!(decision.action, ActionType::Block);
    }

    #[tokio::test]
    async fn test_should_block_cached() {
        let mut executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        assert!(!executor.should_block(42));

        let _ = executor.force_block(42, ActionType::Block, "test".to_string(), 60000);

        assert!(executor.should_block(42));
    }

    #[tokio::test]
    async fn test_should_not_block_allow() {
        let mut executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        let _ = executor.force_block(42, ActionType::Allow, "test".to_string(), 60000);

        assert!(!executor.should_block(42));
    }

    #[tokio::test]
    async fn test_unblock() {
        let mut executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        assert!(!executor.should_block(42));

        let _ = executor.force_block(42, ActionType::Block, "test".to_string(), 60000);
        assert!(executor.should_block(42));

        let removed = executor.unblock(42);
        assert!(removed);
        assert!(!executor.should_block(42));
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let mut executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        let _ = executor.force_block(42, ActionType::Block, "test".to_string(), 60000);
        let _ = executor.force_block(43, ActionType::Block, "test".to_string(), 60000);

        assert!(executor.should_block(42));
        assert!(executor.should_block(43));

        executor.clear_cache();

        assert!(!executor.should_block(42));
        assert!(!executor.should_block(43));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(5);

        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }

        assert!(limiter.check().is_err());
    }

    #[test]
    fn test_severity_to_action() {
        let executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        assert_eq!(
            executor.determine_action_from_severity(Severity::Critical),
            ActionType::Kill
        );
        assert_eq!(
            executor.determine_action_from_severity(Severity::High),
            ActionType::Block
        );
        assert_eq!(
            executor.determine_action_from_severity(Severity::Medium),
            ActionType::Alert
        );
        assert_eq!(
            executor.determine_action_from_severity(Severity::Low),
            ActionType::Alert
        );
        assert_eq!(
            executor.determine_action_from_severity(Severity::Informational),
            ActionType::Allow
        );
    }

    #[test]
    fn test_metrics_snapshot() {
        let executor = EbpfExecutor::new(
            Arc::new(NoOpExecutor::default()),
            EbpfExecutorConfig::default(),
        );

        let snapshot = executor.metrics();
        assert_eq!(snapshot.decisions_total, 0);
    }

    #[test]
    fn test_decision_cache_entry() {
        let decision = ActionDecision::new(
            "test-rule".to_string(),
            ActionType::Block,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/test".to_string(),
            },
            "Test".to_string(),
            vec![],
        );

        let entry = DecisionCacheEntry {
            decision,
            expires_at_ns: now_ns() + 60_000_000_000,
            hit_count: 0,
        };

        assert!(entry.expires_at_ns > now_ns());
    }
}
