// StateStore - Manages partial match state with TTL/LRU/quota
//
// This module provides efficient state storage and management for partial matches:
// - Time-based eviction (TTL via maxspan)
// - LRU eviction under memory pressure
// - Per-sequence and per-entity quotas
// - Sharded storage for parallelism

use crate::metrics::EvictionReason;
use crate::state::{NfaStateId, PartialMatch};
use crate::{NfaError, NfaResult};
use ahash::AHashMap;
use parking_lot::RwLock;
use priority_queue::PriorityQueue;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the state store
#[derive(Debug, Clone)]
pub struct StateStoreConfig {
    /// Maximum number of partial matches per sequence (0 = unlimited)
    pub max_partial_matches_per_sequence: usize,

    /// Maximum number of partial matches per entity (0 = unlimited)
    pub max_partial_matches_per_entity: usize,

    /// Maximum total partial matches across all sequences (0 = unlimited)
    pub max_total_partial_matches: usize,

    /// LRU eviction threshold (as percentage of max_total)
    /// When exceeding this, trigger LRU eviction
    pub lru_eviction_threshold: f32,

    /// Cleanup interval for expired states
    pub cleanup_interval: Duration,

    /// Default maxspan for cleanup (in milliseconds)
    /// Sequences without a maxspan will use this value for cleanup
    pub default_maxspan_ms: u64,
}

impl Default for StateStoreConfig {
    fn default() -> Self {
        Self {
            max_partial_matches_per_sequence: 10_000,
            max_partial_matches_per_entity: 100,
            max_total_partial_matches: 1_000_000,
            lru_eviction_threshold: 0.9, // Trigger LRU at 90% capacity
            cleanup_interval: Duration::from_secs(5),
            default_maxspan_ms: 60_000, // 1 minute default
        }
    }
}

/// Per-entity quota configuration
#[derive(Debug, Clone)]
pub struct QuotaConfig {
    /// Maximum partial matches per entity
    pub max_per_entity: usize,

    /// Maximum partial matches per sequence
    pub max_per_sequence: usize,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_per_entity: 100,
            max_per_sequence: 10_000,
        }
    }
}

/// A shard of the state store
///
/// State is sharded by entity key to reduce lock contention
/// and enable parallel processing.
#[derive(Debug)]
struct StateShard {
    /// Partial matches indexed by (sequence_id, entity_key, state_id)
    matches: AHashMap<(String, u128, NfaStateId), PartialMatch>,

    /// LRU queue ordered by last access time
    /// Key: (sequence_id, entity_key, state_id)
    /// Priority: timestamp (lower = older, higher eviction priority)
    lru_queue: PriorityQueue<(String, u128, NfaStateId), u64>,

    /// Per-entity match count (for quota enforcement)
    entity_counts: AHashMap<(String, u128), usize>,

    /// Per-sequence match count
    sequence_counts: AHashMap<String, usize>,
}

impl StateShard {
    fn new() -> Self {
        Self {
            matches: AHashMap::default(),
            lru_queue: PriorityQueue::new(),
            entity_counts: AHashMap::default(),
            sequence_counts: AHashMap::default(),
        }
    }

    fn insert(
        &mut self,
        key: (String, u128, NfaStateId),
        match_state: PartialMatch,
        timestamp: u64,
    ) {
        self.entity_counts
            .entry((key.0.clone(), key.1))
            .and_modify(|c| *c += 1)
            .or_insert(1);

        self.sequence_counts
            .entry(key.0.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);

        self.matches.insert(key.clone(), match_state);
        self.lru_queue.push(key, timestamp);
    }

    fn remove(&mut self, key: &(String, u128, NfaStateId)) -> Option<PartialMatch> {
        let match_state = self.matches.remove(key)?;
        self.lru_queue.remove(key);

        let entity_key = (key.0.clone(), key.1);
        if let Some(count) = self.entity_counts.get_mut(&entity_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.entity_counts.remove(&entity_key);
            }
        }

        let seq_id = &key.0;
        if let Some(count) = self.sequence_counts.get_mut(seq_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.sequence_counts.remove(seq_id);
            }
        }

        Some(match_state)
    }

    fn get(&self, key: &(String, u128, NfaStateId)) -> Option<&PartialMatch> {
        self.matches.get(key)
    }

    fn get_entity_count(&self, sequence_id: &str, entity_key: u128) -> usize {
        self.entity_counts
            .get(&(sequence_id.to_string(), entity_key))
            .copied()
            .unwrap_or(0)
    }

    fn get_sequence_count(&self, sequence_id: &str) -> usize {
        self.sequence_counts.get(sequence_id).copied().unwrap_or(0)
    }

    fn total_matches(&self) -> usize {
        self.matches.len()
    }
}

impl Default for StateShard {
    fn default() -> Self {
        Self::new()
    }
}

/// StateStore - manages partial match state with TTL/LRU/quota
///
/// State is sharded across multiple shards to reduce lock contention.
/// The default shard count is 16, which provides a good balance between
/// memory overhead and parallelism.
#[derive(Debug)]
pub struct StateStore {
    /// Shards indexed by entity_key % num_shards
    shards: Vec<RwLock<StateShard>>,

    /// Number of shards
    num_shards: usize,

    /// Configuration
    config: StateStoreConfig,
}

impl StateStore {
    /// Create a new state store with default configuration
    pub fn new(config: StateStoreConfig) -> Self {
        let num_shards = 16; // Default shard count
        let shards = (0..num_shards)
            .map(|_| RwLock::new(StateShard::new()))
            .collect();

        Self {
            shards,
            num_shards,
            config,
        }
    }

    /// Get the shard index for a given entity key
    fn get_shard_index(&self, entity_key: u128) -> usize {
        (entity_key as usize) % self.num_shards
    }

    /// Insert or update a partial match
    pub fn insert(&self, match_state: PartialMatch) -> NfaResult<()> {
        let sequence_id = match_state.sequence_id.clone();
        let entity_key = match_state.entity_key;
        let state_id = match_state.current_state;
        let key = (sequence_id, entity_key, state_id);
        let timestamp = match_state.last_match_ns;

        // Check quota before inserting
        self.check_quota(&key)?;

        let shard_idx = self.get_shard_index(entity_key);
        let mut shard = self.shards[shard_idx].write();

        shard.insert(key, match_state, timestamp);
        Ok(())
    }

    /// Remove a partial match
    pub fn remove(
        &self,
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
    ) -> Option<PartialMatch> {
        let shard_idx = self.get_shard_index(entity_key);
        let key = (sequence_id.to_string(), entity_key, state_id);
        let mut shard = self.shards[shard_idx].write();
        shard.remove(&key)
    }

    /// Get a partial match
    pub fn get(
        &self,
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
    ) -> Option<PartialMatch> {
        let shard_idx = self.get_shard_index(entity_key);
        let key = (sequence_id.to_string(), entity_key, state_id);
        let shard = self.shards[shard_idx].read();
        shard.get(&key).cloned()
    }

    /// Check if inserting would violate quota
    fn check_quota(&self, key: &(String, u128, NfaStateId)) -> NfaResult<()> {
        let shard_idx = self.get_shard_index(key.1);
        let shard = self.shards[shard_idx].read();

        // Check per-entity quota
        let entity_count = shard.get_entity_count(&key.0, key.1);
        if entity_count >= self.config.max_partial_matches_per_entity {
            return Err(NfaError::QuotaExceeded {
                rule_id: key.0.clone(),
                reason: format!(
                    "entity quota exceeded: {} >= {}",
                    entity_count, self.config.max_partial_matches_per_entity
                ),
            });
        }

        // Check per-sequence quota
        let seq_count = shard.get_sequence_count(&key.0);
        if seq_count >= self.config.max_partial_matches_per_sequence {
            return Err(NfaError::QuotaExceeded {
                rule_id: key.0.clone(),
                reason: format!(
                    "sequence quota exceeded: {} >= {}",
                    seq_count, self.config.max_partial_matches_per_sequence
                ),
            });
        }

        Ok(())
    }

    /// Cleanup expired partial matches based on maxspan
    /// Takes maxspan_ms as a parameter since the store doesn't track per-sequence maxspan
    pub fn cleanup_expired(&self, now_ns: u64, maxspan_ms: u64) -> Vec<PartialMatch> {
        let mut expired = Vec::new();
        let maxspan_ns = maxspan_ms * 1_000_000;

        for shard in &self.shards {
            let mut shard_write = shard.write();
            let keys_to_remove: Vec<_> = shard_write
                .matches
                .iter()
                .filter(|(_, pm)| {
                    pm.terminated || {
                        let elapsed = now_ns.saturating_sub(pm.created_ns);
                        elapsed > maxspan_ns
                    }
                })
                .map(|(key, _)| key.clone())
                .collect();

            for key in keys_to_remove {
                if let Some(pm) = shard_write.remove(&key) {
                    expired.push(pm);
                }
            }
        }

        expired
    }

    /// Evict LRU entries if we're over capacity
    pub fn evict_lru(&self, count: usize) -> Vec<PartialMatch> {
        let mut evicted = Vec::new();

        // For simplicity, evict from each shard proportionally
        let per_shard = (count / self.num_shards) + 1;

        for shard in &self.shards {
            let mut shard_write = shard.write();

            for _ in 0..per_shard {
                if let Some((key, _)) = shard_write.lru_queue.pop() {
                    if let Some(pm) = shard_write.remove(&key) {
                        evicted.push(pm);
                    }
                }
            }
        }

        evicted
    }

    /// Get total number of partial matches across all shards
    pub fn total_matches(&self) -> usize {
        self.shards.iter().map(|s| s.read().total_matches()).sum()
    }

    /// Get configuration
    pub fn config(&self) -> &StateStoreConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{NfaSequence, PartialMatch};
    use kestrel_event::Event;

    fn create_test_partial_match(
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
    ) -> PartialMatch {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(entity_key)
            .build()
            .expect("failed to build test event");

        PartialMatch::new(sequence_id.to_string(), entity_key, event, state_id)
    }

    #[test]
    fn test_state_store_insert_get() {
        let config = StateStoreConfig::default();
        let store = StateStore::new(config);

        let pm = create_test_partial_match("seq1", 12345, 0);
        store.insert(pm.clone()).unwrap();

        let retrieved = store.get("seq1", 12345, 0);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().entity_key, 12345);
    }

    #[test]
    fn test_state_store_remove() {
        let config = StateStoreConfig::default();
        let store = StateStore::new(config);

        let pm = create_test_partial_match("seq1", 12345, 0);
        store.insert(pm).unwrap();

        let removed = store.remove("seq1", 12345, 0);
        assert!(removed.is_some());

        let retrieved = store.get("seq1", 12345, 0);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_entity_quota() {
        let mut config = StateStoreConfig::default();
        config.max_partial_matches_per_entity = 2;

        let store = StateStore::new(config);

        // Insert first match
        let pm1 = create_test_partial_match("seq1", 12345, 0);
        store.insert(pm1).unwrap();

        // Insert second match
        let pm2 = create_test_partial_match("seq1", 12345, 1);
        store.insert(pm2).unwrap();

        // Third match should exceed quota
        let pm3 = create_test_partial_match("seq1", 12345, 2);
        let result = store.insert(pm3);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NfaError::QuotaExceeded { .. }
        ));
    }

    #[test]
    fn test_sequence_quota() {
        let mut config = StateStoreConfig::default();
        config.max_partial_matches_per_sequence = 2;

        let store = StateStore::new(config);

        // Use entities that hash to the same shard (same entity key % num_shards)
        // With 16 shards, we can use entities that are multiples of 16
        let base_entity = 0; // All will hash to shard 0

        // Insert first state (entity 0, state 0)
        let pm1 = create_test_partial_match("seq1", base_entity, 0);
        store.insert(pm1).unwrap();

        // Insert second state (entity 0, state 1)
        let pm2 = create_test_partial_match("seq1", base_entity, 1);
        store.insert(pm2).unwrap();

        // Insert third state (entity 0, state 2) - this should exceed sequence quota
        let pm3 = create_test_partial_match("seq1", base_entity, 2);
        let result = store.insert(pm3);
        assert!(result.is_err());
    }

    #[test]
    fn test_total_matches() {
        let config = StateStoreConfig::default();
        let store = StateStore::new(config);

        assert_eq!(store.total_matches(), 0);

        store
            .insert(create_test_partial_match("seq1", 11111, 0))
            .unwrap();
        store
            .insert(create_test_partial_match("seq1", 22222, 0))
            .unwrap();
        store
            .insert(create_test_partial_match("seq2", 33333, 0))
            .unwrap();

        assert_eq!(store.total_matches(), 3);
    }
}
