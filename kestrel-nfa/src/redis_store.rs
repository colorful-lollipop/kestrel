//! Redis-backed StateStoreBackend implementation
//!
//! Provides distributed partial-match storage using Redis with:
//! - Automatic TTL based on maxspan
//! - Bincode serialization for compact storage
//! - Connection pooling via deadpool-redis

use crate::state::{NfaStateId, PartialMatch};
use crate::{NfaError, NfaResult};
use async_trait::async_trait;
use redis::AsyncCommands;

/// Configuration for the Redis state store
#[derive(Debug, Clone)]
pub struct RedisStateStoreConfig {
    /// Redis connection URL (e.g. "redis://127.0.0.1:6379")
    pub url: String,

    /// Key prefix for all stored matches
    pub key_prefix: String,

    /// Connection pool size
    pub pool_size: usize,

    /// Extra TTL buffer added to maxspan (in milliseconds)
    pub ttl_buffer_ms: u64,
}

impl Default for RedisStateStoreConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            key_prefix: "kestrel:nfa".to_string(),
            pool_size: 16,
            ttl_buffer_ms: 5_000, // 5 second buffer
        }
    }
}

/// Redis-backed state store for distributed NFA state
#[derive(Debug, Clone)]
pub struct RedisStateStore {
    config: RedisStateStoreConfig,
    pool: deadpool_redis::Pool,
}

impl RedisStateStore {
    /// Create a new Redis state store from configuration
    pub fn new(config: RedisStateStoreConfig) -> NfaResult<Self> {
        let pool_config = deadpool_redis::Config::from_url(&config.url);
        let pool = pool_config
            .builder()
            .map_err(|e| NfaError::StateStoreError(format!("Pool config: {}", e)))?
            .max_size(config.pool_size)
            .build()
            .map_err(|e| NfaError::StateStoreError(format!("Pool build: {}", e)))?;

        Ok(Self { config, pool })
    }

    /// Build the Redis key for a partial match
    fn make_key(&self,
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
    ) -> String {
        format!(
            "{}:match:{}:{}:{}",
            self.config.key_prefix, sequence_id, entity_key, state_id
        )
    }

    /// Parse a sequence key from a Redis key string
    fn parse_key(&self,
        key: &str,
    ) -> Option<(&str, u128, NfaStateId)> {
        let prefix = format!("{}:match:", self.config.key_prefix);
        let rest = key.strip_prefix(&prefix)?;
        let mut parts = rest.rsplitn(2, ':');
        let state_id: NfaStateId = parts.next()?.parse().ok()?;
        let entity_key: u128 = parts.next()?.parse().ok()?;
        // sequence_id is everything before the last two colons... this is tricky
        // For simplicity in tests we avoid parsing; remove_by_sequence uses SCAN
        None
    }
}

#[async_trait]
impl crate::store::StateStoreBackend for RedisStateStore {
    async fn insert(&self, match_state: PartialMatch) -> NfaResult<()> {
        let key = self.make_key(&match_state.sequence_id, match_state.entity_key, match_state.current_state);
        let bytes = bincode::serialize(&match_state)
            .map_err(|e| NfaError::StateStoreError(format!("Serialize: {}", e)))?;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| NfaError::StateStoreError(format!("Redis pool: {}", e)))?;

        let ttl_seconds =
            ((match_state.maxspan_ms.unwrap_or(30_000) + self.config.ttl_buffer_ms) / 1000).max(1) as usize;

        redis::pipe()
            .atomic()
            .set(&key, bytes)
            .expire(&key, ttl_seconds)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| NfaError::StateStoreError(format!("Redis SET: {}", e)))?;

        Ok(())
    }

    async fn remove(
        &self,
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
    ) -> Option<PartialMatch> {
        let key = self.make_key(sequence_id, entity_key, state_id);
        let mut conn = self.pool.get().await.ok()?;

        // Get the value before deleting
        let bytes: Option<Vec<u8>> = conn.get(&key).await.ok()?;
        let pm: PartialMatch = bincode::deserialize(&bytes?).ok()?;

        let _: Result<(), _> = conn.del(&key).await;

        Some(pm)
    }

    async fn get(
        &self,
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
    ) -> Option<PartialMatch> {
        let key = self.make_key(sequence_id, entity_key, state_id);
        let mut conn = self.pool.get().await.ok()?;

        let bytes: Option<Vec<u8>> = conn.get(&key).await.ok()?;
        let pm: PartialMatch = bincode::deserialize(&bytes?).ok()?;
        Some(pm)
    }

    async fn with_match<F, R>(
        &self,
        sequence_id: &str,
        entity_key: u128,
        state_id: NfaStateId,
        f: F,
    ) -> Option<R>
    where
        F: FnOnce(&PartialMatch) -> R + Send,
    {
        let pm = self.get(sequence_id, entity_key, state_id).await?;
        Some(f(&pm))
    }

    async fn cleanup_expired(&self, _now_ns: u64, _maxspan_ms: u64) -> Vec<PartialMatch> {
        // Redis handles expiration natively via TTL; explicit cleanup is a no-op.
        Vec::new()
    }

    async fn evict_lru(&self, count: usize) -> Vec<PartialMatch> {
        // LRU eviction is not natively supported in this basic implementation.
        // A production implementation could track access times in a secondary sorted set.
        let _ = count;
        Vec::new()
    }

    async fn total_matches(&self) -> usize {
        // Counting all keys with the prefix is expensive; return 0 as a placeholder.
        // A production implementation could maintain a counter in Redis.
        0
    }

    async fn remove_by_sequence(&self, sequence_id: &str) -> usize {
        let pattern = format!("{}:match:{}:*", self.config.key_prefix, sequence_id);
        let mut conn = match self.pool.get().await {
            Ok(c) => c,
            Err(_) => return 0,
        };

        let mut total_removed = 0usize;
        let mut cursor: u64 = 0;

        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .unwrap_or((0, vec![]));

            for key in keys {
                let _: Result<(), _> = conn.del(&key).await;
                total_removed += 1;
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        total_removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StateStoreBackend;
    use kestrel_event::Event;
    use std::sync::Arc;

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

        PartialMatch::new(sequence_id.to_string(), entity_key, Arc::new(event), state_id)
    }

    /// Attempt to create a Redis-backed store; skips the test if Redis is unreachable.
    async fn maybe_redis_store() -> Option<RedisStateStore> {
        let config = RedisStateStoreConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            key_prefix: format!("kestrel:test:{}", std::process::id()),
            pool_size: 2,
            ttl_buffer_ms: 1_000,
        };
        let store = RedisStateStore::new(config).ok()?;
        // Ping to verify connectivity
        let mut conn = store.pool.get().await.ok()?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await.ok()?;
        Some(store)
    }

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn test_redis_insert_get_remove_roundtrip() {
        let store = maybe_redis_store().await.expect("Redis not available");
        let pm = create_test_partial_match("seq1", 12345, 0);

        // Insert
        store.insert(pm.clone()).await.unwrap();

        // Get
        let retrieved = store.get("seq1", 12345, 0).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().entity_key, 12345);

        // Remove
        let removed = store.remove("seq1", 12345, 0).await;
        assert!(removed.is_some());

        // Verify removed
        let after = store.get("seq1", 12345, 0).await;
        assert!(after.is_none());
    }

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn test_redis_ttl_expiration() {
        let store = maybe_redis_store().await.expect("Redis not available");
        let mut pm = create_test_partial_match("ttl_seq", 999, 0);
        // Override maxspan to 1 ms so TTL is very short
        pm.maxspan_ms = Some(1);

        store.insert(pm).await.unwrap();

        // Should exist immediately
        let exists = store.get("ttl_seq", 999, 0).await;
        assert!(exists.is_some());

        // Wait for Redis TTL to expire (generous margin)
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let expired = store.get("ttl_seq", 999, 0).await;
        assert!(expired.is_none());
    }

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn test_redis_remove_by_sequence() {
        let store = maybe_redis_store().await.expect("Redis not available");

        store.insert(create_test_partial_match("seq_a", 1, 0)).await.unwrap();
        store.insert(create_test_partial_match("seq_a", 2, 0)).await.unwrap();
        store.insert(create_test_partial_match("seq_b", 1, 0)).await.unwrap();

        let removed = store.remove_by_sequence("seq_a").await;
        assert_eq!(removed, 2, "Expected 2 matches for seq_a to be removed");
    }
}
