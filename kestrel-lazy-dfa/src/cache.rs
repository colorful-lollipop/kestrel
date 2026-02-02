// DFA Cache - LRU cache for compiled DFAs
//
// Manages a cache of compiled DFAs with memory limits and LRU eviction.

use crate::dfa::LazyDfa;
use crate::{LazyDfaError, LazyDfaResult};
use lru::LruCache;
use parking_lot::RwLock;

/// Configuration for the DFA cache
#[derive(Debug, Clone)]
pub struct DfaCacheConfig {
    /// Maximum number of DFAs to cache
    pub max_dfas: usize,

    /// Maximum total memory for all DFAs (in bytes)
    pub max_total_memory: usize,

    /// Memory threshold for eviction (0.0 - 1.0)
    /// When memory usage exceeds this fraction, evict LRU entries
    pub memory_eviction_threshold: f64,
}

impl Default for DfaCacheConfig {
    fn default() -> Self {
        Self {
            max_dfas: 100,
            max_total_memory: 10 * 1024 * 1024, // 10MB
            memory_eviction_threshold: 0.8,
        }
    }
}

/// Cache entry with metadata
struct CacheEntry {
    /// The cached DFA
    dfa: LazyDfa,

    /// Last access time (for LRU eviction)
    last_access: std::time::Instant,

    /// Access count
    access_count: usize,
}

impl CacheEntry {
    fn new(dfa: LazyDfa) -> Self {
        Self {
            dfa,
            last_access: std::time::Instant::now(),
            access_count: 0,
        }
    }

    fn memory_usage(&self) -> usize {
        self.dfa.memory_usage()
    }
}

/// DFA cache with LRU eviction
pub struct DfaCache {
    /// LRU cache of sequence_id -> CacheEntry
    cache: RwLock<LruCache<String, CacheEntry>>,

    /// Configuration
    config: DfaCacheConfig,

    /// Current total memory usage
    memory_usage: RwLock<usize>,
}

impl DfaCache {
    pub fn new(config: DfaCacheConfig) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(config.max_dfas).unwrap(),
            )),
            config,
            memory_usage: RwLock::new(0),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(DfaCacheConfig::default())
    }

    /// Insert a DFA into the cache
    pub fn insert(&self, sequence_id: String, dfa: LazyDfa) -> LazyDfaResult<()> {
        // Check memory limit before insertion
        let memory = dfa.memory_usage();
        if memory > self.config.max_total_memory {
            return Err(LazyDfaError::MemoryLimitExceeded {
                size: memory,
                max: self.config.max_total_memory,
            });
        }

        // Evict if necessary
        self.ensure_memory_available(memory)?;

        // Insert the DFA
        let entry = CacheEntry::new(dfa);
        {
            let mut cache = self.cache.write();
            cache.put(sequence_id.clone(), entry);
        }

        // Update memory usage
        *self.memory_usage.write() += memory;

        Ok(())
    }

    /// Get a DFA from the cache
    pub fn get(&self, sequence_id: &str) -> Option<LazyDfa> {
        let mut cache = self.cache.write();
        if let Some(entry) = cache.get_mut(sequence_id) {
            entry.last_access = std::time::Instant::now();
            entry.access_count += 1;
            Some(entry.dfa.clone())
        } else {
            None
        }
    }

    /// Check if a DFA is cached
    pub fn contains(&self, sequence_id: &str) -> bool {
        let cache = self.cache.read();
        cache.contains(sequence_id)
    }

    /// Remove a DFA from the cache
    pub fn remove(&self, sequence_id: &str) -> Option<usize> {
        let mut cache = self.cache.write();
        if let Some(entry) = cache.pop(sequence_id) {
            let memory = entry.memory_usage();
            *self.memory_usage.write() = memory.saturating_sub(memory);
            Some(memory)
        } else {
            None
        }
    }

    /// Clear the cache
    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();
        *self.memory_usage.write() = 0;
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        let memory = *self.memory_usage.read();

        CacheStats {
            count: cache.len(),
            memory_usage: memory,
            memory_limit: self.config.max_total_memory,
            max_count: self.config.max_dfas,
        }
    }

    /// Ensure enough memory is available by evicting LRU entries
    fn ensure_memory_available(&self, required: usize) -> LazyDfaResult<()> {
        let current = *self.memory_usage.read();
        let _available = self.config.max_total_memory.saturating_sub(current);
        let threshold = (self.config.max_total_memory as f64 * self.config.memory_eviction_threshold) as usize;

        // If we're below threshold, no need to evict
        if current + required < threshold {
            return Ok(());
        }

        // Need to evict
        let to_free = (current + required).saturating_sub(threshold);
        let mut freed = 0;

        let mut cache = self.cache.write();

        while freed < to_free && !cache.is_empty() {
            if let Some((_, entry)) = cache.pop_lru() {
                freed += entry.memory_usage();
            }
        }

        // Update memory usage
        *self.memory_usage.write() = current.saturating_sub(freed);

        Ok(())
    }

    /// Get the number of cached DFAs
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cached DFAs
    pub count: usize,

    /// Current memory usage
    pub memory_usage: usize,

    /// Memory limit
    pub memory_limit: usize,

    /// Maximum number of DFAs
    pub max_count: usize,
}

impl CacheStats {
    pub fn memory_usage_ratio(&self) -> f64 {
        if self.memory_limit == 0 {
            0.0
        } else {
            self.memory_usage as f64 / self.memory_limit as f64
        }
    }

    pub fn count_ratio(&self) -> f64 {
        if self.max_count == 0 {
            0.0
        } else {
            self.count as f64 / self.max_count as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = DfaCache::with_default_config();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_insert_get() {
        let cache = DfaCache::with_default_config();

        let dfa = LazyDfa::new("seq-1".to_string(), 2);
        cache.insert("seq-1".to_string(), dfa).unwrap();

        assert_eq!(cache.len(), 1);
        assert!(cache.contains("seq-1"));

        let retrieved = cache.get("seq-1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().sequence_id(), "seq-1");
    }

    #[test]
    fn test_cache_stats() {
        let cache = DfaCache::with_default_config();
        let mut dfa = LazyDfa::new("seq-1".to_string(), 2);
        // Add a state to ensure memory usage is calculated
        dfa.add_state(vec![0, 1]);

        cache.insert("seq-1".to_string(), dfa).unwrap();

        let stats = cache.stats();
        assert_eq!(stats.count, 1);
        assert!(stats.memory_usage > 0);
    }

    #[test]
    fn test_cache_remove() {
        let cache = DfaCache::with_default_config();
        let dfa = LazyDfa::new("seq-1".to_string(), 2);

        cache.insert("seq-1".to_string(), dfa).unwrap();
        assert!(cache.contains("seq-1"));

        cache.remove("seq-1");
        assert!(!cache.contains("seq-1"));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_clear() {
        let cache = DfaCache::with_default_config();

        cache.insert("seq-1".to_string(), LazyDfa::new("seq-1".to_string(), 2)).unwrap();
        cache.insert("seq-2".to_string(), LazyDfa::new("seq-2".to_string(), 2)).unwrap();

        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_lru_eviction() {
        let config = DfaCacheConfig {
            max_dfas: 2,
            max_total_memory: 1024 * 1024,
            memory_eviction_threshold: 0.8,
        };
        let cache = DfaCache::new(config);

        // Insert 3 DFAs (exceeds max_dfas)
        cache.insert("seq-1".to_string(), LazyDfa::new("seq-1".to_string(), 1)).unwrap();
        cache.insert("seq-2".to_string(), LazyDfa::new("seq-2".to_string(), 1)).unwrap();
        cache.insert("seq-3".to_string(), LazyDfa::new("seq-3".to_string(), 1)).unwrap();

        // Should only have 2 due to LRU eviction
        assert_eq!(cache.len(), 2);
        assert!(cache.contains("seq-2"));
        assert!(cache.contains("seq-3"));
        // seq-1 should have been evicted
        assert!(!cache.contains("seq-1"));
    }

    #[test]
    fn test_stats_ratios() {
        let stats = CacheStats {
            count: 50,
            memory_usage: 5 * 1024 * 1024,
            memory_limit: 10 * 1024 * 1024,
            max_count: 100,
        };

        assert_eq!(stats.memory_usage_ratio(), 0.5);
        assert_eq!(stats.count_ratio(), 0.5);
    }
}
