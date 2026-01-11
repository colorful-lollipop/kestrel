//! Mock Time Audit API
//!
//! This module provides a controllable time source for testing and replay.
//! It allows the system to return controlled/fixed timestamps instead of real time,
//! which is essential for:
//! - Deterministic testing
//! - Offline replay with reproducible results
//! - Time travel debugging

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Time provider trait
///
/// Abstraction over time sources that allows mocking for testing.
pub trait TimeProvider: Send + Sync {
    /// Get current monotonic timestamp in nanoseconds
    fn mono_ns(&self) -> u64;

    /// Get current wall clock timestamp in nanoseconds
    fn wall_ns(&self) -> u64;

    /// Advance time by a duration (for mock time)
    fn advance(&self, _duration: Duration) {
        // Default implementation does nothing
        // Mock time providers will override this
    }

    /// Set absolute time (for mock time)
    fn set_time(&self, _mono_ns: u64, _wall_ns: u64) {
        // Default implementation does nothing
        // Mock time providers will override this
    }
}

/// Real time provider using system clock
#[derive(Debug, Clone)]
pub struct RealTimeProvider;

impl TimeProvider for RealTimeProvider {
    fn mono_ns(&self) -> u64 {
        // Use std::time::Instant for monotonic time
        // Since Instant::elapsed() gives duration since creation,
        // we need a different approach for absolute monotonic time
        // For now, use UNIX time as approximation
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn wall_ns(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

/// Mock time provider for testing and replay
///
/// Uses atomic counters to provide deterministic time values.
#[derive(Debug, Clone)]
pub struct MockTimeProvider {
    mono: Arc<AtomicU64>,
    wall: Arc<AtomicU64>,
}

impl MockTimeProvider {
    /// Create a new mock time provider starting at zero
    pub fn new() -> Self {
        Self {
            mono: Arc::new(AtomicU64::new(0)),
            wall: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a new mock time provider with specific starting values
    pub fn with_values(mono_ns: u64, wall_ns: u64) -> Self {
        Self {
            mono: Arc::new(AtomicU64::new(mono_ns)),
            wall: Arc::new(AtomicU64::new(wall_ns)),
        }
    }

    /// Get the current monotonic time value
    pub fn get_mono(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }

    /// Get the current wall clock time value
    pub fn get_wall(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }
}

impl Default for MockTimeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeProvider for MockTimeProvider {
    fn mono_ns(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }

    fn wall_ns(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }

    fn advance(&self, duration: Duration) {
        let delta = duration.as_nanos() as u64;
        self.mono.fetch_add(delta, Ordering::SeqCst);
        self.wall.fetch_add(delta, Ordering::SeqCst);
    }

    fn set_time(&self, mono_ns: u64, wall_ns: u64) {
        self.mono.store(mono_ns, Ordering::SeqCst);
        self.wall.store(wall_ns, Ordering::SeqCst);
    }
}

/// Global time manager
///
/// Provides a way to switch between real and mock time sources.
pub struct TimeManager {
    provider: Arc<dyn TimeProvider>,
}

impl TimeManager {
    /// Create a new time manager with real time provider
    pub fn real() -> Self {
        Self {
            provider: Arc::new(RealTimeProvider),
        }
    }

    /// Create a new time manager with mock time provider
    pub fn mock() -> Self {
        Self {
            provider: Arc::new(MockTimeProvider::new()),
        }
    }

    /// Create a new time manager with a specific mock time provider
    pub fn with_mock(mock: MockTimeProvider) -> Self {
        Self {
            provider: Arc::new(mock),
        }
    }

    /// Get current monotonic timestamp in nanoseconds
    pub fn mono_ns(&self) -> u64 {
        self.provider.mono_ns()
    }

    /// Get current wall clock timestamp in nanoseconds
    pub fn wall_ns(&self) -> u64 {
        self.provider.wall_ns()
    }

    /// Get a reference to the inner time provider
    pub fn provider(&self) -> &Arc<dyn TimeProvider> {
        &self.provider
    }
}

impl Clone for TimeManager {
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_time_provider() {
        let provider = RealTimeProvider;
        let mono = provider.mono_ns();
        let wall = provider.wall_ns();

        // Should return non-zero values
        assert!(mono > 0);
        assert!(wall > 0);
    }

    #[test]
    fn test_mock_time_provider_initial() {
        let provider = MockTimeProvider::new();
        assert_eq!(provider.mono_ns(), 0);
        assert_eq!(provider.wall_ns(), 0);
    }

    #[test]
    fn test_mock_time_provider_with_values() {
        let provider = MockTimeProvider::with_values(1000, 2000);
        assert_eq!(provider.mono_ns(), 1000);
        assert_eq!(provider.wall_ns(), 2000);
    }

    #[test]
    fn test_mock_time_provider_advance() {
        let provider = MockTimeProvider::new();

        provider.advance(Duration::from_nanos(500));

        assert_eq!(provider.mono_ns(), 500);
        assert_eq!(provider.wall_ns(), 500);

        provider.advance(Duration::from_nanos(300));

        assert_eq!(provider.mono_ns(), 800);
        assert_eq!(provider.wall_ns(), 800);
    }

    #[test]
    fn test_mock_time_provider_set_time() {
        let provider = MockTimeProvider::new();

        provider.set_time(5000, 6000);

        assert_eq!(provider.mono_ns(), 5000);
        assert_eq!(provider.wall_ns(), 6000);

        // Advance after set
        provider.advance(Duration::from_nanos(1000));

        assert_eq!(provider.mono_ns(), 6000);
        assert_eq!(provider.wall_ns(), 7000);
    }

    #[test]
    fn test_time_manager_real() {
        let manager = TimeManager::real();

        let mono = manager.mono_ns();
        let wall = manager.wall_ns();

        // Should return non-zero values from system clock
        assert!(mono > 0);
        assert!(wall > 0);
    }

    #[test]
    fn test_time_manager_mock() {
        let manager = TimeManager::mock();

        assert_eq!(manager.mono_ns(), 0);
        assert_eq!(manager.wall_ns(), 0);
    }

    #[test]
    fn test_time_manager_clone() {
        let manager1 = TimeManager::mock();
        let manager2 = manager1.clone();

        manager2.provider().advance(Duration::from_nanos(100));

        // Both should share the same underlying mock provider
        assert_eq!(manager1.mono_ns(), 100);
        assert_eq!(manager2.mono_ns(), 100);
    }
}
