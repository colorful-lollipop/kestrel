//! Object Pool for Reducing Allocations
//!
//! This module provides object pooling to reduce heap allocations
//! in hot paths. This is particularly useful for event processing
//! where we need to allocate Vecs and other collections frequently.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A simple object pool for reusable objects
///
/// # Type Parameters
/// * `T` - The type of object to pool. Must implement Default.
pub struct ObjectPool<T: Default> {
    /// Pre-allocated objects
    pool: Mutex<Vec<T>>,
    /// Maximum size of the pool
    max_size: usize,
    /// Current size of the pool (atomic for fast check)
    current_size: AtomicUsize,
    /// Total number of objects created (for metrics)
    total_created: AtomicUsize,
    /// Total number of objects reused (for metrics)
    total_reused: AtomicUsize,
}

impl<T: Default> ObjectPool<T> {
    /// Create a new object pool with the given capacity
    ///
    /// # Arguments
    /// * `initial_capacity` - Initial number of objects to pre-allocate
    /// * `max_size` - Maximum number of objects to keep in the pool
    pub fn new(initial_capacity: usize, max_size: usize) -> Self {
        let mut pool = Vec::with_capacity(initial_capacity);
        for _ in 0..initial_capacity {
            pool.push(T::default());
        }

        Self {
            pool: Mutex::new(pool),
            max_size,
            current_size: AtomicUsize::new(initial_capacity),
            total_created: AtomicUsize::new(initial_capacity),
            total_reused: AtomicUsize::new(0),
        }
    }

    /// Acquire an object from the pool
    ///
    /// If the pool is empty, creates a new object.
    /// Returns the object and a guard that returns it to the pool when dropped.
    pub fn acquire(&self) -> PooledObject<T> {
        let obj = {
            let mut pool = self.pool.lock().unwrap();
            if let Some(obj) = pool.pop() {
                self.current_size.fetch_sub(1, Ordering::Relaxed);
                self.total_reused.fetch_add(1, Ordering::Relaxed);
                obj
            } else {
                drop(pool);
                self.total_created.fetch_add(1, Ordering::Relaxed);
                T::default()
            }
        };

        PooledObject {
            obj: Some(obj),
            pool: self,
        }
    }

    /// Try to acquire an object from the pool without blocking
    ///
    /// Returns None if the pool lock is poisoned.
    pub fn try_acquire(&self) -> Option<PooledObject<T>> {
        let mut pool = self.pool.lock().ok()?;
        if let Some(obj) = pool.pop() {
            drop(pool);
            self.current_size.fetch_sub(1, Ordering::Relaxed);
            self.total_reused.fetch_add(1, Ordering::Relaxed);
            Some(PooledObject {
                obj: Some(obj),
                pool: self,
            })
        } else {
            drop(pool);
            self.total_created.fetch_add(1, Ordering::Relaxed);
            Some(PooledObject {
                obj: Some(T::default()),
                pool: self,
            })
        }
    }

    /// Return an object to the pool
    ///
    /// If the pool is at capacity, the object is dropped.
    fn release(&self, mut obj: T) {
        // Only keep objects if we're under the max size
        let current = self.current_size.load(Ordering::Relaxed);
        if current < self.max_size {
            // Clear/reset the object before returning to pool
            obj = T::default();

            if let Ok(mut pool) = self.pool.lock() {
                pool.push(obj);
                self.current_size.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get pool metrics
    pub fn metrics(&self) -> PoolMetrics {
        PoolMetrics {
            current_size: self.current_size.load(Ordering::Relaxed),
            max_size: self.max_size,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_reused: self.total_reused.load(Ordering::Relaxed),
        }
    }

    /// Get the number of available objects in the pool
    pub fn available(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }
}

/// Metrics for the object pool
#[derive(Debug, Clone, Copy)]
pub struct PoolMetrics {
    /// Current number of objects in the pool
    pub current_size: usize,
    /// Maximum pool size
    pub max_size: usize,
    /// Total number of objects created
    pub total_created: usize,
    /// Total number of objects reused from pool
    pub total_reused: usize,
}

impl PoolMetrics {
    /// Calculate reuse rate (0.0 to 1.0)
    pub fn reuse_rate(&self) -> f64 {
        let total = self.total_created + self.total_reused;
        if total == 0 {
            0.0
        } else {
            self.total_reused as f64 / total as f64
        }
    }
}

/// A pooled object that returns to the pool when dropped
pub struct PooledObject<'a, T: Default> {
    obj: Option<T>,
    pool: &'a ObjectPool<T>,
}

impl<'a, T: Default> PooledObject<'a, T> {
    /// Get a reference to the object
    pub fn get(&self) -> &T {
        self.obj.as_ref().unwrap()
    }

    /// Get a mutable reference to the object
    pub fn get_mut(&mut self) -> &mut T {
        self.obj.as_mut().unwrap()
    }

    /// Take ownership of the object (prevents it from returning to pool)
    pub fn take(mut self) -> T {
        self.obj.take().unwrap()
    }
}

impl<'a, T: Default> std::ops::Deref for PooledObject<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<'a, T: Default> std::ops::DerefMut for PooledObject<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

impl<'a, T: Default> Drop for PooledObject<'a, T> {
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            self.pool.release(obj);
        }
    }
}

/// Specialized pool for Vec<Event> to reduce allocations in EventBus
pub type EventVecPool = ObjectPool<Vec<kestrel_event::Event>>;

impl EventVecPool {
    /// Create a new pool for event vectors with specified capacity
    pub fn for_events(initial_capacity: usize, max_size: usize, vec_capacity: usize) -> Self {
        let mut pool = Vec::with_capacity(initial_capacity);
        for _ in 0..initial_capacity {
            pool.push(Vec::with_capacity(vec_capacity));
        }

        Self {
            pool: Mutex::new(pool),
            max_size,
            current_size: AtomicUsize::new(initial_capacity),
            total_created: AtomicUsize::new(initial_capacity),
            total_reused: AtomicUsize::new(0),
        }
    }
}

/// Global pool manager for sharing pools across components
pub struct PoolManager {
    /// Pool for event batches
    pub event_batch_pool: Option<Arc<EventVecPool>>,
}

use std::sync::Arc;

impl PoolManager {
    /// Create a new pool manager with default pools
    pub fn new() -> Self {
        Self {
            event_batch_pool: Some(Arc::new(EventVecPool::for_events(16, 64, 100))),
        }
    }

    /// Create a pool manager without pools (allocations always happen)
    pub fn empty() -> Self {
        Self {
            event_batch_pool: None,
        }
    }
}

impl Default for PoolManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_basic() {
        let pool = ObjectPool::<Vec<u32>>::new(2, 4);

        // Acquire from initial pool
        let obj1 = pool.acquire();
        assert_eq!(pool.available(), 1);

        // Acquire another
        let obj2 = pool.acquire();
        assert_eq!(pool.available(), 0);

        // Acquire creates new
        let obj3 = pool.acquire();
        assert_eq!(pool.available(), 0);

        // Drop returns to pool
        drop(obj1);
        assert_eq!(pool.available(), 1);

        drop(obj2);
        drop(obj3);
        assert_eq!(pool.available(), 3); // But max is 4

        // Check metrics
        let metrics = pool.metrics();
        assert_eq!(metrics.current_size, 3);
        assert_eq!(metrics.max_size, 4);
        assert!(metrics.total_created >= 3);
    }

    #[test]
    fn test_pooled_object_deref() {
        let pool = ObjectPool::<Vec<u32>>::new(1, 2);
        
        let mut obj = pool.acquire();
        obj.get_mut().push(42);
        
        assert_eq!(obj.get()[0], 42);
        assert_eq!(obj.len(), 1);
    }

    #[test]
    fn test_reuse_rate() {
        let pool = ObjectPool::<Vec<u32>>::new(10, 20);

        // Acquire and release many times
        for _ in 0..100 {
            let obj = pool.acquire();
            drop(obj);
        }

        let metrics = pool.metrics();
        assert!(metrics.reuse_rate() > 0.8, "Should have high reuse rate");
    }
}
