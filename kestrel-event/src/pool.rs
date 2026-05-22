//! Lock-free event object pool
//!
//! Provides [`EventPool`] for reusing [`Event`] allocations without
//! deallocating, reducing allocation pressure in the hot path.

use crate::Event;
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Statistics for an [`EventPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventPoolStats {
    /// Maximum number of events the pool can hold.
    pub capacity: usize,
    /// Number of events currently available in the pool.
    pub available: usize,
    /// Number of events currently acquired from the pool.
    pub acquired: usize,
    /// Total number of events ever allocated by this pool.
    pub total_allocated: usize,
}

/// A lock-free pool of reusable [`Event`] objects.
///
/// Events are stored directly (not wrapped in `Arc`) to avoid double
/// refcounting. The pool is safe to share across threads.
pub struct EventPool {
    queue: ArrayQueue<Event>,
    capacity: usize,
    total_allocated: AtomicUsize,
    acquired_count: AtomicUsize,
}

impl EventPool {
    /// Create a new pool with the given capacity, pre-allocating event slots.
    pub fn new(capacity: usize) -> Arc<Self> {
        let queue = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            let _ = queue.push(Event::new(0, 0, 0, 0));
        }
        Arc::new(Self {
            queue,
            capacity,
            total_allocated: AtomicUsize::new(capacity),
            acquired_count: AtomicUsize::new(0),
        })
    }

    /// Acquire an event from the pool.
    ///
    /// If the pool has available events, one is reused. Otherwise a new event
    /// is allocated.
    pub fn acquire(self: &Arc<Self>) -> PooledEvent {
        let event = if let Some(mut event) = self.queue.pop() {
            event.clear();
            event
        } else {
            self.total_allocated.fetch_add(1, Ordering::Relaxed);
            Event::new(0, 0, 0, 0)
        };
        self.acquired_count.fetch_add(1, Ordering::AcqRel);
        PooledEvent {
            pool: Arc::clone(self),
            event: Some(event),
        }
    }

    /// Release a pooled event back to the pool.
    ///
    /// The event's fields are cleared before it is returned.
    pub fn release(&self, mut pooled: PooledEvent) {
        if let Some(mut event) = pooled.event.take() {
            event.clear();
            let _ = self.queue.push(event);
            self.acquired_count.fetch_sub(1, Ordering::Release);
        }
    }

    /// Get current pool statistics.
    pub fn stats(&self) -> EventPoolStats {
        EventPoolStats {
            capacity: self.capacity,
            available: self.queue.len(),
            acquired: self.acquired_count.load(Ordering::Acquire),
            total_allocated: self.total_allocated.load(Ordering::Relaxed),
        }
    }
}

/// A smart pointer wrapping an event acquired from an [`EventPool`].
///
/// When dropped, the event is automatically returned to its pool.
pub struct PooledEvent {
    pool: Arc<EventPool>,
    event: Option<Event>,
}

impl PooledEvent {
    /// Convert into an owned [`Event`], removing it from pool management.
    ///
    /// The event will **not** be returned to the pool.
    pub fn into_event(mut self) -> Event {
        self.pool.acquired_count.fetch_sub(1, Ordering::Release);
        self.event.take().expect("event should be present")
    }
}

impl std::ops::Deref for PooledEvent {
    type Target = Event;

    fn deref(&self) -> &Event {
        self.event.as_ref().expect("event should be present")
    }
}

impl std::ops::DerefMut for PooledEvent {
    fn deref_mut(&mut self) -> &mut Event {
        self.event.as_mut().expect("event should be present")
    }
}

impl Drop for PooledEvent {
    fn drop(&mut self) {
        if let Some(mut event) = self.event.take() {
            event.clear();
            let _ = self.pool.queue.push(event);
            self.pool.acquired_count.fetch_sub(1, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_schema::TypedValue;

    #[test]
    fn test_pool_acquire_release_cycle() {
        let pool = EventPool::new(4);
        assert_eq!(pool.stats().available, 4);
        assert_eq!(pool.stats().acquired, 0);

        let mut e1 = pool.acquire();
        e1.event_type_id = 1;
        e1.fields.push((1, TypedValue::I64(42)));

        assert_eq!(pool.stats().acquired, 1);
        assert_eq!(pool.stats().available, 3);

        drop(e1);

        assert_eq!(pool.stats().acquired, 0);
        assert_eq!(pool.stats().available, 4);

        let e2 = pool.acquire();
        assert_eq!(e2.event_type_id, 0); // cleared
        assert!(e2.fields.is_empty()); // cleared
        assert_eq!(pool.stats().acquired, 1);
    }

    #[test]
    fn test_pooled_event_auto_return_on_drop() {
        let pool = EventPool::new(2);
        {
            let mut e = pool.acquire();
            e.event_type_id = 99;
            e.fields.push((5, TypedValue::String("hello".into())));
            assert_eq!(pool.stats().acquired, 1);
            assert_eq!(pool.stats().available, 1);
        }
        assert_eq!(pool.stats().acquired, 0);
        assert_eq!(pool.stats().available, 2);
    }

    #[test]
    fn test_pool_exhaustion_falls_back_to_allocation() {
        let pool = EventPool::new(2);
        let _e1 = pool.acquire();
        let _e2 = pool.acquire();
        assert_eq!(pool.stats().available, 0);
        assert_eq!(pool.stats().acquired, 2);
        assert_eq!(pool.stats().total_allocated, 2);

        // Exhausted: acquire allocates a new event
        let _e3 = pool.acquire();
        assert_eq!(pool.stats().acquired, 3);
        assert_eq!(pool.stats().total_allocated, 3);
    }

    #[test]
    fn test_pooled_event_into_event() {
        let pool = EventPool::new(2);
        let mut e = pool.acquire();
        e.event_type_id = 7;
        let owned = e.into_event();
        assert_eq!(owned.event_type_id, 7);
        assert_eq!(pool.stats().acquired, 0);
        assert_eq!(pool.stats().available, 1); // not returned to pool
    }

    #[test]
    fn test_pool_release_manual() {
        let pool = EventPool::new(2);
        let e = pool.acquire();
        assert_eq!(pool.stats().acquired, 1);
        pool.release(e);
        assert_eq!(pool.stats().acquired, 0);
        assert_eq!(pool.stats().available, 2);
    }

    #[test]
    fn test_pool_stats_accuracy() {
        let pool = EventPool::new(3);
        let stats = pool.stats();
        assert_eq!(stats.capacity, 3);
        assert_eq!(stats.available, 3);
        assert_eq!(stats.acquired, 0);
        assert_eq!(stats.total_allocated, 3);

        let e1 = pool.acquire();
        let e2 = pool.acquire();
        let stats = pool.stats();
        assert_eq!(stats.available, 1);
        assert_eq!(stats.acquired, 2);
        assert_eq!(stats.total_allocated, 3);

        drop(e1);
        drop(e2);
        let stats = pool.stats();
        assert_eq!(stats.available, 3);
        assert_eq!(stats.acquired, 0);
        assert_eq!(stats.total_allocated, 3);
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EventPool>();
        assert_send_sync::<PooledEvent>();
        assert_send_sync::<EventPoolStats>();
    }
}
