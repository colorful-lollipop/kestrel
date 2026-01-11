//! Interest Pushdown
//!
//! Implements rule interest pushdown to filter events at the kernel level.
//! This reduces CPU usage by only sending events that rules care about.

use crate::EbpfEventType;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use tracing::debug;

/// Interest pushdown configuration
///
/// Tracks which event types and fields are needed by loaded rules.
pub struct InterestPushdown {
    /// Event types that rules are interested in
    event_types: RwLock<HashSet<EbpfEventType>>,

    /// Field interests per event type
    /// Maps event type to set of field IDs that rules need
    field_interests: RwLock<HashMap<u32, HashSet<u32>>>,

    /// Predicate filters per event type
    /// Simple filters that can be applied in eBPF
    predicate_filters: RwLock<HashMap<u32, Vec<PredicateFilter>>>,
}

/// Simple predicate filter that can be evaluated in eBPF
#[derive(Debug, Clone)]
pub struct PredicateFilter {
    /// Field ID to filter on
    pub field_id: u32,

    /// Comparison operator
    pub op: FilterOp,

    /// Value to compare against
    pub value: FilterValue,
}

/// Comparison operators for eBPF filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    /// Equals
    Eq,

    /// Not equals
    Ne,

    /// Greater than
    Gt,

    /// Less than
    Lt,

    /// Greater or equal
    Ge,

    /// Less or equal
    Le,

    /// Contains (for strings)
    Contains,

    /// Starts with (for strings)
    StartsWith,

    /// Ends with (for strings)
    EndsWith,
}

/// Filter values
#[derive(Debug, Clone)]
pub enum FilterValue {
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    String(String),
}

impl InterestPushdown {
    /// Create a new interest pushdown
    pub fn new() -> Self {
        Self {
            event_types: RwLock::new(HashSet::new()),
            field_interests: RwLock::new(HashMap::new()),
            predicate_filters: RwLock::new(HashMap::new()),
        }
    }

    /// Update the set of event types that rules are interested in
    pub fn update_event_types(&self, event_types: Vec<EbpfEventType>) {
        let mut types = self.event_types.write().unwrap();
        types.clear();
        types.extend(event_types);
        debug!(count = types.len(), "Updated event type interests");
    }

    /// Add field interest for an event type
    pub fn add_field_interest(&self, event_type: u32, field_id: u32) {
        let mut interests = self.field_interests.write().unwrap();
        interests
            .entry(event_type)
            .or_insert_with(HashSet::new)
            .insert(field_id);
    }

    /// Add predicate filter for an event type
    pub fn add_predicate_filter(&self, event_type: u32, filter: PredicateFilter) {
        let mut filters = self.predicate_filters.write().unwrap();
        filters
            .entry(event_type)
            .or_insert_with(Vec::new)
            .push(filter);
    }

    /// Check if an event type is interesting
    pub fn is_event_type_interesting(&self, event_type: EbpfEventType) -> bool {
        let types = self.event_types.read().unwrap();
        types.contains(&event_type)
    }

    /// Get field interests for an event type
    pub fn get_field_interests(&self, event_type: u32) -> HashSet<u32> {
        let interests = self.field_interests.read().unwrap();
        interests.get(&event_type).cloned().unwrap_or_default()
    }

    /// Get predicate filters for an event type
    pub fn get_predicate_filters(&self, event_type: u32) -> Vec<PredicateFilter> {
        let filters = self.predicate_filters.read().unwrap();
        filters.get(&event_type).cloned().unwrap_or_default()
    }

    /// Clear all interests
    pub fn clear(&self) {
        self.event_types.write().unwrap().clear();
        self.field_interests.write().unwrap().clear();
        self.predicate_filters.write().unwrap().clear();
        debug!("Cleared all interests");
    }
}

impl Default for InterestPushdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interest_pushdown_creation() {
        let pushdown = InterestPushdown::new();
        assert!(!pushdown.is_event_type_interesting(EbpfEventType::ProcessExec));
    }

    #[test]
    fn test_update_event_types() {
        let pushdown = InterestPushdown::new();

        pushdown.update_event_types(vec![EbpfEventType::ProcessExec, EbpfEventType::ProcessExit]);

        assert!(pushdown.is_event_type_interesting(EbpfEventType::ProcessExec));
        assert!(pushdown.is_event_type_interesting(EbpfEventType::ProcessExit));
        assert!(!pushdown.is_event_type_interesting(EbpfEventType::FileOpen));
    }

    #[test]
    fn test_add_field_interest() {
        let pushdown = InterestPushdown::new();

        pushdown.add_field_interest(1, 10);
        pushdown.add_field_interest(1, 20);
        pushdown.add_field_interest(1, 10); // Duplicate

        let interests = pushdown.get_field_interests(1);
        assert_eq!(interests.len(), 2);
        assert!(interests.contains(&10));
        assert!(interests.contains(&20));
    }

    #[test]
    fn test_add_predicate_filter() {
        let pushdown = InterestPushdown::new();

        let filter = PredicateFilter {
            field_id: 10,
            op: FilterOp::Eq,
            value: FilterValue::U32(100),
        };

        pushdown.add_predicate_filter(1, filter.clone());

        let filters = pushdown.get_predicate_filters(1);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].field_id, 10);
    }

    #[test]
    fn test_clear() {
        let pushdown = InterestPushdown::new();

        pushdown.update_event_types(vec![EbpfEventType::ProcessExec]);
        pushdown.add_field_interest(1, 10);

        assert!(pushdown.is_event_type_interesting(EbpfEventType::ProcessExec));

        pushdown.clear();

        assert!(!pushdown.is_event_type_interesting(EbpfEventType::ProcessExec));
        assert_eq!(pushdown.get_field_interests(1).len(), 0);
    }
}
