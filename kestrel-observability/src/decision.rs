use kestrel_schema::{EntityKey, Severity, TypedValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// A structured log of a detection decision
///
/// This captures everything needed to understand why a rule fired or didn't fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionLog {
    /// Decision ID (unique)
    pub decision_id: String,
    /// Timestamp of the decision
    pub timestamp_ns: u64,
    /// Rule ID
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Event ID that triggered the decision
    pub event_id: u64,
    /// Event type ID
    pub event_type_id: u16,
    /// Entity key
    pub entity_key: EntityKey,
    /// Whether the rule matched
    pub matched: bool,
    /// Severity if matched
    pub severity: Option<Severity>,
    /// Evaluation duration
    #[serde(with = "duration_millis")]
    pub duration: Duration,
    /// Individual predicate evaluations
    pub predicates: Vec<PredicateDecision>,
    /// NFA state transitions (for sequence rules)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nfa_transitions: Option<Vec<NfaTransitionLog>>,
    /// Actions taken
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub actions: Vec<ActionLog>,
    /// Captured field values
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub captured_fields: HashMap<String, TypedValue>,
    /// Error if evaluation failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A predicate evaluation decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateDecision {
    /// Predicate ID
    pub predicate_id: String,
    /// Whether the predicate matched
    pub matched: bool,
    /// Human-readable explanation
    pub explanation: String,
    /// Duration of predicate evaluation
    #[serde(with = "duration_micros")]
    pub duration: Duration,
    /// Field values that were checked
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub checked_fields: HashMap<String, Option<TypedValue>>,
    /// Expected values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<String>,
    /// Actual value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_value: Option<String>,
}

/// NFA state transition log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfaTransitionLog {
    /// From state
    pub from_state: String,
    /// To state
    pub to_state: String,
    /// Event ID that caused the transition
    pub event_id: u64,
    /// Whether this was a match
    pub is_match: bool,
}

/// Action log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLog {
    /// Action type
    pub action_type: String,
    /// Target of the action
    pub target: String,
    /// Whether the action succeeded
    pub success: bool,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Duration serialization helper (milliseconds)
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

/// Duration serialization helper (microseconds)
mod duration_micros {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_micros() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let micros = u64::deserialize(deserializer)?;
        Ok(Duration::from_micros(micros))
    }
}
