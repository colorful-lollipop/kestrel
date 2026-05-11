//! EventProcessor trait and implementations.
//!
//! This module decomposes the monolithic [`DetectionEngine`] into discrete
//! processor units that can be composed via [`CompositeProcessor`].

use crate::EngineMode;
use kestrel_core::{ActionDecision, Alert, EventEvidence, Severity};
use kestrel_event::Event;
use kestrel_nfa::SequenceAlert;
use kestrel_schema::{FieldId, SchemaRegistry};
use smallvec::SmallVec;
use std::sync::Arc;

/// Result of processing a single event through one or more processors.
#[derive(Debug, Default)]
pub struct ProcessResult {
    pub alerts: SmallVec<[Alert; 2]>,
    pub inline_actions: SmallVec<[ActionDecision; 1]>,
}

impl ProcessResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.alerts.clear();
        self.inline_actions.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.alerts.is_empty() && self.inline_actions.is_empty()
    }

    pub fn extend(&mut self, other: ProcessResult) {
        self.alerts.extend(other.alerts);
        self.inline_actions.extend(other.inline_actions);
    }
}

/// Immutable context passed to every `process()` call.
pub struct ProcessingContext<'a> {
    pub schema: &'a SchemaRegistry,
    pub partition_id: usize,
    pub mode: EngineMode,
    pub timestamp_ns: u64,
}

/// Errors that can occur during event processing.
#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("Predicate evaluation failed: {0}")]
    Evaluation(String),
    #[error("Runtime unavailable: {0}")]
    RuntimeUnavailable(String),
    #[error("Fatal: {0}")]
    Fatal(String),
}

/// Core trait for event detection logic.
pub trait EventProcessor: Send + Sync {
    /// Process a single event, appending any matches to `output`.
    fn process(
        &self,
        event: &Event,
        ctx: &ProcessingContext<'_>,
        output: &mut ProcessResult,
    ) -> Result<(), ProcessorError>;

    /// Field IDs required for evaluation.
    fn required_fields(&self) -> &[FieldId];

    /// Event type IDs this processor subscribes to. Empty = all.
    fn event_types(&self) -> &[u16];

    /// Human-readable name for diagnostics.
    fn name(&self) -> &'static str;
}

/// Create an alert from a sequence match.
pub fn alert_from_sequence_match(seq_alert: &SequenceAlert) -> Alert {
    let events: Vec<EventEvidence> = seq_alert
        .events
        .iter()
        .map(|e| EventEvidence {
            event_type_id: e.event_type_id,
            timestamp_ns: e.ts_mono_ns,
            fields: vec![],
        })
        .collect();

    let alert_context = serde_json::json!({
        "sequence_id": seq_alert.sequence_id,
        "entity_key": seq_alert.entity_key,
        "captures": seq_alert.captures,
    });

    Alert {
        id: format!("{}-{}", seq_alert.rule_id, seq_alert.timestamp_ns),
        rule_id: seq_alert.rule_id.clone(),
        rule_name: seq_alert.rule_name.clone(),
        severity: Severity::High,
        title: format!("Sequence matched: {}", seq_alert.sequence_id),
        description: Some(format!(
            "Entity {} completed sequence {}",
            seq_alert.entity_key, seq_alert.sequence_id
        )),
        timestamp_ns: seq_alert.timestamp_ns,
        events,
        context: alert_context,
    }
}

/// Create an alert from a single-event rule match.
pub fn alert_from_single_event(
    rule_id: &str,
    rule_name: &str,
    event: &Event,
    severity: Severity,
) -> Alert {
    Alert {
        id: format!("{}-{}", rule_id, event.ts_mono_ns),
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        severity,
        title: format!("Single-event rule matched: {}", rule_name),
        description: None,
        timestamp_ns: event.ts_mono_ns,
        events: vec![EventEvidence {
            event_type_id: event.event_type_id,
            timestamp_ns: event.ts_mono_ns,
            fields: vec![],
        }],
        context: serde_json::json!({"rule_type": "single_event"}),
    }
}

/// Chains multiple processors together.
pub struct CompositeProcessor {
    processors: Vec<Arc<dyn EventProcessor>>,
}

impl CompositeProcessor {
    pub fn new(processors: Vec<Arc<dyn EventProcessor>>) -> Self {
        Self { processors }
    }
}

impl EventProcessor for CompositeProcessor {
    fn process(
        &self,
        event: &Event,
        ctx: &ProcessingContext<'_>,
        output: &mut ProcessResult,
    ) -> Result<(), ProcessorError> {
        for processor in &self.processors {
            processor.process(event, ctx, output)?;
        }
        Ok(())
    }

    fn required_fields(&self) -> &[FieldId] {
        &[]
    }

    fn event_types(&self) -> &[u16] {
        &[]
    }

    fn name(&self) -> &'static str {
        "CompositeProcessor"
    }
}

/// Stub processor for single-event rules.
pub struct SingleEventProcessor;

impl EventProcessor for SingleEventProcessor {
    fn process(
        &self,
        _event: &Event,
        _ctx: &ProcessingContext<'_>,
        _output: &mut ProcessResult,
    ) -> Result<(), ProcessorError> {
        Ok(())
    }

    fn required_fields(&self) -> &[FieldId] {
        &[]
    }

    fn event_types(&self) -> &[u16] {
        &[]
    }

    fn name(&self) -> &'static str {
        "SingleEventProcessor"
    }
}

/// Stub processor for NFA sequence rules.
pub struct NfaEventProcessor;

impl EventProcessor for NfaEventProcessor {
    fn process(
        &self,
        _event: &Event,
        _ctx: &ProcessingContext<'_>,
        _output: &mut ProcessResult,
    ) -> Result<(), ProcessorError> {
        Ok(())
    }

    fn required_fields(&self) -> &[FieldId] {
        &[]
    }

    fn event_types(&self) -> &[u16] {
        &[]
    }

    fn name(&self) -> &'static str {
        "NfaEventProcessor"
    }
}
