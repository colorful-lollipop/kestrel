//! Intermediate Representation (IR) for EQL queries
//!
//! The IR is a backend-agnostic representation that can be compiled
//! to either Wasm or Lua predicates. It represents predicates as DAGs
//! and sequences as state machines.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IR for a compiled EQL rule
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrRule {
    /// Rule identifier
    pub rule_id: String,
    /// Rule type
    pub rule_type: IrRuleType,
    /// Predicates (indexed by step ID or "main" for single event)
    pub predicates: HashMap<String, IrPredicate>,
    /// Sequence configuration (for sequence rules)
    pub sequence: Option<IrSequence>,
    /// Captures for alert output
    pub captures: Vec<IrCapture>,
}

/// Rule type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrRuleType {
    /// Single event rule
    Event { event_type: String },
    /// Sequence rule
    Sequence { event_types: Vec<String> },
}

/// Predicate DAG (Directed Acyclic Graph)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrPredicate {
    /// Predicate identifier
    pub id: String,
    /// Event type this predicate operates on
    pub event_type: String,
    /// Root operation of the predicate DAG
    pub root: IrNode,
    /// Required field IDs (for host API registration)
    pub required_fields: Vec<u32>,
    /// Required regex patterns
    pub required_regex: Vec<String>,
    /// Required glob patterns
    pub required_globs: Vec<String>,
}

/// IR node (DAG node)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrNode {
    /// Literal value
    Literal { value: IrLiteral },
    /// Load field value
    LoadField { field_id: u32 },
    /// Binary operation
    BinaryOp {
        op: IrBinaryOp,
        left: Box<IrNode>,
        right: Box<IrNode>,
    },
    /// Unary operation
    UnaryOp { op: IrUnaryOp, operand: Box<IrNode> },
    /// Function call
    FunctionCall { func: IrFunction, args: Vec<IrNode> },
    /// In operation (constant set membership)
    In {
        value: Box<IrNode>,
        values: Vec<IrLiteral>,
    },
}

/// Literal value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrLiteral {
    Bool(bool),
    Int(i64),
    String(String),
    Null,
}

/// Binary operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrBinaryOp {
    // Logical
    And,
    Or,
    // Comparison
    Eq,
    NotEq,
    Less,
    LessEq,
    Greater,
    GreaterEq,
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

/// Unary operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrUnaryOp {
    Not,
    Neg,
}

/// Built-in function
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrFunction {
    /// String contains: `contains(string, substring)`
    Contains,
    /// String starts with: `startsWith(string, prefix)`
    StartsWith,
    /// String ends with: `endsWith(string, suffix)`
    EndsWith,
    /// Regular expression match: `regex(pattern, string)`
    Regex,
    /// Wildcard/glob match: `wildcard(pattern, string)`
    Wildcard,
    /// Case-insensitive string compare: `stringEqualsCi(a, b)`
    StringEqualsCi,
}

/// Sequence configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrSequence {
    /// Group by field ID
    pub by_field_id: u32,
    /// Sequence steps (each references a predicate by ID)
    pub steps: Vec<IrSeqStep>,
    /// Maximum time span (in milliseconds)
    pub maxspan_ms: Option<u64>,
    /// Until step (references a predicate by ID)
    pub until: Option<String>,
}

/// Sequence step
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrSeqStep {
    /// Step identifier (references predicate ID)
    pub predicate_id: String,
    /// Step index in sequence
    pub index: usize,
}

/// Field capture for alert output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrCapture {
    /// Field ID to capture
    pub field_id: u32,
    /// Alias in output
    pub alias: String,
    /// Source step (for sequences)
    pub source_step: Option<String>,
}

impl IrRule {
    /// Create a new IR rule
    pub fn new(rule_id: String, rule_type: IrRuleType) -> Self {
        Self {
            rule_id,
            rule_type,
            predicates: HashMap::new(),
            sequence: None,
            captures: Vec::new(),
        }
    }

    /// Add a predicate to the rule
    pub fn add_predicate(&mut self, predicate: IrPredicate) {
        self.predicates.insert(predicate.id.clone(), predicate);
    }

    /// Add a capture to the rule
    pub fn add_capture(&mut self, capture: IrCapture) {
        self.captures.push(capture);
    }

    /// Set sequence configuration
    pub fn set_sequence(&mut self, sequence: IrSequence) {
        self.sequence = Some(sequence);
    }

    /// Validate the IR rule
    pub fn validate(&self) -> Result<(), String> {
        // Check that predicates exist
        for (id, pred) in &self.predicates {
            if pred.id != *id {
                return Err(format!("Predicate ID mismatch: {} != {}", id, pred.id));
            }
        }

        // For sequence rules, validate that all step predicates exist
        if let Some(seq) = &self.sequence {
            for step in &seq.steps {
                if !self.predicates.contains_key(&step.predicate_id) {
                    return Err(format!(
                        "Sequence step references unknown predicate: {}",
                        step.predicate_id
                    ));
                }
            }

            if let Some(until_pred) = &seq.until {
                if !self.predicates.contains_key(until_pred) {
                    return Err(format!(
                        "Until references unknown predicate: {}",
                        until_pred
                    ));
                }
            }
        }

        // Validate captures reference valid field IDs
        for capture in &self.captures {
            if capture.field_id == 0 {
                return Err(format!("Invalid field ID in capture: {}", capture.alias));
            }
        }

        Ok(())
    }
}

impl IrNode {
    /// Get all field IDs referenced in this node
    pub fn field_ids(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        match self {
            IrNode::LoadField { field_id } => {
                ids.push(*field_id);
            }
            IrNode::BinaryOp { left, right, .. } => {
                ids.extend(left.field_ids());
                ids.extend(right.field_ids());
            }
            IrNode::UnaryOp { operand, .. } => {
                ids.extend(operand.field_ids());
            }
            IrNode::FunctionCall { args, .. } => {
                for arg in args {
                    ids.extend(arg.field_ids());
                }
            }
            IrNode::In { value, .. } => {
                ids.extend(value.field_ids());
            }
            _ => {}
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get all regex patterns used in this node
    pub fn regex_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        match self {
            IrNode::FunctionCall { func, args } => {
                if *func == IrFunction::Regex {
                    if let Some(IrNode::Literal {
                        value: IrLiteral::String(pattern),
                    }) = args.first()
                    {
                        patterns.push(pattern.clone());
                    }
                }
                for arg in args {
                    patterns.extend(arg.regex_patterns());
                }
            }
            IrNode::BinaryOp { left, right, .. } => {
                patterns.extend(left.regex_patterns());
                patterns.extend(right.regex_patterns());
            }
            IrNode::UnaryOp { operand, .. } => {
                patterns.extend(operand.regex_patterns());
            }
            IrNode::In { value, values } => {
                patterns.extend(value.regex_patterns());
                for val in values {
                    if let IrLiteral::String(s) = val {
                        patterns.push(s.clone());
                    }
                }
            }
            _ => {}
        }
        patterns.sort();
        patterns.dedup();
        patterns
    }

    /// Get all glob patterns used in this node
    pub fn glob_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        match self {
            IrNode::FunctionCall { func, args } => {
                if *func == IrFunction::Wildcard {
                    if let Some(IrNode::Literal {
                        value: IrLiteral::String(pattern),
                    }) = args.first()
                    {
                        patterns.push(pattern.clone());
                    }
                }
                for arg in args {
                    patterns.extend(arg.glob_patterns());
                }
            }
            IrNode::BinaryOp { left, right, .. } => {
                patterns.extend(left.glob_patterns());
                patterns.extend(right.glob_patterns());
            }
            IrNode::UnaryOp { operand, .. } => {
                patterns.extend(operand.glob_patterns());
            }
            _ => {}
        }
        patterns.sort();
        patterns.dedup();
        patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_rule_validation() {
        let mut rule = IrRule::new(
            "test-rule".to_string(),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: "process".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };

        rule.add_predicate(predicate);

        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_ir_sequence_validation() {
        let mut rule = IrRule::new(
            "test-seq".to_string(),
            IrRuleType::Sequence {
                event_types: vec!["process".to_string(), "file".to_string()],
            },
        );

        // Add predicates
        rule.add_predicate(IrPredicate {
            id: "step0".to_string(),
            event_type: "process".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        });

        rule.add_predicate(IrPredicate {
            id: "step1".to_string(),
            event_type: "file".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        });

        // Add sequence
        rule.set_sequence(IrSequence {
            by_field_id: 1,
            steps: vec![
                IrSeqStep {
                    predicate_id: "step0".to_string(),
                    index: 0,
                },
                IrSeqStep {
                    predicate_id: "step1".to_string(),
                    index: 1,
                },
            ],
            maxspan_ms: Some(5000),
            until: None,
        });

        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_ir_field_extraction() {
        let node = IrNode::BinaryOp {
            op: IrBinaryOp::And,
            left: Box::new(IrNode::LoadField { field_id: 1 }),
            right: Box::new(IrNode::LoadField { field_id: 2 }),
        };

        let ids = node.field_ids();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn test_ir_regex_extraction() {
        let node = IrNode::FunctionCall {
            func: IrFunction::Regex,
            args: vec![
                IrNode::Literal {
                    value: IrLiteral::String(".*\\.exe".to_string()),
                },
                IrNode::LoadField { field_id: 3 },
            ],
        };

        let patterns = node.regex_patterns();
        assert_eq!(patterns, vec![".*\\.exe".to_string()]);
    }
}
