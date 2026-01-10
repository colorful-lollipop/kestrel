//! EQL Abstract Syntax Tree (AST) definitions

use serde::{Deserialize, Serialize};

/// EQL query type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Query {
    /// Single event query: `event where <condition>`
    Event(Box<EventQuery>),
    /// Sequence query: `sequence [A where ...] [B where ...]`
    Sequence(Box<SequenceQuery>),
}

/// Single event query
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventQuery {
    /// Event type (e.g., "process", "file", "network")
    pub event_type: String,
    /// Filter condition
    pub condition: Option<Expr>,
    /// Field captures for alert output
    pub captures: Vec<CaptureField>,
}

/// Sequence query
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequenceQuery {
    /// Sequence steps
    pub steps: Vec<SequenceStep>,
    /// Group by field (optional)
    pub by: Option<String>,
    /// Maximum time span for sequence
    pub maxspan: Option<Duration>,
    /// Until condition (terminates sequence)
    pub until: Option<Box<SequenceStep>>,
    /// Field captures for alert output
    pub captures: Vec<CaptureField>,
}

/// Sequence step
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequenceStep {
    /// Event type for this step
    pub event_type: String,
    /// Filter condition
    pub condition: Option<Expr>,
    /// Step identifier (for reference in until/captures)
    pub id: Option<String>,
}

/// Duration (maxspan)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Duration {
    pub value: u64,
    pub unit: DurationUnit,
}

/// Duration unit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurationUnit {
    Milliseconds,
    Seconds,
    Minutes,
    Hours,
}

/// Field capture for alert output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureField {
    pub field_path: String,
    pub alias: Option<String>,
    pub source_step: Option<String>, // For sequences: which step to capture from
}

/// Expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    /// Boolean literal
    BoolLiteral(bool),
    /// Integer literal
    IntLiteral(i64),
    /// String literal
    StringLiteral(String),
    /// Null value
    Null,
    /// Field reference: `process.executable`
    FieldRef(String),
    /// Binary operation: `a and b`, `x > 5`
    BinaryOp(Box<BinaryOp>),
    /// Unary operation: `not x`, `-x`
    UnaryOp(Box<UnaryOp>),
    /// Function call: `wildcard("*.exe")`
    FunctionCall(FunctionCall),
    /// In expression: `x in (1, 2, 3)`
    In(Box<InExpr>),
}

/// Binary operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryOp {
    pub operator: BinaryOperator,
    pub left: Expr,
    pub right: Expr,
}

/// Binary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOperator {
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnaryOp {
    pub operator: UnaryOperator,
    pub operand: Expr,
}

/// Unary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOperator {
    Not,
    Minus,
}

/// Function call
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub function: String,
    pub args: Vec<Expr>,
}

/// In expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InExpr {
    pub value: Box<Expr>,
    pub values: Vec<Expr>,
}

/// Type annotation for expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Type {
    Bool,
    Int,
    String,
    Null,
    Unknown,
}

impl Query {
    /// Get all event types referenced in the query
    pub fn event_types(&self) -> Vec<String> {
        match self {
            Query::Event(eq) => vec![eq.event_type.clone()],
            Query::Sequence(sq) => {
                let mut types: Vec<String> = sq.steps.iter().map(|s| s.event_type.clone()).collect();
                if let Some(until) = &sq.until {
                    types.push(until.event_type.clone());
                }
                types
            }
        }
    }

    /// Get all field references in the query
    pub fn field_refs(&self) -> Vec<String> {
        let mut refs = Vec::new();
        match self {
            Query::Event(eq) => {
                if let Some(cond) = &eq.condition {
                    refs.extend(extract_field_refs(cond));
                }
                refs.extend(eq.captures.iter().map(|c| c.field_path.clone()));
            }
            Query::Sequence(sq) => {
                for step in &sq.steps {
                    if let Some(cond) = &step.condition {
                        refs.extend(extract_field_refs(cond));
                    }
                }
                if let Some(until) = &sq.until {
                    if let Some(cond) = &until.condition {
                        refs.extend(extract_field_refs(cond));
                    }
                }
                refs.extend(sq.captures.iter().map(|c| c.field_path.clone()));
                if let Some(by) = &sq.by {
                    refs.push(by.clone());
                }
            }
        }
        refs
    }
}

/// Helper to extract field references from an expression
fn extract_field_refs(expr: &Expr) -> Vec<String> {
    let mut refs = Vec::new();
    match expr {
        Expr::FieldRef(path) => refs.push(path.clone()),
        Expr::BinaryOp(op) => {
            refs.extend(extract_field_refs(&op.left));
            refs.extend(extract_field_refs(&op.right));
        }
        Expr::UnaryOp(op) => {
            refs.extend(extract_field_refs(&op.operand));
        }
        Expr::FunctionCall(fc) => {
            for arg in &fc.args {
                refs.extend(extract_field_refs(arg));
            }
        }
        Expr::In(in_expr) => {
            refs.extend(extract_field_refs(&in_expr.value));
            for val in &in_expr.values {
                refs.extend(extract_field_refs(val));
            }
        }
        _ => {}
    }
    refs
}
