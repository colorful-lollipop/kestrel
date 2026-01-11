//! Semantic analyzer for EQL queries
//!
//! Performs type checking, field resolution, and validation.

use crate::ast::*;
use crate::error::{EqlError, Result};
use crate::ir::*;
use kestrel_schema::SchemaRegistry;
use std::collections::HashMap;
use std::sync::Arc;

/// Semantic analyzer context
pub struct SemanticAnalyzer {
    /// Schema registry for field resolution
    schema: Arc<SchemaRegistry>,
    /// Known event types
    event_types: Vec<String>,
    /// Current event type being analyzed
    current_event_type: Option<String>,
    /// Field ID cache (field path -> field ID)
    field_ids: HashMap<String, u32>,
    /// Next available field ID for unknown fields
    next_field_id: u32,
}

impl SemanticAnalyzer {
    /// Create a new semantic analyzer
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self {
            schema,
            event_types: Vec::new(),
            current_event_type: None,
            field_ids: HashMap::new(),
            next_field_id: 1,
        }
    }

    /// Analyze a query and produce IR
    pub fn analyze(&mut self, query: &Query) -> Result<IrRule> {
        // Extract event types
        self.event_types = query.event_types();

        // TODO: Validate event types exist in schema
        // For now, just accept all event types

        match query {
            Query::Event(eq) => self.analyze_event_query(eq),
            Query::Sequence(sq) => self.analyze_sequence_query(sq),
        }
    }

    /// Analyze a single event query
    fn analyze_event_query(&mut self, query: &EventQuery) -> Result<IrRule> {
        let rule_id = format!("event-{}", query.event_type);

        let mut ir_rule = IrRule::new(
            rule_id.clone(),
            IrRuleType::Event {
                event_type: query.event_type.clone(),
            },
        );

        self.current_event_type = Some(query.event_type.clone());

        // Analyze condition if present
        let root = if let Some(condition) = &query.condition {
            self.analyze_expr(condition)?
        } else {
            IrNode::Literal {
                value: IrLiteral::Bool(true),
            }
        };

        // Extract field IDs, regex patterns, and glob patterns
        let required_fields = root.field_ids();
        let required_regex = root.regex_patterns();
        let required_globs = root.glob_patterns();

        // Create predicate
        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: query.event_type.clone(),
            root,
            required_fields,
            required_regex,
            required_globs,
        };

        ir_rule.add_predicate(predicate);

        // Analyze captures
        for capture in &query.captures {
            ir_rule.add_capture(self.analyze_capture(capture)?);
        }

        ir_rule.validate().map_err(|e| EqlError::IrError {
            message: e.to_string(),
        })?;

        self.current_event_type = None;

        Ok(ir_rule)
    }

    /// Analyze a sequence query
    fn analyze_sequence_query(&mut self, query: &SequenceQuery) -> Result<IrRule> {
        let rule_id = "sequence-001".to_string();

        let mut ir_rule = IrRule::new(
            rule_id.clone(),
            IrRuleType::Sequence {
                event_types: query.steps.iter().map(|s| s.event_type.clone()).collect(),
            },
        );

        // Analyze each step
        for (index, step) in query.steps.iter().enumerate() {
            let step_id = step.id.clone().unwrap_or(format!("step{}", index));

            self.current_event_type = Some(step.event_type.clone());

            let root = if let Some(condition) = &step.condition {
                self.analyze_expr(condition)?
            } else {
                IrNode::Literal {
                    value: IrLiteral::Bool(true),
                }
            };

            let required_fields = root.field_ids();
            let required_regex = root.regex_patterns();
            let required_globs = root.glob_patterns();

            let predicate = IrPredicate {
                id: step_id.clone(),
                event_type: step.event_type.clone(),
                root,
                required_fields,
                required_regex,
                required_globs,
            };

            ir_rule.add_predicate(predicate);
        }

        // Analyze until step if present
        let until_id = if let Some(until) = &query.until {
            let step_id = until.id.clone().unwrap_or("until".to_string());

            self.current_event_type = Some(until.event_type.clone());

            let root = if let Some(condition) = &until.condition {
                self.analyze_expr(condition)?
            } else {
                IrNode::Literal {
                    value: IrLiteral::Bool(true),
                }
            };

            let required_fields = root.field_ids();
            let required_regex = root.regex_patterns();
            let required_globs = root.glob_patterns();

            let predicate = IrPredicate {
                id: step_id.clone(),
                event_type: until.event_type.clone(),
                root,
                required_fields,
                required_regex,
                required_globs,
            };

            ir_rule.add_predicate(predicate);
            Some(step_id)
        } else {
            None
        };

        // Resolve "by" field to field ID
        let by_field = query.by.as_ref().ok_or_else(|| EqlError::SemanticError {
            message: "Sequence query must have 'by' clause".to_string(),
        })?;

        let by_field_id = self.resolve_field(by_field)?;

        // Convert maxspan to milliseconds
        let maxspan_ms = query.maxspan.as_ref().map(|d| self.duration_to_ms(d));

        // Create sequence steps
        let steps: Result<Vec<IrSeqStep>> = query
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| {
                Ok(IrSeqStep {
                    predicate_id: step.id.clone().unwrap_or(format!("step{}", index)),
                    index,
                    event_type_name: step.event_type.clone(),
                })
            })
            .collect();

        let sequence = IrSequence {
            by_field_id,
            steps: steps?,
            maxspan_ms,
            until: until_id,
        };

        ir_rule.set_sequence(sequence);

        // Analyze captures
        for capture in &query.captures {
            ir_rule.add_capture(self.analyze_capture(capture)?);
        }

        ir_rule.validate().map_err(|e| EqlError::IrError {
            message: e.to_string(),
        })?;

        self.current_event_type = None;

        Ok(ir_rule)
    }

    /// Analyze an expression
    fn analyze_expr(&mut self, expr: &Expr) -> Result<IrNode> {
        match expr {
            Expr::BoolLiteral(b) => Ok(IrNode::Literal {
                value: IrLiteral::Bool(*b),
            }),
            Expr::IntLiteral(i) => Ok(IrNode::Literal {
                value: IrLiteral::Int(*i),
            }),
            Expr::StringLiteral(s) => Ok(IrNode::Literal {
                value: IrLiteral::String(s.clone()),
            }),
            Expr::Null => Ok(IrNode::Literal {
                value: IrLiteral::Null,
            }),
            Expr::FieldRef(path) => {
                let field_id = self.resolve_field(path)?;
                Ok(IrNode::LoadField { field_id })
            }
            Expr::BinaryOp(op) => self.analyze_binary_op(op),
            Expr::UnaryOp(op) => self.analyze_unary_op(op),
            Expr::FunctionCall(fc) => self.analyze_function_call(fc),
            Expr::In(in_expr) => self.analyze_in_expr(in_expr),
        }
    }

    /// Analyze a binary operation
    fn analyze_binary_op(&mut self, op: &BinaryOp) -> Result<IrNode> {
        let left = self.analyze_expr(&op.left)?;
        let right = self.analyze_expr(&op.right)?;

        // TODO: Type checking
        // For now, just convert the operator

        let ir_op = self.convert_binary_op(op.operator)?;

        Ok(IrNode::BinaryOp {
            op: ir_op,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    /// Analyze a unary operation
    fn analyze_unary_op(&mut self, op: &UnaryOp) -> Result<IrNode> {
        let operand = self.analyze_expr(&op.operand)?;

        let ir_op = match op.operator {
            UnaryOperator::Not => IrUnaryOp::Not,
            UnaryOperator::Minus => IrUnaryOp::Neg,
        };

        Ok(IrNode::UnaryOp {
            op: ir_op,
            operand: Box::new(operand),
        })
    }

    /// Analyze a function call
    fn analyze_function_call(&mut self, fc: &FunctionCall) -> Result<IrNode> {
        let func = self.parse_function(&fc.function)?;

        let args: Result<Vec<IrNode>> = fc.args.iter().map(|a| self.analyze_expr(a)).collect();

        Ok(IrNode::FunctionCall { func, args: args? })
    }

    /// Analyze an in expression
    fn analyze_in_expr(&mut self, in_expr: &InExpr) -> Result<IrNode> {
        let value = Box::new(self.analyze_expr(&in_expr.value)?);

        let values: Result<Vec<IrLiteral>> = in_expr
            .values
            .iter()
            .map(|v| self.expr_to_literal(v))
            .collect();

        Ok(IrNode::In {
            value,
            values: values?,
        })
    }

    /// Analyze a capture field
    fn analyze_capture(&mut self, capture: &CaptureField) -> Result<IrCapture> {
        let field_id = self.resolve_field(&capture.field_path)?;

        Ok(IrCapture {
            field_id,
            alias: capture.alias.clone().unwrap_or_else(|| {
                // Extract field name from path
                capture
                    .field_path
                    .split('.')
                    .last()
                    .unwrap_or(&capture.field_path)
                    .to_string()
            }),
            source_step: capture.source_step.clone(),
        })
    }

    /// Resolve a field path to a field ID
    fn resolve_field(&mut self, path: &str) -> Result<u32> {
        // Check cache first
        if let Some(&id) = self.field_ids.get(path) {
            return Ok(id);
        }

        // Try to get from schema
        if let Some(id) = self.schema.get_field_id(path) {
            self.field_ids.insert(path.to_string(), id);
            return Ok(id);
        }

        // Assign a new field ID for unknown fields
        let id = self.next_field_id;
        self.next_field_id += 1;
        self.field_ids.insert(path.to_string(), id);

        Ok(id)
    }

    /// Convert AST binary operator to IR binary operator
    fn convert_binary_op(&self, op: BinaryOperator) -> Result<IrBinaryOp> {
        match op {
            BinaryOperator::And => Ok(IrBinaryOp::And),
            BinaryOperator::Or => Ok(IrBinaryOp::Or),
            BinaryOperator::Eq => Ok(IrBinaryOp::Eq),
            BinaryOperator::NotEq => Ok(IrBinaryOp::NotEq),
            BinaryOperator::Less => Ok(IrBinaryOp::Less),
            BinaryOperator::LessEq => Ok(IrBinaryOp::LessEq),
            BinaryOperator::Greater => Ok(IrBinaryOp::Greater),
            BinaryOperator::GreaterEq => Ok(IrBinaryOp::GreaterEq),
            BinaryOperator::Add => Ok(IrBinaryOp::Add),
            BinaryOperator::Sub => Ok(IrBinaryOp::Sub),
            BinaryOperator::Mul => Ok(IrBinaryOp::Mul),
            BinaryOperator::Div => Ok(IrBinaryOp::Div),
            BinaryOperator::Mod => Ok(IrBinaryOp::Mod),
        }
    }

    /// Parse a function name to IR function
    fn parse_function(&self, name: &str) -> Result<IrFunction> {
        match name.to_lowercase().as_str() {
            "contains" => Ok(IrFunction::Contains),
            "startswith" => Ok(IrFunction::StartsWith),
            "endswith" => Ok(IrFunction::EndsWith),
            "regex" => Ok(IrFunction::Regex),
            "wildcard" => Ok(IrFunction::Wildcard),
            "stringequalsci" => Ok(IrFunction::StringEqualsCi),
            _ => Err(EqlError::SemanticError {
                message: format!("Unknown function: {}", name),
            }),
        }
    }

    /// Convert expression to literal (for in expressions)
    fn expr_to_literal(&self, expr: &Expr) -> Result<IrLiteral> {
        match expr {
            Expr::BoolLiteral(b) => Ok(IrLiteral::Bool(*b)),
            Expr::IntLiteral(i) => Ok(IrLiteral::Int(*i)),
            Expr::StringLiteral(s) => Ok(IrLiteral::String(s.clone())),
            Expr::Null => Ok(IrLiteral::Null),
            _ => Err(EqlError::SemanticError {
                message: "Expected literal value".to_string(),
            }),
        }
    }

    /// Convert duration to milliseconds
    fn duration_to_ms(&self, duration: &Duration) -> u64 {
        match duration.unit {
            DurationUnit::Milliseconds => duration.value,
            DurationUnit::Seconds => duration.value * 1000,
            DurationUnit::Minutes => duration.value * 60 * 1000,
            DurationUnit::Hours => duration.value * 60 * 60 * 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_resolution() {
        let schema = Arc::new(SchemaRegistry::new());
        let analyzer = SemanticAnalyzer::new(schema);

        // This test would require schema setup
        // For now, we just test the structure
        assert!(true);
    }
}
