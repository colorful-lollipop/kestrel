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

        // Validate event types exist in schema
        for event_type in &self.event_types {
            if self.schema.get_event_type_id(event_type).is_none() {
                return Err(EqlError::UnknownEventType {
                    event_type: event_type.clone(),
                });
            }
        }

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

    /// Get the type of an IR node for type checking
    fn get_node_type(&self, node: &IrNode) -> Result<Type> {
        match node {
            IrNode::Literal { value } => match value {
                IrLiteral::Bool(_) => Ok(Type::Bool),
                IrLiteral::Int(_) => Ok(Type::Int),
                IrLiteral::String(_) => Ok(Type::String),
                IrLiteral::Null => Ok(Type::Null),
            },
            IrNode::LoadField { field_id } => {
                if let Some(field_def) = self.schema.get_field(*field_id) {
                    match field_def.data_type {
                        kestrel_schema::FieldDataType::Bool => Ok(Type::Bool),
                        kestrel_schema::FieldDataType::I64 | kestrel_schema::FieldDataType::U64 => {
                            Ok(Type::Int)
                        }
                        kestrel_schema::FieldDataType::String => Ok(Type::String),
                        _ => Ok(Type::Unknown),
                    }
                } else {
                    Ok(Type::Unknown)
                }
            }
            _ => Ok(Type::Unknown),
        }
    }

    /// Check types for binary operations
    fn check_binary_op_types(
        &self,
        op: BinaryOperator,
        left: &IrNode,
        right: &IrNode,
        left_expr: &Expr,
        right_expr: &Expr,
    ) -> Result<()> {
        let left_type = self.get_node_type(left)?;
        let right_type = self.get_node_type(right)?;

        match op {
            // Logical operators: both operands must be boolean
            BinaryOperator::And | BinaryOperator::Or => {
                if left_type != Type::Bool {
                    return Err(EqlError::TypeMismatch {
                        expected: "bool".to_string(),
                        found: format!("{:?}", left_type),
                        location: format!("{:?}", left_expr),
                    });
                }
                if right_type != Type::Bool {
                    return Err(EqlError::TypeMismatch {
                        expected: "bool".to_string(),
                        found: format!("{:?}", right_type),
                        location: format!("{:?}", right_expr),
                    });
                }
            }

            // Comparison operators: operands must have compatible types
            BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Less
            | BinaryOperator::LessEq
            | BinaryOperator::Greater
            | BinaryOperator::GreaterEq => {
                if !self.are_types_compatible(&left_type, &right_type) {
                    return Err(EqlError::TypeMismatch {
                        expected: format!("{:?}", left_type),
                        found: format!("{:?}", right_type),
                        location: format!("{:?}", right_expr),
                    });
                }
            }

            // Arithmetic operators: operands should be numeric
            BinaryOperator::Add
            | BinaryOperator::Sub
            | BinaryOperator::Mul
            | BinaryOperator::Div
            | BinaryOperator::Mod => {
                if !self.is_numeric_type(&left_type) {
                    return Err(EqlError::TypeMismatch {
                        expected: "numeric type".to_string(),
                        found: format!("{:?}", left_type),
                        location: format!("{:?}", left_expr),
                    });
                }
                if !self.is_numeric_type(&right_type) {
                    return Err(EqlError::TypeMismatch {
                        expected: "numeric type".to_string(),
                        found: format!("{:?}", right_type),
                        location: format!("{:?}", right_expr),
                    });
                }
            }
        }

        Ok(())
    }

    /// Check if two types are compatible for comparison
    fn are_types_compatible(&self, left: &Type, right: &Type) -> bool {
        match (left, right) {
            // Exact matches are always compatible
            (l, r) if l == r => true,

            // Both numeric types are compatible (int and u64)
            (Type::Int, Type::Int) => true,

            // String comparisons
            (Type::String, Type::String) => true,

            // Boolean comparisons
            (Type::Bool, Type::Bool) => true,

            // Null comparisons (null can be compared with any type)
            (Type::Null, _) | (_, Type::Null) => true,

            // All other combinations are incompatible
            _ => false,
        }
    }

    /// Check if a type is numeric
    fn is_numeric_type(&self, type_: &Type) -> bool {
        matches!(type_, Type::Int)
    }

    /// Analyze a binary operation
    fn analyze_binary_op(&mut self, op: &BinaryOp) -> Result<IrNode> {
        let left = self.analyze_expr(&op.left)?;
        let right = self.analyze_expr(&op.right)?;

        // Perform type checking
        self.check_binary_op_types(op.operator, &left, &right, &op.left, &op.right)?;

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
    fn test_analyzer_creation() {
        let schema = Arc::new(SchemaRegistry::new());
        let analyzer = SemanticAnalyzer::new(schema);

        // Verify analyzer is properly initialized
        // The analyzer should be created without panicking
        // and should have empty field IDs cache
        assert!(analyzer.field_ids.is_empty());
        assert_eq!(analyzer.next_field_id, 1);
    }

    #[test]
    fn test_type_checking() {
        let mut analyzer = SemanticAnalyzer::new(Arc::new(SchemaRegistry::new()));

        // Test compatible types for comparison
        let left = IrNode::Literal {
            value: IrLiteral::Int(5),
        };
        let right = IrNode::Literal {
            value: IrLiteral::Int(10),
        };
        let left_expr = Expr::IntLiteral(5);
        let right_expr = Expr::IntLiteral(10);

        // Should not error - int comparison is valid
        let result = analyzer.check_binary_op_types(
            BinaryOperator::Eq,
            &left,
            &right,
            &left_expr,
            &right_expr,
        );
        assert!(result.is_ok());

        // Test incompatible types for comparison
        let left_bool = IrNode::Literal {
            value: IrLiteral::Bool(true),
        };
        let right_int = IrNode::Literal {
            value: IrLiteral::Int(10),
        };
        let left_expr_bool = Expr::BoolLiteral(true);

        // Should error - bool vs int comparison is invalid
        let result = analyzer.check_binary_op_types(
            BinaryOperator::Eq,
            &left_bool,
            &right_int,
            &left_expr_bool,
            &right_expr,
        );
        assert!(result.is_err());

        // Test logical operators with bool operands
        let left_bool2 = IrNode::Literal {
            value: IrLiteral::Bool(true),
        };
        let right_bool2 = IrNode::Literal {
            value: IrLiteral::Bool(false),
        };
        let left_expr_bool2 = Expr::BoolLiteral(true);
        let right_expr_bool2 = Expr::BoolLiteral(false);

        // Should not error - bool and/or is valid
        let result = analyzer.check_binary_op_types(
            BinaryOperator::And,
            &left_bool2,
            &right_bool2,
            &left_expr_bool2,
            &right_expr_bool2,
        );
        assert!(result.is_ok());

        // Test arithmetic operators with numeric operands
        let result = analyzer.check_binary_op_types(
            BinaryOperator::Add,
            &left,
            &right,
            &left_expr,
            &right_expr,
        );
        assert!(result.is_ok());

        // Test arithmetic operators with non-numeric operands
        let result = analyzer.check_binary_op_types(
            BinaryOperator::Add,
            &left_bool,
            &right_bool2,
            &left_expr_bool,
            &right_expr_bool2,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_event_type_validation() {
        use crate::ast::{EventQuery, Query, SequenceQuery, SequenceStep};
        use kestrel_schema::EventTypeDef;

        let mut schema = SchemaRegistry::new();
        // Register "process" and "file" event types
        schema
            .register_event_type(EventTypeDef {
                name: "process".to_string(),
                description: Some("Process event".to_string()),
                parent: None,
            })
            .unwrap();
        schema
            .register_event_type(EventTypeDef {
                name: "file".to_string(),
                description: Some("File event".to_string()),
                parent: None,
            })
            .unwrap();
        let schema = Arc::new(schema);
        let mut analyzer = SemanticAnalyzer::new(schema);

        // Create a query with valid event type
        let query = Query::Event(Box::new(EventQuery {
            event_type: "process".to_string(),
            condition: None,
            captures: vec![],
        }));

        let result = analyzer.analyze(&query);
        assert!(result.is_ok(), "Valid event type should pass validation");

        // Create a query with invalid event type
        let query = Query::Event(Box::new(EventQuery {
            event_type: "invalid_event".to_string(),
            condition: None,
            captures: vec![],
        }));

        let result = analyzer.analyze(&query);
        assert!(result.is_err(), "Invalid event type should fail validation");
        match result.unwrap_err() {
            EqlError::UnknownEventType { event_type } => {
                assert_eq!(event_type, "invalid_event");
            }
            _ => panic!("Expected UnknownEventType error"),
        }

        // Test sequence query with valid event types
        let query = Query::Sequence(Box::new(SequenceQuery {
            steps: vec![
                SequenceStep {
                    event_type: "process".to_string(),
                    condition: None,
                    id: None,
                },
                SequenceStep {
                    event_type: "file".to_string(),
                    condition: None,
                    id: None,
                },
            ],
            by: Some("process.entity_id".to_string()),
            maxspan: None,
            until: None,
            captures: vec![],
        }));

        let result = analyzer.analyze(&query);
        assert!(
            result.is_ok(),
            "Valid sequence event types should pass validation"
        );

        // Test sequence query with invalid event type
        let query = Query::Sequence(Box::new(SequenceQuery {
            steps: vec![
                SequenceStep {
                    event_type: "process".to_string(),
                    condition: None,
                    id: None,
                },
                SequenceStep {
                    event_type: "invalid_event".to_string(),
                    condition: None,
                    id: None,
                },
            ],
            by: Some("process.entity_id".to_string()),
            maxspan: None,
            until: None,
            captures: vec![],
        }));

        let result = analyzer.analyze(&query);
        assert!(
            result.is_err(),
            "Invalid sequence event type should fail validation"
        );
        match result.unwrap_err() {
            EqlError::UnknownEventType { event_type } => {
                assert_eq!(event_type, "invalid_event");
            }
            _ => panic!("Expected UnknownEventType error"),
        }
    }
}
