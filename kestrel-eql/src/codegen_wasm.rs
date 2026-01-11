//! Wasm code generator
//!
//! Generates WAT (WebAssembly Text format) from IR.
//!
//! ## Architecture
//!
//! The codegen generates a single Wasm module per rule with:
//! - One `pred_init` export for initialization
//! - One `pred_eval(predicate_id, event_handle)` dispatcher
//! - Internal functions for each predicate (e.g., `$pred_eval_0`, `$pred_eval_1`)
//! - String data section for literals
//!
//! ## Type System
//!
//! The codegen tracks field types and calls appropriate Host API getters:
//! - `event_get_i64` for i64 fields
//! - `event_get_u64` for u64 fields
//! - `event_get_str` for string fields (returns pointer/length)
//! - `event_get_bool` for boolean fields

use crate::error::{EqlError, Result};
use crate::ir::*;
use std::collections::HashMap;
use std::io::Write;

/// Field type for Wasm codegen
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmFieldType {
    I64,
    U64,
    String,
    Bool,
}

/// Wasm code generator
pub struct WasmCodeGenerator {
    /// Map of predicate IDs to indices
    predicate_indices: HashMap<String, usize>,
    /// Map of field IDs to types
    field_types: HashMap<u32, WasmFieldType>,
    /// String literals pool
    string_literals: Vec<String>,
}

impl WasmCodeGenerator {
    /// Create a new Wasm code generator
    pub fn new() -> Self {
        Self {
            predicate_indices: HashMap::new(),
            field_types: HashMap::new(),
            string_literals: Vec::new(),
        }
    }

    /// Generate WAT code for an IR rule
    pub fn generate(&mut self, rule: &IrRule) -> Result<String> {
        let mut output = Vec::new();

        // Build predicate index map
        for (idx, pred_id) in rule.predicates.keys().enumerate() {
            self.predicate_indices.insert(pred_id.clone(), idx);
        }

        // Analyze field types from all predicates
        self.analyze_field_types(rule)?;

        // Collect string literals
        self.collect_string_literals(rule)?;

        // Write module header
        writeln!(output, "(module")?;
        writeln!(output, "  ;; Import Host API v1 functions")?;
        writeln!(output, "  (import \"kestrel\" \"event_get_i64\"")?;
        writeln!(
            output,
            "    (func $event_get_i64 (param i32 i32) (result i64)))"
        )?;
        writeln!(output, "  (import \"kestrel\" \"event_get_u64\"")?;
        writeln!(
            output,
            "    (func $event_get_u64 (param i32 i32) (result i64)))"
        )?;
        writeln!(output, "  (import \"kestrel\" \"event_get_str\"")?;
        writeln!(
            output,
            "    (func $event_get_str (param i32 i32 i32) (result i32)))"
        )?;
        writeln!(output, "  (import \"kestrel\" \"event_get_bool\"")?;
        writeln!(
            output,
            "    (func $event_get_bool (param i32 i32) (result i32)))"
        )?;
        writeln!(output, "  (import \"kestrel\" \"re_match\"")?;
        writeln!(
            output,
            "    (func $re_match (param i32 i32 i32) (result i32)))"
        )?;
        writeln!(output, "  (import \"kestrel\" \"glob_match\"")?;
        writeln!(
            output,
            "    (func $glob_match (param i32 i32 i32) (result i32)))"
        )?;
        writeln!(output)?;

        // Write memory section (for string operations)
        writeln!(output, "  (memory (export \"memory\") 16)")?;
        writeln!(output, "  (data (i32.const 0) \"\")")?;
        writeln!(output)?;

        // Export pred_init
        writeln!(output, "  ;; pred_init: Initialize the predicate")?;
        writeln!(output, "  (func (export \"pred_init\") (result i32)")?;
        writeln!(output, "    (i32.const 0)  ;; Return 0 = success")?;
        writeln!(output, "  )")?;
        writeln!(output)?;

        // Export pred_eval dispatcher
        self.generate_pred_eval_dispatcher(&mut output, rule)?;

        // Generate internal predicate functions
        for (pred_id, predicate) in &rule.predicates {
            let idx =
                self.predicate_indices
                    .get(pred_id)
                    .ok_or_else(|| EqlError::CodegenError {
                        message: format!("Predicate ID not found: {}", pred_id),
                    })?;
            self.generate_pred_eval_internal(&mut output, *idx, pred_id, predicate)?;
        }

        // Export pred_capture
        self.generate_pred_capture(&mut output, rule)?;

        writeln!(output, ")")?;

        String::from_utf8(output).map_err(|e| EqlError::CodegenError {
            message: format!("Failed to convert output to string: {}", e),
        })
    }

    /// Generate the pred_eval dispatcher
    fn generate_pred_eval_dispatcher(&self, output: &mut Vec<u8>, rule: &IrRule) -> Result<()> {
        writeln!(output, "  ;; pred_eval: Dispatch to appropriate predicate")?;
        writeln!(output, "  (func (export \"pred_eval\") (param $predicate_id i32) (param $event_handle i32) (result i32)")?;
        writeln!(output, "    (local $result i32)")?;

        // Generate dispatch logic using if-else chain
        let mut first = true;
        for (pred_id, _) in rule.predicates.iter() {
            let idx = self.predicate_indices.get(pred_id).unwrap();
            if first {
                write!(
                    output,
                    "    (if (i32.eq (local.get $predicate_id) (i32.const {}))",
                    idx
                )?;
                first = false;
            } else {
                write!(
                    output,
                    "    (else (if (i32.eq (local.get $predicate_id) (i32.const {}))",
                    idx
                )?;
            }
            writeln!(output, "")?;
            writeln!(output, "      (then")?;
            writeln!(
                output,
                "        (call $pred_eval_{} (local.get $event_handle))",
                idx
            )?;
            writeln!(output, "        (local.set $result)")?;
            writeln!(output, "      )")?;
        }

        // Close all the if-else blocks
        for _ in 0..rule.predicates.len().saturating_sub(1) {
            writeln!(output, "    )")?;
        }
        if !rule.predicates.is_empty() {
            writeln!(output, "    ))")?;
        }

        // Default case: return 0 (no match)
        writeln!(output, "    (local.get $result)")?;
        writeln!(output, "  )")?;
        writeln!(output)?;

        Ok(())
    }

    /// Generate internal pred_eval function for a single predicate
    fn generate_pred_eval_internal(
        &self,
        output: &mut Vec<u8>,
        idx: usize,
        pred_id: &str,
        predicate: &IrPredicate,
    ) -> Result<()> {
        writeln!(
            output,
            "  ;; Internal pred_eval for {}: {}",
            pred_id, predicate.event_type
        )?;
        writeln!(
            output,
            "  (func $pred_eval_{} (param $event_handle i32) (result i32)",
            idx
        )?;

        // Generate expression evaluation
        self.generate_node(output, &predicate.root, true)?;

        writeln!(output, "  )")?;
        writeln!(output)?;

        Ok(())
    }

    /// Analyze field types from all predicates
    fn analyze_field_types(&mut self, rule: &IrRule) -> Result<()> {
        // For now, default all fields to I64
        // TODO: Extract from IR metadata or schema
        for predicate in rule.predicates.values() {
            self.analyze_node_types(&predicate.root)?;
        }
        Ok(())
    }

    /// Analyze field types in an IR node
    fn analyze_node_types(&mut self, node: &IrNode) -> Result<()> {
        match node {
            IrNode::LoadField { field_id } => {
                // Default to I64 if not already set
                self.field_types
                    .entry(*field_id)
                    .or_insert(WasmFieldType::I64);
            }
            IrNode::BinaryOp { op: _, left, right } => {
                self.analyze_node_types(left)?;
                self.analyze_node_types(right)?;
            }
            IrNode::UnaryOp { op: _, operand } => {
                self.analyze_node_types(operand)?;
            }
            IrNode::FunctionCall { func: _, args } => {
                for arg in args {
                    self.analyze_node_types(arg)?;
                }
            }
            IrNode::In { value, values: _ } => {
                self.analyze_node_types(value)?;
            }
            IrNode::Literal { value: _ } => {
                // Literals don't affect field types
            }
        }
        Ok(())
    }

    /// Collect string literals from all predicates
    fn collect_string_literals(&mut self, rule: &IrRule) -> Result<()> {
        for predicate in rule.predicates.values() {
            self.collect_node_literals(&predicate.root)?;
        }
        Ok(())
    }

    /// Collect string literals from an IR node
    fn collect_node_literals(&mut self, node: &IrNode) -> Result<()> {
        match node {
            IrNode::Literal { value } => {
                if let IrLiteral::String(s) = value {
                    if !self.string_literals.contains(s) {
                        self.string_literals.push(s.clone());
                    }
                }
            }
            IrNode::LoadField { field_id: _ } => {
                // LoadField doesn't contain string literals
            }
            IrNode::BinaryOp { op: _, left, right } => {
                self.collect_node_literals(left)?;
                self.collect_node_literals(right)?;
            }
            IrNode::UnaryOp { op: _, operand } => {
                self.collect_node_literals(operand)?;
            }
            IrNode::FunctionCall { func: _, args } => {
                for arg in args {
                    self.collect_node_literals(arg)?;
                }
            }
            IrNode::In { value, values } => {
                self.collect_node_literals(value)?;
                for value in values {
                    if let IrLiteral::String(s) = value {
                        if !self.string_literals.contains(s) {
                            self.string_literals.push(s.clone());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Generate pred_capture function
    fn generate_pred_capture(&self, output: &mut Vec<u8>, _rule: &IrRule) -> Result<()> {
        writeln!(
            output,
            "  ;; pred_capture: Capture fields from matching event"
        )?;
        writeln!(
            output,
            "  (func (export \"pred_capture\") (param $event_handle i32) (result i32)"
        )?;
        writeln!(output, "    ;; For now, return 0 (no captures)")?;
        writeln!(output, "    (i32.const 0)")?;
        writeln!(output, "  )")?;
        writeln!(output)?;

        Ok(())
    }

    /// Generate IR node as WAT
    fn generate_node(&self, output: &mut Vec<u8>, node: &IrNode, is_root: bool) -> Result<()> {
        match node {
            IrNode::Literal { value } => {
                self.generate_literal(output, value, is_root)?;
            }
            IrNode::LoadField { field_id } => {
                self.generate_load_field(output, *field_id, is_root)?;
            }
            IrNode::BinaryOp { op, left, right } => {
                self.generate_binary_op(output, op, left, right, is_root)?;
            }
            IrNode::UnaryOp { op, operand } => {
                self.generate_unary_op(output, op, operand, is_root)?;
            }
            IrNode::FunctionCall { func, args } => {
                self.generate_function_call(output, func, args, is_root)?;
            }
            IrNode::In { value, values } => {
                self.generate_in(output, value, values, is_root)?;
            }
        }

        Ok(())
    }

    /// Generate literal value
    fn generate_literal(
        &self,
        output: &mut Vec<u8>,
        value: &IrLiteral,
        is_root: bool,
    ) -> Result<()> {
        match value {
            IrLiteral::Bool(b) => {
                if is_root {
                    writeln!(output, "    (i32.const {})", if *b { 1 } else { 0 })?;
                } else {
                    writeln!(output, "    (i64.const {})", if *b { 1 } else { 0 })?;
                }
            }
            IrLiteral::Int(i) => {
                writeln!(output, "    (i64.const {})", i)?;
            }
            IrLiteral::String(s) => {
                // For strings, we'd need to allocate memory
                writeln!(output, "    ;; String literal: \"{}\"", s)?;
                writeln!(
                    output,
                    "    (i64.const 0)  ;; TODO: Implement string literals"
                )?;
            }
            IrLiteral::Null => {
                writeln!(output, "    (i64.const 0)  ;; Null")?;
            }
        }

        Ok(())
    }

    /// Generate field load with appropriate typed getter
    fn generate_load_field(
        &self,
        output: &mut Vec<u8>,
        field_id: u32,
        is_root: bool,
    ) -> Result<()> {
        writeln!(output, "    ;; Load field {}", field_id)?;

        // Get field type (default to I64)
        let field_type = self
            .field_types
            .get(&field_id)
            .copied()
            .unwrap_or(WasmFieldType::I64);

        match field_type {
            WasmFieldType::I64 => {
                writeln!(output, "    (local.get $event_handle)")?;
                writeln!(output, "    (i32.const {})", field_id)?;
                writeln!(output, "    (call $event_get_i64)")?;
                if is_root {
                    writeln!(output, "    (i64.const 0)")?;
                    writeln!(output, "    (i64.ne)")?;
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            WasmFieldType::U64 => {
                writeln!(output, "    (local.get $event_handle)")?;
                writeln!(output, "    (i32.const {})", field_id)?;
                writeln!(output, "    (call $event_get_u64)")?;
                if is_root {
                    writeln!(output, "    (i64.const 0)")?;
                    writeln!(output, "    (i64.ne)")?;
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            WasmFieldType::String => {
                writeln!(output, "    ;; String field comparison not yet implemented")?;
                writeln!(output, "    (i64.const 0)")?;
                if is_root {
                    writeln!(output, "    (i32.const 0)")?;
                }
            }
            WasmFieldType::Bool => {
                writeln!(output, "    (local.get $event_handle)")?;
                writeln!(output, "    (i32.const {})", field_id)?;
                writeln!(output, "    (call $event_get_bool)")?;
                if is_root {
                    // event_get_bool already returns i32, so no conversion needed
                } else {
                    // Convert to i64 for intermediate operations
                    writeln!(output, "    (i64.extend_i32_u)")?;
                }
            }
        }

        Ok(())
    }

    /// Generate binary operation
    fn generate_binary_op(
        &self,
        output: &mut Vec<u8>,
        op: &IrBinaryOp,
        left: &IrNode,
        right: &IrNode,
        is_root: bool,
    ) -> Result<()> {
        writeln!(output, "    ;; Binary operation: {:?}", op)?;

        // Generate left operand (not as root to keep intermediate value)
        self.generate_node(output, left, false)?;

        // Generate right operand
        self.generate_node(output, right, false)?;

        // Apply operation
        match op {
            IrBinaryOp::And => {
                writeln!(output, "    (i64.and)")?;
                if is_root {
                    writeln!(output, "    (i64.const 0)")?;
                    writeln!(output, "    (i64.ne)")?;
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::Or => {
                writeln!(output, "    (i64.or)")?;
                if is_root {
                    writeln!(output, "    (i64.const 0)")?;
                    writeln!(output, "    (i64.ne)")?;
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::Eq => {
                writeln!(output, "    (i64.eq)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::NotEq => {
                writeln!(output, "    (i64.ne)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::Less => {
                writeln!(output, "    (i64.lt_s)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::LessEq => {
                writeln!(output, "    (i64.le_s)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::Greater => {
                writeln!(output, "    (i64.gt_s)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrBinaryOp::GreaterEq => {
                writeln!(output, "    (i64.ge_s)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            _ => {
                writeln!(output, "    ;; TODO: {:?}", op)?;
                writeln!(output, "    (i64.const 0)")?;
            }
        }

        Ok(())
    }

    /// Generate unary operation
    fn generate_unary_op(
        &self,
        output: &mut Vec<u8>,
        op: &IrUnaryOp,
        operand: &IrNode,
        is_root: bool,
    ) -> Result<()> {
        writeln!(output, "    ;; Unary operation: {:?}", op)?;

        self.generate_node(output, operand, false)?;

        match op {
            IrUnaryOp::Not => {
                writeln!(output, "    (i64.eqz)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            IrUnaryOp::Neg => {
                writeln!(output, "    (i64.const 0)")?;
                writeln!(output, "    (i64.sub)")?;
            }
        }

        Ok(())
    }

    /// Generate function call
    fn generate_function_call(
        &self,
        output: &mut Vec<u8>,
        func: &IrFunction,
        args: &[IrNode],
        is_root: bool,
    ) -> Result<()> {
        writeln!(output, "    ;; Function call: {:?}", func)?;

        // For now, generate stub for function calls
        writeln!(
            output,
            "    ;; TODO: Implement {:?} with {} args",
            func,
            args.len()
        )?;
        writeln!(output, "    (i64.const 0)")?;

        if is_root {
            writeln!(output, "    (i32.const 0)")?;
        }

        Ok(())
    }

    /// Generate in expression
    fn generate_in(
        &self,
        output: &mut Vec<u8>,
        value: &IrNode,
        values: &[IrLiteral],
        is_root: bool,
    ) -> Result<()> {
        writeln!(output, "    ;; In expression with {} values", values.len())?;

        // Generate value
        self.generate_node(output, value, false)?;

        // TODO: Generate comparisons for each value
        writeln!(output, "    ;; TODO: Compare with each value")?;
        writeln!(output, "    (i64.const 0)")?;

        if is_root {
            writeln!(output, "    (i32.const 0)")?;
        }

        Ok(())
    }
}

impl Default for WasmCodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_simple_predicate() {
        let mut generator = WasmCodeGenerator::new();

        let rule = IrRule::new(
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

        let mut rule_with_pred = rule;
        rule_with_pred.add_predicate(predicate);

        let result = generator.generate(&rule_with_pred);
        assert!(result.is_ok());

        let wat = result.unwrap();
        assert!(wat.contains("(module"));
        assert!(wat.contains("pred_init"));
        assert!(wat.contains("pred_eval"));
        // Should have dispatcher with predicate_id parameter
        assert!(wat.contains("(param $predicate_id i32)"));
    }

    #[test]
    fn test_dispatcher_with_multiple_predicates() {
        let mut generator = WasmCodeGenerator::new();

        let rule = IrRule::new(
            "test-rule".to_string(),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let pred1 = IrPredicate {
            id: "pred1".to_string(),
            event_type: "process".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };

        let pred2 = IrPredicate {
            id: "pred2".to_string(),
            event_type: "process".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(false),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };

        let mut rule_with_preds = rule;
        rule_with_preds.add_predicate(pred1);
        rule_with_preds.add_predicate(pred2);

        let result = generator.generate(&rule_with_preds);
        assert!(result.is_ok());

        let wat = result.unwrap();
        // Should have internal functions for each predicate
        assert!(wat.contains("$pred_eval_0"));
        assert!(wat.contains("$pred_eval_1"));
    }

    #[test]
    fn test_field_type_tracking() {
        let mut generator = WasmCodeGenerator::new();

        let rule = IrRule::new(
            "test-rule".to_string(),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: "process".to_string(),
            root: IrNode::LoadField { field_id: 42 },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };

        let mut rule_with_pred = rule;
        rule_with_pred.add_predicate(predicate);

        let result = generator.generate(&rule_with_pred);
        assert!(result.is_ok());

        let wat = result.unwrap();
        // Should call event_get_i64 for field 42
        assert!(wat.contains("$event_get_i64"));
        assert!(wat.contains("(i32.const 42)"));
    }
}
