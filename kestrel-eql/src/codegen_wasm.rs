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

/// String literal entry
struct StringLiteral {
    /// The string value
    value: String,
    /// Offset in data section
    offset: u32,
    /// Length in bytes
    length: u32,
}

/// Wasm code generator
pub struct WasmCodeGenerator {
    /// Map of predicate IDs to indices
    predicate_indices: HashMap<String, usize>,
    /// Map of field IDs to types
    field_types: HashMap<u32, WasmFieldType>,
    /// String literals pool
    string_literals: Vec<StringLiteral>,
    /// Next available offset in data section
    next_offset: u32,
}

impl WasmCodeGenerator {
    /// Create a new Wasm code generator
    pub fn new() -> Self {
        Self {
            predicate_indices: HashMap::new(),
            field_types: HashMap::new(),
            string_literals: Vec::new(),
            next_offset: 0,
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

        // Collect string literals and compute offsets
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
        writeln!(output, "  (import \"kestrel\" \"alert_emit\"")?;
        writeln!(
            output,
            "    (func $alert_emit (param i32 i32) (result i32)))"
        )?;
        writeln!(output)?;

        // Write memory section (for string operations)
        writeln!(
            output,
            "  ;; Memory: 16 pages (1MB) for string literals and buffers"
        )?;
        writeln!(output, "  (memory (export \"memory\") 16)")?;
        writeln!(output)?;

        // Write string data section
        self.write_string_data_section(&mut output)?;

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

    /// Write string data section with all literals
    fn write_string_data_section(&self, output: &mut Vec<u8>) -> Result<()> {
        writeln!(output, "  ;; String literals data section")?;

        for lit in &self.string_literals {
            // Escape special characters for WAT
            let escaped = self.escape_wat_string(&lit.value);
            writeln!(
                output,
                "  (data (i32.const {}) \"{}\")",
                lit.offset, escaped
            )?;
        }

        if self.string_literals.is_empty() {
            writeln!(output, "  (data (i32.const 0) \"\")")?;
        }

        writeln!(output)?;
        Ok(())
    }

    /// Escape string for WAT data section
    fn escape_wat_string(&self, s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                '\\' => result.push_str("\\\\"),
                '"' => result.push_str("\\\""),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                '\0' => result.push_str("\\00"),
                c if c.is_ascii_control() => {
                    result.push('\\');
                    result.push(((c as u8) / 100 + b'0') as char);
                    result.push((((c as u8) / 10) % 10 + b'0') as char);
                    result.push(((c as u8) % 10 + b'0') as char);
                }
                _ => result.push(c),
            }
        }
        result
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
        for predicate in rule.predicates.values() {
            self.analyze_node_types(&predicate.root)?;
        }
        Ok(())
    }

    /// Analyze field types in an IR node
    fn analyze_node_types(&mut self, node: &IrNode) -> Result<()> {
        match node {
            IrNode::LoadField { field_id } => {
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
            IrNode::Literal { value: _ } => {}
        }
        Ok(())
    }

    /// Collect string literals from all predicates
    fn collect_string_literals(&mut self, rule: &IrRule) -> Result<()> {
        self.string_literals.clear();
        self.next_offset = 0;

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
                    if !self.string_literals.iter().any(|lit| lit.value == *s) {
                        let offset = self.next_offset;
                        self.string_literals.push(StringLiteral {
                            value: s.clone(),
                            offset,
                            length: s.len() as u32,
                        });
                        self.next_offset += s.len() as u32 + 1; // +1 for null terminator
                    }
                }
            }
            IrNode::LoadField { field_id: _ } => {}
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
                for val in values {
                    if let IrLiteral::String(s) = val {
                        if !self.string_literals.iter().any(|lit| lit.value == *s) {
                            let offset = self.next_offset;
                            self.string_literals.push(StringLiteral {
                                value: s.clone(),
                                offset,
                                length: s.len() as u32,
                            });
                            self.next_offset += s.len() as u32 + 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Get offset and length for a string literal
    fn get_string_literal_info(&self, s: &str) -> Option<(u32, u32)> {
        self.string_literals
            .iter()
            .find(|lit| lit.value == s)
            .map(|lit| (lit.offset, lit.length))
    }

    /// Generate pred_capture function
    fn generate_pred_capture(&self, output: &mut Vec<u8>, rule: &IrRule) -> Result<()> {
        writeln!(
            output,
            "  ;; pred_capture: Capture fields from matching event"
        )?;
        writeln!(
            output,
            "  (func (export \"pred_capture\") (param $event_handle i32) (param $capture_ptr i32) (result i32)"
        )?;

        if rule.captures.is_empty() {
            writeln!(output, "    (i32.const 0)  ;; No captures defined")?;
        } else {
            writeln!(output, "    ;; TODO: Implement field captures")?;
            writeln!(output, "    (i32.const 0)")?;
        }

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
                let val = if *b { 1 } else { 0 };
                writeln!(output, "    (i32.const {})", val)?;
                if !is_root {
                    writeln!(output, "    (i64.extend_i32_u)")?;
                }
            }
            IrLiteral::Int(i) => {
                writeln!(output, "    (i64.const {})", i)?;
            }
            IrLiteral::String(s) => {
                // String literal: get offset and load from data section
                if let Some((offset, length)) = self.get_string_literal_info(s) {
                    writeln!(output, "    ;; String literal: \"{}\"", s)?;
                    writeln!(output, "    (i32.const {})  ;; offset", offset)?;
                    writeln!(output, "    (i32.const {})  ;; length", length)?;
                    if is_root {
                        writeln!(output, "    (i32.const 1)  ;; true (non-empty)")?;
                    }
                } else {
                    writeln!(
                        output,
                        "    (i32.const 0)  ;; String literal not found: \"{}\"",
                        s
                    )?;
                    if is_root {
                        writeln!(output, "    (i32.const 0)")?;
                    }
                }
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
                writeln!(output, "    ;; String field comparison")?;
                writeln!(output, "    (local.get $event_handle)")?;
                writeln!(output, "    (i32.const {})", field_id)?;
                writeln!(output, "    (i32.const 0)  ;; buffer ptr")?;
                writeln!(output, "    (i32.const 256)  ;; buffer size")?;
                writeln!(output, "    (call $event_get_str)")?;
                writeln!(output, "    (i32.const 0)  ;; string ptr")?;
                writeln!(output, "    (i32.ne)")?;
                if is_root {
                    writeln!(output, "    (if (result i32)")?;
                    writeln!(output, "      (then (i32.const 1))")?;
                    writeln!(output, "      (else (i32.const 0))")?;
                    writeln!(output, "    )")?;
                }
            }
            WasmFieldType::Bool => {
                writeln!(output, "    (local.get $event_handle)")?;
                writeln!(output, "    (i32.const {})", field_id)?;
                writeln!(output, "    (call $event_get_bool)")?;
                if is_root {
                    // event_get_bool already returns i32 (0 or 1)
                    writeln!(output, "    (i32.eqz)")?;
                    writeln!(output, "    (i32.const 0)")?;
                    writeln!(output, "    (i32.neq)")?;
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

        match op {
            IrBinaryOp::And | IrBinaryOp::Or => {
                self.generate_logical_binary_op(output, op, left, right, is_root)?;
            }
            IrBinaryOp::Eq
            | IrBinaryOp::NotEq
            | IrBinaryOp::Less
            | IrBinaryOp::LessEq
            | IrBinaryOp::Greater
            | IrBinaryOp::GreaterEq => {
                self.generate_comparison_binary_op(output, op, left, right, is_root)?;
            }
            IrBinaryOp::Add
            | IrBinaryOp::Sub
            | IrBinaryOp::Mul
            | IrBinaryOp::Div
            | IrBinaryOp::Mod => {
                self.generate_arithmetic_binary_op(output, op, left, right, is_root)?;
            }
        }

        Ok(())
    }

    /// Generate logical binary operation (and/or)
    fn generate_logical_binary_op(
        &self,
        output: &mut Vec<u8>,
        op: &IrBinaryOp,
        left: &IrNode,
        right: &IrNode,
        is_root: bool,
    ) -> Result<()> {
        // Generate left operand
        self.generate_node(output, left, false)?;
        writeln!(output, "    (i64.const 0)")?;
        writeln!(output, "    (i64.ne)")?;

        // Generate right operand
        self.generate_node(output, right, false)?;
        writeln!(output, "    (i64.const 0)")?;
        writeln!(output, "    (i64.ne)")?;

        match op {
            IrBinaryOp::And => {
                writeln!(output, "    (i64.and)")?;
            }
            IrBinaryOp::Or => {
                writeln!(output, "    (i64.or)")?;
            }
            _ => {}
        }

        if is_root {
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
        }

        Ok(())
    }

    /// Generate comparison binary operation
    fn generate_comparison_binary_op(
        &self,
        output: &mut Vec<u8>,
        op: &IrBinaryOp,
        left: &IrNode,
        right: &IrNode,
        is_root: bool,
    ) -> Result<()> {
        // Generate left operand
        self.generate_node(output, left, false)?;

        // Generate right operand
        self.generate_node(output, right, false)?;

        match op {
            IrBinaryOp::Eq => {
                writeln!(output, "    (i64.eq)")?;
            }
            IrBinaryOp::NotEq => {
                writeln!(output, "    (i64.ne)")?;
            }
            IrBinaryOp::Less => {
                writeln!(output, "    (i64.lt_s)")?;
            }
            IrBinaryOp::LessEq => {
                writeln!(output, "    (i64.le_s)")?;
            }
            IrBinaryOp::Greater => {
                writeln!(output, "    (i64.gt_s)")?;
            }
            IrBinaryOp::GreaterEq => {
                writeln!(output, "    (i64.ge_s)")?;
            }
            _ => {}
        }

        if is_root {
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
        }

        Ok(())
    }

    /// Generate arithmetic binary operation
    fn generate_arithmetic_binary_op(
        &self,
        output: &mut Vec<u8>,
        op: &IrBinaryOp,
        left: &IrNode,
        right: &IrNode,
        is_root: bool,
    ) -> Result<()> {
        // Generate left operand
        self.generate_node(output, left, false)?;

        // Generate right operand
        self.generate_node(output, right, false)?;

        match op {
            IrBinaryOp::Add => {
                writeln!(output, "    (i64.add)")?;
            }
            IrBinaryOp::Sub => {
                writeln!(output, "    (i64.sub)")?;
            }
            IrBinaryOp::Mul => {
                writeln!(output, "    (i64.mul)")?;
            }
            IrBinaryOp::Div => {
                writeln!(output, "    (i64.div_s")?;
                writeln!(output, "    )")?;
            }
            IrBinaryOp::Mod => {
                writeln!(output, "    (i64.rem_s)")?;
            }
            _ => {}
        }

        if is_root {
            writeln!(output, "    (i64.const 0)")?;
            writeln!(output, "    (i64.ne)")?;
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
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
                writeln!(output, "    (i64.const 0)")?;
                writeln!(output, "    (i64.eq)")?;
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

        match func {
            IrFunction::Contains => {
                self.generate_string_function(output, "contains", args, is_root)?;
            }
            IrFunction::StartsWith => {
                self.generate_string_function(output, "startsWith", args, is_root)?;
            }
            IrFunction::EndsWith => {
                self.generate_string_function(output, "endsWith", args, is_root)?;
            }
            IrFunction::Regex => {
                self.generate_regex_function(output, args, is_root)?;
            }
            IrFunction::Wildcard => {
                self.generate_wildcard_function(output, args, is_root)?;
            }
            IrFunction::StringEqualsCi => {
                self.generate_string_function(output, "stringEqualsCi", args, is_root)?;
            }
        }

        Ok(())
    }

    /// Generate string function (contains, startsWith, endsWith)
    fn generate_string_function(
        &self,
        output: &mut Vec<u8>,
        func_name: &str,
        args: &[IrNode],
        is_root: bool,
    ) -> Result<()> {
        if args.len() < 2 {
            writeln!(output, "    ;; Error: {} requires 2 args", func_name)?;
            writeln!(output, "    (i64.const 0)")?;
            return Ok(());
        }

        // args[0] is the string to search in (usually a field)
        // args[1] is the pattern (usually a string literal)

        // Generate the haystack (string to search in)
        writeln!(output, "    ;; Get haystack string")?;
        self.generate_node(output, &args[0], false)?;
        writeln!(output, "    (i32.const 0)  ;; buffer")?;
        writeln!(output, "    (i32.const 256)  ;; buffer size")?;
        writeln!(output, "    (call $event_get_str)  ;; get haystack")?;
        writeln!(output, "    (local.set $haystack_ptr)")?;
        writeln!(output, "    (local.get $haystack_ptr)")?;

        // Generate the needle (pattern to search for)
        if let IrNode::Literal {
            value: IrLiteral::String(s),
        } = &args[1]
        {
            if let Some((offset, length)) = self.get_string_literal_info(s) {
                writeln!(output, "    ;; Needle: \"{}\"", s)?;
                writeln!(output, "    (i32.const {})  ;; needle offset", offset)?;
            } else {
                writeln!(output, "    (i32.const 0)  ;; needle offset (not found)")?;
            }
        } else {
            writeln!(output, "    ;; Needle is not a literal")?;
            writeln!(output, "    (i32.const 0)")?;
        }

        // Use glob_match for string matching (simple prefix/suffix check)
        writeln!(output, "    (call $glob_match)")?;

        if is_root {
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
        }

        Ok(())
    }

    /// Generate regex function
    fn generate_regex_function(
        &self,
        output: &mut Vec<u8>,
        args: &[IrNode],
        is_root: bool,
    ) -> Result<()> {
        if args.len() < 2 {
            writeln!(output, "    ;; Error: regex requires 2 args")?;
            writeln!(output, "    (i64.const 0)")?;
            return Ok(());
        }

        // args[0] is the pattern (literal)
        // args[1] is the string to match

        // Generate pattern
        if let IrNode::Literal {
            value: IrLiteral::String(s),
        } = &args[0]
        {
            if let Some((offset, _length)) = self.get_string_literal_info(s) {
                writeln!(output, "    (i32.const {})  ;; pattern offset", offset)?;
            } else {
                writeln!(output, "    (i32.const 0)  ;; pattern offset")?;
            }
        } else {
            writeln!(output, "    (i32.const 0)  ;; pattern")?;
        }

        // Generate string to match
        writeln!(output, "    (i32.const 0)  ;; buffer")?;
        writeln!(output, "    (i32.const 256)  ;; buffer size")?;
        writeln!(output, "    (call $event_get_str)")?;

        writeln!(output, "    (call $re_match)")?;

        if is_root {
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
        }

        Ok(())
    }

    /// Generate wildcard function
    fn generate_wildcard_function(
        &self,
        output: &mut Vec<u8>,
        args: &[IrNode],
        is_root: bool,
    ) -> Result<()> {
        if args.len() < 2 {
            writeln!(output, "    ;; Error: wildcard requires 2 args")?;
            writeln!(output, "    (i64.const 0)")?;
            return Ok(());
        }

        // args[0] is the pattern (literal)
        // args[1] is the string to match

        // Generate pattern
        if let IrNode::Literal {
            value: IrLiteral::String(s),
        } = &args[0]
        {
            if let Some((offset, _length)) = self.get_string_literal_info(s) {
                writeln!(output, "    (i32.const {})  ;; pattern offset", offset)?;
            } else {
                writeln!(output, "    (i32.const 0)  ;; pattern offset")?;
            }
        } else {
            writeln!(output, "    (i32.const 0)  ;; pattern")?;
        }

        // Generate string to match
        writeln!(output, "    (i32.const 0)  ;; buffer")?;
        writeln!(output, "    (i32.const 256)  ;; buffer size")?;
        writeln!(output, "    (call $event_get_str)")?;

        writeln!(output, "    (call $glob_match)")?;

        if is_root {
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
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

        // Generate value to check
        self.generate_node(output, value, false)?;

        // For each value in the set, generate a comparison and OR them together
        let mut first = true;
        for val in values {
            if first {
                writeln!(output, "    (i64.const 0)")?;
                self.generate_literal_value(output, val)?;
                writeln!(output, "    (i64.eq)")?;
                first = false;
            } else {
                writeln!(output, "    (i64.const 0)")?;
                self.generate_literal_value(output, val)?;
                writeln!(output, "    (i64.eq)")?;
                writeln!(output, "    (i64.or)")?;
            }
        }

        if is_root {
            writeln!(output, "    (if (result i32)")?;
            writeln!(output, "      (then (i32.const 1))")?;
            writeln!(output, "      (else (i32.const 0))")?;
            writeln!(output, "    )")?;
        }

        Ok(())
    }

    /// Generate a literal value (without newlines)
    fn generate_literal_value(&self, output: &mut Vec<u8>, value: &IrLiteral) -> Result<()> {
        match value {
            IrLiteral::Bool(b) => {
                writeln!(output, "    (i32.const {})", if *b { 1 } else { 0 })?;
                writeln!(output, "    (i64.extend_i32_u)")?;
            }
            IrLiteral::Int(i) => {
                writeln!(output, "    (i64.const {})", i)?;
            }
            IrLiteral::String(s) => {
                if let Some((offset, _length)) = self.get_string_literal_info(s) {
                    writeln!(output, "    (i32.const {})", offset)?;
                } else {
                    writeln!(output, "    (i32.const 0)")?;
                }
            }
            IrLiteral::Null => {
                writeln!(output, "    (i64.const 0)")?;
            }
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
        assert!(wat.contains("$event_get_i64"));
        assert!(wat.contains("(i32.const 42)"));
    }

    #[test]
    fn test_string_literal_in_data_section() {
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
            root: IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("/bin/bash".to_string()),
                }),
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
        // Should have string data section with the literal
        assert!(wat.contains("(data"));
        assert!(wat.contains("/bin/bash"));
    }

    #[test]
    fn test_arithmetic_operations() {
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
            root: IrNode::BinaryOp {
                op: IrBinaryOp::Add,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::Int(10),
                }),
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
        // Should have i64.add for Add operation
        assert!(wat.contains("(i64.add)"));
    }

    #[test]
    fn test_function_call() {
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
            root: IrNode::FunctionCall {
                func: IrFunction::Contains,
                args: vec![
                    IrNode::LoadField { field_id: 1 },
                    IrNode::Literal {
                        value: IrLiteral::String("suspicious".to_string()),
                    },
                ],
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
        // Should reference glob_match for contains
        assert!(wat.contains("$glob_match"));
    }
}
