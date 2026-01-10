//! Wasm code generator
//!
//! Generates WAT (WebAssembly Text format) from IR.

use crate::ir::*;
use crate::error::{EqlError, Result};
use std::io::Write;

/// Wasm code generator
pub struct WasmCodeGenerator {
    // Add generator state if needed
}

impl WasmCodeGenerator {
    /// Create a new Wasm code generator
    pub fn new() -> Self {
        Self {}
    }

    /// Generate WAT code for an IR rule
    pub fn generate(&self, rule: &IrRule) -> Result<String> {
        let mut output = Vec::new();

        // Write module header
        writeln!(output, "(module")?;
        writeln!(output, "  ;; Import Host API v1 functions")?;
        writeln!(output, "  (import \"kestrel\" \"event_get_i64\"")?;
        writeln!(output, "    (func $event_get_i64 (param i32 i32) (result i64)))")?;
        writeln!(output, "  (import \"kestrel\" \"event_get_u64\"")?;
        writeln!(output, "    (func $event_get_u64 (param i32 i32) (result i64)))")?;
        writeln!(output, "  (import \"kestrel\" \"event_get_str\"")?;
        writeln!(output, "    (func $event_get_str (param i32 i32) (result i32)))")?;
        writeln!(output, "  (import \"kestrel\" \"re_match\"")?;
        writeln!(output, "    (func $re_match (param i32 i32) (result i32)))")?;
        writeln!(output, "  (import \"kestrel\" \"glob_match\"")?;
        writeln!(output, "    (func $glob_match (param i32 i32) (result i32)))")?;
        writeln!(output, "  (import \"kestrel\" \"alert_emit\"")?;
        writeln!(output, "    (func $alert_emit (param i32) (result i32)))")?;
        writeln!(output)?;

        // Export pred_init
        writeln!(output, "  ;; pred_init: Initialize the predicate")?;
        writeln!(output, "  (func (export \"pred_init\") (result i32)")?;
        writeln!(output, "    (i32.const 0)  ;; Return 0 = success")?;
        writeln!(output, "  )")?;
        writeln!(output)?;

        // Export pred_eval for each predicate
        for (pred_id, predicate) in &rule.predicates {
            self.generate_pred_eval(&mut output, pred_id, predicate)?;
        }

        // Export pred_capture
        self.generate_pred_capture(&mut output, rule)?;

        writeln!(output, ")")?;

        String::from_utf8(output).map_err(|e| {
            EqlError::CodegenError {
                message: format!("Failed to convert output to string: {}", e),
            }
        })
    }

    /// Generate pred_eval function
    fn generate_pred_eval(
        &self,
        output: &mut Vec<u8>,
        pred_id: &str,
        predicate: &IrPredicate,
    ) -> Result<()> {
        writeln!(output, "  ;; pred_eval for {}: {}", pred_id, predicate.event_type)?;
        writeln!(output, "  (func (export \"pred_eval\") (param $event_handle i32) (result i32)")?;

        // Generate expression evaluation
        self.generate_node(output, &predicate.root, true)?;

        writeln!(output, "  )")?;
        writeln!(output)?;

        Ok(())
    }

    /// Generate pred_capture function
    fn generate_pred_capture(&self, output: &mut Vec<u8>, rule: &IrRule) -> Result<()> {
        writeln!(output, "  ;; pred_capture: Capture fields from matching event")?;
        writeln!(output, "  (func (export \"pred_capture\") (param $event_handle i32) (result i32)")?;
        writeln!(output, "    ;; For now, return 0 (no captures)")?;
        writeln!(output, "    (i32.const 0)")?;
        writeln!(output, "  )")?;
        writeln!(output)?;

        Ok(())
    }

    /// Generate IR node as WAT
    fn generate_node(
        &self,
        output: &mut Vec<u8>,
        node: &IrNode,
        is_root: bool,
    ) -> Result<()> {
        match node {
            IrNode::Literal { value } => {
                self.generate_literal(output, value, is_root)?;
            }
            IrNode::LoadField { field_id } => {
                // Generate field load
                writeln!(output, "    ;; Load field {}", field_id)?;
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
                writeln!(output, "    (i64.const 0)  ;; TODO: Implement string literals")?;
            }
            IrLiteral::Null => {
                writeln!(output, "    (i64.const 0)  ;; Null")?;
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
        writeln!(output, "    ;; TODO: Implement {:?} with {} args", func, args.len())?;
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
        let generator = WasmCodeGenerator::new();

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
    }
}
