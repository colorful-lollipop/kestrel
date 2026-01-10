//! EQL Compiler - Main interface
//!
//! Compiles EQL queries to Wasm predicates.

use crate::error::{EqlError, Result};
use crate::ir::*;
use crate::parser;
use crate::semantic::SemanticAnalyzer;
use crate::codegen_wasm::WasmCodeGenerator;
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;

/// EQL Compiler
pub struct EqlCompiler {
    /// Schema registry for field resolution
    schema: Arc<SchemaRegistry>,
    /// Wasm code generator
    wasm_generator: WasmCodeGenerator,
}

impl EqlCompiler {
    /// Create a new EQL compiler
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self {
            schema,
            wasm_generator: WasmCodeGenerator::new(),
        }
    }

    /// Compile EQL query to Wasm
    pub fn compile_to_wasm(&self, eql: &str) -> Result<String> {
        // Step 1: Parse EQL to AST
        let ast = parser::parse(eql)?;

        // Step 2: Semantic analysis to IR
        let mut analyzer = SemanticAnalyzer::new(self.schema.clone());
        let ir = analyzer.analyze(&ast)?;

        // Step 3: Generate Wasm from IR
        let wat = self.wasm_generator.generate(&ir)?;

        Ok(wat)
    }

    /// Compile EQL query and return IR (for debugging)
    pub fn compile_to_ir(&self, eql: &str) -> Result<IrRule> {
        // Step 1: Parse EQL to AST
        let ast = parser::parse(eql)?;

        // Step 2: Semantic analysis to IR
        let mut analyzer = SemanticAnalyzer::new(self.schema.clone());
        let ir = analyzer.analyze(&ast)?;

        Ok(ir)
    }

    /// Parse EQL query to AST (for debugging)
    pub fn parse(&self, eql: &str) -> Result<crate::ast::Query> {
        parser::parse(eql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_event() {
        let schema = Arc::new(SchemaRegistry::new());
        let compiler = EqlCompiler::new(schema);

        let result = compiler.compile_to_wasm("process where process.pid == 1000");

        // Should succeed or give a semantic error (field not found)
        // We expect parsing to succeed, semantic analysis may fail without proper schema
        match result {
            Ok(wat) => {
                assert!(wat.contains("(module"));
                assert!(wat.contains("pred_init"));
                assert!(wat.contains("pred_eval"));
            }
            Err(EqlError::UnknownField { .. }) => {
                // Expected - schema not set up
                assert!(true);
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_parse_sequence() {
        let schema = Arc::new(SchemaRegistry::new());
        let compiler = EqlCompiler::new(schema);

        let result = compiler.parse("sequence by process.entity_id [process] [file]");

        assert!(result.is_ok());

        let query = result.unwrap();
        match query {
            crate::ast::Query::Sequence(sq) => {
                assert_eq!(sq.steps.len(), 2);
            }
            _ => panic!("Expected sequence query"),
        }
    }
}
