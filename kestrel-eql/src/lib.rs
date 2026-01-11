//! Kestrel EQL Compiler
//!
//! Compiles EQL (Event Query Language) queries to Wasm predicates.

pub mod ast;
pub mod codegen_wasm;
pub mod compiler;
pub mod error;
pub mod ir;
pub mod parser;
pub mod semantic;

// Re-exports
pub use compiler::EqlCompiler;
pub use error::{EqlError, Result};
pub use ir::{IrLiteral, IrNode, IrPredicate, IrRule, IrRuleType};
