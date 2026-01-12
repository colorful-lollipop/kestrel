#!/usr/bin/env rust-script

//! Quick demonstration of type checking in EQL semantic analyzer
//! This script shows that type checking is working for binary operations.

use kestrel_eql::ast::*;
use kestrel_eql::ir::*;
use kestrel_eql::semantic::SemanticAnalyzer;
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;

fn main() {
    println!("=== EQL Type Checking Demo ===\n");

    let analyzer = SemanticAnalyzer::new(Arc::new(SchemaRegistry::new()));

    // Test 1: Valid integer comparison
    println!("1. Testing valid integer comparison (5 == 10)...");
    let left_int = IrNode::Literal {
        value: IrLiteral::Int(5),
    };
    let right_int = IrNode::Literal {
        value: IrLiteral::Int(10),
    };
    let left_expr = Expr::IntLiteral(5);
    let right_expr = Expr::IntLiteral(10);

    match analyzer.check_binary_op_types(
        BinaryOperator::Eq,
        &left_int,
        &right_int,
        &left_expr,
        &right_expr,
    ) {
        Ok(_) => println!("   ✅ PASS: Integer comparison is valid"),
        Err(e) => println!("   ❌ FAIL: {}", e),
    }

    // Test 2: Invalid boolean vs integer comparison
    println!("\n2. Testing invalid comparison (true == 10)...");
    let left_bool = IrNode::Literal {
        value: IrLiteral::Bool(true),
    };
    let left_expr_bool = Expr::BoolLiteral(true);

    match analyzer.check_binary_op_types(
        BinaryOperator::Eq,
        &left_bool,
        &right_int,
        &left_expr_bool,
        &right_expr,
    ) {
        Ok(_) => println!("   ❌ FAIL: Should not allow bool vs int comparison"),
        Err(e) => println!("   ✅ PASS: Correctly rejected - {}", e),
    }

    // Test 3: Valid boolean AND
    println!("\n3. Testing valid boolean AND (true and false)...");
    let right_bool = IrNode::Literal {
        value: IrLiteral::Bool(false),
    };
    let right_expr_bool = Expr::BoolLiteral(false);

    match analyzer.check_binary_op_types(
        BinaryOperator::And,
        &left_bool,
        &right_bool,
        &left_expr_bool,
        &right_expr_bool,
    ) {
        Ok(_) => println!("   ✅ PASS: Boolean AND is valid"),
        Err(e) => println!("   ❌ FAIL: {}", e),
    }

    // Test 4: Invalid boolean AND with integer
    println!("\n4. Testing invalid boolean AND (true and 10)...");

    match analyzer.check_binary_op_types(
        BinaryOperator::And,
        &left_bool,
        &right_int,
        &left_expr_bool,
        &right_expr,
    ) {
        Ok(_) => println!("   ❌ FAIL: Should not allow bool AND int"),
        Err(e) => println!("   ✅ PASS: Correctly rejected - {}", e),
    }

    // Test 5: Valid arithmetic
    println!("\n5. Testing valid arithmetic (5 + 10)...");

    match analyzer.check_binary_op_types(
        BinaryOperator::Add,
        &left_int,
        &right_int,
        &left_expr,
        &right_expr,
    ) {
        Ok(_) => println!("   ✅ PASS: Integer addition is valid"),
        Err(e) => println!("   ❌ FAIL: {}", e),
    }

    // Test 6: Invalid arithmetic with boolean
    println!("\n6. Testing invalid arithmetic (true + false)...");

    match analyzer.check_binary_op_types(
        BinaryOperator::Add,
        &left_bool,
        &right_bool,
        &left_expr_bool,
        &right_expr_bool,
    ) {
        Ok(_) => println!("   ❌ FAIL: Should not allow boolean addition"),
        Err(e) => println!("   ✅ PASS: Correctly rejected - {}", e),
    }

    println!("\n=== All type checking tests completed! ===");
}
