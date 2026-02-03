//! Demonstration of improved test helpers
//!
//! This example shows how the new test helpers simplify test code

use kestrel_eql::ir::{IrRule, IrRuleType, IrPredicate, node_helpers::*};
use kestrel_nfa::test_helpers::MockEvaluator;
use kestrel_event::Event;

fn main() {
    println!("=== Test Helpers Demo ===\n");
    
    // =========================================================================
    // Demo 1: Creating predicates with the builder pattern
    // =========================================================================
    println!("1. Predicate Builder Pattern");
    println!("   Before: Required 10+ lines of boilerplate");
    println!("   After:  Clean, readable builder pattern\n");
    
    // Using the new builder pattern
    let predicate = IrPredicate::builder("main", "process")
        .condition(field_eq_string(1, "bash"))
        .build();
    
    println!("   Created predicate: id={}, event_type={}", predicate.id, predicate.event_type);
    println!("   Auto-populated fields: {:?}", predicate.required_fields);
    
    // Complex predicate with AND
    let complex_pred = IrPredicate::builder("complex", "process")
        .condition(and(
            field_eq_string(1, "bash"),
            field_eq_int(2, 1000)
        ))
        .build();
    
    println!("   Complex predicate fields: {:?}", complex_pred.required_fields);
    
    // =========================================================================
    // Demo 2: Creating rules with less boilerplate
    // =========================================================================
    println!("\n2. Rule Creation");
    
    let mut rule = IrRule::new(
        "test-rule".to_string(),
        IrRuleType::Event { event_type: "process".to_string() },
    );
    
    rule.add_predicate(IrPredicate::builder("main", "process")
        .condition(string_contains(1, "suspicious"))
        .build());
    
    println!("   Rule created with {} predicates", rule.predicates.len());
    
    // =========================================================================
    // Demo 3: Improved MockEvaluator
    // =========================================================================
    println!("\n3. Mock Evaluator with Tracking");
    
    // Create evaluator with specific results for different predicates
    let evaluator = MockEvaluator::new(true)  // default: true
        .with_result("pred1", true)
        .with_result("pred2", false)
        .with_failure("pred3")  // This one will fail
        .with_required_fields(vec![1, 2, 3, 4, 5]);
    
    let event = Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();
    
    // Evaluate different predicates
    let result1 = evaluator.evaluate("pred1", &event).unwrap();
    let result2 = evaluator.evaluate("pred2", &event).unwrap();
    let result3 = evaluator.evaluate("pred3", &event); // This will fail
    
    println!("   pred1 result: {} (expected: true)", result1);
    println!("   pred2 result: {} (expected: false)", result2);
    println!("   pred3 result: {:?} (expected: Error)", result3);
    
    // Check call tracking
    println!("   Total evaluate() calls: {}", evaluator.total_calls());
    println!("   pred1 was called: {}", evaluator.was_called("pred1"));
    println!("   pred1 call count: {}", evaluator.predicate_calls("pred1"));
    
    // =========================================================================
    // Demo 4: Before vs After comparison
    // =========================================================================
    println!("\n4. Before vs After Comparison");
    println!("\n   BEFORE (old way):");
    println!("   ----------------");
    println!("   let predicate = IrPredicate {{");
    println!("       id: \"main\".to_string(),");
    println!("       event_type: \"process\".to_string(),");
    println!("       root: IrNode::BinaryOp {{");
    println!("           op: IrBinaryOp::Eq,");
    println!("           left: Box::new(IrNode::LoadField {{ field_id: 1 }}),");
    println!("           right: Box::new(IrNode::Literal {{");
    println!("               value: IrLiteral::String(\"bash\".to_string()),");
    println!("           }}),");
    println!("       }},");
    println!("       required_fields: vec![1],");
    println!("       required_regex: vec![],");
    println!("       required_globs: vec![],");
    println!("   }};");
    
    println!("\n   AFTER (new way):");
    println!("   ---------------");
    println!("   let predicate = IrPredicate::builder(\"main\", \"process\")");
    println!("       .condition(field_eq_string(1, \"bash\"))");
    println!("       .build();");
    
    println!("\n   Lines of code: 12 -> 3 (75% reduction)");
    println!("   Auto-populated fields: No -> Yes");
    println!("   Readability: Moderate -> High");
    
    println!("\n=== Demo Complete ===");
}
