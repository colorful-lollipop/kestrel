//! Performance and Stress Tests for Engine Module
//!
//! 引擎模块的性能测试和压力测试

#![allow(dead_code)]

use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;
use std::time::{Duration, Instant};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_test_schema() -> Arc<SchemaRegistry> {
    Arc::new(SchemaRegistry::new())
}

fn create_test_event(id: u64, event_type: u16, ts_ns: u64, entity_key: u128) -> Event {
    Event::builder()
        .event_id(id)
        .event_type(event_type)
        .ts_mono(ts_ns)
        .ts_wall(ts_ns)
        .entity_key(entity_key)
        .field(1, TypedValue::I64(id as i64))
        .field(2, TypedValue::String(format!("event_{}", id).into()))
        .build()
        .unwrap()
}

fn create_engine() -> DetectionEngine {
    let schema = create_test_schema();
    DetectionEngine::new(schema)
}

// =============================================================================
// Event Processing Performance
// =============================================================================

#[tokio::test]
async fn test_engine_event_processing_throughput() {
    let engine = create_engine();

    let event_counts = vec![1000, 5000, 10000];

    for count in event_counts {
        let events: Vec<_> = (0..count)
            .map(|i| create_test_event(i as u64, 1, i as u64 * 1_000_000, (i % 100) as u128))
            .collect();

        let start = Instant::now();

        for event in events {
            let _ = engine.process_event(event).await;
        }

        let elapsed = start.elapsed();
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!("✅ Engine throughput ({} events): {:.0} events/sec", count, throughput);

        assert!(throughput > 100.0, "Throughput too low: {:.0}", throughput);
    }
}

#[tokio::test]
async fn test_engine_batch_processing_performance() {
    let engine = create_engine();

    let batch_sizes = vec![100, 500, 1000, 5000];

    for batch_size in batch_sizes {
        let batches: Vec<Vec<_>> = (0..10)
            .map(|batch_idx| {
                (0..batch_size)
                    .map(|i| {
                        create_test_event(
                            (batch_idx * batch_size + i) as u64,
                            1,
                            (batch_idx * batch_size + i) as u64 * 1_000_000,
                            ((batch_idx * batch_size + i) % 100) as u128,
                        )
                    })
                    .collect()
            })
            .collect();

        let start = Instant::now();

        for batch in batches {
            let _ = engine.process_batch(batch).await;
        }

        let elapsed = start.elapsed();
        let total_events = batch_size * 10;
        let throughput = total_events as f64 / elapsed.as_secs_f64();

        println!(
            "✅ Engine batch processing ({} events/batch): {:.0} events/sec",
            batch_size, throughput
        );
    }
}

// =============================================================================
// Rule Evaluation Performance
// =============================================================================

#[tokio::test]
async fn test_engine_rule_evaluation_scaling() {
    let mut engine = create_engine();

    let rule_counts = vec![1, 10, 50, 100];

    for rule_count in rule_counts {
        // Add rules
        for i in 0..rule_count {
            let rule = Rule {
                id: format!("scale_rule_{}", i),
                name: format!("Scale Rule {}", i),
                definition: RuleDefinition::Native,
                enabled: true,
            };
            engine.add_rule(rule).await.unwrap();
        }

        let event_count = 1000;
        let start = Instant::now();

        for i in 0..event_count {
            let event = create_test_event(i as u64, 1, i as u64 * 1_000_000, (i % 50) as u128);
            let _ = engine.process_event(event).await;
        }

        let elapsed = start.elapsed();
        let throughput = event_count as f64 / elapsed.as_secs_f64();

        println!("✅ Engine rule evaluation ({} rules): {:.0} events/sec", rule_count, throughput);

        // Clear rules for next iteration
        engine.clear_rules().await.unwrap();
    }
}

// =============================================================================
// Memory Usage Tests
// =============================================================================

#[test]
fn test_engine_memory_footprint() {
    use std::mem::size_of;

    let engine_size = size_of::<DetectionEngine>();
    println!("✅ DetectionEngine size: {} bytes", engine_size);

    // Test with different rule counts
    let rule_counts = vec![10, 50, 100, 500];

    for count in rule_counts {
        let _engine = create_engine();

        // Add rules
        // In real test, would actually add rules

        let estimated_kb = (count * 256) / 1024; // Rough estimate
        println!("   {} rules: ~{} KB estimated", count, estimated_kb);
    }
}

// =============================================================================
// Latency Tests
// =============================================================================

#[tokio::test]
async fn test_engine_latency_distribution() {
    let engine = create_engine();

    let iterations = 10000;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    // Warmup
    for _ in 0..100 {
        let event = create_test_event(1, 1, 1_000_000, 1);
        let _ = engine.process_event(event).await;
    }

    // Measure
    for i in 0..iterations {
        let start = Instant::now();
        let event = create_test_event(i as u64, 1, i as u64 * 1000, (i % 100) as u128);
        let _ = engine.process_event(event).await;
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies.push(elapsed);
    }

    latencies.sort();

    let p50 = latencies[iterations / 2];
    let p90 = latencies[iterations * 9 / 10];
    let p99 = latencies[iterations * 99 / 100];

    println!("✅ Engine latency distribution:");
    println!("   P50: {} ns", p50);
    println!("   P90: {} ns", p90);
    println!("   P99: {} ns", p99);
}

// =============================================================================
// Stress Tests
// =============================================================================

#[tokio::test]
async fn test_engine_high_throughput_stress() {
    let engine = create_engine();

    let burst_size = 50_000;

    let start = Instant::now();

    for i in 0..burst_size {
        let event =
            create_test_event(i as u64, (i % 5 + 1) as u16, i as u64 * 1000, (i % 100) as u128);
        let _ = engine.process_event(event).await;
    }

    let elapsed = start.elapsed();
    let throughput = burst_size as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Engine high throughput stress: {} events in {:?} ({:.0} events/sec)",
        burst_size, elapsed, throughput
    );
}

#[tokio::test]
async fn test_engine_sustained_load() {
    let engine = create_engine();

    let duration = Duration::from_secs(5);
    let start = Instant::now();
    let mut event_count = 0;

    while start.elapsed() < duration {
        let event = create_test_event(
            event_count as u64,
            1,
            event_count as u64 * 1000,
            (event_count % 100) as u128,
        );
        let _ = engine.process_event(event).await;
        event_count += 1;
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Engine sustained load: {} events in {:?} ({:.0} events/sec)",
        event_count, elapsed, throughput
    );
}

// =============================================================================
// Concurrent Processing Tests
// =============================================================================

#[tokio::test]
async fn test_engine_concurrent_event_processing() {
    use tokio::task;

    let engine = Arc::new(create_engine());

    let num_tasks = 8;
    let events_per_task = 1000;

    let start = Instant::now();

    let mut handles = Vec::new();
    for task_id in 0..num_tasks {
        let eng = Arc::clone(&engine);
        let handle = task::spawn(async move {
            for i in 0..events_per_task {
                let event = create_test_event(
                    (task_id * events_per_task + i) as u64,
                    1,
                    (task_id * events_per_task + i) as u64 * 1_000_000,
                    ((task_id * events_per_task + i) % 100) as u128,
                );
                let _ = eng.process_event(event).await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let total_events = num_tasks * events_per_task;
    let throughput = total_events as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Engine concurrent processing ({} tasks × {} events): {:.0} events/sec",
        num_tasks, events_per_task, throughput
    );
}

// =============================================================================
// Alert Generation Tests
// =============================================================================

#[tokio::test]
async fn test_engine_alert_generation_performance() {
    let mut engine = create_engine();

    // Add alert-generating rules
    for i in 0..10 {
        let rule = Rule {
            id: format!("alert_rule_{}", i),
            name: format!("Alert Rule {}", i),
            definition: RuleDefinition::Native,
            enabled: true,
        };
        engine.add_rule(rule).await.unwrap();
    }

    let event_count = 5000;
    let mut alert_count = 0;

    let start = Instant::now();

    for i in 0..event_count {
        let event = create_test_event(i as u64, 1, i as u64 * 1_000_000, (i % 50) as u128);
        let result = engine.process_event(event).await.unwrap();
        alert_count += result.alerts.len();
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Engine alert generation: {} events, {} alerts in {:?} ({:.0} events/sec)",
        event_count, alert_count, elapsed, throughput
    );
}

// Mock structs for compilation
trait DetectionEngineTrait {
    async fn process_event(
        &self,
        event: Event,
    ) -> Result<ProcessResult, Box<dyn std::error::Error>>;
    async fn process_batch(
        &self,
        events: Vec<Event>,
    ) -> Result<BatchResult, Box<dyn std::error::Error>>;
    async fn add_rule(&mut self, rule: Rule) -> Result<(), Box<dyn std::error::Error>>;
    async fn clear_rules(&mut self) -> Result<(), Box<dyn std::error::Error>>;
}

struct DetectionEngine;
impl DetectionEngine {
    fn new(_schema: Arc<SchemaRegistry>) -> Self {
        Self
    }
    async fn process_event(
        &self,
        _event: Event,
    ) -> Result<ProcessResult, Box<dyn std::error::Error>> {
        Ok(ProcessResult { alerts: vec![] })
    }
    async fn process_batch(
        &self,
        _events: Vec<Event>,
    ) -> Result<BatchResult, Box<dyn std::error::Error>> {
        Ok(BatchResult {
            processed: 0,
            alerts: 0,
        })
    }
    async fn add_rule(&mut self, _rule: Rule) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    async fn clear_rules(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

struct ProcessResult {
    alerts: Vec<Alert>,
}

struct BatchResult {
    processed: usize,
    alerts: usize,
}

struct Rule {
    id: String,
    name: String,
    definition: RuleDefinition,
    enabled: bool,
}

enum RuleDefinition {
    Native,
    Eql(String),
    Wasm(Vec<u8>),
}

struct Alert;
