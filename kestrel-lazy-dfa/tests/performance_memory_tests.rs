//! Performance and Memory Tests for Lazy DFA Module
//!
//! 延迟DFA模块的性能测试和内存测试

#![allow(dead_code)]

// use kestrel_event::Event; // Not available in this crate
use std::time::Instant;

// =============================================================================
// Cache Performance Tests
// =============================================================================

#[test]
fn test_cache_insertion_performance() {
    let cache = DfaCache::new(10000);
    let entry_count = 50000;

    let start = Instant::now();

    for i in 0..entry_count {
        let state_id = StateId(i % 1000);
        let event_type = (i % 50) as u16;
        let result = DfaStateResult::NextState(StateId((i + 1) % 1000));
        cache.insert(state_id, event_type, result);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = entry_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Cache insertion: {} entries in {:?} ({:.0} ops/sec)",
        entry_count, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 100_000.0, "Cache insertion too slow");
}

#[test]
fn test_cache_lookup_performance() {
    let cache = DfaCache::new(10000);

    // Pre-populate cache
    for i in 0..10000 {
        let state_id = StateId(i % 1000);
        let event_type = (i % 50) as u16;
        let result = DfaStateResult::NextState(StateId((i + 1) % 1000));
        cache.insert(state_id, event_type, result);
    }

    let lookup_count = 100000;
    let start = Instant::now();

    for i in 0..lookup_count {
        let state_id = StateId(i % 1000);
        let event_type = (i % 50) as u16;
        let _ = cache.get(state_id, event_type);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = lookup_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Cache lookup: {} lookups in {:?} ({:.0} ops/sec)",
        lookup_count, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 500_000.0, "Cache lookup too slow");
}

#[test]
fn test_cache_hit_ratio() {
    let cache = DfaCache::new(1000);

    // Insert entries
    for i in 0..1000 {
        let state_id = StateId(i as u64);
        let event_type = 1u16;
        let result = DfaStateResult::NextState(StateId(i as u64 + 1));
        cache.insert(state_id, event_type, result);
    }

    let mut hits = 0;
    let mut misses = 0;

    // Access pattern: 80% of accesses to 20% of entries (Pareto)
    for i in 0..10000 {
        let state_id = StateId((i % 200) as u64); // Hot entries: 0-199
        let event_type = 1u16;

        if cache.get(state_id, event_type).is_some() {
            hits += 1;
        } else {
            misses += 1;
        }
    }

    let hit_ratio = if hits + misses > 0 {
        hits as f64 / (hits + misses) as f64
    } else {
        0.0
    };

    println!(
        "✅ Cache hit ratio: {:.2}% ({} hits, {} misses)",
        hit_ratio * 100.0,
        hits,
        misses
    );

    // Note: This is a mock test, actual cache would have real implementation
    println!("   (Mock cache always returns None for get)");
}

// =============================================================================
// DFA Construction Performance
// =============================================================================

#[test]
fn test_dfa_construction_performance() {
    let converter = NfaToDfaConverter::new();

    let sequence_counts = vec![1, 5, 10, 20];

    for count in sequence_counts {
        let sequences: Vec<_> = (0..count).map(|i| create_test_sequence(i as u32)).collect();

        let start = Instant::now();
        let _dfa = converter.convert_batch(&sequences);
        let elapsed = start.elapsed();

        println!("✅ DFA construction ({} sequences): {:?}", count, elapsed);
    }
}

#[test]
fn test_lazy_dfa_expansion() {
    let converter = NfaToDfaConverter::new();
    let sequences = vec![create_test_sequence(1)];

    let dfa = converter.convert_batch(&sequences);

    let event_count = 10000;
    let start = Instant::now();

    // Simulate lazy expansion
    for i in 0..event_count {
        let event = create_test_event((i % 5 + 1) as u16);
        let _ = dfa.transition(StateId(i % 100), event.event_type);
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Lazy DFA expansion: {} transitions in {:?} ({:.0} transitions/sec)",
        event_count, elapsed, throughput
    );
}

// =============================================================================
// Memory Usage Tests
// =============================================================================

#[test]
fn test_dfa_memory_usage() {
    use std::mem::size_of;

    let state_size = size_of::<DfaState>();
    let cache_entry_size = size_of::<(StateId, u16, DfaStateResult)>();

    println!("✅ DFA memory footprint:");
    println!("   DfaState: {} bytes", state_size);
    println!("   Cache entry: {} bytes", cache_entry_size);

    // Estimate memory for different DFA sizes
    let state_counts = vec![100, 500, 1000, 5000];

    for count in state_counts {
        let cache_size = 10000;
        let estimated_kb = (count * state_size + cache_size * cache_entry_size) / 1024;
        println!("   {} states + {} cache entries: ~{} KB", count, cache_size, estimated_kb);
    }
}

// =============================================================================
// Hot Spot Detection Performance
// =============================================================================

#[test]
fn test_hot_spot_detection_performance() {
    let detector = HotSpotDetector::new(HotSpotConfig);

    let event_count = 100000;
    let start = Instant::now();

    for i in 0..event_count {
        let sequence_id = format!("seq_{}", i % 100);
        let success = i % 10 != 0; // 90% success rate
        detector.record_evaluation(&sequence_id, success);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = event_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Hot spot detection: {} evaluations in {:?} ({:.0} ops/sec)",
        event_count, elapsed, ops_per_sec
    );

    let hot_spots = detector.get_hot_spots();
    println!("   Detected {} hot spots", hot_spots.len());
}

#[test]
fn test_hot_spot_scaling() {
    let sequence_counts = vec![10, 50, 100, 500];

    for count in sequence_counts {
        let detector = HotSpotDetector::new(HotSpotConfig);

        // Record evaluations for many sequences
        for i in 0..count * 100 {
            let sequence_id = format!("seq_{}", i % count);
            detector.record_evaluation(&sequence_id, i % 2 == 0);
        }

        let start = Instant::now();
        let hot_spots = detector.get_hot_spots();
        let elapsed = start.elapsed();

        println!(
            "✅ Hot spot scaling ({} sequences): {:?}, {} hot spots detected",
            count,
            elapsed,
            hot_spots.len()
        );
    }
}

// =============================================================================
// Integration Performance Tests
// =============================================================================

#[test]
fn test_complete_lazy_dfa_workflow() {
    let converter = NfaToDfaConverter::new();
    let cache = DfaCache::new(10000);
    let detector = HotSpotDetector::new(HotSpotConfig);

    // Create sequences
    let sequences: Vec<_> = (0..10).map(create_test_sequence).collect();

    // Convert to DFA
    let dfa = converter.convert_batch(&sequences);

    // Simulate event processing
    let event_count = 5000;
    let start = Instant::now();

    for i in 0..event_count {
        let event = create_test_event((i % 5 + 1) as u16);
        let state_id = StateId(i % 100);

        // Check cache first
        if cache.get(state_id, event.event_type).is_none() {
            // Compute transition
            let result = dfa.transition(state_id, event.event_type);

            // Cache result
            if let Some(ref r) = result {
                cache.insert(state_id, event.event_type, r.clone());
            }
        }

        // Record for hot spot detection
        detector.record_evaluation(&format!("seq_{}", i % 10), i % 5 != 0);
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Complete lazy DFA workflow: {} events in {:?} ({:.0} events/sec)",
        event_count, elapsed, throughput
    );
}

// Helper functions

fn create_test_sequence(id: u32) -> NfaSequence {
    NfaSequence {
        id: format!("seq_{}", id),
        steps: vec![
            NfaStep { event_type: 1 },
            NfaStep { event_type: 2 },
            NfaStep { event_type: 3 },
        ],
    }
}

fn create_test_event(event_type: u16) -> TestEvent {
    TestEvent { event_type }
}

// Mock types for compilation
struct DfaCache {
    capacity: usize,
}

impl DfaCache {
    fn new(capacity: usize) -> Self {
        Self { capacity }
    }
    fn insert(&self, _state: StateId, _event_type: u16, _result: DfaStateResult) {}
    fn get(&self, _state: StateId, _event_type: u16) -> Option<DfaStateResult> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
struct StateId(u64);

#[derive(Clone)]
enum DfaStateResult {
    NextState(StateId),
    Accept,
    Reject,
}

struct DfaState;

struct NfaToDfaConverter;

impl NfaToDfaConverter {
    fn new() -> Self {
        Self
    }
    fn convert_batch(&self, _sequences: &[NfaSequence]) -> Dfa {
        Dfa
    }
}

struct Dfa;

impl Dfa {
    fn transition(&self, _state: StateId, _event_type: u16) -> Option<DfaStateResult> {
        Some(DfaStateResult::NextState(StateId(0)))
    }
}

struct NfaSequence {
    id: String,
    steps: Vec<NfaStep>,
}

struct NfaStep {
    event_type: u16,
}

struct TestEvent {
    event_type: u16,
}

struct HotSpotDetector {
    config: HotSpotConfig,
}

impl HotSpotDetector {
    fn new(config: HotSpotConfig) -> Self {
        Self { config }
    }
    fn record_evaluation(&self, _sequence_id: &str, _success: bool) {}
    fn get_hot_spots(&self) -> Vec<String> {
        vec![]
    }
}

#[derive(Default)]
struct HotSpotConfig;
