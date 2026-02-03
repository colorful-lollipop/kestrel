// Hybrid Engine - Integrates AC-DFA, Lazy DFA, and NFA
//
// The hybrid engine automatically chooses the optimal matching strategy
// based on rule complexity and runtime hot spot detection.

use crate::analyzer::{analyze_rule, MatchingStrategy, StrategyRecommendation};
use crate::{HybridEngineError, HybridEngineResult};
use kestrel_ac_dfa::AcMatcher;
use kestrel_event::Event;
use kestrel_lazy_dfa::{
    DfaCache, HotSpotDetector, LazyDfaConfig, NfaToDfaConverter,
};
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, SequenceAlert};
use std::sync::Arc;
use parking_lot::RwLock;

/// Configuration for the hybrid engine
#[derive(Debug, Clone)]
pub struct HybridEngineConfig {
    /// NFA engine configuration
    pub nfa_config: NfaEngineConfig,

    /// Lazy DFA configuration
    pub lazy_dfa_config: LazyDfaConfig,

    /// Enable AC-DFA pre-filtering
    pub enable_ac_dfa: bool,

    /// Enable lazy DFA for hot sequences
    pub enable_lazy_dfa: bool,

    /// Minimum hotness score for DFA conversion
    pub min_hotness_score: f64,
}

impl Default for HybridEngineConfig {
    fn default() -> Self {
        Self {
            nfa_config: NfaEngineConfig::default(),
            lazy_dfa_config: LazyDfaConfig::default(),
            enable_ac_dfa: true,
            enable_lazy_dfa: true,
            min_hotness_score: 10.0,
        }
    }
}

/// Strategy used for a specific rule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStrategy {
    /// AC-DFA only
    AcDfa,

    /// Lazy DFA only
    LazyDfa,

    /// NFA only
    Nfa,

    /// AC-DFA pre-filter + NFA
    HybridAcNfa,
}

/// Hybrid matching engine
pub struct HybridEngine {
    /// NFA engine (fallback for complex rules)
    nfa_engine: NfaEngine,

    /// AC-DFA matcher for string literals
    ac_matcher: Option<AcMatcher>,

    /// Lazy DFA cache for hot sequences
    dfa_cache: DfaCache,

    /// Hot spot detector
    hot_detector: HotSpotDetector,

    /// NFA to DFA converter
    dfa_converter: NfaToDfaConverter,

    /// Strategy per rule
    rule_strategies: RwLock<std::collections::HashMap<String, RuleStrategy>>,

    /// Configuration
    config: HybridEngineConfig,
}

impl HybridEngine {
    pub fn new(
        config: HybridEngineConfig,
        predicate_evaluator: Arc<dyn kestrel_nfa::PredicateEvaluator>,
    ) -> HybridEngineResult<Self> {
        let nfa_engine = NfaEngine::new(config.nfa_config.clone(), predicate_evaluator);

        let dfa_cache = DfaCache::new(config.lazy_dfa_config.cache_config.clone());
        let hot_detector = HotSpotDetector::new(config.lazy_dfa_config.hot_spot_threshold.clone());
        let dfa_converter = NfaToDfaConverter::new(config.lazy_dfa_config.max_dfa_states);

        Ok(Self {
            nfa_engine,
            ac_matcher: None,
            dfa_cache,
            hot_detector,
            dfa_converter,
            rule_strategies: RwLock::new(std::collections::HashMap::new()),
            config,
        })
    }

    /// Load a sequence and determine optimal strategy
    pub fn load_sequence(&mut self, compiled: CompiledSequence) -> HybridEngineResult<()> {
        // Extract ID before moving compiled
        let sequence_id = compiled.id.clone();

        // Analyze rule complexity
        let recommendation = self.analyze_sequence(&compiled)?;

        // Determine strategy
        let strategy = self.determine_strategy(&recommendation)?;

        // Store strategy
        self.rule_strategies
            .write()
            .insert(sequence_id.clone(), strategy);

        match strategy {
            RuleStrategy::AcDfa => {
                // Load into AC-DFA (will be done in bulk after all sequences loaded)
                tracing::debug!(
                    "Loaded sequence {} with AC-DFA strategy",
                    sequence_id
                );
            }
            RuleStrategy::LazyDfa => {
                // Load into NFA for now, will convert to DFA when hot
                self.nfa_engine.load_sequence(compiled)?;
                tracing::debug!(
                    "Loaded sequence {} with Lazy DFA strategy (will convert when hot)",
                    sequence_id
                );
            }
            RuleStrategy::Nfa => {
                // Load into NFA
                self.nfa_engine.load_sequence(compiled)?;
                tracing::debug!("Loaded sequence {} with NFA strategy", sequence_id);
            }
            RuleStrategy::HybridAcNfa => {
                // Load into NFA, AC-DFA will be used as pre-filter
                self.nfa_engine.load_sequence(compiled)?;
                tracing::debug!(
                    "Loaded sequence {} with Hybrid AC-DFA+NFA strategy",
                    sequence_id
                );
            }
        }

        Ok(())
    }

    /// Analyze a sequence to determine optimal strategy
    fn analyze_sequence(&self, compiled: &CompiledSequence) -> HybridEngineResult<StrategyRecommendation> {
        // Create a dummy IR rule for analysis
        let ir_rule = self.create_ir_rule_from_sequence(compiled)?;

        // Analyze complexity
        let recommendation = analyze_rule(&ir_rule)?;

        Ok(recommendation)
    }

    /// Determine matching strategy from recommendation
    fn determine_strategy(&self, recommendation: &StrategyRecommendation) -> HybridEngineResult<RuleStrategy> {
        let strategy = match recommendation.strategy {
            MatchingStrategy::AcDfa => RuleStrategy::AcDfa,
            MatchingStrategy::LazyDfa => {
                if self.config.enable_lazy_dfa {
                    RuleStrategy::LazyDfa
                } else {
                    RuleStrategy::Nfa
                }
            }
            MatchingStrategy::Nfa => RuleStrategy::Nfa,
            MatchingStrategy::HybridAcNfa => {
                if self.config.enable_ac_dfa {
                    RuleStrategy::HybridAcNfa
                } else {
                    RuleStrategy::Nfa
                }
            }
        };

        Ok(strategy)
    }

    /// Create a dummy IR rule from a compiled sequence
    fn create_ir_rule_from_sequence(&self, compiled: &CompiledSequence) -> HybridEngineResult<kestrel_eql::ir::IrRule> {
        // This is a simplified version - in practice, we'd pass the full IR rule
        Ok(kestrel_eql::ir::IrRule::new(
            compiled.id.clone(),
            kestrel_eql::ir::IrRuleType::Sequence {
                event_types: vec![],
            },
        ))
    }

    /// Build AC-DFA matcher from loaded sequences
    pub fn build_ac_matcher(&mut self) -> HybridEngineResult<()> {
        if !self.config.enable_ac_dfa {
            return Ok(());
        }

        // Build AC-DFA from rules with string literals
        // (In a full implementation, we'd extract patterns from predicates)
        tracing::info!("Building AC-DFA matcher");

        // For now, create an empty matcher
        self.ac_matcher = Some(AcMatcher::builder().build().map_err(|e| {
            HybridEngineError::engine_error("AC-DFA", format!("Failed to build: {}", e))
        })?);

        Ok(())
    }

    /// Process an event through the hybrid engine
    pub fn process_event(&mut self, event: &Event) -> HybridEngineResult<Vec<SequenceAlert>> {
        let mut alerts = Vec::new();

        // Record event in hot spot detector
        // (In a full implementation, we'd track which rules matched)

        // Process through NFA engine (or DFA when available)
        let nfa_alerts = self.nfa_engine.process_event(event)?;
        alerts.extend(nfa_alerts);

        // Check for hot sequences and convert to DFA
        if self.config.enable_lazy_dfa {
            self.check_and_convert_hot_sequences()?;
        }

        Ok(alerts)
    }

    /// Check for hot sequences and convert to DFA
    fn check_and_convert_hot_sequences(&mut self) -> HybridEngineResult<()> {
        let hot_spots = self.hot_detector.get_hot_spots();

        for hot_spot in hot_spots {
            if hot_spot.score < self.config.min_hotness_score {
                continue;
            }

            let sequence_id = &hot_spot.sequence_id;

            // Check if we already have a DFA for this sequence
            if self.dfa_cache.contains(sequence_id) {
                continue;
            }

            // Check if this sequence is using LazyDfa strategy
            let strategies = self.rule_strategies.read();
            let strategy = strategies.get(sequence_id);
            if !matches!(strategy, Some(RuleStrategy::LazyDfa)) {
                continue;
            }
            drop(strategies);

            // Try to get the sequence from NFA engine
            // Note: This requires NFA engine to expose sequence access
            // For now, we'll log the intent
            tracing::info!(
                "Would convert hot sequence {} to DFA (score: {:.2}, matches: {})",
                sequence_id,
                hot_spot.score,
                hot_spot.stats.matches
            );

            // In a full implementation:
            // 1. Get compiled sequence from NFA engine
            // 2. Convert to DFA using self.dfa_converter
            // 3. Insert into self.dfa_cache
            // 4. Update strategy to use DFA for future matches
        }

        Ok(())
    }

    /// Get the strategy for a specific rule
    pub fn get_rule_strategy(&self, sequence_id: &str) -> Option<RuleStrategy> {
        self.rule_strategies.read().get(sequence_id).copied()
    }

    /// Get engine statistics
    pub fn stats(&self) -> EngineStats {
        let dfa_cache_stats = self.dfa_cache.stats();
        let hot_spots = self.hot_detector.get_hot_spots();

        EngineStats {
            nfa_sequence_count: self.nfa_engine.sequence_count(),
            dfa_cache_count: dfa_cache_stats.count,
            dfa_memory_usage: dfa_cache_stats.memory_usage,
            hot_sequence_count: hot_spots.len(),
            total_rules_tracked: self.rule_strategies.read().len(),
        }
    }
}

/// Engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    /// Number of sequences in NFA engine
    pub nfa_sequence_count: usize,

    /// Number of DFAs in cache
    pub dfa_cache_count: usize,

    /// Total DFA memory usage
    pub dfa_memory_usage: usize,

    /// Number of hot sequences
    pub hot_sequence_count: usize,

    /// Total number of rules tracked
    pub total_rules_tracked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = HybridEngineConfig::default();
        assert!(config.enable_ac_dfa);
        assert!(config.enable_lazy_dfa);
    }

    #[test]
    fn test_stats_creation() {
        let stats = EngineStats {
            nfa_sequence_count: 10,
            dfa_cache_count: 5,
            dfa_memory_usage: 1024,
            hot_sequence_count: 2,
            total_rules_tracked: 15,
        };

        assert_eq!(stats.nfa_sequence_count, 10);
        assert_eq!(stats.dfa_cache_count, 5);
    }
}
