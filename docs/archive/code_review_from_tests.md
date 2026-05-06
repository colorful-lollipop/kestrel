# 从测试案例看代码设计问题

## 1. RuleComplexityAnalyzer 设计问题

### 当前设计
```rust
pub struct RuleComplexityAnalyzer;

impl RuleComplexityAnalyzer {
    pub fn analyze(rule: &IrRule) -> Result<StrategyRecommendation, HybridEngineError> {
        // ...
    }
}
```

### 测试暴露的问题
**测试代码重复:**
```rust
// 几乎每个测试都要写这些样板代码
let mut rule = IrRule::new(
    "test-rule".to_string(),
    IrRuleType::Event { event_type: "process".to_string() },
);
let predicate = IrPredicate {
    id: "main".to_string(),
    event_type: "process".to_string(),
    root: IrNode::BinaryOp { ... },
    required_fields: vec![1],
    required_regex: vec![],
    required_globs: vec![],
};
rule.add_predicate(predicate);
```

### 问题分析
1. **空结构体反模式** - `RuleComplexityAnalyzer` 是一个空结构体，所有方法都是静态的，这实际上应该是一个模块(module)而不是结构体
2. **缺乏测试辅助工具** - 创建测试数据需要大量样板代码
3. **魔法数字** - `calculate()` 方法中的权重(10, 30, 20, 15等)是硬编码的，无法配置
4. **单一职责违反** - 一个结构体同时负责分析和推荐策略

### 改进建议

#### 建议 1: 将分析器改为模块
```rust
// analyzer/mod.rs
pub fn analyze(rule: &IrRule) -> Result<StrategyRecommendation, HybridEngineError> {
    let mut complexity = RuleComplexity::new();
    complexity_analyzer::analyze_rule(rule, &mut complexity)?;
    strategy_recommender::recommend(&complexity)
}
```

#### 建议 2: 添加 RuleBuilder 简化测试
```rust
#[cfg(test)]
pub mod test_helpers {
    pub struct RuleBuilder {
        rule: IrRule,
    }
    
    impl RuleBuilder {
        pub fn event_rule(name: &str, event_type: &str) -> Self {
            Self {
                rule: IrRule::new(
                    name.to_string(),
                    IrRuleType::Event { event_type: event_type.to_string() }
                )
            }
        }
        
        pub fn with_string_eq(mut self, field_id: u32, value: &str) -> Self {
            let predicate = IrPredicate {
                id: "main".to_string(),
                event_type: self.rule.event_type(),
                root: IrNode::BinaryOp {
                    op: IrBinaryOp::Eq,
                    left: Box::new(IrNode::LoadField { field_id }),
                    right: Box::new(IrNode::Literal { 
                        value: IrLiteral::String(value.to_string()) 
                    }),
                },
                required_fields: vec![field_id],
                required_regex: vec![],
                required_globs: vec![],
            };
            self.rule.add_predicate(predicate);
            self
        }
        
        pub fn build(self) -> IrRule { self.rule }
    }
}

// 测试代码简化后:
let rule = RuleBuilder::event_rule("test", "process")
    .with_string_eq(1, "bash")
    .build();
```

#### 建议 3: 可配置的权重
```rust
pub struct ComplexityWeights {
    pub per_sequence_step: u8,
    pub regex_penalty: u8,
    pub glob_penalty: u8,
    pub function_penalty: u8,
    pub capture_penalty: u8,
    pub until_penalty: u8,
    pub string_literal_bonus: u8,
}

impl Default for ComplexityWeights {
    fn default() -> Self {
        Self {
            per_sequence_step: 10,
            regex_penalty: 30,
            glob_penalty: 20,
            function_penalty: 15,
            capture_penalty: 10,
            until_penalty: 25,
            string_literal_bonus: 2,
        }
    }
}

pub fn analyze_with_weights(
    rule: &IrRule, 
    weights: &ComplexityWeights
) -> Result<StrategyRecommendation, HybridEngineError> {
    // ...
}
```

---

## 2. IrRule 和 IrPredicate 的设计问题

### 测试暴露的问题
**字段重复和默认值处理:**
```rust
// 测试中不断重复 required_fields, required_regex, required_globs
let predicate = IrPredicate {
    id: "main".to_string(),
    event_type: "process".to_string(),
    root: IrNode::BinaryOp { ... },
    required_fields: vec![1],  // 重复
    required_regex: vec![],     // 重复
    required_globs: vec![],     // 重复
};
```

### 问题分析
1. **构造器不完整** - `IrPredicate` 应该有 `Default` 实现
2. **字段冗余** - `required_fields`, `required_regex`, `required_globs` 可以从 `root` AST 推导
3. **缺少验证** - 可以在创建时验证字段一致性

### 改进建议

#### 建议 1: 实现 Default 和 Builder
```rust
impl Default for IrPredicate {
    fn default() -> Self {
        Self {
            id: String::new(),
            event_type: String::new(),
            root: IrNode::Literal { value: IrLiteral::Bool(true) },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        }
    }
}

impl IrPredicate {
    pub fn builder(id: impl Into<String>, event_type: impl Into<String>) -> PredicateBuilder {
        PredicateBuilder::new(id, event_type)
    }
}

pub struct PredicateBuilder {
    predicate: IrPredicate,
}

impl PredicateBuilder {
    pub fn condition(mut self, node: IrNode) -> Self {
        self.predicate.root = node;
        // 自动推导 required_fields
        self.predicate.required_fields = node.extract_field_ids();
        self
    }
    
    pub fn build(self) -> IrPredicate { self.predicate }
}
```

---

## 3. MockEvaluator 的设计问题

### 当前设计
```rust
struct MockEvaluator;

impl PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, _predicate_id: &str, _event: &Event) -> Result<bool, NfaError> {
        Ok(true)  // 总是返回 true
    }
    // ...
}
```

### 测试暴露的问题
1. **无法测试失败场景** - 总是返回 true，无法测试 predicate 失败的情况
2. **无法验证调用** - 不知道 evaluator 被调用了多少次
3. **状态无关** - 无法模拟基于 predicate_id 或 event 的不同返回值

### 改进建议

#### 建议: 改进 MockEvaluator
```rust
#[derive(Default)]
struct MockEvaluator {
    call_count: AtomicUsize,
    predicate_results: HashMap<String, bool>,
    default_result: bool,
}

impl MockEvaluator {
    fn with_result(mut self, predicate_id: &str, result: bool) -> Self {
        self.predicate_results.insert(predicate_id.to_string(), result);
        self
    }
    
    fn with_default_result(mut self, result: bool) -> Self {
        self.default_result = result;
        self
    }
    
    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, predicate_id: &str, _event: &Event) -> Result<bool, NfaError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.predicate_results.get(predicate_id)
            .copied()
            .unwrap_or(self.default_result))
    }
}

// 测试中可以这样用:
let evaluator = MockEvaluator::default()
    .with_result("pred1", true)
    .with_result("pred2", false)  // 模拟失败
    .with_default_result(true);
```

---

## 4. 测试组织问题

### 当前问题
**测试文件过大:**
- `comprehensive_functional_test.rs` 有 880+ 行
- 包含 21 个测试函数
- 难以维护和定位测试

**测试分类不清:**
```rust
// 这些测试混合在一起
fn test_string_equality()      // 字符串操作
fn test_logical_and()          // 逻辑操作
fn test_single_step_sequence() // 序列变体
fn test_empty_predicate()      // 边界情况
```

### 改进建议

#### 建议: 按功能拆分测试文件
```
 tests/
   ├── string_operations_test.rs    # test_string_equality, test_string_contains, etc.
   ├── logical_operations_test.rs   # test_logical_and, test_logical_or, etc.
   ├── sequence_test.rs             # test_single_step_sequence, test_two_step_sequence, etc.
   ├── edge_cases_test.rs           # test_empty_predicate, test_maxspan_variations, etc.
   └── integration_test.rs          # test_full_pipeline_simple_rule, etc.
```

---

## 5. 错误处理设计问题

### 测试暴露的问题
```rust
// 测试中很多 unwrap()，但没有测试错误场景
let rec = RuleComplexityAnalyzer::analyze(&rule).unwrap();
engine.load_sequence(seq).unwrap();
```

### 问题分析
1. **缺少错误测试** - 大多数测试只测试成功场景
2. **错误类型不够具体** - `HybridEngineError` 可能过于笼统

### 改进建议

#### 建议: 添加具体的错误变体
```rust
pub enum AnalysisError {
    EmptyRule,
    InvalidPredicate(String),
    UnsupportedOperation(String),
    CircularReference { predicate_id: String },
}

// 测试错误场景
#[test]
fn test_analyze_empty_rule() {
    let rule = IrRule::new("empty", IrRuleType::Event { event_type: "test".into() });
    let result = RuleComplexityAnalyzer::analyze(&rule);
    assert!(matches!(result, Err(AnalysisError::EmptyRule)));
}
```

---

## 总结

| 问题 | 严重程度 | 改进优先级 |
|------|----------|------------|
| 空结构体反模式 | 中 | 中 |
| 缺少测试辅助 Builder | 高 | 高 |
| MockEvaluator 功能不足 | 中 | 中 |
| 硬编码权重 | 低 | 低 |
| 测试文件过大 | 中 | 中 |
| 缺少错误场景测试 | 高 | 高 |
