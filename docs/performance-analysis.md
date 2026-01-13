# Kestrel 性能分析与优化方案

## 当前性能基准

| 指标 | 目标 | 实测 | 状态 |
|------|------|------|------|
| 吞吐量 | 10k EPS | **4.9M EPS** | ✅ 490x |
| 单事件 P99 | <1µs | **531ns** | ✅ 2x |
| NFA P99 | <10µs | **10.66µs** | ⚠️ **超标6.6%** |
| 空闲内存 | <50MB | **6.39MB** | ✅ 8x |

**关键发现**: NFA P99延迟需要优化

---

## 🔍 算法瓶颈分析

### 瓶颈1: NFA Engine process_event() - 内存分配

**位置**: `kestrel-nfa/src/engine.rs:164-179`

**问题**:
```rust
// ❌ 当前实现
let relevant_sequence_ids: Vec<String> =  // 每次分配新Vec
    self.event_type_index
        .get(&event_type_id)
        .cloned()  // ❌ clone整个Vec<String>
        .unwrap_or_default();

let sequences_to_process: Vec<(String, NfaSequence)> =  // 再次分配
    relevant_sequence_ids
        .into_iter()
        .filter_map(|seq_id| {
            self.sequences
                .get(&seq_id)
                .cloned()  // ❌ clone整个NfaSequence
                .map(|seq| (seq_id, seq))
        })
        .collect();
```

**成本分析**:
- 每次 `process_event()` 调用至少分配 2 次 Vec
- `NfaSequence` 包含 `Vec<SeqStep>`，clone开销大
- 对于 10k EPS，每秒分配 20,000 次 Vec

**影响**: P99延迟的6.6%超标

---

### 瓶颈2: 重复计算 relevant_steps

**位置**: `kestrel-nfa/src/engine.rs:210-238`

**问题**:
```rust
// ❌ 过滤两次
let relevant_steps: Vec<_> = sequence
    .steps.iter()
    .filter(|step| step.event_type_id == event_type_id)
    .collect();

// ... 后面又过滤又排序
let mut relevant_steps: Vec<_> = sequence
    .steps.iter()
    .filter(|step| step.event_type_id == event_type_id)  // ❌ 重复过滤
    .collect();
relevant_steps.sort_by_key(|step| step.state_id);
```

**成本**:
- 重复遍历 `steps` 数组
- 重复分配 Vec
- 重复执行闭包

---

### 瓶颈3: get_expected_state() 全遍历

**位置**: `kestrel-nfa/src/engine.rs:241`

**问题**:
```rust
// ❌ 可能遍历所有状态
let expected_state = self.get_expected_state(sequence, entity_key)?;
```

如果 `get_expected_state()` 遍历所有 `0..max_state`：
- 时间复杂度: O(number of states)
- 最坏情况: O(sequence length)

---

### 瓶颈4: 锁竞争

**位置**: `kestrel-nfa/src/engine.rs:161`

**问题**:
```rust
// ❌ 每个事件都加写锁
self.metrics.write().record_event();
```

在高并发下:
- 4.9M EPS = 每秒 490万次写锁
- RwLock 在写锁时会阻塞所有读者
- 即使是 parking_lot::RwLock 也有开销

---

### 瓶颈5: StateStore HashMap 查找

**位置**: `kestrel-nfa/src/store.rs`

**问题**:
- 多个 HashMap 查找: `matches`, `entity_counts`, `sequence_counts`
- 复合 key: `(String, u128, NfaStateId)`
- LRU queue 每次插入/删除: O(log n)

---

## ✅ 优化方案

### 优化1: 零拷贝事件类型索引

**优先级**: 🔴 P0 (影响P99延迟)

**方案**:
```rust
// ✅ 优化后
pub struct NfaEngine {
    // 使用引用计数，避免clone
    sequences: Arc<RwLock<HashMap<String, Arc<NfaSequence>>>>,

    // 事件类型索引使用引用
    event_type_index: HashMap<u16, Vec<Arc<String>>>,  // 共享String
}

pub fn process_event(&self, event: &Event) -> NfaResult<Vec<SequenceAlert>> {
    // 使用Arc避免clone
    let relevant_sequence_ids = self.event_type_index
        .get(&event_type_id)
        .map(|ids| &ids[..])  // 零拷贝slice
        .unwrap_or(&[]);

    for seq_id in relevant_sequence_ids {
        let sequence = self.sequences.read().get(seq_id)?.clone();  // Arc<NfaSequence>
        // ...
    }
}
```

**预期收益**:
- 减少 50% 内存分配
- P99 延迟降低 15-20%

---

### 优化2: 预计算 relevant_steps

**优先级**: 🔴 P0

**方案**:
```rust
// ✅ 在 NfaSequence 中预计算
pub struct NfaSequence {
    steps: Vec<SeqStep>,
    // 新增: event_type_id -> [step_indices] 映射
    event_type_to_steps: HashMap<u16, Vec<usize>>,
}

impl NfaSequence {
    pub fn from_ir(ir: IrSequence) -> Self {
        let mut event_type_to_steps = HashMap::new();
        for (idx, step) in steps.iter().enumerate() {
            event_type_to_steps
                .entry(step.event_type_id)
                .or_insert_with(Vec::new)
                .push(idx);
        }
        // ...
    }

    pub fn get_relevant_steps(&self, event_type_id: u16) -> &[usize] {
        self.event_type_to_steps
            .get(&event_type_id)
            .map(|v| &v[..])
            .unwrap_or(&[])
    }
}
```

**预期收益**:
- 消除重复过滤
- 减少分支预测失败
- P99 延迟降低 10-15%

---

### 优化3: 状态查找优化

**优先级**: 🟡 P1

**方案**:
```rust
// ✅ 直接从状态存储获取最高状态
let max_state = self.state_store
    .get_highest_state(&sequence.id, entity_key)?;

// 或者使用位图
let active_states = self.state_store
    .get_active_states_bitmap(&sequence.id, entity_key)?;
```

**预期收益**:
- O(1) 状态查找
- P99 延迟降低 5-10%

---

### 优化4: 无锁计数器

**优先级**: 🟡 P1

**方案**:
```rust
// ✅ 使用AtomicU64替代RwLock
pub struct NfaEngine {
    metrics: Arc<NfaMetrics>,
}

pub struct NfaMetrics {
    events_processed: AtomicU64,  // 无锁
    // ...
}

impl NfaMetrics {
    pub fn record_event(&self) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);
    }
}
```

**预期收益**:
- 消除锁竞争
- 吞吐量提升 10-20%

---

### 优化5: StateStore 分片优化

**优先级**: 🟢 P2

**方案**:
```rust
// ✅ 增加分片数量，减少锁竞争
const SHARD_COUNT: usize = 64;  // 从16增加到64

// 使用CAS操作避免锁
pub struct StateShard {
    matches: AtomicHashMap<...>,  // 如果可用
}
```

**预期收益**:
- 减少锁竞争
- 多核扩展性更好

---

### 优化6: 内存池 (Arena Allocator)

**优先级**: 🟢 P2

**方案**:
```rust
// ✅ 使用bumpalo或自定义arena
use bumpalo::Bump;

pub struct NfaEngine {
    arena: Bump,  // 局部内存池
}

pub fn process_event(&mut self, event: &Event) -> NfaResult<Vec<SequenceAlert>> {
    self.arena.reset();  // 快速重置
    let alerts = self.arena.alloc(Vec::new());
    // ...
}
```

**预期收益**:
- 减少分配器压力
- 更好的缓存局部性

---

## 📊 优化优先级矩阵

| 优化项 | 难度 | 收益 | 优先级 | 预计时间 |
|-------|------|------|--------|---------|
| 零拷贝事件索引 | 中 | 高 | 🔴 P0 | 2-4h |
| 预计算 relevant_steps | 低 | 高 | 🔴 P0 | 1-2h |
| 状态查找优化 | 中 | 中 | 🟡 P1 | 2-3h |
| 无锁计数器 | 低 | 中 | 🟡 P1 | 1h |
| StateStore分片 | 高 | 低 | 🟢 P2 | 4-6h |
| 内存池 | 高 | 中 | 🟢 P2 | 4-6h |

**总预计时间**: 14-22 小时
**预期P99改善**: 从10.66µs → <8µs (25%提升)

---

## 🎯 实施计划

### Phase A: 快速优化 (1-2天)

```bash
# 优先级排序
1. 预计算 relevant_steps          # 1-2h, 高收益
2. 无锁计数器                      # 1h, 中收益
3. 零拷贝事件索引                  # 2-4h, 高收益
```

**目标**: NFA P99 < 9µs

### Phase B: 深度优化 (3-4天)

```bash
4. 状态查找优化                    # 2-3h
5. StateStore分片                  # 4-6h
6. 内存池                          # 4-6h
```

**目标**: NFA P99 < 8µs

---

## 📈 预期性能提升

| 阶段 | NFA P99 | 吞吐量 | 内存 |
|------|---------|--------|------|
| 当前 | 10.66µs | 4.9M EPS | 6.39MB |
| Phase A | **<9µs** | **5.5M EPS** | 6.5MB |
| Phase B | **<8µs** | **6M+ EPS** | 6.2MB |

**最终**: 超过所有设计目标 🎉
