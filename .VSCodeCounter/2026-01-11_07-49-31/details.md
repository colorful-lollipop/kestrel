# Details

Date : 2026-01-11 07:49:31

Directory /root/code/Kestrel

Total : 51 files,  11694 codes, 1350 comments, 2920 blanks, all 15964 lines

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)

## Files
| filename | language | code | comment | blank | total |
| :--- | :--- | ---: | ---: | ---: | ---: |
| [.claude/settings.local.json](/.claude/settings.local.json) | JSON | 9 | 0 | 1 | 10 |
| [AGENT.md](/AGENT.md) | Markdown | 152 | 0 | 64 | 216 |
| [CLAUDE.md](/CLAUDE.md) | Markdown | 4 | 0 | 0 | 4 |
| [PROGRESS.md](/PROGRESS.md) | Markdown | 1,155 | 0 | 313 | 1,468 |
| [README.md](/README.md) | Markdown | 258 | 0 | 94 | 352 |
| [examples/basic_usage.md](/examples/basic_usage.md) | Markdown | 55 | 0 | 18 | 73 |
| [examples/lua_rule_package.md](/examples/lua_rule_package.md) | Markdown | 192 | 0 | 61 | 253 |
| [examples/wasm_rule_package.md](/examples/wasm_rule_package.md) | Markdown | 214 | 0 | 71 | 285 |
| [kestrel-cli/src/main.rs](/kestrel-cli/src/main.rs) | Rust | 110 | 11 | 32 | 153 |
| [kestrel-core/src/alert.rs](/kestrel-core/src/alert.rs) | Rust | 158 | 31 | 44 | 233 |
| [kestrel-core/src/eventbus.rs](/kestrel-core/src/eventbus.rs) | Rust | 315 | 25 | 62 | 402 |
| [kestrel-core/src/lib.rs](/kestrel-core/src/lib.rs) | Rust | 34 | 9 | 9 | 52 |
| [kestrel-core/src/replay.rs](/kestrel-core/src/replay.rs) | Rust | 588 | 67 | 147 | 802 |
| [kestrel-core/src/time.rs](/kestrel-core/src/time.rs) | Rust | 178 | 44 | 52 | 274 |
| [kestrel-ebpf/build.rs](/kestrel-ebpf/build.rs) | Rust | 57 | 4 | 10 | 71 |
| [kestrel-ebpf/src/bpf/main.bpf.c](/kestrel-ebpf/src/bpf/main.bpf.c) | C | 117 | 29 | 33 | 179 |
| [kestrel-ebpf/src/bpf/vmlinux.h](/kestrel-ebpf/src/bpf/vmlinux.h) | C++ | 35 | 7 | 9 | 51 |
| [kestrel-ebpf/src/lib.rs](/kestrel-ebpf/src/lib.rs) | Rust | 248 | 72 | 82 | 402 |
| [kestrel-ebpf/src/normalize.rs](/kestrel-ebpf/src/normalize.rs) | Rust | 337 | 55 | 70 | 462 |
| [kestrel-ebpf/src/programs.rs](/kestrel-ebpf/src/programs.rs) | Rust | 39 | 39 | 18 | 96 |
| [kestrel-ebpf/src/pushdown.rs](/kestrel-ebpf/src/pushdown.rs) | Rust | 138 | 35 | 44 | 217 |
| [kestrel-engine/src/lib.rs](/kestrel-engine/src/lib.rs) | Rust | 564 | 41 | 122 | 727 |
| [kestrel-eql/src/ast.rs](/kestrel-eql/src/ast.rs) | Rust | 175 | 44 | 20 | 239 |
| [kestrel-eql/src/codegen_wasm.rs](/kestrel-eql/src/codegen_wasm.rs) | Rust | 1,007 | 96 | 143 | 1,246 |
| [kestrel-eql/src/compiler.rs](/kestrel-eql/src/compiler.rs) | Rust | 72 | 18 | 20 | 110 |
| [kestrel-eql/src/error.rs](/kestrel-eql/src/error.rs) | Rust | 64 | 10 | 15 | 89 |
| [kestrel-eql/src/ir.rs](/kestrel-eql/src/ir.rs) | Rust | 335 | 66 | 39 | 440 |
| [kestrel-eql/src/lib.rs](/kestrel-eql/src/lib.rs) | Rust | 10 | 4 | 3 | 17 |
| [kestrel-eql/src/parser.rs](/kestrel-eql/src/parser.rs) | Rust | 286 | 22 | 52 | 360 |
| [kestrel-eql/src/semantic.rs](/kestrel-eql/src/semantic.rs) | Rust | 306 | 45 | 69 | 420 |
| [kestrel-eql/tests/eql_tests.rs](/kestrel-eql/tests/eql_tests.rs) | Rust | 257 | 7 | 70 | 334 |
| [kestrel-event/src/lib.rs](/kestrel-event/src/lib.rs) | Rust | 199 | 29 | 39 | 267 |
| [kestrel-nfa/src/engine.rs](/kestrel-nfa/src/engine.rs) | Rust | 427 | 70 | 93 | 590 |
| [kestrel-nfa/src/lib.rs](/kestrel-nfa/src/lib.rs) | Rust | 57 | 29 | 24 | 110 |
| [kestrel-nfa/src/metrics.rs](/kestrel-nfa/src/metrics.rs) | Rust | 246 | 34 | 67 | 347 |
| [kestrel-nfa/src/state.rs](/kestrel-nfa/src/state.rs) | Rust | 224 | 54 | 63 | 341 |
| [kestrel-nfa/src/store.rs](/kestrel-nfa/src/store.rs) | Rust | 331 | 59 | 80 | 470 |
| [kestrel-rules/src/lib.rs](/kestrel-rules/src/lib.rs) | Rust | 238 | 36 | 66 | 340 |
| [kestrel-runtime-lua/src/lib.rs](/kestrel-runtime-lua/src/lib.rs) | Rust | 336 | 55 | 80 | 471 |
| [kestrel-runtime-wasm/src/lib.rs](/kestrel-runtime-wasm/src/lib.rs) | Rust | 615 | 89 | 121 | 825 |
| [kestrel-schema/src/lib.rs](/kestrel-schema/src/lib.rs) | Rust | 286 | 50 | 59 | 395 |
| [plan.md](/plan.md) | Markdown | 275 | 0 | 98 | 373 |
| [plan2.md](/plan2.md) | Markdown | 398 | 0 | 131 | 529 |
| [rules/example_rule.json](/rules/example_rule.json) | JSON | 9 | 0 | 1 | 10 |
| [rules/lua_example_rule/README.md](/rules/lua_example_rule/README.md) | Markdown | 220 | 0 | 86 | 306 |
| [rules/lua_example_rule/manifest.json](/rules/lua_example_rule/manifest.json) | JSON | 19 | 0 | 1 | 20 |
| [rules/lua_example_rule/predicate.lua](/rules/lua_example_rule/predicate.lua) | Lua | 12 | 42 | 6 | 60 |
| [rules/wasm_example_rule/README.md](/rules/wasm_example_rule/README.md) | Markdown | 166 | 0 | 62 | 228 |
| [rules/wasm_example_rule/manifest.json](/rules/wasm_example_rule/manifest.json) | JSON | 19 | 0 | 1 | 20 |
| [rules/wasm_example_rule/rule.wat](/rules/wasm_example_rule/rule.wat) | WebAssembly Text Format | 19 | 22 | 8 | 49 |
| [suggest.md](/suggest.md) | Markdown | 129 | 0 | 47 | 176 |

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)