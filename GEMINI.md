# Kestrel Project Context

## Project Overview

**Kestrel** is a next-generation endpoint behavior detection engine designed for Linux and HarmonyOS. It combines high performance with a unique architecture featuring:

*   **Language:** Rust (Edition 2021)
*   **Core Technologies:**
    *   **eBPF:** Kernel-level event collection (zero-copy).
    *   **Host NFA:** Non-Deterministic Finite Automaton for complex sequence detection.
    *   **Dual Runtimes:** WebAssembly (Wasmtime) and LuaJIT for rule execution.
    *   **EQL:** Support for a compatible subset of Elastic Event Query Language.
*   **Goal:** Real-time threat detection and blocking on low-power edge devices with offline replay capabilities.

## Architecture

The system is modularized into several crates within a Cargo workspace:

### Key Components

*   **`kestrel-core`**: Core data structures (EventBus, Alert, Action, Time).
*   **`kestrel-engine`**: The main detection loop integrating single-event and sequence rules.
*   **`kestrel-nfa`**: The NFA state machine engine for sequence detection (stateful).
*   **`kestrel-eql`**: Compiler that transforms EQL rules into Intermediate Representation (IR) and Wasm.
*   **`kestrel-ebpf`**: eBPF programs for event collection (RingBuf polling, LSM hooks).
*   **`kestrel-runtime-wasm` / `kestrel-runtime-lua`**: Rule execution runtimes.
*   **`kestrel-schema`**: Strongly typed field system.

### Data Flow

1.  **Rule Compilation:** EQL Rules $\rightarrow$ IR $\rightarrow$ Wasm/Lua (Predicates) & NFA (State Machines).
2.  **Event Collection:** Sources (eBPF, Audit, Replay) $\rightarrow$ Normalizer.
3.  **Processing:** Normalized Events $\rightarrow$ EventBus (Partitioned by Entity) $\rightarrow$ Detection Engine.
4.  **Detection:**
    *   **Single Event:** Evaluated by Wasm/Lua runtime.
    *   **Sequence:** Processed by NFA Engine (Host-side state tracking).
5.  **Output:** Alerts $\rightarrow$ Action System (Block/Allow/Kill).

## Building and Running

### Prerequisites
*   **Rust:** 1.82+
*   **Linux Kernel:** 5.10+ (for eBPF)
*   **Tools:** Git, Clang (for eBPF compilation)

### Build Commands
*   **Release Build:**
    ```bash
    cargo build --workspace --release
    # Or use the script
    ./scripts/build.sh
    ```
*   **Debug Build:** `cargo build --workspace`

### Running
*   **Start Engine:**
    ```bash
    cargo run --bin kestrel -- run
    ```
*   **Specify Rules:**
    ```bash
    cargo run --bin kestrel -- run --rules /path/to/rules
    ```

### Testing
*   **Unit & Integration Tests:**
    ```bash
    cargo test --workspace
    ```
*   **End-to-End Tests:**
    ```bash
    ./scripts/e2e-test.sh
    ```
*   **Performance Benchmarks:**
    ```bash
    cargo run --bin kestrel-benchmark
    ```

## Development Conventions

*   **Code Style:** Follow standard Rust conventions. Use `cargo fmt` and `cargo clippy`.
*   **Error Handling:** Use `Result<T>` with `thiserror` for library errors. Avoid panics.
*   **Testing:**
    *   **Unit:** Co-located in `src/` modules.
    *   **Integration:** In `tests/` directory of each crate.
    *   **AAA Pattern:** Arrange, Act, Assert.
*   **Commits:** Follow [Conventional Commits](https://www.conventionalcommits.org/) (e.g., `feat:`, `fix:`, `docs:`).

## Directory Structure Highlights

*   `kestrel-*/`: Source code for various workspace crates.
*   `rules/`: Example rule definitions (JSON/EQL).
*   `docs/`: Detailed architectural and design documentation.
*   `scripts/`: Helper scripts for building and testing.
*   `examples/`: Usage examples and guides.
