# Battle Lab

Battle Lab is the minimal scenario-driven validation layer for Kestrel.
It is designed to help security engineers, detection engineers, and researchers
iterate on rules with a repeatable workflow:

1. choose a scenario
2. execute a controlled script in an isolated environment
3. collect or replay events
4. compare observed alerts with expected alerts
5. refine rules and rerun

This first version is intentionally lightweight. It does not yet provide a full
orchestrator, but it establishes the directory convention and scenario assets
needed for a future `kestrel-lab` runner.

## Goals

- Standardize scenario assets for replay and live validation
- Make rule iteration reproducible and team-friendly
- Separate scenario intent, execution steps, and expected detections
- Keep first-party scenarios safe by default

## Scenario Layout

Each scenario lives under `scenarios/<name>/` and should contain:

- `scenario.yaml` — scenario metadata, prerequisites, telemetry expectations, and success criteria
- `attack.sh` — the controlled script that simulates the target behavior
- `expected_alerts.json` — expected rule hits and optional notes for validation
- `notes.md` — optional analysis notes, false-positive notes, or operator guidance

Example:

```text
scenarios/
  reverse_shell/
    scenario.yaml
    attack.sh
    expected_alerts.json
  credential_access/
    scenario.yaml
    attack.sh
    expected_alerts.json
```

## Safety Model

All bundled scenarios should be safe by default.

Recommended safety rules:

- prefer dry-run behavior unless explicitly enabled
- prefer temporary files and loopback traffic over real production targets
- require explicit environment flags before touching sensitive system paths
- assume execution happens inside an isolated container, namespace, or VM

The included scripts follow this model:

- default mode prints and simulates behavior
- `KESTREL_LAB_EXECUTE=1` enables active behavior
- `KESTREL_LAB_ALLOW_REAL_TARGETS=1` is required before using real sensitive targets

## Suggested Workflow

### 1. Replay-first validation

Use replay whenever possible for fast rule iteration:

```bash
cargo run --bin kestrel -- replay --rules ./rules --log /path/to/replay.kest --speed 0
```

Use replay to answer:

- did the expected rules fire?
- did unrelated rules also fire?
- how stable is the rule set across runs?

### 2. Live lab validation

Run the scenario inside an isolated environment while Kestrel is running:

```bash
cargo run --bin kestrel -- run --rules ./rules --ebpf-object /path/to/main.bpf.o
bash scenarios/reverse_shell/attack.sh
```

Recommended isolation options:

- rootless container
- user/network/mount namespace via `unshare`
- disposable VM

## Validation Contract

A scenario is considered usable when it defines:

- what behavior is being simulated
- which event categories are expected (`process`, `file`, `network`)
- which rules should match
- which fields are important for triage
- what “safe execution” means for that scenario

## Near-term Roadmap

The next Battle Lab milestones should be:

1. add a `kestrel-lab` runner that discovers and executes scenarios
2. add replay log generation and result summaries per scenario
3. add scenario assertions for expected / unexpected rules
4. integrate scenario runs into CI for rule regression
5. expose a GUI-facing Replay Lab and Rule Studio on top of the same assets

## Authoring Guidance

When adding new scenarios:

- keep one scenario focused on one tactic or behavior chain
- describe the safe default path clearly
- include expected rule IDs in `expected_alerts.json`
- avoid irreversible destructive actions
- prefer deterministic scripts over heavily timing-sensitive shell tricks

## Current `kestrel-lab` Commands

- `kestrel-lab list`
- `kestrel-lab validate`
- `kestrel-lab show --scenario <id>`
- `kestrel-lab run --scenario <id> [--execute] [--alerts <file>] [--json]`
- `kestrel-lab run-all [--execute] [--json]`
- `kestrel-lab assert --scenario <id> --alerts <file> [--json]`

## Result Archive Convention

`kestrel-lab` writes scenario outputs under `lab-results/` using a session directory layout:

```text
lab-results/
  session-<unix-ts>/
    <scenario-id>/
      stdout.log
      stderr.log
      summary.json
      alerts.json          # if provided
      replay_summary.json  # if replay was requested
```

This structure is designed to become the shared substrate for Replay Lab, Rule Studio, and future Control Plane task execution.
