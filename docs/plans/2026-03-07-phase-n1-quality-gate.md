# Phase N1: 质量门禁恢复与告警清理

## Scope
- Source plan: `docs/next_optimization_plan.md`
- Execution scope for this round: `Phase N1`
- Goal: restore `cargo clippy --workspace` signal quality and remove current workspace build warnings without taking on `Phase N2` performance refactors.

## Constraints
- Repository currently has unrelated in-flight edits; keep changes minimal and scoped.
- Use current workspace as fallback because no worktree directory is configured.
- For `Phase N2` items already identified as larger refactors, prefer narrowly scoped lint suppression only when a real fix would change architecture.

## Steps
1. Run `cargo clippy --workspace` and `cargo build --workspace` to capture the current warning set.
2. Fix low-risk lint issues directly:
   - remove empty/unused doc comments
   - simplify clippy-suggested match/if patterns
   - update benchmark helper signatures
3. Remove compile-time `dead_code` warnings where fields/functions are genuinely unused:
   - delete unused fields/functions when they have no caller and no stored state requirement
   - rename intentionally retained private fields to `_field`
   - add narrow `#[allow(dead_code)]` only for intentional placeholders scheduled for later phases
4. Re-run targeted commands until both `cargo build --workspace` and `cargo clippy --workspace` are warning-free.
5. Run `cargo fmt --all` and re-run the verification commands.
