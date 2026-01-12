# Phase B-1: CI/CD Pipeline (GitHub Actions) Implementation Guide

**Task**: Establish world-class continuous integration pipeline for Kestrel project

**Target**: 100% automated testing with quality gates on every PR

**Estimated Time**: 1-2 days

---

## Task Description

Implement comprehensive GitHub Actions CI/CD pipeline for Kestrel workspace project with:
- Automated testing across Rust versions and platforms
- Code quality checks (fmt, clippy, doc)
- Performance benchmarks as quality gates
- Code coverage tracking with quality gates
- Separate workflows for PRs vs main branch
- Caching for fast builds

---

## Prerequisites

1. **GitHub Repository Setup**
   - Repository: https://github.com/colorful-lollipop/kestrel
   - Branch protection enabled (1 approval required)
   - Actions enabled in repository settings

2. **Required Accounts/Services** (Optional for Phase B-1)
   - Codecov account (for coverage tracking)
   - Coveralls account (alternative coverage service)

3. **Local Environment**
   - Git access to repository
   - gh CLI installed (for workflow testing)

---

## Step-by-Step Implementation

### Step 1: Create GitHub Workflows Directory

```bash
# Create workflows directory
mkdir -p .github/workflows

# Verify directory structure
ls -la .github/
```

**Location**: `.github/workflows/`

---

### Step 2: Create Main CI Workflow

Create file `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_INCREMENTAL: '0'
  RUSTFLAGS: '-D warnings'
  CARGO_TERM_COLOR: always

jobs:
  # ------------------------------------------------------------
  # Job 1: Format and Lint checks (fast feedback)
  # ------------------------------------------------------------
  fmt:
    name: Format Check
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt

      - name: Check formatting
        run: cargo fmt --all -- --check

  clippy:
    name: Clippy Lint
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-

      - name: Run clippy
        run: |
          cargo clippy --workspace --all-targets -- -D warnings
          cargo clippy --workspace --all-targets --all-features -- -D warnings

  # ------------------------------------------------------------
  # Job 2: Test across Rust versions and platforms
  # ------------------------------------------------------------
  test:
    name: Test (${{ matrix.os }} - ${{ matrix.rust }})
    needs: [fmt, clippy]
    runs-on: ${{ matrix.os }}
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, "1.82.0"]  # Latest stable + minimum supported
        include:
          - os: ubuntu-latest
            rust: beta
          - os: ubuntu-latest
            rust: nightly

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@${{ matrix.rust }}
        with:
          components: rustfmt, clippy

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
            target
          key: ${{ runner.os }}-cargo-${{ matrix.rust }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-${{ matrix.rust }}-
            ${{ runner.os }}-cargo-

      - name: Run tests
        run: cargo test --workspace --all-features

      - name: Run tests without default features
        run: cargo test --workspace --no-default-features

  # ------------------------------------------------------------
  # Job 3: Documentation check
  # ------------------------------------------------------------
  docs:
    name: Documentation Check
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-

      - name: Check documentation
        run: |
          cargo doc --no-deps --all-features
          cargo doc --no-deps --no-default-features

  # ------------------------------------------------------------
  # Job 4: Cross-compilation check (optional, Phase B-1+)
  # ------------------------------------------------------------
  cross-compile:
    name: Cross-Compile (${{ matrix.target }})
    needs: [test]
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        target:
          - x86_64-unknown-linux-gnu
          - x86_64-unknown-linux-musl
          - aarch64-unknown-linux-gnu
          - x86_64-apple-darwin
          - x86_64-pc-windows-msvc

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          target: ${{ matrix.target }}

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
            target
          key: ${{ runner.os }}-cargo-${{ matrix.target }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-${{ matrix.target }}-
            ${{ runner.os }}-cargo-

      - name: Build for target
        run: cargo build --release --target ${{ matrix.target }}

  # ------------------------------------------------------------
  # Job 5: Summary (only on success)
  # ------------------------------------------------------------
  ci-summary:
    name: CI Summary
    if: success()
    needs: [fmt, clippy, test, docs]
    runs-on: ubuntu-latest
    steps:
      - run: echo "✅ All CI checks passed successfully!"
```

**Location**: `.github/workflows/ci.yml`

---

### Step 3: Create Coverage Workflow (Depends on Phase B-4)

Create file `.github/workflows/coverage.yml`:

```yaml
name: Code Coverage

on:
  push:
    branches: [main, develop]
  pull_request:

env:
  CARGO_INCREMENTAL: '0'
  RUSTFLAGS: '-D warnings'

jobs:
  tarpaulin:
    name: Code Coverage
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-tarpaulin
        uses: taiki-e/install-action@v2
        with:
          tool: cargo-tarpaulin

      - name: Generate coverage report
        env:
          # Optimized for tarpaulin
          RUSTFLAGS: '-Ccodegen-units=1 -Clink-dead-code -Coverflow-checks=off'
        run: |
          cargo tarpaulin \
            --workspace \
            --all-targets \
            --fail-under 70 \
            --out Xml \
            --out Html \
            --output-dir target/tarpaulin

      - name: Upload coverage to Codecov (optional)
        if: github.event_name == 'push'
        uses: codecov/codecov-action@v5
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          files: target/tarpaulin/tarpaulin.xml
          fail_ci_if_error: false
          verbose: true

      - name: Upload coverage artifacts
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: target/tarpaulin/
          retention-days: 30

      - name: Check coverage threshold
        run: |
          echo "📊 Coverage report generated"
          echo "📁 Report location: target/tarpaulin/index.html"
```

**Location**: `.github/workflows/coverage.yml`

---

### Step 4: Create Benchmark Workflow (Depends on Phase B-2)

Create file `.github/workflows/bench.yml`:

```yaml
name: Benchmarks

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

env:
  CARGO_INCREMENTAL: '0'

jobs:
  bench:
    name: Performance Benchmarks
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
            target/release
            target/criterion
          key: ${{ runner.os }}-bench-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-bench-

      - name: Run benchmarks
        run: |
          cargo bench --workspace

      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: target/criterion/
          retention-days: 30

      - name: Check for regressions
        run: |
          echo "📈 Benchmark results generated"
          echo "📁 Report location: target/criterion/report/"
          echo "ℹ️  Manual review required for regression detection"
```

**Location**: `.github/workflows/bench.yml`

---

### Step 5: Create Release Workflow (Optional, Phase B-2+)

Create file `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-release:
    name: Build Release (${{ matrix.target }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: kestrel-x86_64-linux
          - os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            artifact: kestrel-x86_64-linux-musl
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: kestrel-x86_64-macos
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: kestrel-x86_64-windows.exe

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          target: ${{ matrix.target }}

      - name: Build release binary
        run: cargo build --release --target ${{ matrix.target }}

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: target/${{ matrix.target }}/release/kestrel*

  create-github-release:
    name: Create GitHub Release
    needs: [build-release]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: artifacts/**/*
          generate_release_notes: true
          draft: false
          prerelease: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Location**: `.github/workflows/release.yml`

---

## Verification Steps

### 1. Local Workflow Validation

```bash
# Ensure workflow YAML is valid
yamllint .github/workflows/*.yml

# Or use gh CLI to validate
gh workflow list
```

### 2. Test on Feature Branch

```bash
# Create test branch
git checkout -b feature/ci-pipeline-test

# Commit workflows
git add .github/workflows/
git commit -m "feat: Add CI/CD pipeline"

# Push to remote
git push origin feature/ci-pipeline-test

# Create pull request
gh pr create --title "Add CI/CD Pipeline" --body "Testing CI workflow"
```

### 3. Monitor CI Execution

```bash
# Watch CI status
gh run list --limit 10

# Watch specific workflow
gh run watch

# Download logs on failure
gh run view <run-id> --log
```

### 4. Verify All Checks Pass

Expected checks on PR:
- ✅ Format Check
- ✅ Clippy Lint
- ✅ Test (ubuntu-latest - stable)
- ✅ Test (macos-latest - stable)
- ✅ Test (windows-latest - stable)
- ✅ Test (ubuntu-latest - 1.82.0)
- ✅ Test (ubuntu-latest - beta)
- ✅ Test (ubuntu-latest - nightly)
- ✅ Documentation Check
- ✅ Cross-Compile (all targets)

---

## Rollback Plan

### Scenario 1: Workflow Syntax Error

**Symptoms**: Workflow fails to load with YAML error

**Rollback**:
```bash
# Delete failing workflow
rm .github/workflows/failing-workflow.yml

# Commit rollback
git add .github/workflows/
git commit -m "rollback: Remove broken workflow"
git push origin feature/ci-pipeline-test
```

### Scenario 2: Tests Failing on CI Only

**Symptoms**: Tests pass locally but fail on CI

**Troubleshooting**:
1. Check environment differences (OS, Rust version)
2. Download CI logs: `gh run view <run-id> --log`
3. Replicate locally using same Rust version:
   ```bash
   rustup install 1.82.0
   rustup default 1.82.0
   cargo test --workspace
   ```

**Rollback**: If critical, disable workflow:
```bash
# Rename workflow to disable
mv .github/workflows/ci.yml .github/workflows/ci.yml.disabled
git commit -m "ci: Temporarily disable CI workflow"
```

### Scenario 3: Caching Issues

**Symptoms**: Build fails with corrupted cache

**Rollback**: Clear cache via GitHub UI or add `cache-version` key:
```yaml
- name: Cache dependencies
  uses: actions/cache@v4
  with:
    key: ${{ runner.os }}-cargo-v1-${{ hashFiles('**/Cargo.lock') }}
```

---

## Success Criteria

### Phase B-1 Completion Checklist

- [ ] All workflow files created in `.github/workflows/`
- [ ] Format check passes locally and on CI
- [ ] Clippy passes with zero warnings
- [ ] Tests pass on all matrix combinations (5+ platforms/versions)
- [ ] Documentation builds without errors
- [ ] Cross-compilation succeeds for 5+ targets
- [ ] Coverage workflow runs successfully (after Phase B-4)
- [ ] Benchmark workflow runs successfully (after Phase B-2)
- [ ] Average CI completion time < 10 minutes
- [ ] Cache hit rate > 70% for subsequent runs
- [ ] All PRs blocked until CI passes (branch protection)

---

## Next Steps

### Integration with Phase B Tasks

1. **Phase B-2 (Benchmarks)**: Benchmarks will be integrated into `bench.yml` workflow
2. **Phase B-3 (Load Testing)**: Add load testing job to CI pipeline
3. **Phase B-4 (Coverage)**: Coverage workflow already configured

### Future Enhancements (Phase C/D)

1. **Miri Integration**: Add memory safety testing
2. **Fuzz Testing**: Add fuzz testing workflow
3. **Security Scanning**: Add cargo-audit and cargo-deny
4. **Performance Regression Detection**: Integrate with CodSpeedHQ
5. **Code Quality Metrics**: Integrate with CodeScene

---

## Code Examples

### Example: Conditional Job Execution

```yaml
# Only run on main branch, not on PRs
deploy:
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  runs-on: ubuntu-latest
  needs: [test, coverage]
  steps:
    - run: echo "Deploying to production..."
```

### Example: Custom Cache Key

```yaml
- name: Cache dependencies
  uses: actions/cache@v4
  with:
    path: |
      ~/.cargo/registry/index
      ~/.cargo/registry/cache
      ~/.cargo/git/db
      target
    # Include OS, Rust version, and Cargo.lock hash
    key: ${{ runner.os }}-cargo-${{ matrix.rust }}-${{ hashFiles('**/Cargo.lock') }}
    # Fallback keys for partial cache hits
    restore-keys: |
      ${{ runner.os }}-cargo-${{ matrix.rust }}-
      ${{ runner.os }}-cargo-
```

### Example: Job Timeout Handling

```yaml
test:
  runs-on: ubuntu-latest
  timeout-minutes: 30  # Fail after 30 minutes
  steps:
    - name: Run tests with timeout
      run: |
        timeout 25m cargo test --workspace || {
          echo "⏱️ Tests timed out"
          exit 1
        }
```

---

## Troubleshooting

### Issue: Workflow not triggering

**Solution**:
1. Check branch matches trigger conditions
2. Ensure workflow file is valid YAML
3. Check GitHub Actions logs: `gh workflow view <workflow-name>`

### Issue: Clippy warnings on CI but not locally

**Solution**:
1. Check CI uses same Rust version: `rustup show`
2. Check CI environment variables: `env RUSTFLAGS='-D warnings'`
3. Run locally with CI settings:
   ```bash
   RUSTFLAGS='-D warnings' cargo clippy --all-targets -- -D warnings
   ```

### Issue: Tests timeout on CI

**Solution**:
1. Increase timeout: `timeout-minutes: 45`
2. Split tests into multiple jobs
3. Use `--test-threads=1` for slower CI runners:
   ```bash
   cargo test --workspace -- --test-threads 1
   ```

---

## References

- **GitHub Actions Documentation**: https://docs.github.com/actions
- **Tokio CI Workflow**: https://github.com/tokio-rs/tokio/blob/master/.github/workflows/ci.yml
- **Bevy CI Workflow**: https://github.com/bevyengine/bevy/blob/main/.github/workflows/ci.yml
- **dtolnay Rust Toolchain**: https://github.com/dtolnay/rust-toolchain
- **actions/cache**: https://github.com/actions/cache

---

**Implementation Status**: Draft

**Next Review**: After Phase B-2, B-3, B-4 guides are created
