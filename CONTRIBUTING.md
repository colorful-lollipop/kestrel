# Contributing to Kestrel

Thank you for your interest in contributing to Kestrel! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming and inclusive community.

## Getting Started

### Prerequisites

- Rust 1.82 or later (edition 2021)
- Linux kernel 5.10+ (for eBPF features)
- Git
- clang and LLVM development tools (for eBPF compilation)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/kestrel-detection/kestrel.git
cd kestrel

# Install Rust toolchain
rustup default stable
rustup update

# Install development tools
cargo install cargo-watch
cargo install cargo-edit
cargo install cargo-nextest  # Faster test runner

# Verify setup
cargo test --workspace
cargo clippy --workspace
```

### Building

```bash
# Debug build
cargo build --workspace

# Release build
cargo build --workspace --release

# Build specific crate
cargo build -p kestrel-engine
```

## Development Workflow

### Making Changes

1. **Create a branch** from `main`
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following our [coding standards](#coding-standards)

3. **Test your changes**
   ```bash
   # Run all tests
   cargo test --workspace

   # Run with nextest (faster)
   cargo nextest run --workspace

   # Run specific test
   cargo test -p kestrel-engine test_name

   # Run tests with watch mode
   cargo watch -x test
   ```

4. **Check code quality**
   ```bash
   # Format code
   cargo fmt

   # Run linter
   cargo clippy --workspace --all-targets

   # Check formatting
   cargo fmt --all -- --check
   ```

5. **Commit your changes** following our [commit message guidelines](#commit-messages)
   ```bash
   git add .
   git commit -m "feat: Add new feature description"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   # Then create a PR on GitHub
   ```

## Coding Standards

### Rust Style

- Follow standard Rust style conventions (`cargo fmt`)
- Use `Result<T>` for error handling, avoid panics in library code
- Prefer `thiserror` for defining error types
- Document all public APIs with rustdoc comments (`///`)
- Include examples in documentation

### Code Organization

- Keep modules focused and cohesive
- Prefer composition over inheritance
- Use trait objects sparingly, prefer generics where possible
- Follow the existing project structure

### Performance Considerations

- Profile before optimizing
- Prefer `Arc` over `Rc` in async code
- Use `parking_lot` for locks in hot paths
- Consider cache locality for data structures

### Documentation

```rust
/// Brief description of what this does.
///
/// More detailed explanation...
///
/// # Examples
///
/// ```
/// use kestrel_core::EventBus;
///
/// let bus = EventBus::new(config);
/// ```
///
/// # Errors
///
/// This function will return an error if...
///
/// # Panics
///
/// This function will panic if...
pub fn example_function() -> Result<()> {
    // ...
}
```

## Testing Guidelines

### Unit Tests

- Write tests alongside code in the same module
- Test both success and error paths
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder_creates_valid_event() {
        // Arrange
        let event_type = 1001;
        let timestamp = 1234567890;

        // Act
        let event = Event::builder()
            .event_type(event_type)
            .ts_mono(timestamp)
            .build();

        // Assert
        assert_eq!(event.event_type_id(), event_type);
        assert_eq!(event.ts_mono_ns, timestamp);
    }
}
```

### Integration Tests

- Place in `tests/` directory of the relevant crate
- Test component interactions
- Use realistic data where possible

### Performance Tests

- Use the `kestrel-benchmark` crate for performance tests
- Document expected performance characteristics
- Include regression tests for critical paths

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/changes
- `chore`: Maintenance tasks
- `ci`: CI/CD changes

### Examples

```
feat(engine): Add support for EQL sequence rules

Implemented NFA engine for detecting event sequences with:
- maxspan support for time windows
- until clause for termination conditions
- by clause for entity grouping

Closes #123
```

```
fix(nfa): Correct event type index deduplication

Fixed bug where sequences with multiple steps of the same event
type were indexed multiple times, causing redundant processing.

Fixes #145
```

## Pull Request Process

### Before Submitting

1. **Ensure all tests pass**
   ```bash
   cargo test --workspace
   ```

2. **Run clippy**
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   ```

3. **Format code**
   ```bash
   cargo fmt
   ```

4. **Update documentation** if needed

5. **Add tests** for new functionality

6. **Update CHANGELOG.md** if user-facing

### PR Title

Use the same format as commit messages:

```
feat: Add support for EQL sequence rules
fix: Correct event type index deduplication
```

### PR Description

Include:

- **What** changes were made and why
- **How** the changes were implemented
- **Testing** done
- **Screenshots** if applicable
- **Related issues** (e.g., `Closes #123`)

### Review Process

1. Automated checks must pass
2. At least one maintainer approval required
3. Address review comments promptly
4. Keep PRs focused and small when possible
5. Squash commits if needed before merging

### Getting Help

- Ask questions in the PR description
- Tag maintainers for review using `@`
- Join our discussions for design conversations

## Areas Looking for Contributors

We welcome contributions in these areas:

- **eBPF Programs**: Additional event types and hooks
- **EQL Features**: Expanded query language support
- **Performance**: Optimization and profiling
- **Documentation**: Examples, guides, tutorials
- **Testing**: Test cases and scenarios
- **Integrations**: SIEM, logging platforms

See [GitHub Issues](https://github.com/kestrel-detection/kestrel/issues) for specific tasks.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
