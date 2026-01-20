## Pull Request Checklist

### Before Submitting
- [ ] I have read the [CONTRIBUTING.md](CONTRIBUTING.md) guide
- [ ] My code follows the style guidelines (`cargo fmt` checked)
- [ ] My code passes clippy (`cargo clippy --workspace` checked)
- [ ] I have performed a self-review of my code
- [ ] I have commented complex code sections
- [ ] I have updated documentation as needed
- [ ] I have added tests for new functionality
- [ ] All tests pass locally (`cargo test --workspace`)
- [ ] I have updated `CHANGELOG.md` for user-facing changes

---

## Change Type

<!-- Mark the relevant option with an 'x' -->

- [ ] 🐛 **Bug fix** - Non-breaking change which fixes an issue
- [ ] ✨ **New feature** - Non-breaking change which adds functionality
- [ ] 💥 **Breaking change** - Fix or feature that breaks existing functionality
- [ ] 📚 **Documentation** - Documentation updates only
- [ ] ⚡ **Performance** - Performance improvement (non-breaking)
- [ ] 🧹 **Refactoring** - Code refactoring (non-breaking)
- [ ] ✅ **Tests** - Test improvements or additions only
- [ ] 🔧 **Configuration** - Configuration or build changes

---

## Description

<!-- Provide a clear description of what this PR does and why it's needed -->

### Context
<!-- Why is this change being made? What problem does it solve? -->

### Summary
<!-- Briefly summarize the changes -->

---

## Changes Made

<!-- List the main changes in this PR -->

### Files Changed
<!-- List key files modified -->

- `path/to/file1` - Description of changes
- `path/to/file2` - Description of changes

### Key Modifications
<!-- Describe key modifications -->

1. **Change 1**: Description
2. **Change 2**: Description
3. **Change 3**: Description

---

## Breaking Changes (if applicable)

<!-- If this is a breaking change, describe what breaks and how to migrate -->

### What Breaks
- Description of breaking changes

### Migration Path
- Steps for users to migrate

---

## Testing

### Test Coverage
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed
- [ ] Performance tests run (if applicable)

### Test Scenarios
<!-- Describe the test scenarios you ran -->

```bash
# Paste relevant test commands and output here
```

### Reproduction Steps
<!-- For bug fixes, provide steps to reproduce the bug -->

1. Step 1
2. Step 2
3. Expected behavior vs actual behavior

---

## Performance Impact

<!-- For performance-related changes, provide benchmarks -->

### Before
```
# Benchmark results before changes
```

### After
```
# Benchmark results after changes
```

### Analysis
<!-- Describe performance impact -->

---

## Documentation

### Documentation Changes
- [ ] API documentation updated (rustdoc comments)
- [ ] User documentation updated (docs/*.md)
- [ ] README updated (if needed)
- [ ] Examples updated (if needed)

### New Documentation
<!-- List new documentation files added -->

---

## Screenshots / Demo (if applicable)

<!-- For UI/UX changes or visual features -->

![Screenshot/Demo](link-to-screenshot)

---

## Related Issues

<!-- Link to related issues -->

- Closes #<!-- issue number -->
- Relates to #<!-- issue number -->
- Fixes #<!-- issue number -->
- Refs #<!-- issue number -->

---

## Dependencies

### Added
<!-- List new dependencies added -->

- `crate-name` - Version: - Reason:

### Updated
<!-- List dependencies updated -->

- `crate-name` - From: - To: - Reason:

### Removed
<!-- List dependencies removed -->

- `crate-name` - Reason:

---

## Checklist for Specific Changes

### For Code Changes
- [ ] Code is well-documented
- [ ] Error handling is proper
- [ ] No hardcoded values (use constants/config)
- [ ] Memory efficient (no leaks, excessive allocations)

### For eBPF Changes
- [ ] eBPF programs tested on target kernel
- [ ] Memory access is safe
- [ ] No infinite loops in eBPF code
- [ ] Proper error handling in kernel space

### For Wasm/Lua Runtime Changes
- [ ] Host API compatibility maintained
- [ ] Sandboxing verified
- [ ] Resource limits enforced
- [ ] Error propagation correct

### For Documentation Changes
- [ ] Links are valid
- [ ] Code examples are tested
- [ ] Spelling and grammar checked
- [ ] Consistent with other docs

---

## Additional Notes

<!-- Any additional context, screenshots, or information -->

### Open Questions
<!-- List any open questions or areas needing review -->

1. Question 1
2. Question 2

### Future Work
<!-- List potential follow-up improvements -->

- Improvement 1
- Improvement 2

---

## Reviewer Notes

<!-- For reviewers: specific areas to focus on -->

### Areas Requiring Special Attention
- Area 1
- Area 2

### Testing Instructions
<!-- If reviewers need to test, provide instructions -->

---

## Release Notes

<!-- This will be included in the release notes -->

```markdown
<!-- Summary of changes for release notes -->
```

---

**Thank you for your contribution! 🎉**

For questions, reach out in the PR comments or [GitHub Discussions](https://github.com/kestrel-detection/kestrel/discussions)
