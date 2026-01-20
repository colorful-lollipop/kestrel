# Kestrel Project Governance

## Overview

Kestrel is an open-source project dedicated to providing next-generation endpoint behavioral detection capabilities. This document outlines how the project is governed and decisions are made.

## Project Leadership

### Maintainers
The project is maintained by a team of contributors who have shown commitment and expertise. Current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).

### Roles and Responsibilities

**Maintainers** are responsible for:
- Reviewing and merging pull requests
- Ensuring code quality and architectural consistency
- Facilitating discussions and decision-making
- Maintaining project stability and reliability
- Onboarding new contributors

**Contributors** are community members who:
- Submit pull requests and patches
- Review and discuss issues
- Participate in architectural discussions
- Help with documentation and testing

## Decision Making

### Technical Decisions
Technical decisions are made through consensus among maintainers:
- Proposals should be made as GitHub Issues or Discussions
- Maintainers discuss and reach consensus
- In case of disagreement, a simple majority vote decides
- The project lead has veto power for critical decisions

### Feature Acceptance
New features are evaluated based on:
- Alignment with project goals (see README.md)
- Community demand and use cases
- Implementation complexity and maintenance cost
- Performance impact
- Security implications

### Breaking Changes
Breaking changes require:
- Clear justification and migration path
- Documentation in CHANGELOG.md
- Deprecation period of at least one minor version
- Approval from majority of maintainers

## Branch Management

### Branch Structure
- **main**: Stable development branch, production-ready code
- **develop**: Development branch for next release (if used)
- **feature/***: Feature branches for new functionality
- **fix/***: Bug fix branches
- **hotfix/***: Urgent production fixes

### Merge Policies
- All changes must go through pull requests
- PRs require at least one maintainer approval
- CI/CD checks must pass
- Changes should be small and focused
- Large changes should be broken into smaller, reviewable pieces

## Version Management

### Semantic Versioning
Kestrel follows [Semantic Versioning 2.0.0](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality
- **PATCH**: Backwards-compatible bug fixes

### Release Process
1. Release candidate created on `main` branch
2. Testing and validation period
3. Documentation updates
4. GitHub release created
5. Published to crates.io
6. Documentation deployed to GitHub Pages

### Support Policy
- **Current stable version**: Full support (bug fixes, security updates)
- **Previous stable version**: Critical security updates only
- **Older versions**: Best effort community support

## Community Guidelines

### Code of Conduct
All community members must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Pull Requests**: Code contributions and reviews

### Issue Triage
Issues are labeled and prioritized:
- **P0 - Critical**: Security issues, production outages
- **P1 - High**: Important features, significant bugs
- **P2 - Medium**: Normal bugs, enhancements
- **P3 - Low**: Minor issues, nice-to-have features

## Conflict Resolution

### Disagreement Resolution
1. Discuss the issue openly and respectfully
2. Seek additional input from other maintainers
3. If unresolved, escalate to project lead
4. Final decision rests with project lead

### Code Review Disagreements
- Maintainers may request changes before merging
- Contributors should address review comments
- If disagreement persists, a third maintainer mediates

## Project Management

### Roadmap
The project roadmap is maintained in:
- [README.md](README.md) - High-level vision and goals
- [plan.md](plan.md) - Detailed technical plans
- GitHub Projects - Issue tracking and milestones

### Meetings
- **Weekly sync**: Maintainer coordination (if needed)
- **Monthly community call**: Open to all contributors (if needed)
- **Ad-hoc meetings**: As needed for specific topics

## Amendments

This governance document may be amended by:
- Proposal from any maintainer
- Discussion period of at least 7 days
- Approval from majority of maintainers

## Contact

For questions about governance, please:
- Open a GitHub Discussion
- Contact a maintainer directly
- Email: governance@kestrel-detection.org (TODO: Update with actual email)

---

**Last Updated**: 2025-01-14
