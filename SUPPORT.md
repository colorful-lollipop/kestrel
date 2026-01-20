# Kestrel Support Policy

## Getting Help

This document outlines the various support channels available for Kestrel users and contributors.

## Community Support

### Free Community Support
Free support is available through:
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions, ideas, and general discussions
- **Documentation**: Comprehensive guides and API references

### Response Times
- **Security issues**: Within 48 hours (see SECURITY.md)
- **Critical bugs**: Within 1 week
- **Questions and discussions**: Best effort, typically within a few days
- **Feature requests**: Reviewed at maintainers' discretion

## Support Scope

### What We Support
- Installation and setup issues
- Usage questions
- Bug investigations
- Feature discussions
- Integration assistance

### What We Don't Support
- Custom rule development (beyond examples)
- Production troubleshooting beyond documented issues
- Performance tuning beyond documented guides
- Custom integrations and modifications
- 24/7 emergency support

## Getting Help Effectively

### Before Asking for Help
1. **Search existing resources**
   - Read [README.md](README.md)
   - Check [FAQ.md](FAQ.md) (if available)
   - Search existing [GitHub Issues](https://github.com/kestrel-detection/kestrel/issues)
   - Search [GitHub Discussions](https://github.com/kestrel-detection/kestrel/discussions)

2. **Gather information**
   - Kestrel version: `kestrel --version`
   - Operating system and kernel version: `uname -a`
   - Rust version: `rustc --version`
   - Error messages and logs
   - Minimal reproduction case

### Creating a Support Request

#### Bug Reports
Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Relevant logs and error messages
- Minimal reproduction case if possible

#### Feature Requests
Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:
- Use case description
- Proposed solution
- Alternative approaches considered
- Impact on your use case

#### Questions
Use GitHub Discussions and include:
- Clear question title
- Context and background
- What you've already tried
- Relevant configuration or code snippets

## Priority Levels

### P0 - Critical
- Security vulnerabilities
- Data loss or corruption
- Complete system failure
- Production outages

### P1 - High
- Major functionality broken
- Performance degradation
- Workarounds available but difficult

### P2 - Medium
- Minor functionality issues
- Inconvenient but workable
- Documentation gaps

### P3 - Low
- Nice-to-have features
- Minor annoyances
- Cosmetic issues

## Professional Support

### Commercial Support
Currently, Kestrel does not offer official commercial support. However, for enterprise support needs:
- **Consulting**: Contact individual maintainers or companies specializing in Rust security tools
- **Custom development**: Reach out through GitHub Discussions

### Service Providers
If you or your organization offers professional Kestrel support, let us know and we'll list you here.

## Contributing

### Bug Fixes and Improvements
We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Documentation
Help improve documentation by:
- Fixing typos and errors
- Adding examples
- Expanding explanations
- Translating documentation

## Reporting Security Issues

**DO NOT** file public issues for security vulnerabilities.

See [SECURITY.md](SECURITY.md) for the secure reporting process.

## Community Resources

### Learning Resources
- [README.md](README.md) - Project overview and quick start
- [docs/deployment.md](docs/deployment.md) - Production deployment guide
- [docs/troubleshooting.md](docs/troubleshooting.md) - Common issues and solutions
- [examples/](examples/) - Usage examples and tutorials

### Development Resources
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guide
- [GOVERNANCE.md](GOVERNANCE.md) - Project governance
- [MAINTAINERS.md](MAINTAINERS.md) - Project maintainers

## Contact

### Quick Questions
- Use GitHub Discussions for quick questions

### Formal Inquiries
- Email: support@kestrel-detection.org (TODO: Update with actual email)
- GitHub Issues: Bug reports and feature requests

### Press and Media
- Email: press@kestrel-detection.org (TODO: Update with actual email)

## Support Disclaimer

Kestrel is open-source software provided "as is" without warranties of any kind. The project maintainers provide best-effort community support but cannot guarantee response times or solutions.

## License and Support

Support is provided regardless of:
- Geographic location
- Organization size
- License type (Apache 2.0)
- Usage (commercial or personal)

Everyone is welcome in our community!

---

**Last Updated**: 2025-01-14
