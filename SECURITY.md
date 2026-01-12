# Security Policy

## Supported Versions

Currently, only the latest version of Kestrel is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously and appreciate your efforts to responsibly disclose vulnerabilities.

### How to Report

**DO NOT** file a public issue.

Instead, send an email to our security team at:

**Email:** `security@kestrel-detection.org`

*(If the above email is not configured, please contact the maintainers directly through GitHub's private reporting feature)*

### What to Include

Please include as much of the following information as possible:

- **Description**: A clear description of the vulnerability
- **Impact**: How the vulnerability could be exploited
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Suggested Fix** (optional): Any suggestions for fixing the issue
- **Proof of Concept** (optional): Code or screenshots demonstrating the vulnerability

### What to Expect

1. **Confirmation**: We will acknowledge receipt of your report within 48 hours
2. **Assessment**: We will investigate the issue and determine severity
3. **Coordination**: We will work with you to understand and fix the issue
4. **Disclosure**: We will coordinate a disclosure timeline with you
5. **Credit**: With your permission, we will credit you in the security advisory

### Response Timeline

- **Critical Issues**: Aim for patch within 7 days
- **High Issues**: Aim for patch within 14 days
- **Medium Issues**: Aim for patch within 30 days
- **Low Issues**: Address in next regular release

### Security Best Practices for Kestrel

When deploying Kestrel in production, consider the following:

#### System Hardening

- **Run with minimal privileges**: Don't run as root unless necessary for eBPF
- **Use secure file permissions**: Protect rule files and logs
- **Enable SELinux/AppArmor**: When available
- **Network isolation**: If rules contain sensitive logic

#### Rule Security

- **Review third-party rules**: Always audit rules before deployment
- **Use rule signatures**: Verify rule integrity
- **Limit rule capabilities**: Disable blocking for untrusted rules
- **Sandboxed runtimes**: Keep Wasm sandboxing enabled

#### Update Management

- **Subscribe to security advisories**: Watch releases for security updates
- **Test updates**: Test in non-production before upgrading
- **Backup configurations**: Keep backups of working rule sets
- **Review CHANGELOG**: Check for security-related changes

### Security Features in Kestrel

Kestrel includes several security-focused features:

- **Wasm Sandboxing**: Rules run in isolated Wasm environments
- **Resource Limits**: CPU and memory quotas for rule execution
- **Capability System**: Fine-grained control over rule permissions
- **Audit Logging**: All blocking actions are logged
- **Deterministic Replay**: Verify rule behavior offline

### Known Security Considerations

#### eBPF Capabilities

- **Privileged operations**: eBPF programs require `CAP_BPF` or root
- **Kernel access**: eBPF has access to kernel data structures
- **System stability**: Malformed eBPF can crash the system

**Mitigation**: Only load trusted eBPF programs. Use signed eBPF binaries in production.

#### Rule Execution

- **Arbitrary code execution**: Wasm/Lua rules can execute code
- **Resource exhaustion**: Poorly written rules can consume resources
- **Data exfiltration**: Rules could potentially leak information

**Mitigation**:
- Enable resource limits (fuel, memory, timeout)
- Use strict mode for untrusted rules
- Review and audit all rules

#### Blocking Actions

- **System disruption**: Incorrect blocking rules can disrupt operations
- **Denial of service**: Aggressive blocking can cause DoS
- **Data loss**: Blocking file operations can lead to data loss

**Mitigation**:
- Start with detection-only mode
- Test blocking rules thoroughly
- Implement rollback mechanisms
- Monitor and audit all blocking actions

### Security Audits

| Date | Version | Auditor | Report |
| ------ | ------- | ------- | ------ |
| TBD   | 1.0.0   | TBD     | TBD    |

### Contact

For general security questions or concerns:
- **GitHub**: https://github.com/kestrel-detection/kestrel/discussions/categories/security
- **Email**: security@kestrel-detection.org

Thank you for helping keep Kestrel secure!
