# VulnGuard v0.1.0 - Initial Open-Source Release

**Release Date**: January 17, 2026
**License**: GNU General Public License v3 (GPL-3.0)
**Author**: Nixsoft Technologies Pvt. Ltd.

---

## Overview

VulGuard v0.1.0 is the initial open-source release of a production-grade Linux security compliance agent. This release provides organizations with a deterministic-first, AI-gated tool for auditing, evaluating, and remediating systems against CIS Benchmarks and DISA STIG standards.

This release represents a conservative, security-focused approach to compliance automation, prioritizing safety, auditability, and reversibility over speed or convenience.

---

## Key Features

### 1. Deterministic Audit Engine

- **CIS Benchmark Support**: Audit systems against CIS Benchmarks
- **STIG Support**: Audit systems against DISA STIG requirements
- **Extensible Architecture**: Easy to add custom benchmarks
- **Deterministic Checks**: All checks are executed through defined commands
- **Expected State Validation**: Compares actual state against expected configurations

### 2. Compliance & Risk Decision Engine

- **Severity Normalization**: Normalizes severities across CIS and STIG standards
- **Risk Assessment**: Determines risk levels (low, medium, high, critical)
- **AI Assist Determination**: Automatically determines when AI assistance is needed
- **Approval Gating**: Identifies rules requiring manual approval
- **Exception Handling**: Supports documented exceptions to compliance rules

### 3. AI Gateway & Safety Validator

- **Multi-LLM Support**: Compatible with OpenAI, Anthropic, OpenRouter, Ollama, and local models
- **Strict Validation**: All AI output is validated against allow-lists
- **Confidence Thresholds**: Low-confidence recommendations require manual review
- **Command Validation**: All suggested commands are checked against allow-lists and block-lists
- **Safety Controls**: AI never executes commands directly

### 4. Reversible Remediation Engine

- **Automatic Backups**: Creates backups before any remediation
- **Rollback Capability**: Automatic rollback on failure
- **Dry-Run Mode**: Preview changes before applying
- **Command Safety**: Enforces allow-lists and block-lists
- **Service Restart Handling**: Manages service restarts safely

### 5. Structured Audit Logging

- **JSON-Line Format**: All logs in structured JSON for easy parsing
- **Comprehensive Events**: Logs all scan, evaluation, remediation, and rollback events
- **Audit Trail**: Complete traceability of all actions
- **Log Rotation**: Automatic log rotation to manage disk space

---

## Safety Guarantees

### 1. Deterministic-First Design

- **No Blind Automation**: All actions are deterministic and predictable
- **AI as Advisory**: AI is only used when deterministic logic is insufficient
- **Explicit Commands**: All remediation commands are explicitly defined
- **Reproducible Results**: Same inputs produce same outputs

### 2. Fail-Safe Operations

- **Dry-Run Default**: Default mode is dry-run for safety
- **Rollback on Failure**: Automatic rollback if remediation fails
- **Validation Before Execution**: All commands are validated before execution
- **Error Handling**: Graceful error handling, no silent failures

### 3. Audit Everything

- **Complete Logging**: Every action is logged
- **Traceable**: All actions can be traced to specific users and times
- **Immutable Logs**: Logs cannot be modified after writing
- **Compliance Ready**: Logs support compliance audits

### 4. Reversible Changes

- **Backups**: Automatic backups before any changes
- **Rollback Commands**: Every remediation includes rollback procedures
- **Test Before Apply**: Dry-run mode allows testing before applying
- **Manual Review**: High-risk changes require manual approval

---

## Known Limitations

### 1. Limited Benchmark Coverage

- **Initial Set**: Includes example CIS and STIG rules only
- **Not Comprehensive**: Does not include all CIS or STIG rules
- **Community Contribution Needed**: Full coverage requires community contributions
- **Manual Configuration**: Organizations must add their own benchmarks

### 2. AI Dependency

- **LLM Required**: AI features require an LLM API key or local model
- **Network Dependency**: Cloud LLMs require internet connectivity
- **Cost**: Cloud LLMs may incur costs based on usage
- **Fallback Available**: Falls back to simulated responses if LLM unavailable

### 3. Linux-Only

- **Linux Only**: Designed for Linux systems only
- **No Windows Support**: No Windows or macOS support in this release
- **Distribution Support**: Tested on RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+
- **Kernel Requirements**: Requires Linux kernel 3.10 or later

### 4. Root/Sudo Required

- **Privileged Operations**: Some checks and remediations require root access
- **Security Implication**: Running as root requires careful consideration
- **Least Privilege**: Users should use minimal necessary privileges
- **Audit Trail**: All privileged operations are logged

### 5. Manual Review Required

- **AI Output**: All AI recommendations require manual review
- **High-Risk Changes**: STIG CAT I/II rules require approval
- **Production Deployment**: Requires testing in non-production environments first
- **No Autonomous Operation**: No fully autonomous remediation in this release

### 6. Configuration Complexity

- **YAML Configuration**: Requires understanding of YAML syntax
- **Benchmark Definitions**: Custom benchmarks require YAML knowledge
- **Command Patterns**: Allow-lists and block-lists use regex patterns
- **Learning Curve**: Some technical knowledge required for configuration

---

## Who Should Use This Release

### Suitable For

**Organizations and individuals who**:

- **Need Compliance Auditing**: Require regular CIS or STIG compliance checks
- **Have Linux Infrastructure**: Run Linux systems (RHEL, Ubuntu, CentOS, Debian)
- **Value Safety**: Prioritize safety and reversibility over speed
- **Have Technical Expertise**: Comfortable with Linux administration and YAML configuration
- **Understand Security Risks**: Willing to review all remediation before deployment
- **Require Audit Trails**: Need complete traceability of all compliance actions

**Use Cases**:

- **Regular Compliance Scanning**: Periodic security compliance audits
- **Pre-Deployment Checks**: Verify compliance before deploying to production
- **Incident Response**: Quickly assess compliance after security incidents
- **Continuous Monitoring**: Integrate with continuous monitoring pipelines
- **Documentation**: Generate compliance reports for auditors or regulators

### Ideal Environments

- **Production**: Production environments with strict safety requirements
- **Regulated**: Environments subject to compliance regulations
- **High-Security**: Environments with high security requirements
- **Enterprise**: Enterprise environments with governance requirements

---

## Who Should NOT Use It Yet

### Not Suitable For

**Organizations and individuals who**:

- **Require Windows/macOS**: Need cross-platform support (not available in v0.1.0)
- **Need Full Automation**: Require fully autonomous remediation without review
- **Have Limited Technical Expertise**: Uncomfortable with Linux administration or YAML
- **Need Immediate Remediation**: Require instant, unreviewed remediation actions
- **Have No Testing Environment**: Cannot test in non-production environments first
- **Require Complete Benchmark Coverage**: Need all CIS or STIG rules out-of-the-box

### Wait For Future Releases If You

- **Need Cross-Platform Support**: Windows or macOS support planned for future releases
- **Need More Benchmarks**: Additional CIS and STIG rules planned for future releases
- **Need Enhanced AI Features**: More advanced AI capabilities planned for future releases
- **Need Simplified Configuration**: Improved configuration experience planned for future releases

### Consider Alternatives If You

- **Need Commercial Support**: Require enterprise support and SLAs
- **Need Certified Compliance**: Require certified compliance tools
- **Need Integrated Dashboards**: Require integrated compliance dashboards
- **Need Automated Reporting**: Require automated report generation and distribution

---

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/praveenkore/nixsoftai.git
cd nixsoftai

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m vulnguard.main version
```

### Configuration

1. Copy `.env.example` to `.env`
2. Configure LLM API keys (if using AI features)
3. Review and modify `vulnguard/configs/agent/config.yaml`
4. Add custom benchmarks to `vulnguard/configs/benchmarks/`

### Documentation

- [README.md](README.md) - Main documentation
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System architecture
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) - Configuration guide
- [docs/API.md](docs/API.md) - API reference
- [SECURITY.md](SECURITY.md) - Security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines

---

## Testing

### Pre-Release Testing

- **Unit Tests**: All unit tests pass
- **Integration Tests**: All integration tests pass
- **Manual Testing**: Manual testing on supported Linux distributions
- **Security Review**: Security review of all code changes
- **License Review**: GPL v3 compliance review completed

### Test Coverage

- **Current Coverage**: Approximately 75% code coverage
- **Target Coverage**: 80% code coverage (planned for v0.2.0)

---

## Known Issues

### Minor Issues

1. **LLM Timeout**: Long LLM responses may timeout (default: 30 seconds)
   - **Workaround**: Increase timeout in configuration
   - **Fix Planned**: v0.2.0

2. **Large Log Files**: Log files may grow large over time
   - **Workaround**: Configure log rotation in config.yaml
   - **Fix Planned**: v0.2.0 (improved log management)

3. **Benchmark Loading**: Some benchmark YAML files may not load correctly
   - **Workaround**: Validate YAML syntax before use
   - **Fix Planned**: v0.2.0 (improved error messages)

### No Critical Issues

- No critical or high-severity issues known at release time

---

## Upgrade Path

### From Previous Versions

This is the initial open-source release. There are no previous versions to upgrade from.

### Future Upgrades

Future releases will include:
- Migration guides for configuration changes
- Backward compatibility notes
- Deprecation warnings
- Upgrade instructions

---

## Support

### Getting Help

- **Documentation**: [README.md](README.md) and [docs/](docs/)
- **GitHub Issues**: [Report issues](https://github.com/praveenkore/nixsoftai/issues)
- **GitHub Discussions**: [Ask questions](https://github.com/praveenkore/nixsoftai/discussions)
- **Security Issues**: [Report securely](SECURITY.md)

### Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

VulnGuard v0.1.0 is released under the **GNU General Public License v3 (GPL-3.0)**.

### What This Means

- **Freedom to Use**: You can use VulnGuard for any purpose
- **Freedom to Study**: You can study how VulnGuard works
- **Freedom to Modify**: You can modify VulnGuard to suit your needs
- **Freedom to Distribute**: You can distribute copies of VulnGuard
- **Freedom to Distribute Modified Versions**: You can distribute your modified versions

### Requirements

- **Source Code**: If you distribute VulnGuard, you must also provide source code
- **License**: You must license your modifications under GPL v3
- **Attribution**: You must credit Nixsoft Technologies Pvt. Ltd. as the original author
- **No Warranty**: VulnGuard is provided "AS IS" without warranty

### Commercial Use

- **Allowed**: You may use VulnGuard commercially under GPL v3 terms
- **SaaS**: If you offer VulnGuard as a service, you must disclose source code
- **Derivative Works**: Any derivative works must also be licensed under GPL v3

See the [LICENSE](LICENSE) file for complete terms.

---

## Acknowledgments

This release would not be possible without:

- **Nixsoft Technologies Pvt. Ltd.** - Original author and maintainer
- **Open Source Community** - For feedback and testing
- **CIS and DISA** - For providing security benchmarks
- **Python Community** - For excellent libraries and tools

---

## Disclaimer

**VulnGuard is provided "AS IS" without warranty of any kind, express or implied.**

Nixsoft Technologies Pvt. Ltd. accepts no liability for:
- Security incidents resulting from use of VulnGuard
- Compliance failures due to misconfiguration or misuse
- Damages from incorrect remediation actions
- Any other consequences of using this software

Users are responsible for:
- Validating all compliance results
- Reviewing all remediation commands before execution
- Testing in non-production environments before production deployment
- Understanding the security implications of all actions
- Ensuring compliance with applicable laws and regulations

---

## Next Steps

### Planned for v0.2.0

- Expanded benchmark coverage (more CIS and STIG rules)
- Improved error messages and user experience
- Enhanced log management and rotation
- Additional LLM provider support
- Performance improvements
- Increased test coverage to 80%

### Roadmap

See the [GitHub Projects](https://github.com/praveenkore/nixsoftai/projects) for the full roadmap.

---

**Thank you for using VulnGuard!**

We are committed to making open-source security tools that are safe, reliable, and effective. Your feedback and contributions are welcome.
