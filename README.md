# VulnGuard - Linux Security Compliance Agent

A production-grade Linux Security Compliance Agent that audits, evaluates, and remediates systems against CIS Benchmarks and DISA STIG standards.

## Version

**VulnGuard v1.0.0**

## Overview

VulnGuard is designed for high-trust, regulated environments with strict safety controls and deterministic logic. It provides:

- Deterministic audit engine with no blind automation
- AI advisory with strict validation and confidence thresholds
- Reversible remediation with automatic rollback
- Approval gating for high-risk changes
- Comprehensive audit logging in JSON-line format
- Support for CIS and STIG benchmarks

## Design Philosophy

1. **Deterministic Logic FIRST, AI advisory ONLY when necessary**
2. **AI output is ALWAYS untrusted and MUST be validated**
3. **No blind automation**
4. **Every remediation MUST be reversible**
5. **Every action MUST be auditable**
6. **Safe failure is mandatory (fail-closed)**
7. **Production stability > compliance speed**

## Requirements

- Python 3.8+
- Linux (RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+)
- Root or sudo access for remediation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/VulnGuard-agent-v1.git
cd VulnGuard-agent-v1
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Verify installation:
```bash
python -m vulnguard.main version
```

## Configuration

The main configuration file is located at [`vulnguard/configs/agent/config.yaml`](vulnguard/configs/agent/config.yaml).

Key configuration options:

- **agent.mode**: Default mode (dry-run or commit)
- **logging.level**: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **logging.file_path**: Path to audit log file
- **remediation.auto_backup**: Enable automatic backups
- **remediation.rollback_on_failure**: Enable automatic rollback
- **ai.min_confidence_threshold**: Minimum AI confidence threshold (default: 0.7)
- **remediation.command_allowlist**: Regex patterns for allowed commands
- **remediation.command_blocklist**: Regex patterns for blocked commands

## CLI Usage

### Display Version Information

```bash
python -m vulnguard.main version
```

### List Available Benchmark Rules

```bash
python -m vulnguard.main list-rules
```

### Scan System for Compliance Issues

Scan all available rules:

```bash
python -m vulnguard.main scan
```

Scan specific rules:

```bash
python -m vulnguard.main scan -r cis_1_1_1 -r stig_vuln_220278
```

Save report to file:

```bash
python -m vulnguard.main scan -o report.json
```

Specify output format (json, yaml, or text):

```bash
python -m vulnguard.main scan -f text
```

### Remediate Non-Compliant Issues

**IMPORTANT**: Default mode is `dry-run` for safety. Always review the output before using `commit` mode.

Dry-run remediation (recommended first step):

```bash
python -m vulnguard.main remediate --mode dry-run
```

Dry-run specific rules:

```bash
python -m vulnguard.main remediate -r cis_1_1_1 --mode dry-run
```

Commit remediation (after reviewing dry-run output):

```bash
python -m vulnguard.main remediate --mode commit
```

Force remediation (bypass approval requirements):

```bash
python -m vulnguard.main remediate --mode commit --force
```

Save remediation report:

```bash
python -m vulnguard.main remediate -o remediation_report.json
```

### CLI Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--rule-id` | `-r` | Specific rule ID(s) to scan/remediate |
| `--mode` | `-m` | Remediation mode (dry-run or commit) |
| `--force` | | Force remediation even if approval is required |
| `--output` | `-o` | Output file path for report |
| `--format` | `-f` | Output format (json, yaml, text) |
| `--help` | `-h` | Display help information |

## Benchmark Rules

### CIS Benchmark Example

See [`vulnguard/configs/benchmarks/cis_1_1_1.yaml`](vulnguard/configs/benchmarks/cis_1_1_1.yaml) for an example CIS rule:

- **Rule ID**: 1.1.1
- **Title**: Ensure mounting of cramfs filesystems is disabled
- **Severity**: Level 2 (normalized to medium)
- **OS Compatibility**: Ubuntu, Debian

### STIG Benchmark Example

See [`vulnguard/configs/benchmarks/stig_vuln_220278.yaml`](vulnguard/configs/benchmarks/stig_vuln_220278.yaml) for an example STIG rule:

- **Rule ID**: V-220278
- **Title**: The SSH daemon must not allow authentication using an empty password
- **Severity**: CAT II (normalized to high)
- **OS Compatibility**: RHEL, CentOS, Ubuntu, Debian
- **Approval Required**: True

## Operational Pipeline

1. **Scan** - Deterministic checks only
2. **Evaluate** - Compliance & risk assessment
3. **Decide** - Determine if AI assistance is required
4. **Validate** - Validate AI output (JSON + command allow-list)
5. **Apply** - Remediation (dry-run or commit)
6. **Rollback** - Automatic rollback on failure
7. **Log** - Everything (JSON-line audit log)

## Safety Controls

### Command Allow-List

Commands must match one of these regex patterns:

- `systemctl (enable|disable|start|stop|restart|status) <service>`
- `sysctl -w <key>=<value>`
- `chmod <permissions> <file>`
- `chown <owner> <file>`
- `sed -i <pattern> <file>`
- `echo <content> >> <file>`

### Command Block-List

These commands are explicitly blocked:

- `rm -rf`
- `chmod 777`
- `userdel`
- `groupdel`
- `passwd -l root`
- `setenforce 0`

### Approval Gating

- STIG CAT I and CAT II rules require approval
- Critical severity rules require approval
- Rules with `approval_required: true` require approval

### AI Confidence Threshold

- Default threshold: 0.7
- Confidence < 0.7 requires manual review
- AI never executes commands directly

## Audit Logging

All operations are logged to `/var/log/vulnguard/audit.log` in JSON-line format for easy parsing and analysis.

Log events include:

- `scan_start` - Beginning of a compliance scan
- `scan_result` - Result of a compliance check
- `evaluation` - Compliance evaluation and risk level
- `ai_advisory` - AI recommendation output
- `remediation_start` - Beginning of remediation
- `remediation_result` - Result of remediation
- `rollback` - Rollback execution
- `backup` - Configuration backup
- `approval_request` - Approval requirement
- `error` - Error events

## Project Structure

```
vulnguard/
├── main.py                          # Orchestrator & CLI
├── pkg/
│   ├── scanner/                     # Deterministic Audit Engine
│   │   └── scanner.py
│   ├── engine/                      # Compliance & Risk Decision Engine
│   │   └── engine.py
│   ├── advisor/                     # AI Gateway & Safety Validator
│   │   └── advisor.py
│   ├── remediation/                 # Reversible Remediation Engine
│   │   └── remediation.py
│   └── logging/                     # Structured Audit Logger
│       └── logger.py
├── configs/
│   ├── agent/                       # Global agent config
│   │   └── config.yaml
│   └── benchmarks/                  # CIS / STIG YAML rules
│       ├── cis_1_1_1.yaml
│       └── stig_vuln_220278.yaml
└── requirements.txt                 # Python dependencies
```

## Severity Normalization

| CIS Original | Normalized | STIG Original | Normalized |
|--------------|------------|---------------|------------|
| Level 1      | high       | CAT I         | critical   |
| Level 2      | medium     | CAT II        | high       |
| Level 3      | low        | CAT III       | medium     |

## Risk Levels

- **Critical**: Immediate action required
- **High**: Action required within 24 hours
- **Medium**: Action required within 7 days
- **Low**: Action required within 30 days

## Documentation

For comprehensive documentation, see:

- **[API Documentation](docs/API.md)** - Detailed API reference for all modules and classes
- **[Architecture Documentation](docs/ARCHITECTURE.md)** - System architecture, design principles, and component interactions
- **[Configuration Guide](docs/CONFIGURATION.md)** - Detailed configuration options and best practices
- **[Development Guide](docs/DEVELOPMENT.md)** - Development environment setup, coding standards, and contribution guidelines

## Development

### Running Tests

```bash
pytest
```

### Code Quality

```bash
black vulnguard/
flake8 vulnguard/
mypy vulnguard/
```

## Support

For issues, questions, or contributions, please visit the project repository.

## License

[Specify your license here]

## Disclaimer

VulnGuard is provided as-is for security compliance purposes. Always test in a non-production environment before deploying to production systems. Review all remediation commands carefully before executing in commit mode.
