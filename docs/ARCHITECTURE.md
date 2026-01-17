# VulnGuard Architecture Documentation

This document provides a comprehensive overview of the VulnGuard Linux Security Compliance Agent architecture, design principles, and component interactions.

## Table of Contents

- [Overview](#overview)
- [Design Philosophy](#design-philosophy)
- [System Architecture](#system-architecture)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)
- [Safety Controls](#safety-controls)
- [Extensibility](#extensibility)
- [Performance Considerations](#performance-considerations)

---

## Overview

VulnGuard is a production-grade Linux Security Compliance Agent designed for high-trust, regulated environments. It provides deterministic audit capabilities with AI-assisted advisory services, ensuring safe and reversible remediation of security compliance issues.

### Key Characteristics

- **Deterministic Logic First**: All compliance checks are deterministic and predictable
- **AI Advisory Only**: AI is used only for advisory purposes, never for direct execution
- **Fail-Safe Design**: All operations are reversible and logged
- **Compliance Focused**: Built for CIS Benchmarks and DISA STIG standards
- **Production Ready**: Designed for stability and reliability in regulated environments

---

## Design Philosophy

VulnGuard follows seven core design principles:

### 1. Deterministic Logic FIRST, AI advisory ONLY when necessary

All compliance checks are deterministic and based on predefined rules. AI is only invoked when:
- The scan result is ambiguous
- The rule explicitly requests AI assistance
- There's an error during scanning

### 2. AI output is ALWAYS untrusted and MUST be validated

All AI output undergoes strict validation:
- JSON schema validation
- Command allow-list/block-list validation
- Confidence threshold checking
- Required field verification

### 3. No blind automation

All remediation actions require:
- Explicit dry-run mode by default
- Manual review of proposed changes
- Approval gating for high-risk changes
- Clear logging of all actions

### 4. Every remediation MUST be reversible

All remediation includes:
- Automatic backup before changes
- Rollback commands for each action
- Automatic rollback on failure
- Audit trail of all changes

### 5. Every action MUST be auditable

All operations are logged with:
- Structured JSON-line format
- Complete context and metadata
- Timestamp and system information
- Success/failure status

### 6. Safe failure is mandatory (fail-closed)

The system is designed to:
- Fail safely on errors
- Never leave system in undefined state
- Rollback on remediation failure
- Log all errors for investigation

### 7. Production stability > compliance speed

Prioritizes:
- Predictable behavior over speed
- Safety over automation
- Manual review over blind execution
- Comprehensive logging over brevity

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     VulnGuard Agent                          │
├─────────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Scanner    │  │   Engine     │  │   Advisor    │      │
│  │  (Audit)     │──▶│ (Evaluate)  │──▶│  (AI Assist) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                 │                 │                 │
│         │                 │                 ▼                 │
│         │                 │          ┌──────────────┐      │
│         │                 │          │   Remediation │      │
│         │                 │          │  (Fix)       │      │
│         │                 │          └──────────────┘      │
│         │                 │                 │                 │
│         └─────────────────┴─────────────────┘                 │
│                           │                                 │
│                           ▼                                 │
│                    ┌──────────────┐                         │
│                    │   Logger     │                         │
│                    │  (Audit)     │                         │
│                    └──────────────┘                         │
│                                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Layered Architecture

VulnGuard follows a layered architecture pattern:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│                    (CLI Interface)                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Orchestration Layer                      │
│                  (VulnGuardOrchestrator)                  │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Scanner    │  │   Engine     │  │   Advisor    │
│  (Audit)     │  │ (Evaluate)  │  │ (AI Assist)  │
└──────────────┘  └──────────────┘  └──────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                   ┌──────────────┐
                   │ Remediation  │
                   │   (Fix)     │
                   └──────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Infrastructure Layer                      │
│                     (Audit Logger)                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Scanner Module ([`vulnguard/pkg/scanner/scanner.py`](vulnguard/pkg/scanner/scanner.py))

**Purpose**: Deterministic audit engine for security compliance checks

**Responsibilities**:
- Load and validate benchmark rule configurations
- Execute defined check commands
- Validate results against expected states
- Determine compliance status
- OS compatibility checking

**Key Classes**:
- [`Scanner`](vulnguard/pkg/scanner/scanner.py:65): Main scanner class
- [`ScanResult`](vulnguard/pkg/scanner/scanner.py:17): Scan result data structure

**Supported Check Types**:
- **Command**: Execute shell commands and check exit codes
- **File**: Validate file content, permissions, and ownership
- **Service**: Check service status (enabled/active)
- **Sysctl**: Verify kernel parameter values

**Design Decisions**:
- No AI integration in scanner - all checks are deterministic
- Strict rule validation before execution
- OS compatibility filtering
- Timeout protection for all commands

### 2. Engine Module ([`vulnguard/pkg/engine/engine.py`](vulnguard/pkg/engine/engine.py))

**Purpose**: Compliance and risk decision engine

**Responsibilities**:
- Normalize severities across benchmark standards
- Determine risk levels based on severity and compliance
- Decide if AI assistance is required
- Determine approval requirements
- Generate compliance summaries

**Key Classes**:
- [`ComplianceEngine`](vulnguard/pkg/engine/engine.py:65): Main evaluation engine
- [`EvaluationResult`](vulnguard/pkg/engine/engine.py:13): Evaluation result data structure

**Severity Normalization**:

| Benchmark | Original | Normalized |
|-----------|-----------|------------|
| CIS | Level 1 | high |
| CIS | Level 2 | medium |
| CIS | Level 3 | low |
| STIG | CAT I | critical |
| STIG | CAT II | high |
| STIG | CAT III | medium |

**Risk Level Determination**:
- Compliant rules → low risk
- Non-compliant rules → mapped from normalized severity

**Design Decisions**:
- Centralized severity mapping for consistency
- Risk level based on both severity and compliance status
- AI assist only for ambiguous cases
- Approval gating for high-risk rules

### 3. Advisor Module ([`vulnguard/pkg/advisor/advisor.py`](vulnguard/pkg/advisor/advisor.py))

**Purpose**: AI gateway and safety validator

**Responsibilities**:
- Provide AI assistance for ambiguous findings
- Validate all AI output against safety controls
- Enforce confidence thresholds
- Validate commands against allow-list/block-list
- Never execute commands directly

**Key Classes**:
- [`AIAdvisor`](vulnguard/pkg/advisor/advisor.py:76): AI advisor with safety validation
- [`AIAdvisory`](vulnguard/pkg/advisor/advisor.py:16): AI advisory data structure

**Safety Validation**:
- JSON schema validation
- Required field verification
- Confidence threshold checking (default: 0.7)
- Command allow-list validation
- Command block-list validation
- Data type validation

**Design Decisions**:
- AI is advisory only, never executes directly
- All output must pass strict validation
- Confidence threshold prevents low-quality recommendations
- Command allow-list/block-list prevents dangerous operations
- Manual review required for low-confidence advisories

### 4. Remediation Module ([`vulnguard/pkg/remediation/remediation.py`](vulnguard/pkg/remediation/remediation.py))

**Purpose**: Reversible remediation engine with safety controls

**Responsibilities**:
- Apply security fixes with automatic backup
- Execute remediation commands in dry-run or commit mode
- Automatic rollback on failure
- Validate all commands against allow-list/block-list
- Maintain audit trail of all changes

**Key Classes**:
- [`RemediationEngine`](vulnguard/pkg/remediation/remediation.py:73): Remediation engine with safety controls
- [`RemediationResult`](vulnguard/pkg/remediation/remediation.py:21): Remediation result data structure

**Safety Features**:
- **Automatic Backup**: Backs up files before modification
- **Dry-Run Mode**: Default mode shows what would be done without executing
- **Rollback on Failure**: Automatically reverts changes on failure
- **Command Validation**: All commands validated against allow-list/block-list
- **Approval Gating**: Requires approval for high-risk changes

**Design Decisions**:
- Every remediation is reversible
- Dry-run by default for safety
- Automatic backup before any changes
- Rollback on failure prevents partial states
- Strict command validation

### 5. Logging Module ([`vulnguard/pkg/logging/logger.py`](vulnguard/pkg/logging/logger.py))

**Purpose**: Structured audit logger for all operations

**Responsibilities**:
- Log all operations in JSON-line format
- Provide structured, parseable audit trail
- Support log rotation
- Multiple output formats (JSON, text)

**Key Classes**:
- [`AuditLogger`](vulnguard/pkg/logging/logger.py:17): Structured audit logger

**Log Event Types**:
- `scan_start`: Beginning of a compliance scan
- `scan_result`: Result of a compliance check
- `evaluation`: Compliance evaluation and risk level
- `ai_advisory`: AI recommendation output
- `remediation_start`: Beginning of remediation
- `remediation_result`: Result of remediation
- `rollback`: Rollback execution
- `backup`: Configuration backup
- `approval_request`: Approval requirement
- `error`: Error events
- `system_info`: System information at scan start

**Design Decisions**:
- JSON-line format for easy parsing
- Structured data with consistent schema
- Log rotation to prevent disk space issues
- Both file and console output
- Complete context in every log entry

### 6. Main Orchestrator ([`vulnguard/main.py`](vulnguard/main.py))

**Purpose**: Main orchestrator for VulnGuard operations

**Responsibilities**:
- Coordinate all components
- Manage configuration
- Provide CLI interface
- Generate compliance reports

**Key Classes**:
- [`VulnGuardOrchestrator`](vulnguard/main.py:25): Main orchestrator class

**Design Decisions**:
- Centralized coordination of all components
- Configuration-driven behavior
- Clean separation of concerns
- Comprehensive error handling
- Multiple output formats

---

## Data Flow

### Scan Workflow

```
User Request
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  VulnGuardOrchestrator.run_scan()                        │
└─────────────────────────────────────────────────────────────┘
    │
    ├──▶ Log System Info
    │
    ├──▶ Scanner.scan_all()
    │       │
    │       ├──▶ Load Rule Files
    │       │
    │       ├──▶ Check OS Compatibility
    │       │
    │       └──▶ Execute Checks
    │               │
    │               ├──▶ Command Checks
    │               ├──▶ File Checks
    │               ├──▶ Service Checks
    │               └──▶ Sysctl Checks
    │
    ├──▶ Engine.evaluate_batch()
    │       │
    │       ├──▶ Normalize Severity
    │       │
    │       ├──▶ Determine Risk Level
    │       │
    │       ├──▶ Check AI Assist Required
    │       │
    │       └──▶ Check Approval Required
    │
    └──▶ Advisor.get_advisory() [if needed]
            │
            ├──▶ Get AI Response
            │
            ├──▶ Validate JSON Schema
            │
            ├──▶ Validate Commands
            │
            └──▶ Check Confidence Threshold
```

### Remediation Workflow

```
User Request
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  VulnGuardOrchestrator.run_remediation()                 │
└─────────────────────────────────────────────────────────────┘
    │
    ├──▶ Check if Compliant (skip if yes)
    │
    ├──▶ Check Approval Required
    │       │
    │       └──▶ Log Approval Request [if needed]
    │
    ├──▶ Load Rule Data
    │
    ├──▶ Determine Commands
    │       │
    │       ├──▶ Use AI Advisory [if available]
    │       │
    │       └──▶ Use Rule Remediation [if no AI]
    │
    ├──▶ Validate Commands
    │       │
    │       ├──▶ Check Block-List
    │       │
    │       └──▶ Check Allow-List
    │
    ├──▶ Backup Files [if auto_backup enabled]
    │
    ├──▶ Execute Commands
    │       │
    │       ├──▶ Dry-Run Mode [if mode=dry-run]
    │       │
    │       └──▶ Commit Mode [if mode=commit]
    │
    ├──▶ Check Success
    │       │
    │       ├──▶ Success → Log Result
    │       │
    │       └──▶ Failure → Rollback [if rollback_on_failure]
    │               │
    │               └──▶ Log Rollback
    │
    └──▶ Return RemediationResult
```

---

## Security Architecture

### Security Principles

1. **Least Privilege**: Only necessary permissions are used
2. **Defense in Depth**: Multiple layers of security controls
3. **Fail-Safe**: System fails securely on errors
4. **Audit Trail**: Complete logging of all actions
5. **Reversibility**: All changes can be undone

### Security Controls

#### 1. Command Validation

**Allow-List**:
- Only commands matching allow-list patterns can be executed
- Regex-based pattern matching
- Configurable per deployment

**Block-List**:
- Dangerous commands are explicitly blocked
- Regex-based pattern matching
- Prevents accidental execution of harmful commands

**Default Allow-List Patterns**:
```python
r'^systemctl\s+(enable|disable|start|stop|restart|status)\s+[a-zA-Z0-9_-]+$'
r'^sysctl\s+-w\s+[a-zA-Z0-9._-]+=.+$'
r'^chmod\s+[0-7]{3,4}\s+[a-zA-Z0-9_./-]+$'
r'^chown\s+[a-zA-Z0-9_:.-]+\s+[a-zA-Z0-9_./-]+$'
r'^sed\s+-i\s+.+\s+[a-zA-Z0-9_./-]+$'
r'^echo\s+.+\s*>>?\s*[a-zA-Z0-9_./-]+$'
```

**Default Block-List Patterns**:
```python
r'rm\s+-rf'
r'chmod\s+777'
r'userdel'
r'groupdel'
r'passwd\s+-l\s+root'
r'setenforce\s+0'
```

#### 2. Approval Gating

Rules requiring approval:
- STIG CAT I and CAT II rules
- Critical severity rules
- Rules with `approval_required: true`

#### 3. AI Safety

- AI never executes commands directly
- All AI output is validated
- Confidence threshold enforcement
- Manual review for low-confidence recommendations

#### 4. Backup and Rollback

- Automatic backup before changes
- Rollback commands for each action
- Automatic rollback on failure
- Backup retention policy

#### 5. Audit Logging

- Complete audit trail of all actions
- JSON-line format for easy parsing
- Log rotation to prevent disk space issues
- Both file and console output

---

## Safety Controls

### 1. Dry-Run Mode (Default)

All remediation operations default to dry-run mode:
- Shows what would be done without executing
- Allows review before committing
- Prevents accidental changes

### 2. Automatic Backup

Before any remediation:
- Files are backed up to timestamped directory
- Backup path is logged
- Multiple backup versions retained

### 3. Rollback on Failure

If remediation fails:
- Automatic rollback is triggered
- Rollback commands are executed
- Rollback is logged
- System is returned to previous state

### 4. Approval Gating

High-risk changes require approval:
- Manual review before execution
- Explicit approval flag required
- Approval requests are logged

### 5. Command Validation

All commands are validated:
- Checked against block-list first
- Then checked against allow-list
- Invalid commands are rejected
- Validation failures are logged

### 6. Confidence Threshold

AI recommendations below threshold:
- Require manual review
- Are not automatically applied
- Low confidence is logged

### 7. OS Compatibility

Rules are filtered by OS:
- Only compatible rules are executed
- OS is detected automatically
- Incompatible rules are skipped

---

## Extensibility

### Adding New Benchmark Rules

Create a new YAML file in [`vulnguard/configs/benchmarks/`](vulnguard/configs/benchmarks/):

```yaml
benchmark: CIS
id: "1.2.3"
title: "Example rule title"
rationale: "Explanation of why this rule is important"
severity: medium
original_severity: Level2
os_compatibility:
  - ubuntu
  - rhel

check:
  type: command
  command: "example command"
  expected_state: "expected value"

remediation:
  commands:
    - "remediation command 1"
    - "remediation command 2"
  requires_restart: false
  requires_reboot: false

rollback:
  commands:
    - "rollback command 1"
    - "rollback command 2"

ai_assist: false
approval_required: false
exception_allowed: true
```

### Adding New Check Types

Extend the [`Scanner`](vulnguard/pkg/scanner/scanner.py:65) class with new check methods:

```python
def _check_custom(self, check_config: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Execute a custom check.
    
    Args:
        check_config: Check configuration dictionary
        
    Returns:
        Tuple of (compliant, actual_state, output)
    """
    # Implement custom check logic
    pass
```

### Custom Severity Mapping

Configure custom severity mapping in [`vulnguard/configs/agent/config.yaml`](vulnguard/configs/agent/config.yaml):

```yaml
severity_mapping:
  CIS:
    Level1: "critical"
    Level2: "high"
    Level3: "medium"
  STIG:
    CAT_I: "critical"
    CAT_II: "high"
    CAT_III: "medium"
  CUSTOM:
    HIGH: "critical"
    MEDIUM: "high"
    LOW: "medium"
```

### Custom Command Allow-List/Block-List

Configure custom command lists in [`vulnguard/configs/agent/config.yaml`](vulnguard/configs/agent/config.yaml):

```yaml
command_allowlist:
  - "^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$"
  - "^custom_command\\s+.+$"

command_blocklist:
  - "rm\\s+-rf"
  - "dangerous_command"
```

---

## Performance Considerations

### 1. Parallel Scanning

Currently, scanning is sequential. Future enhancements could include:
- Parallel execution of independent checks
- Thread pool for concurrent operations
- Result aggregation

### 2. Caching

Potential caching strategies:
- Rule file caching
- OS detection caching
- Command result caching (with TTL)

### 3. Log Rotation

Current implementation:
- RotatingFileHandler with configurable size
- Configurable backup count
- Prevents disk space exhaustion

### 4. Command Timeout

Current implementation:
- 30 second timeout for scan commands
- 60 second timeout for remediation commands
- Prevents hanging operations

### 5. Memory Usage

Considerations:
- Large rule sets may require significant memory
- Batch processing for large numbers of rules
- Streaming for large log files

---

## Deployment Architecture

### Standalone Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                      Linux Server                         │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              VulnGuard Agent                         │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │
│  │  │ Scanner │ │ Engine  │ │Advisor  │ │Remediate│ │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ │ │
│  └───────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              Configuration Files                     │ │
│  └───────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              Audit Logs                             │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Distributed Deployment (Future)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Server 1   │     │   Server 2   │     │   Server N   │
│  VulnGuard   │     │  VulnGuard   │     │  VulnGuard   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Central Log    │
                    │  Aggregator    │
                    └────────────────┘
```

---

## Monitoring and Observability

### Log Analysis

All logs are in JSON-line format for easy parsing:

```bash
# Parse logs with jq
cat /var/log/vulnguard/audit.log | jq '.event_type'

# Count events by type
cat /var/log/vulnguard/audit.log | jq -r '.event_type' | sort | uniq -c

# Find failed remediations
cat /var/log/vulnguard/audit.log | jq 'select(.event_type == "remediation_result" and .data.success == false)'
```

### Metrics to Monitor

- **Scan Duration**: Time to complete scans
- **Remediation Success Rate**: Percentage of successful remediations
- **Rollback Rate**: Frequency of rollback executions
- **AI Confidence Distribution**: Distribution of AI confidence scores
- **Approval Request Rate**: Frequency of approval requirements
- **Error Rate**: Frequency of errors

### Alerts

Consider alerting on:
- High error rates
- Frequent rollbacks
- Low AI confidence scores
- Critical severity findings
- Failed remediations

---

## Future Enhancements

### Planned Features

1. **Parallel Scanning**: Execute multiple checks concurrently
2. **Scheduled Scans**: Run scans on a schedule
3. **Notification System**: Send alerts on findings
4. **Dashboard**: Web-based monitoring interface
5. **API Server**: RESTful API for integration
6. **Custom Benchmark Support**: User-defined benchmarks
7. **Exception Management**: Track and manage exceptions
8. **Compliance Reporting**: Generate compliance reports
9. **Integration Hooks**: Integrate with other security tools
10. **Policy Enforcement**: Enforce compliance policies

### Technical Debt

1. **AI Integration**: Currently simulated, needs real AI service
2. **Error Recovery**: More sophisticated error handling
3. **Testing**: Comprehensive test suite needed
4. **Documentation**: Additional documentation for contributors
5. **Performance**: Optimization for large rule sets

---

## Contributing

When contributing to VulnGuard:

1. Follow the design philosophy
2. Maintain safety-first approach
3. Add comprehensive logging
4. Include rollback mechanisms
5. Update documentation
6. Add tests for new features
7. Follow code style guidelines

---

## License

[Specify your license here]
