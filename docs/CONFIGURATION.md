# VulnGuard Configuration Guide

This document provides detailed information about configuring the VulnGuard Linux Security Compliance Agent.

## Table of Contents

- [Overview](#overview)
- [Configuration File](#configuration-file)
- [Configuration Sections](#configuration-sections)
- [Benchmark Rules](#benchmark-rules)
- [Environment Variables](#environment-variables)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

VulnGuard uses a hierarchical configuration system:

1. **Main Configuration**: [`vulnguard/configs/agent/config.yaml`](vulnguard/configs/agent/config.yaml) - Global agent settings
2. **Benchmark Rules**: [`vulnguard/configs/benchmarks/*.yaml`](vulnguard/configs/benchmarks/) - Individual rule configurations
3. **Environment Variables**: Optional override of configuration values

All configuration files use YAML format for readability and maintainability.

---

## Configuration File

### Location

The main configuration file is located at:

```
vulnguard/configs/agent/config.yaml
```

### Configuration Structure

```yaml
agent:
  name: "VulnGuard"
  version: "1.0.0"
  mode: "dry-run"

logging:
  level: "INFO"
  format: "json"
  file_path: "/var/log/vulnguard/audit.log"
  max_size_mb: 100
  backup_count: 10

benchmarks:
  directory: "configs/benchmarks"
  supported_types:
    - "CIS"
    - "STIG"
  default_benchmark: "CIS"

severity_mapping:
  CIS:
    Level1: "high"
    Level2: "medium"
    Level3: "low"
  STIG:
    CAT_I: "critical"
    CAT_II: "high"
    CAT_III: "medium"

remediation:
  default_mode: "dry-run"
  auto_backup: true
  backup_directory: "/var/lib/vulnguard/backups"
  rollback_on_failure: true
  max_retries: 3

command_allowlist:
  - "^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$"
  - "^sysctl\\s+-w\\s+[a-zA-Z0-9._-]+=.+$"
  - "^chmod\\s+[0-7]{3,4}\\s+[a-zA-Z0-9_./-]+$"
  - "^chown\\s+[a-zA-Z0-9_:.-]+\\s+[a-zA-Z0-9_./-]+$"
  - "^sed\\s+-i\\s+.+\\s+[a-zA-Z0-9_./-]+$"
  - "^echo\\s+.+\\s*>>?\\s*[a-zA-Z0-9_./-]+$"

command_blocklist:
  - "rm\\s+-rf"
  - "chmod\\s+777"
  - "userdel"
  - "groupdel"
  - "passwd\\s+-l\\s+root"
  - "setenforce\\s+0"

ai:
  enabled: true
  min_confidence_threshold: 0.7
  require_approval_for:
    - "CAT_I"
    - "CAT_II"
    - "critical"
  max_retries: 2
  timeout_seconds: 30

approval:
  required_for_stig: true
  required_for_critical: true
  required_for_high: false
  approval_method: "manual"

os:
  supported:
    - "rhel"
    - "ubuntu"
    - "centos"
    - "debian"
  min_versions:
    rhel: "8"
    ubuntu: "20.04"
    centos: "8"
    debian: "10"

output:
  format: "json"
  include_timestamp: true
  include_system_info: true
  include_remediation_commands: true
```

---

## Configuration Sections

### Agent Configuration

Controls basic agent behavior.

```yaml
agent:
  name: "VulnGuard"              # Agent name
  version: "1.0.0"             # Agent version
  mode: "dry-run"                # Default mode: dry-run or commit
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `name` | string | `"VulnGuard"` | Agent name for logging and identification |
| `version` | string | `"1.0.0"` | Agent version |
| `mode` | string | `"dry-run"` | Default operational mode |

**Mode Options:**

- **`dry-run`**: Show what would be done without executing (recommended for testing)
- **`commit`**: Execute remediation commands (use with caution)

**Recommendation:** Always start with `dry-run` mode and review output before switching to `commit`.

---

### Logging Configuration

Controls logging behavior and output.

```yaml
logging:
  level: "INFO"                  # Log level
  format: "json"                 # Log format
  file_path: "/var/log/vulnguard/audit.log"  # Log file path
  max_size_mb: 100               # Maximum log file size in MB
  backup_count: 10               # Number of backup files to keep
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `level` | string | `"INFO"` | Logging level |
| `format` | string | `"json"` | Log format |
| `file_path` | string | `"/var/log/vulnguard/audit.log"` | Path to log file |
| `max_size_mb` | integer | `100` | Maximum log file size before rotation |
| `backup_count` | integer | `10` | Number of backup files to retain |

**Log Level Options:**

- **`DEBUG`**: Detailed diagnostic information
- **`INFO`**: General informational messages (default)
- **`WARNING`**: Warning messages
- **`ERROR`**: Error messages
- **`CRITICAL`**: Critical error messages

**Log Format Options:**

- **`json`**: Structured JSON-line format (recommended for parsing)
- **`text`**: Human-readable text format

**Recommendation:** Use `json` format for production environments to enable easy log parsing and analysis.

---

### Benchmark Configuration

Controls benchmark rule loading and execution.

```yaml
benchmarks:
  directory: "configs/benchmarks"  # Directory containing benchmark rules
  supported_types:
    - "CIS"                       # CIS Benchmarks
    - "STIG"                      # DISA STIG Benchmarks
  default_benchmark: "CIS"         # Default benchmark type
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `directory` | string | `"configs/benchmarks"` | Path to benchmark rule files |
| `supported_types` | list | `["CIS", "STIG"]` | Supported benchmark types |
| `default_benchmark` | string | `"CIS"` | Default benchmark type |

**Supported Benchmark Types:**

- **`CIS`**: Center for Internet Security Benchmarks
- **`STIG`**: DISA Security Technical Implementation Guides

---

### Severity Mapping

Controls how benchmark-specific severities are normalized.

```yaml
severity_mapping:
  CIS:
    Level1: "high"                 # CIS Level 1 → high
    Level2: "medium"               # CIS Level 2 → medium
    Level3: "low"                  # CIS Level 3 → low
  STIG:
    CAT_I: "critical"              # STIG CAT I → critical
    CAT_II: "high"                # STIG CAT II → high
    CAT_III: "medium"              # STIG CAT III → medium
```

**Normalized Severity Levels:**

- **`critical`**: Highest severity, immediate action required
- **`high`**: High severity, action required within 24 hours
- **`medium`**: Medium severity, action required within 7 days
- **`low`**: Low severity, action required within 30 days

**Custom Severity Mapping:**

You can add custom severity mappings for custom benchmarks:

```yaml
severity_mapping:
  CIS:
    Level1: "critical"             # Override default mapping
    Level2: "high"
    Level3: "medium"
  STIG:
    CAT_I: "critical"
    CAT_II: "high"
    CAT_III: "medium"
  CUSTOM:
    HIGH: "critical"               # Custom benchmark
    MEDIUM: "high"
    LOW: "medium"
```

---

### Remediation Configuration

Controls remediation behavior and safety features.

```yaml
remediation:
  default_mode: "dry-run"          # Default remediation mode
  auto_backup: true               # Automatic backup before remediation
  backup_directory: "/var/lib/vulnguard/backups"  # Backup directory
  rollback_on_failure: true        # Automatic rollback on failure
  max_retries: 3                 # Maximum retry attempts
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `default_mode` | string | `"dry-run"` | Default remediation mode |
| `auto_backup` | boolean | `true` | Automatically backup before changes |
| `backup_directory` | string | `"/var/lib/vulnguard/backups"` | Directory for backups |
| `rollback_on_failure` | boolean | `true` | Automatically rollback on failure |
| `max_retries` | integer | `3` | Maximum retry attempts |

**Remediation Mode Options:**

- **`dry-run`**: Show what would be done without executing (recommended)
- **`commit`**: Execute remediation commands

**Recommendation:** Keep `auto_backup` and `rollback_on_failure` enabled for production environments.

---

### Command Allow-List

Controls which commands are allowed for execution.

```yaml
command_allowlist:
  - "^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$"
  - "^sysctl\\s+-w\\s+[a-zA-Z0-9._-]+=.+$"
  - "^chmod\\s+[0-7]{3,4}\\s+[a-zA-Z0-9_./-]+$"
  - "^chown\\s+[a-zA-Z0-9_:.-]+\\s+[a-zA-Z0-9_./-]+$"
  - "^sed\\s+-i\\s+.+\\s+[a-zA-Z0-9_./-]+$"
  - "^echo\\s+.+\\s*>>?\\s*[a-zA-Z0-9_./-]+$"
```

**How It Works:**

1. Commands are validated against allow-list patterns using regex matching
2. Only commands matching at least one pattern are allowed
3. Commands are first checked against block-list, then allow-list

**Default Allow-List Patterns:**

| Pattern | Description |
|---------|-------------|
| `^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$` | Service management commands |
| `^sysctl\\s+-w\\s+[a-zA-Z0-9._-]+=.+$` | Kernel parameter commands |
| `^chmod\\s+[0-7]{3,4}\\s+[a-zA-Z0-9_./-]+$` | Permission change commands |
| `^chown\\s+[a-zA-Z0-9_:.-]+\\s+[a-zA-Z0-9_./-]+$` | Ownership change commands |
| `^sed\\s+-i\\s+.+\\s+[a-zA-Z0-9_./-]+$` | File editing commands |
| `^echo\\s+.+\\s*>>?\\s*[a-zA-Z0-9_./-]+$` | File append commands |

**Adding Custom Patterns:**

```yaml
command_allowlist:
  - "^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$"
  - "^custom_command\\s+[a-zA-Z0-9_]+$"  # Add custom pattern
```

**Recommendation:** Be conservative with allow-list patterns. Only add patterns for commands you understand and trust.

---

### Command Block-List

Controls which commands are explicitly blocked.

```yaml
command_blocklist:
  - "rm\\s+-rf"                   # Block recursive delete
  - "chmod\\s+777"                # Block world-writable permissions
  - "userdel"                      # Block user deletion
  - "groupdel"                     # Block group deletion
  - "passwd\\s+-l\\s+root"        # Block root account lock
  - "setenforce\\s+0"              # Block SELinux disable
```

**How It Works:**

1. Commands are first checked against block-list patterns
2. Commands matching any block-list pattern are immediately rejected
3. Block-list takes precedence over allow-list

**Default Block-List Patterns:**

| Pattern | Reason |
|---------|--------|
| `rm\\s+-rf` | Prevents accidental recursive deletion |
| `chmod\\s+777` | Prevents world-writable permissions |
| `userdel` | Prevents accidental user deletion |
| `groupdel` | Prevents accidental group deletion |
| `passwd\\s+-l\\s+root` | Prevents root account lock |
| `setenforce\\s+0` | Prevents SELinux disable |

**Adding Custom Patterns:**

```yaml
command_blocklist:
  - "rm\\s+-rf"
  - "chmod\\s+777"
  - "dangerous_command\\s+.+"  # Add custom pattern
```

**Recommendation:** Add patterns for any commands that could cause significant damage or security issues.

---

### AI Configuration

Controls AI advisory behavior and safety settings.

```yaml
ai:
  enabled: true                    # Enable AI advisory
  min_confidence_threshold: 0.7    # Minimum confidence threshold
  require_approval_for:
    - "CAT_I"                     # Require approval for STIG CAT I
    - "CAT_II"                    # Require approval for STIG CAT II
    - "critical"                   # Require approval for critical severity
  max_retries: 2                 # Maximum retry attempts
  timeout_seconds: 30              # AI request timeout
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable AI advisory functionality |
| `min_confidence_threshold` | float | `0.7` | Minimum confidence threshold (0.0 - 1.0) |
| `require_approval_for` | list | `["CAT_I", "CAT_II", "critical"]` | Severities requiring approval |
| `max_retries` | integer | `2` | Maximum retry attempts for AI requests |
| `timeout_seconds` | integer | `30` | AI request timeout in seconds |

**Confidence Threshold:**

- **Range**: 0.0 to 1.0
- **Default**: 0.7 (70% confidence)
- **Effect**: AI recommendations below this threshold require manual review

**Adjusting Confidence Threshold:**

```yaml
ai:
  enabled: true
  min_confidence_threshold: 0.9    # More conservative (90%)
  # OR
  min_confidence_threshold: 0.5    # Less conservative (50%)
```

**Recommendation:** Use higher thresholds (0.8-0.9) for production environments and lower thresholds (0.6-0.7) for testing.

---

### Approval Configuration

Controls approval gating for remediation.

```yaml
approval:
  required_for_stig: true          # Require approval for STIG rules
  required_for_critical: true       # Require approval for critical severity
  required_for_high: false         # Require approval for high severity
  approval_method: "manual"        # Approval method
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `required_for_stig` | boolean | `true` | Require approval for all STIG rules |
| `required_for_critical` | boolean | `true` | Require approval for critical severity |
| `required_for_high` | boolean | `false` | Require approval for high severity |
| `approval_method` | string | `"manual"` | Approval method |

**Approval Method Options:**

- **`manual`**: Requires manual approval before remediation
- **`auto`**: Automatic approval (use with caution)

**Recommendation:** Keep `manual` approval for production environments to ensure human review of high-risk changes.

---

### OS Configuration

Controls OS compatibility and version requirements.

```yaml
os:
  supported:
    - "rhel"                      # Red Hat Enterprise Linux
    - "ubuntu"                     # Ubuntu
    - "centos"                     # CentOS
    - "debian"                     # Debian
  min_versions:
    rhel: "8"                     # Minimum RHEL version
    ubuntu: "20.04"                # Minimum Ubuntu version
    centos: "8"                    # Minimum CentOS version
    debian: "10"                   # Minimum Debian version
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `supported` | list | `["rhel", "ubuntu", "centos", "debian"]` | Supported OS types |
| `min_versions` | object | See default | Minimum versions for each OS |

**Supported OS Types:**

- **`rhel`**: Red Hat Enterprise Linux
- **`ubuntu`**: Ubuntu
- **`centos`**: CentOS
- **`debian`**: Debian

**Adding Custom OS Support:**

```yaml
os:
  supported:
    - "rhel"
    - "ubuntu"
    - "centos"
    - "debian"
    - "fedora"                    # Add custom OS
  min_versions:
    rhel: "8"
    ubuntu: "20.04"
    centos: "8"
    debian: "10"
    fedora: "35"                  # Minimum Fedora version
```

---

### Output Configuration

Controls report output format and content.

```yaml
output:
  format: "json"                  # Output format
  include_timestamp: true          # Include timestamp in reports
  include_system_info: true        # Include system information
  include_remediation_commands: true  # Include remediation commands
```

**Options:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `format` | string | `"json"` | Output format |
| `include_timestamp` | boolean | `true` | Include timestamp in reports |
| `include_system_info` | boolean | `true` | Include system information |
| `include_remediation_commands` | boolean | `true` | Include remediation commands |

**Output Format Options:**

- **`json`**: JSON format (machine-readable)
- **`yaml`**: YAML format (human-readable)
- **`text`**: Plain text format (human-readable)

**Recommendation:** Use `json` format for automated processing and `text` format for human review.

---

## Benchmark Rules

Benchmark rules are defined as YAML files in [`vulnguard/configs/benchmarks/`](vulnguard/configs/benchmarks/).

### Rule File Structure

```yaml
benchmark: CIS                    # Benchmark type (CIS or STIG)
id: "1.1.1"                    # Rule identifier
title: "Ensure mounting of cramfs filesystems is disabled"  # Rule title
rationale: "The cramfs filesystem type is a compressed read-only Linux filesystem..."  # Explanation
severity: medium                  # Normalized severity
original_severity: Level2         # Original severity from benchmark
os_compatibility:
  - ubuntu                       # Supported OS types
  - debian

check:
  type: command                  # Check type (command, file, service, sysctl)
  command: "modprobe -n -v cramfs"  # Check command
  expected_state: "not found"     # Expected state

remediation:
  commands:
    - "echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf"
  requires_restart: false         # Service restart required
  requires_reboot: false         # System reboot required

rollback:
  commands:
    - "sed -i '/^install cramfs/d' /etc/modprobe.d/cramfs.conf"

ai_assist: false                # AI assistance required
approval_required: false        # Approval required for remediation
exception_allowed: true        # Exception allowed for this rule
```

### Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `benchmark` | string | Yes | Benchmark type (CIS or STIG) |
| `id` | string | Yes | Rule identifier |
| `title` | string | Yes | Rule title |
| `rationale` | string | Yes | Explanation of why the rule is important |
| `severity` | string | Yes | Normalized severity (critical, high, medium, low) |
| `original_severity` | string | Yes | Original severity from benchmark |
| `os_compatibility` | list | Yes | Supported OS types |
| `check` | object | Yes | Check configuration |
| `remediation` | object | Yes | Remediation configuration |
| `rollback` | object | Yes | Rollback configuration |
| `ai_assist` | boolean | No | AI assistance required (default: false) |
| `approval_required` | boolean | No | Approval required (default: false) |
| `exception_allowed` | boolean | No | Exception allowed (default: false) |

### Check Types

#### Command Check

```yaml
check:
  type: command
  command: "modprobe -n -v cramfs"
  expected_state: "not found"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Check type: "command" |
| `command` | string | Yes | Command to execute |
| `expected_state` | string | Yes | Expected state or output |

**Expected State Values:**

- **`true`**, **`enabled`**, **`active`**, **`running`**: Command should succeed (exit code 0)
- **`false`**, **`disabled`**, **`inactive`**, **`stopped`**: Command should fail (exit code != 0)
- **Other values**: Exact match required

#### File Check

```yaml
check:
  type: file
  path: /etc/ssh/sshd_config
  expected_content: "PermitEmptyPasswords no"
  expected_permissions: "600"
  expected_owner: "root"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Check type: "file" |
| `path` | string | Yes | File path to check |
| `expected_content` | string | No | Expected content in file |
| `expected_permissions` | string | No | Expected file permissions |
| `expected_owner` | string | No | Expected file owner |

#### Service Check

```yaml
check:
  type: service
  service_name: "sshd"
  expected_state: "enabled"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Check type: "service" |
| `service_name` | string | Yes | Service name to check |
| `expected_state` | string | Yes | Expected state (enabled, disabled, active, inactive) |

#### Sysctl Check

```yaml
check:
  type: sysctl
  key: "net.ipv4.ip_forward"
  expected_value: "0"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Check type: "sysctl" |
| `key` | string | Yes | Sysctl key to check |
| `expected_value` | string | Yes | Expected value |

### Remediation Configuration

```yaml
remediation:
  commands:
    - "echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf"
  requires_restart: false
  requires_reboot: false
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `commands` | list | Yes | List of remediation commands |
| `requires_restart` | boolean | No | Service restart required (default: false) |
| `requires_reboot` | boolean | No | System reboot required (default: false) |

### Rollback Configuration

```yaml
rollback:
  commands:
    - "sed -i '/^install cramfs/d' /etc/modprobe.d/cramfs.conf"
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `commands` | list | Yes | List of rollback commands |

---

## Environment Variables

Configuration values can be overridden using environment variables.

### Naming Convention

Environment variables use the following naming convention:

```
VULNGUARD_<SECTION>_<KEY>
```

For example:
- `VULNGUARD_AGENT_MODE`
- `VULNGUARD_LOGGING_LEVEL`
- `VULNGUARD_AI_MIN_CONFIDENCE_THRESHOLD`

### Supported Environment Variables

| Environment Variable | Configuration Path | Description |
|--------------------|-------------------|-------------|
| `VULNGUARD_AGENT_MODE` | `agent.mode` | Default agent mode |
| `VULNGUARD_LOGGING_LEVEL` | `logging.level` | Log level |
| `VULNGUARD_LOGGING_FORMAT` | `logging.format` | Log format |
| `VULNGUARD_LOGGING_FILE_PATH` | `logging.file_path` | Log file path |
| `VULNGUARD_REMEDIATION_DEFAULT_MODE` | `remediation.default_mode` | Default remediation mode |
| `VULNGUARD_REMEDIATION_AUTO_BACKUP` | `remediation.auto_backup` | Automatic backup |
| `VULNGUARD_REMEDIATION_ROLLBACK_ON_FAILURE` | `remediation.rollback_on_failure` | Rollback on failure |
| `VULNGUARD_AI_ENABLED` | `ai.enabled` | Enable AI advisory |
| `VULNGUARD_AI_MIN_CONFIDENCE_THRESHOLD` | `ai.min_confidence_threshold` | Minimum confidence threshold |

### Example Usage

```bash
# Set agent mode to commit
export VULNGUARD_AGENT_MODE=commit

# Set log level to DEBUG
export VULNGUARD_LOGGING_LEVEL=DEBUG

# Set AI confidence threshold to 0.9
export VULNGUARD_AI_MIN_CONFIDENCE_THRESHOLD=0.9

# Run VulnGuard
python -m vulnguard.main scan
```

---

## Best Practices

### 1. Start with Dry-Run Mode

Always start with dry-run mode to review proposed changes:

```yaml
agent:
  mode: "dry-run"
```

### 2. Enable Automatic Backup and Rollback

Keep automatic backup and rollback enabled:

```yaml
remediation:
  auto_backup: true
  rollback_on_failure: true
```

### 3. Use Conservative AI Confidence Threshold

Use higher confidence thresholds for production:

```yaml
ai:
  min_confidence_threshold: 0.9
```

### 4. Require Manual Approval

Keep manual approval for high-risk changes:

```yaml
approval:
  required_for_stig: true
  required_for_critical: true
  approval_method: "manual"
```

### 5. Use JSON Log Format

Use JSON format for easy parsing and analysis:

```yaml
logging:
  format: "json"
```

### 6. Implement Log Rotation

Configure log rotation to prevent disk space issues:

```yaml
logging:
  max_size_mb: 100
  backup_count: 10
```

### 7. Regularly Review Command Lists

Regularly review and update command allow-list and block-list:

```yaml
command_allowlist:
  - "^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$"
  # Add new patterns as needed

command_blocklist:
  - "rm\\s+-rf"
  # Add new dangerous patterns as needed
```

### 8. Test Configuration Changes

Always test configuration changes in a non-production environment:

```bash
# Test with dry-run mode
python -m vulnguard.main remediate --mode dry-run

# Review output before committing
python -m vulnguard.main remediate --mode commit
```

### 9. Monitor Logs Regularly

Regularly monitor logs for errors and issues:

```bash
# View recent logs
tail -f /var/log/vulnguard/audit.log | jq

# Search for errors
grep "ERROR" /var/log/vulnguard/audit.log | jq
```

### 10. Keep Backup Retention Policy

Configure appropriate backup retention:

```yaml
remediation:
  backup_directory: "/var/lib/vulnguard/backups"
  # Implement cleanup script for old backups
```

---

## Troubleshooting

### Issue: Configuration File Not Found

**Symptom:** VulnGuard fails to start with "config file not found" error.

**Solution:**

1. Check configuration file path:
   ```bash
   ls -la vulnguard/configs/agent/config.yaml
   ```

2. Verify file permissions:
   ```bash
   chmod 644 vulnguard/configs/agent/config.yaml
   ```

3. Check YAML syntax:
   ```bash
   python -c "import yaml; yaml.safe_load(open('vulnguard/configs/agent/config.yaml'))"
   ```

### Issue: Rules Not Loading

**Symptom:** No benchmark rules are found or loaded.

**Solution:**

1. Check benchmark directory:
   ```bash
   ls -la vulnguard/configs/benchmarks/
   ```

2. Verify rule file format:
   ```bash
   python -c "import yaml; yaml.safe_load(open('vulnguard/configs/benchmarks/cis_1_1_1.yaml'))"
   ```

3. Check rule file permissions:
   ```bash
   chmod 644 vulnguard/configs/benchmarks/*.yaml
   ```

### Issue: Commands Not Executing

**Symptom:** Remediation commands are not executed or fail.

**Solution:**

1. Check command allow-list:
   ```yaml
   command_allowlist:
     - "^systemctl\\s+(enable|disable|start|stop|restart|status)\\s+[a-zA-Z0-9_-]+$"
   ```

2. Verify command doesn't match block-list:
   ```yaml
   command_blocklist:
     - "rm\\s+-rf"
   ```

3. Test command manually:
   ```bash
   # Test the command
   systemctl status sshd
   ```

### Issue: AI Advisory Not Generated

**Symptom:** AI advisory is not generated for a rule.

**Solution:**

1. Check if AI is enabled:
   ```yaml
   ai:
     enabled: true
   ```

2. Verify rule requires AI assist:
   ```yaml
   ai_assist: true
   ```

3. Check confidence threshold:
   ```yaml
   ai:
     min_confidence_threshold: 0.7
   ```

### Issue: Rollback Not Executing

**Symptom:** Rollback is not executed on remediation failure.

**Solution:**

1. Check rollback configuration:
   ```yaml
   remediation:
     rollback_on_failure: true
   ```

2. Verify rollback commands are defined:
   ```yaml
   rollback:
     commands:
       - "sed -i '/^install cramfs/d' /etc/modprobe.d/cramfs.conf"
   ```

3. Check backup was created:
   ```bash
   ls -la /var/lib/vulnguard/backups/
   ```

### Issue: Logs Not Writing

**Symptom:** Logs are not being written to file.

**Solution:**

1. Check log directory exists:
   ```bash
   mkdir -p /var/log/vulnguard
   ```

2. Verify log directory permissions:
   ```bash
   chmod 755 /var/log/vulnguard
   ```

3. Check disk space:
   ```bash
   df -h /var/log/vulnguard
   ```

### Issue: OS Compatibility Issues

**Symptom:** Rules are skipped due to OS incompatibility.

**Solution:**

1. Check detected OS:
   ```bash
   cat /etc/os-release
   ```

2. Verify rule OS compatibility:
   ```yaml
   os_compatibility:
     - ubuntu
     - rhel
   ```

3. Add OS to supported list if needed:
   ```yaml
   os:
     supported:
       - "rhel"
       - "ubuntu"
       - "centos"
       - "debian"
       - "fedora"  # Add custom OS
   ```

---

## License

[Specify your license here]
