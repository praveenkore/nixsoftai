# Canonical STIG Rule Format Guide

## Overview

This guide explains the canonical STIG rule format for VulnGuard. The canonical format enables a single rule file to support multiple Linux distributions (RHEL family and Debian family) with OS-specific implementations.

## Canonical Schema

```yaml
benchmark: STIG
id: "V-XXXXX"
title: "Rule Title"
stig_id: "STIG-ID-XXX"
original_severity: "CAT I|CAT II|CAT III"
severity: critical|high|medium|low
cci: CCI-XXXXX
srg: SRG-OS-XXXXXX

rationale: |
  Multi-line rationale explaining the security requirement.

implementations:
  rhel_family:
    os: ["rhel", "centos", "almalinux", "rocky"]
    check:
      type: command|file|service|sysctl
      command: ["cmd", "arg1", "arg2"]  # for type: command
      path: "/path/to/file"  # for type: file
      service: "sshd"  # for type: service
      sysctl: "kernel.randomize_va_space"  # for type: sysctl
      expected_state: equals|contains|exists|enabled|active
      expected_value: "expected value"
      expected_type: string|integer|boolean  # optional
      description: "Human-readable check description"
    remediation:
      commands: ["cmd1", "cmd2"]
      requires_restart: false|true
      requires_reboot: false|true
      description: "Human-readable remediation description"
      service_restart: "sshd"  # optional, service to restart
    rollback:
      commands: ["cmd1", "cmd2"]
      description: "Human-readable rollback description"
      service_restart: "sshd"  # optional, service to restart
      requires_reboot: false|true  # optional

  debian_family:
    os: ["debian", "ubuntu"]
    check: { ... }  # Debian-specific check
    remediation: { ... }  # Debian-specific remediation
    rollback: { ... }  # Debian-specific rollback
```

## OS Families

### RHEL Family
- **rhel**: Red Hat Enterprise Linux
- **centos**: CentOS (including CentOS Stream)
- **almalinux**: AlmaLinux
- **rocky**: Rocky Linux

### Debian Family
- **debian**: Debian Linux
- **ubuntu**: Ubuntu

## Check Types

### Type: Command
```yaml
check:
  type: command
  command: ["grep", "-rs", "maxlogins", "/etc/security/limits.conf", "/etc/security/limits.d/*.conf"]
  expected_state: contains
  expected_value: "* hard maxlogins 10"
  description: "Verify maxlogins is set to 10"
```

**Expected States for Command:**
- `equals`: Command output exactly matches expected_value
- `contains`: Command output contains expected_value
- `exists`: Command exits with success (exit code 0)

### Type: File
```yaml
check:
  type: file
  path: "/etc/ssh/sshd_config"
  pattern: "Include /etc/crypto-policies/back-ends/opensshserver.config"
  expected_state: exists
  description: "Verify crypto policies are included"
```

**Expected States for File:**
- `exists`: Pattern found in file
- `absent`: Pattern not found in file

### Type: Service
```yaml
check:
  type: service
  service: "sshd"
  expected_state: enabled
  description: "Verify SSH daemon is enabled"
```

**Expected States for Service:**
- `enabled`: Service is enabled (starts on boot)
- `disabled`: Service is disabled
- `active`: Service is currently running
- `inactive`: Service is not running

### Type: Sysctl
```yaml
check:
  type: sysctl
  sysctl: "kernel.randomize_va_space"
  expected_state: equals
  expected_value: "2"
  expected_type: integer
  description: "Verify ASLR is set to full randomization"
```

**Expected States for Sysctl:**
- `equals`: Sysctl value exactly matches expected_value
- `not_equals`: Sysctl value does not match expected_value

## Remediation Fields

### Commands
List of commands to execute for remediation:
```yaml
remediation:
  commands:
    - "echo '* hard maxlogins 10' >> /etc/security/limits.d/maxlogins.conf"
    - "systemctl reload rsyslog"
```

### Restart Requirements
- `requires_restart`: True if a service restart is needed (but not full system reboot)
- `requires_reboot`: True if a full system reboot is required

### Service Restart
Optional field specifying which service to restart:
```yaml
remediation:
  service_restart: "sshd"
```

## Rollback Fields

Rollback commands should reverse the remediation changes:
```yaml
rollback:
  commands:
    - "sed -i '/maxlogins/d' /etc/security/limits.d/maxlogins.conf"
  service_restart: "sshd"
  requires_reboot: true  # optional
```

## AlmaLinux STIG Rules - Quick Reference

### Completed Canonical Rules
| STIG ID | Title | Check Type | OS Family |
|----------|-------|-------------|-----------|
| ALMA-09-001010 | Limit concurrent sessions to 10 | command | rhel_family |
| ALMA-09-001890 | Exit shell sessions after 10 minutes | command | rhel_family |
| ALMA-09-002770 | SSH log connection attempts | command | rhel_family |
| ALMA-09-002880 | Monitor remote access methods | command | rhel_family |
| ALMA-09-003100 | SSH crypto policies | file | rhel_family |
| ALMA-09-003320 | FIPS mode | command | rhel_family |

### Additional Rules to Convert

From `Alma-linux-stig-rules.txt`, here are key rules still needing conversion:

**GUI/Session Management:**
- ALMA-09-001120: GNOME session lock after 15 minutes
- ALMA-09-001230: Screensaver picture-uri
- ALMA-09-001340: Session idle-delay
- ALMA-09-001450: Screensaver lock-delay
- ALMA-09-002000: Smartcard removal action

**SSH/Network Security:**
- ALMA-09-002990: SSH client ciphers
- ALMA-09-003210: SSH client MACs
- ALMA-09-003325: SSH key exchange algorithms

**Kernel Parameters:**
- ASLR kernel randomization (various V-XXXXX IDs)
- System core dump limits
- Kernel stack execution protection

**Package Management:**
- AIDE installation and configuration
- Audit daemon configuration
- SELinux enforcing mode

## Conversion Process

1. **Extract STIG Rule:**
   ```bash
   # Find rule in Alma-linux-stig-rules.txt
   grep "ALMA-09-XXXXXX" Alma-linux-stig-rules.txt
   ```

2. **Identify Check Method:**
   - Command: Check uses shell command
   - File: Check examines file content
   - Service: Check uses systemctl
   - Sysctl: Check reads kernel parameter

3. **Determine Check Type:**
   - `equals`: Exact match required
   - `contains`: Pattern exists in output
   - `exists`: Command succeeds/pattern found

4. **Extract Remediation Commands:**
   - List all commands from "Fix" section
   - Identify if service restart needed
   - Identify if reboot required

5. **Create Rollback Commands:**
   - Reverse each remediation command
   - Include sed/grep for file reversions
   - Note service restarts and reboots

6. **Add Debian Family Implementation (if applicable):**
   - Convert RPM commands to APT
   - Update service names if different
   - Adjust file paths for Debian

## Example Conversion

### Source (AlmaLinux STIG):
```
STIG ID: ALMA-09-001010 |  Severity: low (CAT III)
Check:
$ grep -rs maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf
/etc/security/limits.d/maxlogins.conf:* hard maxlogins 10
Fix:
* hard maxlogins 10
```

### Target (Canonical YAML):
```yaml
benchmark: STIG
id: "V-269102"
title: "AlmaLinux OS 9 must limit the number of concurrent sessions to ten..."
stig_id: "ALMA-09-001010"
original_severity: "CAT III"
severity: low
implementations:
  rhel_family:
    os: ["rhel", "centos", "almalinux", "rocky"]
    check:
      type: command
      command: ["grep", "-rs", "maxlogins", "/etc/security/limits.conf", "/etc/security/limits.d/*.conf"]
      expected_state: contains
      expected_value: "* hard maxlogins 10"
    remediation:
      commands: ["echo '* hard maxlogins 10' >> /etc/security/limits.d/maxlogins.conf"]
    rollback:
      commands: ["sed -i '/maxlogins/d' /etc/security/limits.d/maxlogins.conf"]
```

## Command Mapping: RHEL → Debian

| RHEL Command | Debian Equivalent |
|--------------|-------------------|
| `rpm -q package` | `dpkg -l package \| grep package` |
| `dnf install package` | `apt-get install -y package` |
| `systemctl start service` | `systemctl start service` |
| `firewall-cmd --add-port` | `ufw allow port` |
| `getenforce` | `sestatus` (SELinux) |

## Testing Canonical Rules

```bash
# Test specific rule
python -m vulnguard.main scan --rule stig_alma_09_001010_canonical.yaml

# Test all canonical rules
python -m vulnguard.main scan --benchmark-dir vulnguard/configs/benchmarks/

# Test remediation in dry-run mode
python -m vulnguard.main remediate --mode dry-run --rule stig_alma_09_001010_canonical.yaml
```

## Next Steps

1. Complete conversion of remaining AlmaLinux STIG rules
2. Add Debian family implementations where applicable
3. Test canonical rules on AlmaLinux and Ubuntu systems
4. Update scanner to fully support canonical format
5. Migrate legacy rules to canonical format
