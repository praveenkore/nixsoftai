# VulnGuard Project Brief

## Project Identity

**Project Name:** VulnGuard - Linux Security Compliance Agent  
**Version:** 1.0.0  
**Developer:** Nixsoft Technologies Pvt. Ltd.  
**License:** GNU General Public License v3 (GPL-3.0)  
**Repository:** https://github.com/praveenkore/nixsoftai  

## Core Purpose

VulnGuard is a production-grade Linux Security Compliance Agent designed for high-trust, regulated environments. It audits, evaluates, and remediates systems against CIS Benchmarks and DISA STIG standards with deterministic logic and AI-assisted advisory services.

## Core Requirements

### Functional Requirements

1. **Security Compliance Auditing**
   - Scan systems against CIS Benchmarks
   - Scan systems against DISA STIG standards
   - Support for multiple rule types: command, file, service, sysctl checks
   - OS compatibility filtering (RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+)

2. **Deterministic Compliance Engine**
   - All compliance checks must be deterministic and predictable
   - No AI integration in scanning - all checks rule-based
   - Strict rule validation before execution
   - Timeout protection for all commands

3. **AI-Assisted Advisory**
   - AI used only for advisory purposes, never direct execution
   - Support for multiple LLM providers (OpenAI, Anthropic, OpenRouter, Ollama, Local)
   - All AI output must pass strict validation:
     - JSON schema validation
     - Command allow-list/block-list validation
     - Confidence threshold checking (default: 0.7)
     - Required field verification

4. **Reversible Remediation**
   - Every remediation MUST be reversible
   - Automatic backup before changes
   - Rollback commands for each action
   - Automatic rollback on failure
   - Dry-run mode by default

5. **Comprehensive Audit Logging**
   - All operations logged in JSON-line format
   - Structured data with consistent schema
   - Log rotation to prevent disk space issues
   - Complete context in every log entry

6. **Safety Controls**
   - Command allow-list for allowed operations
   - Command block-list for dangerous operations
   - Approval gating for high-risk changes
   - Fail-safe design (fail-closed)

7. **CLI Interface**
   - Scan command for compliance checking
   - Remediate command for fixing issues
   - Support for dry-run and commit modes
   - Multiple output formats (json, yaml, text)

### Non-Functional Requirements

1. **Security**
   - No command injection vulnerabilities (never use shell=True)
   - Secure file permissions (0600 for files, 0700 for directories)
   - Atomic file operations to prevent TOCTOU vulnerabilities
   - All commands validated against allow-list/block-list

2. **Reliability**
   - Production stability > compliance speed
   - Predictable behavior over speed
   - Safe failure is mandatory
   - Never leave system in undefined state

3. **Maintainability**
   - Clean separation of concerns
   - Modular architecture
   - Comprehensive documentation
   - Type hints for all functions
   - PEP 8 compliance

4. **Extensibility**
   - Easy to add new benchmark rules
   - Easy to add new LLM providers
   - Configuration-driven behavior
   - Plugin-friendly architecture

## Core Goals

### Primary Goals

1. **Provide Safe, Deterministic Security Compliance**
   - All compliance checks are deterministic
   - AI is advisory only, never executes directly
   - Every remediation is reversible
   - All actions are auditable

2. **Support Regulated Environments**
   - Designed for high-trust environments
   - Meets compliance requirements
   - Passes security audits and penetration testing
   - Follows enterprise security standards

3. **Enable AI-Assisted Security Analysis**
   - AI provides intelligent recommendations
   - All AI output validated and untrusted
   - Multiple LLM provider support
   - Confidence thresholds ensure quality

4. **Ensure Production Readiness**
   - Comprehensive error handling
   - Automatic rollback on failure
   - Extensive logging for troubleshooting
   - Dry-run mode for testing

### Secondary Goals

1. **Developer Experience**
   - Easy to understand codebase
   - Clear documentation
   - Comprehensive testing
   - Development tools setup

2. **User Experience**
   - Intuitive CLI interface
   - Clear output and error messages
   - Multiple output formats
   - Helpful error reporting

3. **Performance**
   - Efficient scanning
   - Connection pooling for HTTP requests
   - Rate limiting to prevent API quota exhaustion
   - Lazy loading to avoid circular dependencies

## Design Philosophy

VulnGuard follows seven core design principles:

1. **Deterministic Logic FIRST, AI advisory ONLY when necessary**
   - All compliance checks are deterministic
   - AI only invoked for ambiguous findings, errors, or explicit requests

2. **AI output is ALWAYS untrusted and MUST be validated**
   - JSON schema validation
   - Command allow-list/block-list validation
   - Confidence threshold checking
   - Required field verification

3. **No blind automation**
   - Dry-run mode by default
   - Manual review of proposed changes
   - Approval gating for high-risk changes
   - Clear logging of all actions

4. **Every remediation MUST be reversible**
   - Automatic backup before changes
   - Rollback commands for each action
   - Automatic rollback on failure
   - Audit trail of all changes

5. **Every action MUST be auditable**
   - Structured JSON-line format
   - Complete context and metadata
   - Timestamp and system information
   - Success/failure status

6. **Safe failure is mandatory (fail-closed)**
   - Fail safely on errors
   - Never leave system in undefined state
   - Rollback on remediation failure
   - Log all errors for investigation

7. **Production stability > compliance speed**
   - Predictable behavior over speed
   - Safety over automation
   - Manual review over blind execution
   - Comprehensive logging over brevity

## Project Scope

### In Scope

- Linux security compliance auditing
- CIS Benchmark support
- DISA STIG support
- AI-assisted advisory services
- Reversible remediation
- Comprehensive audit logging
- Multiple LLM provider integration
- CLI interface
- Configuration management
- Testing framework

### Out of Scope

- Windows/macOS support (Linux only)
- Real-time monitoring
- Intrusion detection
- Network security scanning
- Cloud platform integration
- GUI interface
- Mobile applications
- Commercial SaaS offering

## Success Criteria

1. **Functional Success**
   - All benchmark rules execute correctly
   - AI advisory provides helpful recommendations
   - Remediation is safe and reversible
   - Audit logging is comprehensive

2. **Security Success**
   - No command injection vulnerabilities
   - No TOCTOU vulnerabilities
   - All commands validated
   - Secure file permissions enforced

3. **Quality Success**
   - Test coverage > 80%
   - Code passes linting (flake8)
   - Code passes type checking (mypy)
   - Documentation is comprehensive

4. **User Success**
   - CLI is intuitive and easy to use
   - Error messages are clear and actionable
   - Output is readable and parseable
   - Configuration is well-documented

## Constraints

### Technical Constraints

- Python 3.8+ required
- Linux OS required (RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+)
- Root or sudo access required for remediation
- Network access required for cloud LLM providers

### Security Constraints

- Never use shell=True for command execution
- All commands must be parameterized
- All AI output must be validated
- All files must have secure permissions
- All file operations must be atomic

### Legal Constraints

- GPL v3 license must be maintained
- Nixsoft Technologies Pvt. Ltd. must be credited
- Project name "VulnGuard" must not be rebranded
- Derivative works must also be GPL v3

### Operational Constraints

- Default mode must be dry-run
- Automatic backup must be enabled
- Rollback on failure must be enabled
- Approval gating for high-risk changes
