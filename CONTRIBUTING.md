# Contributing to VulnGuard

Thank you for your interest in contributing to VulnGuard! This document outlines the contribution process, coding standards, and requirements for participating in this open-source security compliance project.

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [License Agreement](#license-agreement)
- [Security Considerations](#security-considerations)
- [Benchmark Changes](#benchmark-changes)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)

---

## Overview

VulnGuard is a Linux security compliance agent that helps organizations identify and address security vulnerabilities against CIS Benchmarks and DISA STIG standards.

**Project Characteristics**:
- **License**: GNU General Public License v3 (GPL-3.0)
- **Author**: Nixsoft Technologies Pvt. Ltd.
- **Design Philosophy**: Deterministic-first, AI-gated
- **Security-Sensitive**: All changes must be carefully reviewed

**By contributing**, you agree to:
- License your contributions under GPL v3
- Follow Nixsoft usage guidelines
- Adhere to security best practices
- Not introduce proprietary code

---

## Getting Started

### Prerequisites

- Python 3.8+
- Git
- GitHub account
- Understanding of Linux security concepts
- Familiarity with CIS Benchmarks and/or DISA STIG

### Development Setup

1. **Fork the repository**:
   ```bash
   # Fork https://github.com/praveenkore/nixsoftai.git
   ```

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/nixsoftai.git
   cd nixsoftai
   ```

3. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # If available
   ```

5. **Install development tools**:
   ```bash
   pip install black flake8 mypy pytest
   ```

6. **Run tests**:
   ```bash
   pytest
   ```

---

## Contribution Workflow

### Step 1: Identify an Issue

- Browse [GitHub Issues](https://github.com/praveenkore/nixsoftai/issues)
- Check for existing issues or feature requests
- Comment on existing issues if you plan to work on them
- Create a new issue if needed, describing your proposed change

### Step 2: Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

**Branch Naming Conventions**:
- Features: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`
- Refactoring: `refactor/description`

### Step 3: Make Changes

- Write clean, well-documented code
- Follow coding standards (see below)
- Add tests for new functionality
- Update documentation as needed
- Ensure all files have GPL v3 license headers

### Step 4: Test Your Changes

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=vulnguard --cov-report=html
```

### Step 5: Submit Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a pull request on GitHub
3. Fill out the PR template completely
4. Link to related issues
5. Wait for review and address feedback

---

## Coding Standards

### Code Style

**Python Style**:
- Follow PEP 8 guidelines
- Use `black` for automatic formatting:
  ```bash
  black vulnguard/
  ```

**Linting**:
- Use `flake8` for linting:
  ```bash
  flake8 vulnguard/
  ```

**Type Hints**:
- Use type hints for all function signatures
- Run `mypy` for type checking:
  ```bash
  mypy vulnguard/
  ```

### Documentation

**Docstrings**:
- Use Google-style docstrings
- Document all public functions and classes
- Include parameter types and return types

Example:
```python
def scan_system(rule_id: str) -> ScanResult:
    """
    Scan the system for a specific security rule.

    Args:
        rule_id: The identifier of the rule to scan.

    Returns:
        ScanResult object containing scan results.

    Raises:
        ValueError: If rule_id is not found.
    """
    pass
```

**Comments**:
- Comment complex logic
- Explain "why", not "what"
- Keep comments up-to-date

### Code Quality

**Principles**:
- **Deterministic First**: Prefer deterministic logic over AI assistance
- **Fail-Safe**: Code should fail gracefully, not crash
- **Audit Everything**: All operations must be logged
- **Validate Inputs**: Never trust user input
- **Reversible**: All changes should be reversible
- **Testable**: Code should be easily testable

---

## License Agreement

### GPL v3 License

**By contributing to VulnGuard, you agree that**:

1. **Your contribution is licensed under GPL v3**:
   - Anyone can use, modify, and distribute your code
   - Your code must include GPL v3 license headers
   - Your code cannot be relicensed under a non-GPL license

2. **No proprietary code**:
   - Do not submit code that you cannot license under GPL v3
   - Do not include code from proprietary sources
   - Ensure all third-party code is GPL-compatible

3. **Attribution**:
   - Your contributions will be attributed to you
   - Nixsoft Technologies Pvt. Ltd. remains the original author
   - The "VulnGuard" name cannot be removed or rebranded

### License Headers

**All new source files must include**:

```python
# VulnGuard - Linux Security Compliance Agent
# Copyright (c) Nixsoft Technologies Pvt. Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
```

### No Proprietary Code Rule

**Do NOT submit**:
- Code from proprietary projects
- Code with incompatible licenses (e.g., MIT, Apache, BSD without GPL compatibility)
- Code that requires non-GPL dependencies
- Code that cannot be freely distributed

**If unsure**:
- Ask before submitting
- Document the source of any code you include
- Verify license compatibility of all dependencies

---

## Security Considerations

### Security-Sensitive Project

VulnGuard is a security tool. All contributions must:

1. **Prioritize Security**:
   - Never introduce security vulnerabilities
   - Validate all inputs thoroughly
   - Use safe coding practices
   - Consider security implications of every change

2. **Maintain Determinism**:
   - Avoid introducing nondeterministic behavior
   - Ensure consistent results across runs
   - Document any AI usage clearly

3. **Audit Trail**:
   - Log all security-relevant operations
   - Maintain traceability of changes
   - Support compliance auditing

### Specific Security Guidelines

**Command Execution**:
- Never execute untrusted commands
- Validate all commands against allow-lists
- Implement proper error handling

**AI Integration**:
- Never trust AI output blindly
- Always validate AI recommendations
- Implement confidence thresholds
- Log all AI interactions

**Data Handling**:
- Never log sensitive data (passwords, keys, tokens)
- Securely handle configuration files
- Implement proper file permissions

**Remediation**:
- Always provide rollback capabilities
- Test remediation in safe environments
- Warn before destructive operations

### Security Review

All pull requests will be reviewed for:
- Security vulnerabilities
- Compliance with security best practices
- Proper input validation
- Safe error handling
- Appropriate logging

---

## Benchmark Changes

### CIS Benchmarks

**When proposing CIS benchmark changes**:

1. **Reference Official CIS Documentation**:
   - Link to official CIS benchmark
   - Cite specific CIS control number
   - Document any deviations

2. **Justify Changes**:
   - Explain why the change is needed
   - Provide evidence or references
   - Consider backward compatibility

3. **Test Thoroughly**:
   - Test on multiple Linux distributions
   - Verify expected behavior
   - Document test results

4. **Update Metadata**:
   - Update benchmark metadata in YAML files
   - Include CIS version and date
   - Document OS compatibility

### DISA STIG

**When proposing STIG changes**:

1. **Reference Official STIG Documentation**:
   - Link to official DISA STIG
   - Cite specific STIG rule ID
   - Document any deviations

2. **Maintain STIG Compliance**:
   - Ensure changes align with STIG requirements
   - Do not introduce non-compliant configurations
   - Document rationale for any modifications

3. **Security Classification**:
   - Respect STIG severity classifications
   - Maintain CAT I/II/III designations
   - Document approval requirements

### Benchmark File Format

```yaml
rule_id: "1.1.1"
title: "Ensure mounting of cramfs filesystems is disabled"
benchmark: "CIS"
severity: "Level 2"
description: >
  Disabling cramfs filesystems prevents potential security
  vulnerabilities associated with this filesystem type.
rationale: >
  The cramfs filesystem is not commonly used and may have
  security vulnerabilities. Disabling it reduces attack surface.
os_compatibility:
  - Ubuntu
  - Debian
check_command: "modprobe -n cramfs"
expected_state: "not loaded"
remediation:
  commands:
    - "echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf"
  rollback:
    - "rm /etc/modprobe.d/cramfs.conf"
approval_required: false
```

---

## Testing Requirements

### Unit Tests

**Requirements**:
- All new functions must have unit tests
- Test coverage should not decrease
- Tests should be deterministic and repeatable

**Test Structure**:
```python
import pytest
from vulnguard.pkg.scanner.scanner import Scanner

def test_scan_compliant_system():
    """Test scanning a compliant system."""
    scanner = Scanner()
    result = scanner.scan("cis_1_1_1")
    assert result.compliant is True

def test_scan_non_compliant_system():
    """Test scanning a non-compliant system."""
    scanner = Scanner()
    result = scanner.scan("cis_1_1_1")
    assert result.compliant is False
    assert "cramfs" in result.check_output
```

### Integration Tests

**Requirements**:
- Test interactions between components
- Test end-to-end workflows
- Test with real system configurations

### Security Tests

**Requirements**:
- Test input validation
- Test command allow-list enforcement
- Test error handling
- Test audit logging

### Test Coverage

**Target**: Minimum 80% code coverage

**Check coverage**:
```bash
pytest --cov=vulnguard --cov-report=term-missing
```

---

## Pull Request Process

### PR Checklist

Before submitting a pull request, ensure:

- [ ] Code follows project style guidelines
- [ ] All tests pass (`pytest`)
- [ ] Code is formatted with `black`
- [ ] Code passes `flake8` linting
- [ ] Type hints are correct (`mypy`)
- [ ] New files have GPL v3 license headers
- [ ] Documentation is updated
- [ ] Tests are added/updated
- [ ] Security implications are considered
- [ ] Commit messages are clear and descriptive

### Commit Messages

**Format**:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation change
- `style`: Code style change (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance task

**Example**:
```
feat(scanner): add support for custom benchmark paths

- Add configuration option for custom benchmark directories
- Validate benchmark paths on initialization
- Update documentation with new option

Closes #123
```

### Review Process

1. **Automated Checks**:
   - CI/CD pipeline runs tests
   - Code quality checks pass
   - License headers are present

2. **Manual Review**:
   - Maintainers review code quality
   - Security review for security implications
   - Documentation review for completeness

3. **Feedback**:
   - Address all review comments
   - Update PR with fixes
   - Request re-review when ready

4. **Merge**:
   - PR is merged after approval
   - Maintainer handles merge
   - Branch is deleted after merge

---

## Getting Help

### Questions?

- Check [GitHub Discussions](https://github.com/praveenkore/nixsoftai/discussions)
- Review existing issues and PRs
- Read the [documentation](docs/)

### Security Concerns?

- Report via [SECURITY.md](SECURITY.md)
- Do not post security issues publicly
- Follow responsible disclosure process

---

## Recognition

Contributors will be acknowledged in:
- CONTRIBUTORS file
- Release notes
- Project documentation

Thank you for contributing to VulnGuard and helping make open-source security tools better for everyone!

---

## License

By contributing to VulnGuard, you agree that your contributions are licensed under the GNU General Public License v3 (GPL-3.0).

See the [LICENSE](LICENSE) file for complete terms.

Contributors will be acknowledged in:
- CONTRIBUTORS file
- Release notes
- Project documentation

Thank you for contributing to VulnGuard and helping make open-source security tools better for everyone!

---

## License

By contributing to VulnGuard, you agree that your contributions are licensed under the GNU General Public License v3 (GPL-3.0).

See the [LICENSE](LICENSE) file for complete terms.
