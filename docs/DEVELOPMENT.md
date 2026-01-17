# VulnGuard Development Guide

This document provides comprehensive information for developers contributing to VulnGuard Linux Security Compliance Agent.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Adding New Features](#adding-new-features)
- [Adding New Benchmark Rules](#adding-new-benchmark-rules)
- [Debugging](#debugging)
- [Code Review Process](#code-review-process)
- [Release Process](#release-process)

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment (recommended)
- Linux development environment (RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+)

### Setup Development Environment

1. **Clone the repository:**

```bash
git clone https://github.com/your-org/VulnGuard-agent-v1.git
cd VulnGuard-agent-v1
```

2. **Create virtual environment:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

4. **Install development dependencies:**

```bash
pip install pytest pytest-cov black flake8 mypy python-json-logger
```

5. **Verify installation:**

```bash
python -m vulnguard.main version
```

---

## Development Environment

### Recommended IDE Setup

#### VS Code

Install the following extensions:

- Python (Microsoft)
- Pylance (Microsoft)
- Python Test Explorer (LittleFoxTeam)
- YAML (Red Hat)

Configure VS Code settings:

```json
{
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": [
    "tests"
  ],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

#### PyCharm

Configure PyCharm settings:

1. **Code Style**: Use Black formatter
2. **Inspections**: Enable Flake8 and MyPy
3. **Testing**: Configure pytest runner
4. **Interpreter**: Use project virtual environment

### Development Workflow

1. **Create a feature branch:**

```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes:**

```bash
# Edit files
git add .
git commit -m "feat: add new feature"
```

3. **Run tests:**

```bash
pytest
```

4. **Run linting:**

```bash
black vulnguard/
flake8 vulnguard/
mypy vulnguard/
```

5. **Push changes:**

```bash
git push origin feature/your-feature-name
```

6. **Create pull request:**

```bash
# Create PR on GitHub/GitLab
```

---

## Project Structure

```
vulnguard/
├── main.py                          # Main orchestrator & CLI
├── pkg/                             # Core packages
│   ├── scanner/                      # Deterministic Audit Engine
│   │   ├── __init__.py
│   │   └── scanner.py               # Scanner implementation
│   ├── engine/                       # Compliance & Risk Decision Engine
│   │   ├── __init__.py
│   │   └── engine.py               # Engine implementation
│   ├── advisor/                      # AI Gateway & Safety Validator
│   │   ├── __init__.py
│   │   └── advisor.py              # Advisor implementation
│   ├── remediation/                  # Reversible Remediation Engine
│   │   ├── __init__.py
│   │   └── remediation.py         # Remediation implementation
│   └── logging/                      # Structured Audit Logger
│       ├── __init__.py
│       └── logger.py               # Logger implementation
├── configs/                         # Configuration files
│   ├── agent/                       # Global agent config
│   │   └── config.yaml
│   └── benchmarks/                  # CIS / STIG YAML rules
│       ├── cis_1_1_1.yaml
│       └── stig_vuln_220278.yaml
├── tests/                           # Test files
│   ├── test_scanner.py
│   ├── test_engine.py
│   ├── test_advisor.py
│   ├── test_remediation.py
│   └── test_logger.py
├── docs/                            # Documentation
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── CONFIGURATION.md
│   └── DEVELOPMENT.md
├── requirements.txt                  # Python dependencies
├── setup.py                         # Package setup
└── README.md                        # Project documentation
```

### Module Responsibilities

| Module | Responsibility | Key Classes |
|--------|---------------|-------------|
| [`main.py`](vulnguard/main.py) | Orchestrator & CLI | [`VulnGuardOrchestrator`](vulnguard/main.py:25) |
| [`scanner/`](vulnguard/pkg/scanner/) | Deterministic audit engine | [`Scanner`](vulnguard/pkg/scanner/scanner.py:65), [`ScanResult`](vulnguard/pkg/scanner/scanner.py:17) |
| [`engine/`](vulnguard/pkg/engine/) | Compliance & risk decision engine | [`ComplianceEngine`](vulnguard/pkg/engine/engine.py:65), [`EvaluationResult`](vulnguard/pkg/engine/engine.py:13) |
| [`advisor/`](vulnguard/pkg/advisor/) | AI gateway & safety validator | [`AIAdvisor`](vulnguard/pkg/advisor/advisor.py:76), [`AIAdvisory`](vulnguard/pkg/advisor/advisor.py:16) |
| [`remediation/`](vulnguard/pkg/remediation/) | Reversible remediation engine | [`RemediationEngine`](vulnguard/pkg/remediation/remediation.py:73), [`RemediationResult`](vulnguard/pkg/remediation/remediation.py:21) |
| [`logging/`](vulnguard/pkg/logging/) | Structured audit logger | [`AuditLogger`](vulnguard/pkg/logging/logger.py:17) |

---

## Coding Standards

### Python Version

- Target Python 3.8+
- Use type hints for all function signatures
- Follow PEP 8 style guide

### Code Formatting

Use **Black** for code formatting:

```bash
# Format all files
black vulnguard/

# Format specific file
black vulnguard/main.py

# Check formatting without making changes
black --check vulnguard/
```

### Linting

Use **Flake8** for linting:

```bash
# Lint all files
flake8 vulnguard/

# Lint specific file
flake8 vulnguard/main.py

# Show more details
flake8 --max-line-length=100 vulnguard/
```

### Type Checking

Use **MyPy** for type checking:

```bash
# Type check all files
mypy vulnguard/

# Type check specific file
mypy vulnguard/main.py

# Show more details
mypy --show-error-codes vulnguard/
```

### Naming Conventions

- **Classes**: PascalCase (e.g., `VulnGuardOrchestrator`)
- **Functions**: snake_case (e.g., `run_scan`)
- **Variables**: snake_case (e.g., `scan_result`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `DEFAULT_COMMAND_ALLOWLIST`)
- **Private methods**: _leading_underscore (e.g., `_load_config`)

### Docstrings

Use **Google style** docstrings:

```python
def run_scan(
    self,
    rule_ids: Optional[List[str]] = None
) -> tuple[List[ScanResult], List[EvaluationResult], List[AIAdvisory]]:
    """
    Run the complete VulnGuard pipeline: scan, evaluate, and optionally get AI advisory.
    
    Args:
        rule_ids: Optional list of rule IDs to scan. If None, scans all rules.
        
    Returns:
        Tuple of (scan_results, evaluation_results, ai_advisories)
        
    Raises:
        ValueError: If rule_ids is not a list or contains invalid rule IDs.
        
    Example:
        >>> orchestrator = VulnGuardOrchestrator()
        >>> scan_results, eval_results, ai_advisories = orchestrator.run_scan()
    """
```

### Type Hints

Use type hints for all function signatures:

```python
from typing import Optional, List, Dict, Any, Tuple

def scan_rule(
    self,
    rule_id: str
) -> Optional[ScanResult]:
    """
    Scan a single benchmark rule.
    
    Args:
        rule_id: Rule identifier (e.g., "cis_1_1_1" or "stig_vuln_12345")
        
    Returns:
        ScanResult object, or None if scanning fails
    """
    pass
```

### Error Handling

Follow these error handling patterns:

1. **Log all errors**:
```python
try:
    result = self._execute_command(command)
except Exception as e:
    self.logger.log_error(
        "scan",
        f"Failed to execute command: {str(e)}",
        {"command": command}
    )
    return None
```

2. **Return None on failure** for methods that return optional results:
```python
def scan_rule(self, rule_id: str) -> Optional[ScanResult]:
    try:
        # Implementation
        return result
    except Exception as e:
        self.logger.log_error(...)
        return None
```

3. **Return error tuples** for methods that need to provide error information:
```python
def get_advisory(
    self,
    rule_id: str,
    scan_result: ScanResult,
    evaluation_result: EvaluationResult
) -> tuple[Optional[AIAdvisory], str]:
    try:
        # Implementation
        return advisory, ""
    except Exception as e:
        return None, f"Failed to get AI advisory: {str(e)}"
```

### Logging

Use the [`AuditLogger`](vulnguard/pkg/logging/logger.py:17) for all logging:

```python
# Log scan start
self.logger.log_scan_start(
    benchmark="CIS",
    rule_id="1.1.1",
    system_info={"os": "ubuntu", "version": "20.04"}
)

# Log scan result
self.logger.log_scan_result(
    benchmark="CIS",
    rule_id="1.1.1",
    compliant=True,
    expected_state="not found",
    actual_state="not found",
    check_output="modprobe: ERROR: could not insert 'cramfs'"
)

# Log error
self.logger.log_error(
    "scan",
    f"Failed to load rule: {str(e)}",
    {"rule_id": rule_id}
)
```

### Configuration

Load configuration from [`vulnguard/configs/agent/config.yaml`](vulnguard/configs/agent/config.yaml):

```python
import yaml
from pathlib import Path

def _load_config(self) -> Dict[str, Any]:
    """
    Load agent configuration from YAML file.
    
    Returns:
        Configuration dictionary
    """
    config_path = Path("vulnguard/configs/agent/config.yaml")
    
    if not config_path.exists():
        return self._get_default_config()
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Failed to load config: {e}", file=sys.stderr)
        return self._get_default_config()
```

---

## Testing

### Test Structure

Create test files in the `tests/` directory:

```
tests/
├── test_scanner.py
├── test_engine.py
├── test_advisor.py
├── test_remediation.py
├── test_logger.py
└── conftest.py  # Pytest fixtures
```

### Writing Tests

Use **pytest** for testing:

```python
import pytest
from vulnguard.pkg.scanner.scanner import Scanner, ScanResult

def test_scan_rule_success():
    """Test successful scan of a rule."""
    scanner = Scanner()
    result = scanner.scan_rule("cis_1_1_1")
    
    assert result is not None
    assert isinstance(result, ScanResult)
    assert result.rule_id == "1.1.1"
    assert result.benchmark == "CIS"

def test_scan_rule_not_found():
    """Test scanning a non-existent rule."""
    scanner = Scanner()
    result = scanner.scan_rule("non_existent_rule")
    
    assert result is None

def test_scan_rule_os_incompatible():
    """Test scanning a rule incompatible with current OS."""
    scanner = Scanner()
    result = scanner.scan_rule("stig_vuln_220278")
    
    assert result is not None
    assert result.compliant == False
    assert "OS not supported" in result.check_output
```

### Test Fixtures

Use fixtures in `conftest.py`:

```python
import pytest
from vulnguard.pkg.scanner.scanner import Scanner
from vulnguard.pkg.engine.engine import ComplianceEngine
from vulnguard.pkg.advisor.advisor import AIAdvisor
from vulnguard.pkg.remediation.remediation import RemediationEngine
from vulnguard.pkg.logging.logger import AuditLogger

@pytest.fixture
def logger():
    """Fixture for AuditLogger."""
    return AuditLogger(log_file="/tmp/test_vulnguard.log")

@pytest.fixture
def scanner(logger):
    """Fixture for Scanner."""
    return Scanner(logger=logger)

@pytest.fixture
def engine(logger):
    """Fixture for ComplianceEngine."""
    return ComplianceEngine(logger=logger)

@pytest.fixture
def advisor(logger):
    """Fixture for AIAdvisor."""
    return AIAdvisor(logger=logger)

@pytest.fixture
def remediation(logger):
    """Fixture for RemediationEngine."""
    return RemediationEngine(logger=logger)
```

### Running Tests

Run all tests:

```bash
pytest
```

Run specific test file:

```bash
pytest tests/test_scanner.py
```

Run specific test function:

```bash
pytest tests/test_scanner.py::test_scan_rule_success
```

Run tests with coverage:

```bash
pytest --cov=vulnguard --cov-report=html
```

Run tests with verbose output:

```bash
pytest -v
```

### Test Coverage

Maintain high test coverage:

```bash
# Generate coverage report
pytest --cov=vulnguard --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=vulnguard --cov-report=html
```

Target coverage:
- **Overall**: >80%
- **Critical modules**: >90%

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test interactions between modules
3. **End-to-End Tests**: Test complete workflows
4. **Edge Case Tests**: Test boundary conditions and error cases

---

## Adding New Features

### Feature Development Process

1. **Design the feature**:
   - Define requirements
   - Design API
   - Consider safety implications
   - Plan rollback mechanisms

2. **Implement the feature**:
   - Write code following coding standards
   - Add comprehensive logging
   - Implement error handling
   - Add type hints

3. **Write tests**:
   - Write unit tests
   - Write integration tests
   - Achieve required coverage

4. **Update documentation**:
   - Update API documentation
   - Update configuration guide
   - Update architecture documentation
   - Add examples

5. **Code review**:
   - Submit pull request
   - Address review comments
   - Ensure all checks pass

### Example: Adding New Check Type

1. **Define check type in rule YAML**:

```yaml
check:
  type: custom_check
  custom_parameter: "value"
```

2. **Implement check method in [`Scanner`](vulnguard/pkg/scanner/scanner.py:65)**:

```python
def _check_custom(
    self,
    check_config: Dict[str, Any]
) -> Tuple[bool, str, str]:
    """
    Execute a custom check.
    
    Args:
        check_config: Check configuration dictionary
        
    Returns:
        Tuple of (compliant, actual_state, output)
    """
    custom_parameter = check_config.get('custom_parameter', '')
    
    if not custom_parameter:
        return False, '', 'No custom parameter specified'
    
    # Implement custom check logic
    try:
        result = self._execute_custom_check(custom_parameter)
        compliant = result == expected_value
        actual_state = result
        output = f"Custom check result: {result}"
        
        return compliant, actual_state, output
    except Exception as e:
        self.logger.log_error(
            "scan",
            f"Custom check failed: {str(e)}",
            {"custom_parameter": custom_parameter}
        )
        return False, 'error', str(e)
```

3. **Add check type to [`scan_rule`](vulnguard/pkg/scanner/scanner.py:376)**:

```python
def scan_rule(self, rule_id: str) -> Optional[ScanResult]:
    # ... existing code ...
    
    check_config = rule.get('check', {})
    check_type = check_config.get('type', 'command')
    
    try:
        if check_type == 'command':
            compliant, actual_state, output = self._check_command(check_config)
        elif check_type == 'file':
            compliant, actual_state, output = self._check_file(check_config)
        elif check_type == 'service':
            compliant, actual_state, output = self._check_service(check_config)
        elif check_type == 'sysctl':
            compliant, actual_state, output = self._check_sysctl(check_config)
        elif check_type == 'custom_check':
            compliant, actual_state, output = self._check_custom(check_config)
        else:
            # Handle unknown check type
            pass
    except Exception as e:
        # Handle error
        pass
```

4. **Write tests**:

```python
def test_check_custom_success():
    """Test successful custom check."""
    scanner = Scanner()
    check_config = {
        'type': 'custom_check',
        'custom_parameter': 'test_value'
    }
    
    compliant, actual_state, output = scanner._check_custom(check_config)
    
    assert compliant is True
    assert actual_state == 'expected_value'
    assert 'Custom check result' in output

def test_check_custom_failure():
    """Test failed custom check."""
    scanner = Scanner()
    check_config = {
        'type': 'custom_check',
        'custom_parameter': 'invalid_value'
    }
    
    compliant, actual_state, output = scanner._check_custom(check_config)
    
    assert compliant is False
    assert actual_state != 'expected_value'
```

5. **Update documentation**:
   - Add check type to API documentation
   - Add example rule configuration
   - Update architecture documentation

---

## Adding New Benchmark Rules

### Rule Template

Use the following template for new benchmark rules:

```yaml
# Benchmark Rule Template
# <Benchmark Name> <Version>
# Rule <ID>: <Title>

benchmark: CIS                    # Benchmark type (CIS or STIG)
id: "X.Y.Z"                    # Rule identifier
title: "Rule title"              # Rule title
rationale: "Explanation of why this rule is important"  # Rationale
severity: medium                  # Normalized severity (critical, high, medium, low)
original_severity: Level2         # Original severity from benchmark
os_compatibility:
  - ubuntu                       # Supported OS types
  - rhel
  - centos
  - debian

check:
  type: command                  # Check type (command, file, service, sysctl)
  command: "example command"     # Check command
  expected_state: "expected value"  # Expected state

remediation:
  commands:
    - "remediation command 1"    # List of remediation commands
    - "remediation command 2"
  requires_restart: false         # Service restart required
  requires_reboot: false         # System reboot required

rollback:
  commands:
    - "rollback command 1"       # List of rollback commands
    - "rollback command 2"

ai_assist: false                # AI assistance required
approval_required: false        # Approval required for remediation
exception_allowed: true        # Exception allowed for this rule
```

### Rule Creation Process

1. **Identify the requirement**:
   - Review CIS or STIG documentation
   - Understand the security requirement
   - Identify the check mechanism

2. **Define the check**:
   - Choose check type (command, file, service, sysctl)
   - Write the check command
   - Define expected state

3. **Define the remediation**:
   - Write remediation commands
   - Ensure commands are reversible
   - Add rollback commands

4. **Test the rule**:
   - Test on target OS
   - Verify check works correctly
   - Test remediation in dry-run mode
   - Test rollback

5. **Create the rule file**:
   - Use the template above
   - Save to [`vulnguard/configs/benchmarks/`](vulnguard/configs/benchmarks/)
   - Use descriptive filename (e.g., `cis_1_2_3.yaml`)

6. **Validate the rule**:
   - Run scanner on the rule
   - Verify output is correct
   - Check logs for errors

### Example: Creating a CIS Rule

```yaml
# CIS Benchmark Rule
# CIS Ubuntu Linux 20.04 LTS Benchmark v2.0.0
# Rule 1.1.2: Ensure mounting of freevxfs filesystems is disabled

benchmark: CIS
id: "1.1.2"
title: "Ensure mounting of freevxfs filesystems is disabled"
rationale: "The freevxfs filesystem type is a free implementation of the Veritas filesystem. Removing support for uncommon filesystems reduces the local attack surface of the system."
severity: medium
original_severity: Level2
os_compatibility:
  - ubuntu
  - debian

check:
  type: command
  command: "modprobe -n -v freevxfs"
  expected_state: "not found"

remediation:
  commands:
    - "echo 'install freevxfs /bin/true' >> /etc/modprobe.d/freevxfs.conf"
  requires_restart: false
  requires_reboot: false

rollback:
  commands:
    - "sed -i '/^install freevxfs/d' /etc/modprobe.d/freevxfs.conf"

ai_assist: false
approval_required: false
exception_allowed: true
```

---

## Debugging

### Enabling Debug Logging

Set log level to DEBUG in configuration:

```yaml
logging:
  level: "DEBUG"
```

Or use environment variable:

```bash
export VULNGUARD_LOGGING_LEVEL=DEBUG
python -m vulnguard.main scan
```

### Using Python Debugger

Use pdb for debugging:

```python
import pdb; pdb.set_trace()
```

Or use breakpoint() (Python 3.7+):

```python
breakpoint()
```

### Debugging with VS Code

1. **Create launch configuration**:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: VulnGuard Scan",
      "type": "python",
      "request": "launch",
      "module": "vulnguard.main",
      "args": ["scan"],
      "console": "integratedTerminal"
    }
  ]
}
```

2. **Set breakpoints** in code
3. **Press F5** to start debugging

### Debugging with PyCharm

1. **Create run configuration**:
   - Run → Edit Configurations
   - Add Python configuration
   - Module name: `vulnguard.main`
   - Parameters: `scan`

2. **Set breakpoints** in code
3. **Click Debug** button

### Common Issues

#### Issue: Rule not loading

**Debug steps:**

1. Check rule file exists:
```python
from pathlib import Path
rule_path = Path("vulnguard/configs/benchmarks/cis_1_1_1.yaml")
print(rule_path.exists())
```

2. Check YAML syntax:
```python
import yaml
with open(rule_path, 'r') as f:
    data = yaml.safe_load(f)
print(data)
```

3. Check required fields:
```python
required_fields = [
    'benchmark', 'id', 'title', 'rationale',
    'severity', 'original_severity', 'os_compatibility',
    'check', 'remediation', 'rollback'
]
for field in required_fields:
    if field not in data:
        print(f"Missing field: {field}")
```

#### Issue: Command not executing

**Debug steps:**

1. Check command manually:
```bash
# Test command
modprobe -n -v cramfs
```

2. Check command validation:
```python
from vulnguard.pkg.remediation.remediation import RemediationEngine
engine = RemediationEngine()
is_valid, error = engine._validate_command("modprobe -n -v cramfs")
print(is_valid, error)
```

3. Check allow-list/block-list:
```python
import re
allowlist = [r'^modprobe\s+-n\s+-v\s+[a-zA-Z0-9_-]+$']
command = "modprobe -n -v cramfs"
for pattern in allowlist:
    if re.match(pattern, command):
        print("Command matches allow-list")
```

#### Issue: AI advisory not generated

**Debug steps:**

1. Check AI is enabled:
```python
from vulnguard.main import VulnGuardOrchestrator
orchestrator = VulnGuardOrchestrator()
print(orchestrator.config.get('ai', {}).get('enabled'))
```

2. Check AI assist required:
```python
print(eval_result.ai_assist_required)
```

3. Check confidence threshold:
```python
print(advisory.confidence)
print(orchestrator.config.get('ai', {}).get('min_confidence_threshold'))
```

---

## Code Review Process

### Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] Code follows coding standards
- [ ] All tests pass
- [ ] Test coverage is maintained
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] No sensitive information is included
- [ ] Changes are backwards compatible (if applicable)

### Commit Message Format

Use conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance tasks

**Examples:**

```
feat(scanner): add custom check type support

Add support for custom check types in scanner module.
This allows users to define custom check mechanisms.

- Add _check_custom method
- Update scan_rule to handle custom_check type
- Add tests for custom check type

Closes #123
```

```
fix(remediation): handle backup directory creation failure

Fix issue where remediation fails if backup directory
cannot be created. Now creates directory with proper
error handling.

Fixes #456
```

### Review Guidelines

When reviewing code:

1. **Check for safety**:
   - Are all commands validated?
   - Is error handling comprehensive?
   - Are rollback mechanisms in place?
   - Is logging complete?

2. **Check for quality**:
   - Does code follow standards?
   - Are type hints complete?
   - Are docstrings clear?
   - Are tests comprehensive?

3. **Check for performance**:
   - Are there any performance bottlenecks?
   - Is resource usage reasonable?
   - Are there any unnecessary operations?

4. **Check for security**:
   - Are there any security vulnerabilities?
   - Is sensitive data handled properly?
   - Are inputs validated?

---

## Release Process

### Versioning

Use semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Release Checklist

Before creating a release:

- [ ] All tests pass
- [ ] Documentation is complete
- [ ] Changelog is updated
- [ ] Version is updated
- [ ] Release notes are prepared
- [ ] Tag is created

### Creating a Release

1. **Update version** in files:
   - [`vulnguard/configs/agent/config.yaml`](vulnguard/configs/agent/config.yaml)
   - [`setup.py`](setup.py)
   - [`README.md`](README.md)

2. **Update changelog**:

```markdown
## [1.0.1] - 2024-01-15

### Added
- New check type support
- Custom benchmark support

### Fixed
- Fixed backup directory creation issue
- Fixed command validation bug

### Changed
- Improved error messages
- Updated documentation

### Security
- Fixed potential command injection vulnerability
```

3. **Commit changes**:

```bash
git add .
git commit -m "chore: release v1.0.1"
```

4. **Create tag**:

```bash
git tag -a v1.0.1 -m "Release v1.0.1"
git push origin v1.0.1
```

5. **Create release on GitHub/GitLab**:
   - Go to releases page
   - Click "Create release"
   - Select tag
   - Add release notes
   - Publish release

---

## Contributing Guidelines

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Write tests**
5. **Update documentation**
6. **Submit a pull request**

### Contribution Areas

We welcome contributions in the following areas:

- **New benchmark rules**: Add support for more CIS and STIG rules
- **New check types**: Extend scanner with new check mechanisms
- **Bug fixes**: Fix reported issues
- **Documentation**: Improve documentation
- **Tests**: Add test coverage
- **Performance**: Improve performance
- **Security**: Fix security vulnerabilities

### Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

### Getting Help

- **Documentation**: Check [`README.md`](README.md) and [`docs/`](docs/)
- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact maintainers for sensitive issues

---

## Resources

### Documentation

- [API Documentation](docs/API.md)
- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [README](README.md)

### External Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [DISA STIGs](https://public.cyber.mil/stigs/)
- [Python Documentation](https://docs.python.org/3/)
- [PEP 8 Style Guide](https://peps.python.org/pep-0008/)

### Tools

- [Black](https://black.readthedocs.io/) - Code formatter
- [Flake8](https://flake8.pycqa.org/) - Linter
- [MyPy](https://mypy.readthedocs.io/) - Type checker
- [Pytest](https://docs.pytest.org/) - Testing framework
- [Click](https://click.palletsprojects.com/) - CLI framework

---

## License

[Specify your license here]
