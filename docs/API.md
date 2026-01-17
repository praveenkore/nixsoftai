# VulnGuard API Documentation

This document provides detailed API documentation for the VulnGuard Linux Security Compliance Agent.

## Table of Contents

- [Core Classes](#core-classes)
- [Scanner Module](#scanner-module)
- [Engine Module](#engine-module)
- [Advisor Module](#advisor-module)
- [Remediation Module](#remediation-module)
- [Logging Module](#logging-module)
- [Main Orchestrator](#main-orchestrator)

---

## Core Classes

### ScanResult

Represents the result of a single compliance scan.

```python
class ScanResult:
    def __init__(
        self,
        rule_id: str,
        benchmark: str,
        compliant: bool,
        expected_state: str,
        actual_state: str,
        check_output: str,
        error: Optional[str] = None
    )
```

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier (e.g., "cis_1_1_1", "stig_vuln_220278") |
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `compliant` | `bool` | Whether the system is compliant with the rule |
| `expected_state` | `str` | Expected state from the rule configuration |
| `actual_state` | `str` | Actual state found during the scan |
| `check_output` | `str` | Output from the check command |
| `error` | `Optional[str]` | Optional error message if scan failed |

**Methods:**

- [`to_dict()`](docs/API.md#scanresultto_dict) - Convert scan result to dictionary

#### ScanResult.to_dict()

Convert scan result to dictionary format.

```python
def to_dict(self) -> Dict[str, Any]
```

**Returns:** Dictionary representation of the scan result.

**Example:**
```python
result = ScanResult(
    rule_id="cis_1_1_1",
    benchmark="CIS",
    compliant=False,
    expected_state="not found",
    actual_state="found",
    check_output="install cramfs /bin/true"
)
result_dict = result.to_dict()
```

---

### EvaluationResult

Represents the result of a compliance evaluation.

```python
class EvaluationResult:
    def __init__(
        self,
        rule_id: str,
        benchmark: str,
        compliant: bool,
        severity: str,
        risk_level: str,
        ai_assist_required: bool,
        approval_required: bool,
        exception_allowed: bool
    )
```

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier |
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `compliant` | `bool` | Whether the system is compliant |
| `severity` | `str` | Normalized severity level (critical, high, medium, low) |
| `risk_level` | `str` | Risk level (critical, high, medium, low) |
| `ai_assist_required` | `bool` | Whether AI assistance is required |
| `approval_required` | `bool` | Whether approval is required for remediation |
| `exception_allowed` | `bool` | Whether exception is allowed for this rule |

**Methods:**

- [`to_dict()`](docs/API.md#evaluationresultto_dict) - Convert evaluation result to dictionary

#### EvaluationResult.to_dict()

Convert evaluation result to dictionary format.

```python
def to_dict(self) -> Dict[str, Any]
```

**Returns:** Dictionary representation of the evaluation result.

---

### AIAdvisory

Represents an AI advisory output.

```python
class AIAdvisory:
    def __init__(
        self,
        rule_id: str,
        compliance_status: str,
        risk_level: str,
        analysis: str,
        recommended_action: str,
        commands: List[str],
        rollback_commands: List[str],
        requires_restart: bool,
        requires_reboot: bool,
        confidence: float
    )
```

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier |
| `compliance_status` | `str` | Compliance status (compliant, non_compliant, requires_manual_review) |
| `risk_level` | `str` | Risk level (critical, high, medium, low) |
| `analysis` | `str` | AI analysis of the finding |
| `recommended_action` | `str` | Recommended action to take |
| `commands` | `List[str]` | List of recommended remediation commands |
| `rollback_commands` | `List[str]` | List of rollback commands |
| `requires_restart` | `bool` | Whether service restart is required |
| `requires_reboot` | `bool` | Whether system reboot is required |
| `confidence` | `float` | Confidence score (0.0 - 1.0) |

**Methods:**

- [`to_dict()`](docs/API.md#aiadvisoryto_dict) - Convert AI advisory to dictionary

#### AIAdvisory.to_dict()

Convert AI advisory to dictionary format.

```python
def to_dict(self) -> Dict[str, Any]
```

**Returns:** Dictionary representation of the AI advisory.

---

### RemediationResult

Represents the result of a remediation action.

```python
class RemediationResult:
    def __init__(
        self,
        rule_id: str,
        benchmark: str,
        success: bool,
        commands_executed: List[str],
        output: str,
        error: Optional[str] = None,
        rollback_commands: Optional[List[str]] = None,
        backup_path: Optional[str] = None
    )
```

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier |
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `success` | `bool` | Whether the remediation was successful |
| `commands_executed` | `List[str]` | List of commands that were executed |
| `output` | `str` | Combined output from commands |
| `error` | `Optional[str]` | Optional error message |
| `rollback_commands` | `List[str]` | List of rollback commands |
| `backup_path` | `str` | Path to backup directory |

**Methods:**

- [`to_dict()`](docs/API.md#remediationresultto_dict) - Convert remediation result to dictionary

#### RemediationResult.to_dict()

Convert remediation result to dictionary format.

```python
def to_dict(self) -> Dict[str, Any]
```

**Returns:** Dictionary representation of the remediation result.

---

## Scanner Module

### Scanner

Deterministic audit engine for security compliance checks.

```python
class Scanner:
    def __init__(
        self,
        benchmark_dir: str = "vulnguard/configs/benchmarks",
        logger: Optional[AuditLogger] = None
    )
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `benchmark_dir` | `str` | `"vulnguard/configs/benchmarks"` | Directory containing benchmark rule files |
| `logger` | `Optional[AuditLogger]` | `None` | Optional audit logger instance |

**Methods:**

#### Scanner.scan_rule()

Scan a single benchmark rule.

```python
def scan_rule(self, rule_id: str) -> Optional[ScanResult]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier (e.g., "cis_1_1_1" or "stig_vuln_12345") |

**Returns:** [`ScanResult`](docs/API.md#scanresult) object, or `None` if scanning fails.

**Example:**
```python
scanner = Scanner(benchmark_dir="vulnguard/configs/benchmarks")
result = scanner.scan_rule("cis_1_1_1")
if result:
    print(f"Rule {result.rule_id} is {'compliant' if result.compliant else 'non-compliant'}")
```

#### Scanner.scan_all()

Scan all available benchmark rules.

```python
def scan_all(self, rule_ids: Optional[List[str]] = None) -> List[ScanResult]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rule_ids` | `Optional[List[str]]` | `None` | Optional list of rule IDs to scan. If `None`, scans all rules. |

**Returns:** List of [`ScanResult`](docs/API.md#scanresult) objects.

**Example:**
```python
scanner = Scanner()
# Scan all rules
all_results = scanner.scan_all()
# Scan specific rules
specific_results = scanner.scan_all(rule_ids=["cis_1_1_1", "stig_vuln_220278"])
```

---

## Engine Module

### ComplianceEngine

Compliance and risk decision engine.

```python
class ComplianceEngine:
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        severity_mapping: Optional[Dict[str, Dict[str, str]]] = None
    )
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `logger` | `Optional[AuditLogger]` | `None` | Optional audit logger instance |
| `severity_mapping` | `Optional[Dict[str, Dict[str, str]]]` | `None` | Optional custom severity mapping |

**Default Severity Mapping:**

```python
SEVERITY_MAPPING = {
    'CIS': {
        'Level1': 'high',
        'Level2': 'medium',
        'Level3': 'low'
    },
    'STIG': {
        'CAT_I': 'critical',
        'CAT_II': 'high',
        'CAT_III': 'medium'
    }
}
```

**Methods:**

#### ComplianceEngine.evaluate()

Evaluate a scan result and determine compliance status and risk level.

```python
def evaluate(
    self,
    scan_result: ScanResult,
    rule_data: Optional[Dict[str, Any]] = None
) -> EvaluationResult
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_result` | [`ScanResult`](docs/API.md#scanresult) | Required | Scan result from the scanner |
| `rule_data` | `Optional[Dict[str, Any]]` | `None` | Optional rule configuration data |

**Returns:** [`EvaluationResult`](docs/API.md#evaluationresult) object.

**Example:**
```python
engine = ComplianceEngine()
scan_result = scanner.scan_rule("cis_1_1_1")
eval_result = engine.evaluate(scan_result)
print(f"Risk level: {eval_result.risk_level}")
```

#### ComplianceEngine.evaluate_batch()

Evaluate multiple scan results.

```python
def evaluate_batch(self, scan_results: List[ScanResult]) -> List[EvaluationResult]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_results` | `List[ScanResult]` | List of scan results |

**Returns:** List of [`EvaluationResult`](docs/API.md#evaluationresult) objects.

**Example:**
```python
scan_results = scanner.scan_all()
eval_results = engine.evaluate_batch(scan_results)
```

#### ComplianceEngine.generate_summary()

Generate a summary of evaluation results.

```python
def generate_summary(
    self,
    evaluation_results: List[EvaluationResult]
) -> Dict[str, Any]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `evaluation_results` | `List[EvaluationResult]` | List of evaluation results |

**Returns:** Summary dictionary with the following keys:
- `total_rules`: Total number of rules evaluated
- `compliant_count`: Number of compliant rules
- `non_compliant_count`: Number of non-compliant rules
- `compliance_percentage`: Compliance percentage
- `risk_distribution`: Distribution of risk levels
- `severity_distribution`: Distribution of severity levels
- `benchmark_distribution`: Distribution by benchmark type
- `approval_required_count`: Number of rules requiring approval
- `ai_assist_required_count`: Number of rules requiring AI assistance

**Example:**
```python
summary = engine.generate_summary(eval_results)
print(f"Compliance: {summary['compliance_percentage']}%")
print(f"Critical issues: {summary['risk_distribution']['critical']}")
```

---

## Advisor Module

### AIAdvisor

AI gateway and safety validator.

```python
class AIAdvisor:
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        min_confidence_threshold: float = 0.7,
        command_allowlist: Optional[List[str]] = None,
        command_blocklist: Optional[List[str]] = None
    )
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `logger` | `Optional[AuditLogger]` | `None` | Optional audit logger instance |
| `min_confidence_threshold` | `float` | `0.7` | Minimum confidence threshold (0.0 - 1.0) |
| `command_allowlist` | `Optional[List[str]]` | `None` | Optional custom command allow-list |
| `command_blocklist` | `Optional[List[str]]` | `None` | Optional custom command block-list |

**Default Command Allow-List:**

```python
DEFAULT_COMMAND_ALLOWLIST = [
    r'^systemctl\s+(enable|disable|start|stop|restart|status)\s+[a-zA-Z0-9_-]+$',
    r'^sysctl\s+-w\s+[a-zA-Z0-9._-]+=.+$',
    r'^chmod\s+[0-7]{3,4}\s+[a-zA-Z0-9_./-]+$',
    r'^chown\s+[a-zA-Z0-9_:.-]+\s+[a-zA-Z0-9_./-]+$',
    r'^sed\s+-i\s+.+\s+[a-zA-Z0-9_./-]+$',
    r'^echo\s+.+\s*>>?\s*[a-zA-Z0-9_./-]+$'
]
```

**Default Command Block-List:**

```python
COMMAND_BLOCKLIST = [
    r'rm\s+-rf',
    r'chmod\s+777',
    r'userdel',
    r'groupdel',
    r'passwd\s+-l\s+root',
    r'setenforce\s+0'
]
```

**Methods:**

#### AIAdvisor.get_advisory()

Get AI advisory for a rule.

```python
def get_advisory(
    self,
    rule_id: str,
    scan_result: ScanResult,
    evaluation_result: EvaluationResult
) -> tuple[Optional[AIAdvisory], str]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier |
| `scan_result` | [`ScanResult`](docs/API.md#scanresult) | Scan result from the scanner |
| `evaluation_result` | [`EvaluationResult`](docs/API.md#evaluationresult) | Evaluation result from the engine |

**Returns:** Tuple of ([`AIAdvisory`](docs/API.md#aiadvisory) object or `None`, error message)

**Example:**
```python
advisor = AIAdvisor(min_confidence_threshold=0.8)
advisory, error = advisor.get_advisory(rule_id, scan_result, eval_result)
if advisory:
    print(f"Confidence: {advisory.confidence}")
    print(f"Recommended action: {advisory.recommended_action}")
else:
    print(f"Error: {error}")
```

#### AIAdvisor.requires_manual_review()

Determine if manual review is required.

```python
def requires_manual_review(
    self,
    evaluation_result: EvaluationResult,
    ai_advisory: Optional[AIAdvisory] = None
) -> bool
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `evaluation_result` | [`EvaluationResult`](docs/API.md#evaluationresult) | Required | Evaluation result from the engine |
| `ai_advisory` | `Optional[AIAdvisory]` | `None` | Optional AI advisory |

**Returns:** `True` if manual review is required, `False` otherwise.

---

## Remediation Module

### RemediationEngine

Reversible remediation engine with safety controls.

```python
class RemediationEngine:
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        backup_directory: str = "/var/lib/vulnguard/backups",
        auto_backup: bool = True,
        rollback_on_failure: bool = True,
        command_allowlist: Optional[List[str]] = None,
        command_blocklist: Optional[List[str]] = None
    )
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `logger` | `Optional[AuditLogger]` | `None` | Optional audit logger instance |
| `backup_directory` | `str` | `"/var/lib/vulnguard/backups"` | Directory for storing backups |
| `auto_backup` | `bool` | `True` | Whether to automatically backup before remediation |
| `rollback_on_failure` | `bool` | `True` | Whether to automatically rollback on failure |
| `command_allowlist` | `Optional[List[str]]` | `None` | Optional custom command allow-list |
| `command_blocklist` | `Optional[List[str]]` | `None` | Optional custom command block-list |

**Methods:**

#### RemediationEngine.remediate()

Apply remediation for a non-compliant rule.

```python
def remediate(
    self,
    scan_result: ScanResult,
    evaluation_result: EvaluationResult,
    ai_advisory: Optional[AIAdvisory] = None,
    mode: str = "dry-run",
    force: bool = False
) -> RemediationResult
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_result` | [`ScanResult`](docs/API.md#scanresult) | Required | Scan result from the scanner |
| `evaluation_result` | [`EvaluationResult`](docs/API.md#evaluationresult) | Required | Evaluation result from the engine |
| `ai_advisory` | `Optional[AIAdvisory]` | `None` | Optional AI advisory with remediation commands |
| `mode` | `str` | `"dry-run"` | Remediation mode (`"dry-run"` or `"commit"`) |
| `force` | `bool` | `False` | Force remediation even if approval is required |

**Returns:** [`RemediationResult`](docs/API.md#remediationresult) object.

**Example:**
```python
remediation = RemediationEngine(auto_backup=True)
result = remediation.remediate(
    scan_result=scan_result,
    evaluation_result=eval_result,
    mode="dry-run"
)
if result.success:
    print("Remediation successful")
else:
    print(f"Remediation failed: {result.error}")
```

#### RemediationEngine.remediate_batch()

Apply remediation for multiple non-compliant rules.

```python
def remediate_batch(
    self,
    scan_results: List[ScanResult],
    evaluation_results: List[EvaluationResult],
    ai_advisories: List[AIAdvisory],
    mode: str = "dry-run",
    force: bool = False
) -> List[RemediationResult]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_results` | `List[ScanResult]` | Required | List of scan results |
| `evaluation_results` | `List[EvaluationResult]` | Required | List of evaluation results |
| `ai_advisories` | `List[AIAdvisory]` | Required | List of AI advisories |
| `mode` | `str` | `"dry-run"` | Remediation mode (`"dry-run"` or `"commit"`) |
| `force` | `bool` | `False` | Force remediation even if approval is required |

**Returns:** List of [`RemediationResult`](docs/API.md#remediationresult) objects.

---

## Logging Module

### AuditLogger

Structured audit logger for VulnGuard operations.

```python
class AuditLogger:
    def __init__(
        self,
        log_file: str = "/var/log/vulnguard/audit.log",
        log_level: str = "INFO",
        log_format: str = "json",
        max_size_mb: int = 100,
        backup_count: int = 10
    )
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `log_file` | `str` | `"/var/log/vulnguard/audit.log"` | Path to the log file |
| `log_level` | `str` | `"INFO"` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `log_format` | `str` | `"json"` | Log format (json or text) |
| `max_size_mb` | `int` | `100` | Maximum size of log file in MB before rotation |
| `backup_count` | `int` | `10` | Number of backup files to keep |

**Methods:**

#### AuditLogger.log_scan_start()

Log the start of a compliance scan.

```python
def log_scan_start(
    self,
    benchmark: str,
    rule_id: str,
    system_info: Optional[Dict[str, Any]] = None
) -> None
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `benchmark` | `str` | Required | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Required | Rule identifier |
| `system_info` | `Optional[Dict[str, Any]]` | `None` | Optional system information |

#### AuditLogger.log_scan_result()

Log the result of a compliance scan.

```python
def log_scan_result(
    self,
    benchmark: str,
    rule_id: str,
    compliant: bool,
    expected_state: str,
    actual_state: str,
    check_output: str
) -> None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Rule identifier |
| `compliant` | `bool` | Whether the system is compliant |
| `expected_state` | `str` | Expected state from the rule |
| `actual_state` | `str` | Actual state found |
| `check_output` | `str` | Output from the check command |

#### AuditLogger.log_evaluation()

Log the compliance evaluation result.

```python
def log_evaluation(
    self,
    benchmark: str,
    rule_id: str,
    severity: str,
    risk_level: str,
    ai_assist_required: bool
) -> None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Rule identifier |
| `severity` | `str` | Normalized severity level |
| `risk_level` | `str` | Risk level (low, medium, high, critical) |
| `ai_assist_required` | `bool` | Whether AI assistance is required |

#### AuditLogger.log_ai_advisory()

Log AI advisory output.

```python
def log_ai_advisory(
    self,
    rule_id: str,
    confidence: float,
    recommendation: str,
    commands: Optional[list] = None
) -> None
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rule_id` | `str` | Required | Rule identifier |
| `confidence` | `float` | Required | Confidence score (0.0 - 1.0) |
| `recommendation` | `str` | Required | AI recommendation |
| `commands` | `Optional[list]` | `None` | Optional list of recommended commands |

#### AuditLogger.log_remediation_start()

Log the start of a remediation action.

```python
def log_remediation_start(
    self,
    benchmark: str,
    rule_id: str,
    mode: str,
    commands: list
) -> None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Rule identifier |
| `mode` | `str` | Remediation mode (dry-run or commit) |
| `commands` | `list` | List of commands to execute |

#### AuditLogger.log_remediation_result()

Log the result of a remediation action.

```python
def log_remediation_result(
    self,
    benchmark: str,
    rule_id: str,
    success: bool,
    output: str,
    error: Optional[str] = None
) -> None
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `benchmark` | `str` | Required | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Required | Rule identifier |
| `success` | `bool` | Required | Whether the remediation was successful |
| `output` | `str` | Required | Command output |
| `error` | `Optional[str]` | `None` | Optional error message |

#### AuditLogger.log_rollback()

Log a rollback action.

```python
def log_rollback(
    self,
    benchmark: str,
    rule_id: str,
    reason: str,
    commands: list
) -> None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Rule identifier |
| `reason` | `str` | Reason for rollback |
| `commands` | `list` | List of rollback commands executed |

#### AuditLogger.log_backup()

Log a configuration backup action.

```python
def log_backup(
    self,
    benchmark: str,
    rule_id: str,
    backup_path: str,
    files_backed_up: list
) -> None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Rule identifier |
| `backup_path` | `str` | Path to backup directory |
| `files_backed_up` | `list` | List of files that were backed up |

#### AuditLogger.log_approval_request()

Log an approval request.

```python
def log_approval_request(
    self,
    benchmark: str,
    rule_id: str,
    severity: str,
    reason: str
) -> None
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `benchmark` | `str` | Benchmark type (CIS or STIG) |
| `rule_id` | `str` | Rule identifier |
| `severity` | `str` | Severity level |
| `reason` | `str` | Reason approval is required |

#### AuditLogger.log_error()

Log an error event.

```python
def log_error(
    self,
    event_type: str,
    error_message: str,
    context: Optional[Dict[str, Any]] = None
) -> None
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `event_type` | `str` | Required | Type of event where error occurred |
| `error_message` | `str` | Required | Error message |
| `context` | `Optional[Dict[str, Any]]` | `None` | Optional context information |

#### AuditLogger.log_system_info()

Log system information at the start of a scan.

```python
def log_system_info(
    self,
    os_name: str,
    os_version: str,
    hostname: str,
    additional_info: Optional[Dict[str, Any]] = None
) -> None
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `os_name` | `str` | Required | Operating system name |
| `os_version` | `str` | Required | Operating system version |
| `hostname` | `str` | Required | System hostname |
| `additional_info` | `Optional[Dict[str, Any]]` | `None` | Additional system information |

---

## Main Orchestrator

### VulnGuardOrchestrator

Main orchestrator for VulnGuard operations.

```python
class VulnGuardOrchestrator:
    def __init__(
        self,
        config_path: str = "vulnguard/configs/agent/config.yaml",
        benchmark_dir: str = "vulnguard/configs/benchmarks",
        log_file: str = "/var/log/vulnguard/audit.log"
    )
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_path` | `str` | `"vulnguard/configs/agent/config.yaml"` | Path to the agent configuration file |
| `benchmark_dir` | `str` | `"vulnguard/configs/benchmarks"` | Directory containing benchmark rules |
| `log_file` | `str` | `"/var/log/vulnguard/audit.log"` | Path to the audit log file |

**Methods:**

#### VulnGuardOrchestrator.run_scan()

Run the complete VulnGuard pipeline: scan, evaluate, and optionally get AI advisory.

```python
def run_scan(
    self,
    rule_ids: Optional[List[str]] = None
) -> tuple[List[ScanResult], List[EvaluationResult], List[AIAdvisory]]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rule_ids` | `Optional[List[str]]` | `None` | Optional list of rule IDs to scan. If `None`, scans all rules. |

**Returns:** Tuple of (scan_results, evaluation_results, ai_advisories)

**Example:**
```python
orchestrator = VulnGuardOrchestrator()
scan_results, eval_results, ai_advisories = orchestrator.run_scan()
```

#### VulnGuardOrchestrator.run_remediation()

Run remediation for non-compliant rules.

```python
def run_remediation(
    self,
    scan_results: List[ScanResult],
    evaluation_results: List[EvaluationResult],
    ai_advisories: List[AIAdvisory],
    mode: str = "dry-run",
    force: bool = False
) -> List[RemediationResult]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_results` | `List[ScanResult]` | Required | List of scan results |
| `evaluation_results` | `List[EvaluationResult]` | Required | List of evaluation results |
| `ai_advisories` | `List[AIAdvisory]` | Required | List of AI advisories |
| `mode` | `str` | `"dry-run"` | Remediation mode (dry-run or commit) |
| `force` | `bool` | `False` | Force remediation even if approval is required |

**Returns:** List of [`RemediationResult`](docs/API.md#remediationresult) objects.

**Example:**
```python
scan_results, eval_results, ai_advisories = orchestrator.run_scan()
remediation_results = orchestrator.run_remediation(
    scan_results=scan_results,
    evaluation_results=eval_results,
    ai_advisories=ai_advisories,
    mode="dry-run"
)
```

#### VulnGuardOrchestrator.generate_report()

Generate a compliance report.

```python
def generate_report(
    self,
    scan_results: List[ScanResult],
    evaluation_results: List[EvaluationResult],
    remediation_results: Optional[List[RemediationResult]] = None,
    output_format: str = "json"
) -> str
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_results` | `List[ScanResult]` | Required | List of scan results |
| `evaluation_results` | `List[EvaluationResult]` | Required | List of evaluation results |
| `remediation_results` | `Optional[List[RemediationResult]]` | `None` | Optional list of remediation results |
| `output_format` | `str` | `"json"` | Output format (json, yaml, text) |

**Returns:** Formatted report string.

**Example:**
```python
report = orchestrator.generate_report(
    scan_results=scan_results,
    evaluation_results=eval_results,
    output_format="json"
)
print(report)
```

---

## CLI Interface

The VulnGuard CLI is built using Click and provides the following commands:

### scan

Scan system for compliance issues.

```bash
python -m vulnguard.main scan [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--rule-id` | `-r` | Specific rule ID(s) to scan. Can be specified multiple times. |
| `--output` | `-o` | Output file path for the report. |
| `--format` | `-f` | Output format (json, yaml, text). Default: json. |

**Examples:**

```bash
# Scan all rules
python -m vulnguard.main scan

# Scan specific rules
python -m vulnguard.main scan -r cis_1_1_1 -r stig_vuln_220278

# Save report to file
python -m vulnguard.main scan -o report.json

# Specify output format
python -m vulnguard.main scan -f text
```

### remediate

Remediate non-compliant security issues.

```bash
python -m vulnguard.main remediate [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--rule-id` | `-r` | Specific rule ID(s) to remediate. Can be specified multiple times. |
| `--mode` | `-m` | Remediation mode (dry-run or commit). Default: dry-run. |
| `--force` | | Force remediation even if approval is required. |
| `--output` | `-o` | Output file path for the report. |
| `--format` | `-f` | Output format (json, yaml, text). Default: json. |

**Examples:**

```bash
# Dry-run remediation (recommended first step)
python -m vulnguard.main remediate --mode dry-run

# Dry-run specific rules
python -m vulnguard.main remediate -r cis_1_1_1 --mode dry-run

# Commit remediation (after reviewing dry-run output)
python -m vulnguard.main remediate --mode commit

# Force remediation (bypass approval requirements)
python -m vulnguard.main remediate --mode commit --force

# Save remediation report
python -m vulnguard.main remediate -o remediation_report.json
```

### list-rules

List available benchmark rules.

```bash
python -m vulnguard.main list-rules [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--benchmark-dir` | `-b` | Directory containing benchmark rules. Default: vulnguard/configs/benchmarks. |

**Example:**

```bash
python -m vulnguard.main list-rules
```

### version

Display VulnGuard version information.

```bash
python -m vulnguard.main version
```

**Example:**

```bash
python -m vulnguard.main version
```

---

## Usage Examples

### Complete Workflow Example

```python
from vulnguard.main import VulnGuardOrchestrator

# Initialize orchestrator
orchestrator = VulnGuardOrchestrator()

# Run scan
scan_results, eval_results, ai_advisories = orchestrator.run_scan()

# Generate report
report = orchestrator.generate_report(
    scan_results=scan_results,
    evaluation_results=eval_results,
    output_format="json"
)
print(report)

# Run remediation in dry-run mode
remediation_results = orchestrator.run_remediation(
    scan_results=scan_results,
    evaluation_results=eval_results,
    ai_advisories=ai_advisories,
    mode="dry-run"
)

# Review dry-run output and then commit if satisfied
remediation_results = orchestrator.run_remediation(
    scan_results=scan_results,
    evaluation_results=eval_results,
    ai_advisories=ai_advisories,
    mode="commit"
)
```

### Custom Configuration Example

```python
from vulnguard.main import VulnGuardOrchestrator
from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.scanner.scanner import Scanner
from vulnguard.pkg.engine.engine import ComplianceEngine
from vulnguard.pkg.advisor.advisor import AIAdvisor
from vulnguard.pkg.remediation.remediation import RemediationEngine

# Custom logger
logger = AuditLogger(
    log_file="/var/log/vulnguard/custom.log",
    log_level="DEBUG",
    log_format="json"
)

# Custom scanner
scanner = Scanner(
    benchmark_dir="/path/to/benchmarks",
    logger=logger
)

# Custom engine
engine = ComplianceEngine(
    logger=logger,
    severity_mapping={
        'CIS': {
            'Level1': 'critical',
            'Level2': 'high',
            'Level3': 'medium'
        }
    }
)

# Custom advisor
advisor = AIAdvisor(
    logger=logger,
    min_confidence_threshold=0.9,
    command_allowlist=[
        r'^systemctl\s+(enable|disable|start|stop|restart|status)\s+[a-zA-Z0-9_-]+$'
    ]
)

# Custom remediation engine
remediation = RemediationEngine(
    logger=logger,
    backup_directory="/var/lib/vulnguard/custom_backups",
    auto_backup=True,
    rollback_on_failure=True
)

# Use components individually
scan_result = scanner.scan_rule("cis_1_1_1")
eval_result = engine.evaluate(scan_result)
if eval_result.ai_assist_required:
    advisory, error = advisor.get_advisory(
        rule_id=scan_result.rule_id,
        scan_result=scan_result,
        evaluation_result=eval_result
    )
remediation_result = remediation.remediate(
    scan_result=scan_result,
    evaluation_result=eval_result,
    mode="dry-run"
)
```

---

## Error Handling

All methods in the VulnGuard API follow these error handling patterns:

1. **Scanner methods** return `None` on failure and log errors
2. **Engine methods** return default values on failure and log errors
3. **Advisor methods** return `(None, error_message)` tuples on failure
4. **Remediation methods** return [`RemediationResult`](docs/API.md#remediationresult) objects with `success=False` on failure
5. **Logger methods** log all errors to the audit log

Always check return values and handle errors appropriately in production code.

---

## License

[Specify your license here]
