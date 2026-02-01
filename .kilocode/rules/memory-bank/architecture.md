# VulnGuard Architecture

## System Architecture

VulnGuard follows a layered architecture with clear separation of concerns, designed for security, reliability, and maintainability in regulated environments.

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
│  ┌───────────────────────────────────────────────────────┐      │
│  │              Security Module (Phase 1)               │      │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────┐ │      │
│  │  │  Command     │ │  File        │ │ Atomic   │ │      │
│  │  │  Executor   │ │ Permissions  │ │ Operations│ │      │
│  │  └──────────────┘ └──────────────┘ └──────────┘ │      │
│  └───────────────────────────────────────────────────────┘      │
│                                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Layered Architecture

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
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   Security Layer (Phase 1)                 │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │  Command     │ │  File        │ │ Atomic       │ │
│  │  Executor   │ │ Permissions  │ │ Operations  │ │
│  │ (No Shell)  │ │ (0600/0700) │ │ (TOCTOU)     │ │
│  └──────────────┘ └──────────────┘ └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Source Code Paths

### Project Structure

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
│   │   ├── advisor.py              # Advisor implementation
│   │   ├── llm_client.py          # LLM client abstraction
│   │   └── prompts.py             # AI prompt templates
│   ├── remediation/                  # Reversible Remediation Engine
│   │   ├── __init__.py
│   │   └── remediation.py         # Remediation implementation
│   ├── logging/                      # Structured Audit Logger
│   │   ├── __init__.py
│   │   └── logger.py               # Logger implementation
│   └── security/                     # Phase 1 Security Module
│       ├── __init__.py
│       ├── command_executor.py        # Secure command executor
│       ├── file_permissions.py        # Secure file permissions
│       ├── atomic_operations.py      # Atomic file operations
│       ├── command_validation.py    # Command validation utilities
│       └── path_validator.py        # Secure path validation utilities
├── configs/                         # Configuration files
│   ├── agent/                       # Global agent config
│   │   └── config.yaml
│   └── benchmarks/                  # CIS / STIG YAML rules
│       ├── cis_1_1_1.yaml
│       └── stig_vuln_220278.yaml
└── requirements.txt                  # Python dependencies
```

### Key File Locations

| Component | File Path | Purpose |
|-----------|-------------|---------|
| Main Orchestrator | [`vulnguard/main.py`](../vulnguard/main.py) | CLI interface and component coordination |
| Scanner | [`vulnguard/pkg/scanner/scanner.py`](../vulnguard/pkg/scanner/scanner.py) | Deterministic compliance checking |
| Engine | [`vulnguard/pkg/engine/engine.py`](../vulnguard/pkg/engine/engine.py) | Compliance evaluation and risk assessment |
| Advisor | [`vulnguard/pkg/advisor/advisor.py`](../vulnguard/pkg/advisor/advisor.py) | AI advisory with safety validation |
| LLM Client | [`vulnguard/pkg/advisor/llm_client.py`](../vulnguard/pkg/advisor/llm_client.py) | Multi-provider LLM integration |
| Remediation | [`vulnguard/pkg/remediation/remediation.py`](../vulnguard/pkg/remediation/remediation.py) | Safe, reversible remediation |
| Logger | [`vulnguard/pkg/logging/logger.py`](../vulnguard/pkg/logging/logger.py) | Structured audit logging |
| Command Executor | [`vulnguard/pkg/security/command_executor.py`](../vulnguard/pkg/security/command_executor.py) | Secure command execution |
| File Permissions | [`vulnguard/pkg/security/file_permissions.py`](../vulnguard/pkg/security/file_permissions.py) | Secure file permission management |
| Atomic Operations | [`vulnguard/pkg/security/atomic_operations.py`](../vulnguard/pkg/security/atomic_operations.py) | Atomic file operations |
| Path Validator | [`vulnguard/pkg/security/path_validator.py`](../vulnguard/pkg/security/path_validator.py) | Centralized secure path validation |
| Configuration | [`vulnguard/configs/agent/config.yaml`](../vulnguard/configs/agent/config.yaml) | Global agent configuration |
| Benchmark Rules | [`vulnguard/configs/benchmarks/`](../vulnguard/configs/benchmarks/) | CIS and STIG rule definitions |

## Component Architecture

### 1. Scanner Module

**Purpose:** Deterministic audit engine for security compliance checks

**Key Classes:**
- [`Scanner`](../vulnguard/pkg/scanner/scanner.py:65) - Main scanner class
- [`ScanResult`](../vulnguard/pkg/scanner/scanner.py:17) - Scan result data structure

**Responsibilities:**
- Load and validate benchmark rule configurations
- Execute defined check commands (command, file, service, sysctl)
- Validate results against expected states
- Determine compliance status
- OS compatibility checking

**Design Decisions:**
- No AI integration in scanner - all checks are deterministic
- Strict rule validation before execution
- OS compatibility filtering

- Timeout protection for all commands
- **Parallel Execution**: Uses `ThreadPoolExecutor` for concurrent rule scanning (IO-bound)
- **Caching**: In-memory LRU caching of rule definitions to optimize repeated loads

**Supported Check Types:**
- **Command**: Execute shell commands and check exit codes
- **File**: Validate file content, permissions, and ownership
- **Service**: Check service status (enabled/active)
- **Sysctl**: Verify kernel parameter values

### 2. Engine Module

**Purpose:** Compliance and risk decision engine

**Key Classes:**
- [`ComplianceEngine`](../vulnguard/pkg/engine/engine.py:65) - Main evaluation engine
- [`EvaluationResult`](../vulnguard/pkg/engine/engine.py:13) - Evaluation result data structure

**Responsibilities:**
- Normalize severities across benchmark standards
- Determine risk levels based on severity and compliance
- Decide if AI assistance is required
- Determine approval requirements
- Generate compliance summaries

**Design Decisions:**
- Centralized severity mapping for consistency
- Risk level based on both severity and compliance status
- AI assist only for ambiguous cases
- Approval gating for high-risk rules

**Severity Normalization:**

| Benchmark | Original | Normalized |
|-----------|-----------|------------|
| CIS | Level 1 | high |
| CIS | Level 2 | medium |
| CIS | Level 3 | low |
| STIG | CAT I | critical |
| STIG | CAT II | high |
| STIG | CAT III | medium |

### 3. Advisor Module

**Purpose:** AI gateway and safety validator

**Key Classes:**
- [`AIAdvisor`](../vulnguard/pkg/advisor/advisor.py:76) - AI advisor with safety validation
- [`AIAdvisory`](../vulnguard/pkg/advisor/advisor.py:16) - AI advisory data structure
- [`BaseLLMClient`](../vulnguard/pkg/advisor/llm_client.py:220) - Abstract base for LLM clients
- [`OpenRouterClient`](../vulnguard/pkg/advisor/llm_client.py:296) - OpenRouter API client
- [`OpenAIClient`](../vulnguard/pkg/advisor/llm_client.py:439) - OpenAI API client
- [`AnthropicClient`](../vulnguard/pkg/advisor/llm_client.py:568) - Anthropic API client
- [`OllamaClient`](../vulnguard/pkg/advisor/llm_client.py:698) - Ollama API client
- [`LocalLLMClient`](../vulnguard/pkg/advisor/llm_client.py:828) - Local LLM client
- [`MockLLMClient`](../vulnguard/pkg/advisor/llm_client.py:958) - Mock client for testing

**Responsibilities:**
- Provide AI assistance for ambiguous findings
- Validate all AI output against safety controls
- Enforce confidence thresholds
- Validate commands against allow-list/block-list
- Never execute commands directly

**Safety Validation:**
- JSON schema validation
- Required field verification
- Confidence threshold checking (default: 0.7)
- Command allow-list validation
- Command block-list validation
- Data type validation

**Design Decisions:**
- AI is advisory only, never executes directly
- All output must pass strict validation
- Confidence threshold prevents low-quality recommendations
- Command allow-list/block-list prevents dangerous operations

- Manual review required for low-confidence advisories
- **Resource Management**: HTTP client pool eviction to prevent memory leaks

### 4. Remediation Module

**Purpose:** Reversible remediation engine with safety controls

**Key Classes:**
- [`RemediationEngine`](../vulnguard/pkg/remediation/remediation.py:73) - Remediation engine with safety controls
- [`RemediationResult`](../vulnguard/pkg/remediation/remediation.py:21) - Remediation result data structure

**Responsibilities:**
- Apply security fixes with automatic backup
- Execute remediation commands in dry-run or commit mode
- Automatic rollback on failure
- Validate all commands against allow-list/block-list
- Maintain audit trail of all changes

**Safety Features:**
- **Automatic Backup**: Backs up files before modification
- **Dry-Run Mode**: Default mode shows what would be done without executing
- **Rollback on Failure**: Automatically reverts changes on failure
- **Command Validation**: All commands validated against allow-list/block-list
- **Approval Gating**: Requires approval for high-risk changes

**Design Decisions:**
- Every remediation is reversible
- Dry-run by default for safety
- Automatic backup before any changes
- Rollback on failure prevents partial states
- Strict command validation

### 5. Logging Module

**Purpose:** Structured audit logger for all operations

**Key Classes:**
- [`AuditLogger`](../vulnguard/pkg/logging/logger.py:17) - Structured audit logger

**Responsibilities:**
- Log all operations in JSON-line format
- Provide structured, parseable audit trail
- Support log rotation
- Multiple output formats (JSON, text)

**Log Event Types:**
- `scan_start`: Beginning of a compliance scan
- `scan_result`: Result of a compliance check
- `evaluation`: Compliance evaluation and risk level
- `ai_advisory`: AI recommendation output
- `remediation_start`: Beginning of remediation
- `remediation_result`: Result of remediation
- `rollback`: Rollback execution
- `backup`: Configuration backup

### 6. Plugin Module (New)

**Purpose:** Capability-based extension system

**Key Classes:**
- [`IPlugin`](../vulnguard/pkg/plugins/interface.py) - Abstract Plugin Interface
- [`PluginContext`](../vulnguard/pkg/plugins/context.py) - Secure Sandbox Context
- [`PluginManager`](../vulnguard/pkg/plugins/manager.py) - Lifecycle & Loading Manager

**Responsibilities:**
- Securely load external functionality
- Enforce "Least Privilege" via Capability Manifests
- Sandbox file and command execution

**Security Controls:**
- **Proxies**: Plugins interact with `SecureFileSystemProxy` and `SecureExecutionProxy`, not `os` or `subprocess`.
- **Manifests**: Explicitly declared capabilities (e.g., `FILE_READ: ["/var/log"]`).
- **Signing**: Plugins must be digitally signed (verification enforced by Manager).

### 7. Gateway Module (New)

**Purpose:** Centralized reporting and management

**Key Classes:**
- [`GatewayClient`](../vulnguard/pkg/gateway/client.py) - HTTPS client for reporting
- [`GatewayError`](../vulnguard/pkg/gateway/exceptions.py) - Gateway-specific exceptions

**Responsibilities:**
- Push compliance reports in JSON format to C2 server
- Handle secure authentication (mTLS/API Key)
- Provide retry and error handling for unreliable connections

**Security Controls:**
- **Encryption**: TLS 1.3 for all data in transit.
- **Verification**: Mandatory SSL certificate validation.
- **Authentication**: Pre-shared API keys or certificate-based auth.

- `approval_request`: Approval requirement
- `error`: Error events
- `system_info`: System information at scan start

**Design Decisions:**
- JSON-line format for easy parsing
- Structured data with consistent schema
- Log rotation to prevent disk space issues
- Both file and console output
- Complete context in every log entry

### 6. Security Module (Phase 1)

**Purpose:** Critical security fixes providing secure foundations for all operations

**Key Classes:**
- [`SecureCommandExecutor`](../vulnguard/pkg/security/command_executor.py:47) - Secure command executor with no shell=True
- [`SecureFilePermissions`](../vulnguard/pkg/security/file_permissions.py:41) - Secure file and directory permission manager
- [`AtomicFileOperations`](../vulnguard/pkg/security/atomic_operations.py:41) - Atomic file operations to prevent TOCTOU
- [`CommandValidator`](../vulnguard/pkg/security/command_validation.py:13) - Command validation utilities
- [`PathValidator`](../vulnguard/pkg/security/path_validator.py) - Centralized secure path validation

**Responsibilities:**
- Eliminate command injection vulnerabilities through secure command execution
- Enforce secure file and directory permissions
- Prevent TOCTOU (Time-of-Check Time-of-Use) vulnerabilities with atomic operations
- Prevent Path Traversal and Symlink attacks
- Provide audit logging for all security operations
- Support lazy loading to avoid circular dependencies

**Security Features:**

#### Command Execution Security ([`SecureCommandExecutor`](../vulnguard/pkg/security/command_executor.py:47))
- **Never uses shell=True** - All commands executed with `shell=False`
- **Parameterized execution** - Commands passed as list of arguments
- **Allow-list enforcement** - Only approved commands can execute
- **Block-list enforcement** - Dangerous patterns explicitly blocked
- **Input sanitization** - All inputs validated and sanitized
- **Audit logging** - All command executions logged

**Default Allow-List:**
```python
DEFAULT_COMMAND_ALLOWLIST = [
    r'^systemctl$',
    r'^sysctl$',
    r'^chmod$',
    r'^chown$',
    r'^sed$',
    r'^echo$',
    r'^cat$',
    r'^grep$',
    r'^awk$',
    r'^stat$',
    r'^ls$',
    r'^find$',
    r'^test$',
    r'\[',
    r'^which$',
    r'^id$',
    r'^whoami$',
    r'^hostname$',
    r'^uname$',
    r'^df$',
    r'^du$',
    r'^mount$',
    r'^umount$',
    r'^ps$',
    r'^netstat$',
    r'^ss$',
    r'^ip$',
    r'^getent$',
    r'^pwd$'
]
```

**Default Block-List:**
```python
COMMAND_BLOCKLIST = [
    r'^rm\s+-rf\s*/',
    r'^chmod\s+777',
    r'^dd\s+',
    r'^mkfs',
    r'^fdisk',
    r'^userdel',
    r'^groupdel',
    r'^passwd\s+-l\s+root',
    r'^setenforce\s+0',
    r'^iptables\s+-F',
    r':(){:|:&};:',  # Shellshock
    r'eval\s*\(',
    r'exec\s*\(',
    r'\$\(',
    r'`[^`]*`',  # Backtick command substitution
    r';\s*rm\s',
    r'&&\s*rm\s',
    r'\|\|\s*rm\s',
    r'>\s*/dev/',
    r'>>\s*/etc/',
    r'nc\s+-l',  # Netcat listener
    r'ncat\s+-l',
    r'socat\s+TCP-LISTEN'
]
```

#### File Permission Security ([`SecureFilePermissions`](../vulnguard/pkg/security/file_permissions.py:41))
- **Secure defaults** - Files: 0600, Directories: 0700
- **Explicit permission setting** - All operations specify permissions
- **Permission verification** - Verifies permissions after creation
- **Audit capabilities** - Can audit directory permissions
- **Cross-platform support** - Works consistently across platforms

**Default Permissions:**
```python
DEFAULT_FILE_PERMISSIONS = 0o600  # rw------- (owner read/write only)
DEFAULT_DIR_PERMISSIONS = 0o700   # rwx------ (owner read/write/execute only)
MAX_FILE_PERMISSIONS = 0o644  # rw-r--r-- (owner read/write, group/others read)
MAX_DIR_PERMISSIONS = 0o755   # rwxr-xr-x (owner full, group/others read/execute)
TEMP_FILE_PERMISSIONS = 0o600
TEMP_DIR_PERMISSIONS = 0o700
```

#### Atomic File Operations ([`AtomicFileOperations`](../vulnguard/pkg/security/atomic_operations.py:41))
- **Atomic operations** - Uses `os.replace()`, `open(..., mode='x')`
- **Eliminates race conditions** - Check and use in single operation
- **Symlink Protection** - Explicit checks to prevent symlink following (using `os.path.islink` and `O_NOFOLLOW`)
- **Safe file patterns** - Temporary file patterns for updates
- **Backup support** - Optional backup before operations
- **Error handling** - Proper cleanup on failures

**Available Operations:**
- `atomic_read()` - Atomically read a file (with symlink protection)
- `atomic_write()` - Atomically write content (prevents writing to symlinks)
- `atomic_create()` - Atomically create a new file (fails if exists)
- `atomic_append()` - Atomically append content to a file
- `atomic_replace()` - Atomically replace a file with another
- `atomic_copy()` - Atomically copy a file to a new location
- `atomic_delete()` - Atomically delete a file
- `atomic_file_exists()` - Check if file exists (non-atomic, but safe for most use cases)

#### Secure Path Validation ([`PathValidator`](../vulnguard/pkg/security/path_validator.py))
- **Centralized Validation** - Single source of truth for path sanity
- **Traversal Prevention** - Blocks `../` and absolute path tricks
- **Confinement** - Enforces operations stay within base directories
- **Symlink Policy** - Configurable symlink allowance (default deny)

**Design Decisions:**
- Lazy loading to avoid circular dependencies
- All security operations are auditable
- Defensive programming with comprehensive error handling
- Follows enterprise security standards
- Designed to pass security audits and penetration testing

### 7. Main Orchestrator

**Purpose:** Main orchestrator for VulnGuard operations

**Key Classes:**
- [`VulnGuardOrchestrator`](../vulnguard/main.py:146) - Main orchestrator class

**Responsibilities:**
- Coordinate all components
- Manage configuration
- Provide CLI interface
- Generate compliance reports

**Design Decisions:**
- Centralized coordination of all components
- Configuration-driven behavior
- Clean separation of concerns
- Comprehensive error handling
- Multiple output formats

## Key Technical Decisions

### 1. Deterministic-First Design

**Decision:** All compliance checks are deterministic and rule-based. AI is only used for advisory purposes.

**Rationale:**
- Ensures predictable, repeatable results
- Critical for regulated environments
- Prevents AI hallucinations from affecting compliance status
- Allows for easy auditing and verification

### 2. Multi-Layer AI Validation

**Decision:** All AI output passes through 5+ validation layers before being used.

**Rationale:**
- Prevents AI hallucinations from causing damage
- Ensures all recommendations are safe
- Provides defense-in-depth approach
- Critical for production environments

### 3. Reversible by Design

**Decision:** Every remediation action is reversible with automatic backup and rollback.

**Rationale:**
- Prevents permanent damage from mistakes
- Allows for safe experimentation
- Critical for production systems
- Provides safety net for all changes

### 4. Fail-Safe Architecture

**Decision:** System designed to fail safely (fail-closed) and never leave undefined states.

**Rationale:**
- Ensures system stability even on errors
- Prevents partial or inconsistent states
- Critical for regulated environments
- Allows for predictable recovery

### 5. Configuration-Driven Behavior

**Decision:** All behavior controlled through configuration files, not hardcoded values.

**Rationale:**
- Allows for easy customization
- Supports different deployment scenarios
- Enables environment-specific tuning
- Facilitates maintenance and updates

### 6. Modular Architecture

**Decision:** Clear separation of concerns with independent, interchangeable components.

**Rationale:**
- Enables easy testing and maintenance
- Allows for component reuse
- Supports extensibility and growth
- Facilitates parallel development

### 7. Security-First Implementation

**Decision:** Security controls implemented at the foundational level, not as afterthoughts.

**Rationale:**
- Ensures all operations are secure by default
- Prevents security vulnerabilities from introduction
- Critical for regulated environments
- Simplifies security audits

## Design Patterns

### 1. Layered Architecture

**Pattern:** Clear separation between presentation, orchestration, business logic, and infrastructure layers.

**Benefits:**
- Easy to understand and maintain
- Supports independent development
- Facilitates testing
- Enables component reuse

### 2. Dependency Injection

**Pattern:** Components receive dependencies through constructor parameters, not hardcoded dependencies.

**Benefits:**
- Enables easy testing with mocks
- Supports component interchangeability
- Facilitates modular development
- Improves code flexibility

### 3. Strategy Pattern

**Pattern:** LLM clients use abstract base class with concrete implementations for each provider.

**Benefits:**
- Easy to add new LLM providers
- Consistent interface across providers
- Supports provider switching
- Facilitates testing

### 4. Builder Pattern

**Pattern:** Configuration objects built step-by-step with validation at each step.

**Benefits:**
- Ensures valid configuration
- Provides clear error messages
- Supports complex configuration
- Facilitates configuration reuse

### 5. Factory Pattern

**Pattern:** Component factories create instances based on configuration.

**Benefits:**
- Centralizes object creation
- Supports configuration-driven instantiation
- Enables component reuse
- Facilitates testing

### 6. Observer Pattern

**Pattern:** Logger observes all operations and records events.

**Benefits:**
- Centralized audit logging
- Consistent log format
- Supports multiple log outputs
- Enables comprehensive tracking

### 7. Template Method Pattern

**Pattern:** Base classes define algorithm structure, subclasses implement specific steps.

**Benefits:**
- Ensures consistent behavior
- Supports code reuse
- Enables customization
- Facilitates maintenance

## Critical Implementation Paths

### 1. Scan Workflow

```
User Request (CLI)
    │
    ▼
VulnGuardOrchestrator.run_scan()
    │
    ├─▶ Scanner.scan_all()
    │       │
    │       ├─▶ Load and validate rules
    │       ├─▶ Execute checks (command/file/service/sysctl)
    │       ├─▶ Validate results
    │       └─▶ Return ScanResult[]
    │
    ├─▶ Engine.evaluate_batch()
    │       │
    │       ├─▶ Normalize severities
    │       ├─▶ Determine risk levels
    │       ├─▶ Check AI assist requirements
    │       └─▶ Return EvaluationResult[]
    │
    ├─▶ Advisor.get_advisory() (for rules requiring AI)
    │       │
    │       ├─▶ Call LLM provider
    │       ├─▶ Validate JSON schema
    │       ├─▶ Validate commands
    │       ├─▶ Check confidence threshold
    │       └─▶ Return AIAdvisory[]
    │
    └─▶ Generate report
            │
            └─▶ Return formatted output
```

### 2. Remediation Workflow

```
User Request (CLI)
    │
    ▼
VulnGuardOrchestrator.run_remediation()
    │
    ├─▶ Check mode (dry-run or commit)
    │
    ├─▶ RemediationEngine.remediate_batch()
    │       │
    │       ├─▶ For each non-compliant rule:
    │       │       │
    │       │       ├─▶ Validate approval requirements
    │       │       ├─▶ Create backup (if commit mode)
    │       │       ├─▶ Validate commands
    │       │       ├─▶ Execute commands (if commit mode)
    │       │       ├─▶ Monitor for failures
    │       │       └─▶ Rollback on failure
    │       │
    │       └─▶ Return RemediationResult[]
    │
    └─▶ Generate report
            │
            └─▶ Return formatted output
```

### 3. AI Advisory Workflow

```
Engine determines AI assist required
    │
    ▼
Advisor.get_advisory()
    │
    ├─▶ Build prompt with context
    │
    ├─▶ Call LLM provider
    │       │
    │       ├─▶ OpenRouterClient.generate_response()
    │       │       OR
    │       ├─▶ OpenAIClient.generate_response()
    │       │       OR
    │       ├─▶ AnthropicClient.generate_response()
    │       │       OR
    │       ├─▶ OllamaClient.generate_response()
    │       │       OR
    │       └─▶ LocalLLMClient.generate_response()
    │
    ├─▶ Parse JSON response
    │
    ├─▶ Validate JSON schema
    │
    ├─▶ Validate required fields
    │
    ├─▶ Check confidence threshold
    │
    ├─▶ Validate commands against allow-list
    │
    ├─▶ Validate commands against block-list
    │
    └─▶ Return AIAdvisory (or None if validation fails)
```

### 4. Security Validation Workflow

```
Command execution requested
    │
    ▼
SecureCommandExecutor.execute()
    │
    ├─▶ Validate command against allow-list
    │
    ├─▶ Validate command against block-list
    │
    ├─▶ Sanitize inputs
    │
    ├─▶ Execute with shell=False
    │
    ├─▶ Log execution
    │
    └─▶ Return result
```

## Data Flow

### Configuration Flow

```
config.yaml
    │
    ├─▶ Agent configuration
    │       └─▶ VulnGuardOrchestrator
    │
    ├─▶ Logging configuration
    │       └─▶ AuditLogger
    │
    ├─▶ AI configuration
    │       └─▶ AIAdvisor
    │
    ├─▶ Remediation configuration
    │       └─▶ RemediationEngine
    │
    └─▶ Severity mapping
            └─▶ ComplianceEngine
```

### Scan Data Flow

```
Benchmark Rules (YAML)
    │
    ▼
Scanner
    │
    ├─▶ Load and validate rules
    ├─▶ Execute checks
    ├─▶ Validate results
    └─▶ ScanResult[]
            │
            ▼
Engine
    │
    ├─▶ Normalize severities
    ├─▶ Determine risk levels
    └─▶ EvaluationResult[]
            │
            ▼
Advisor (if needed)
    │
    ├─▶ Call LLM
    ├─▶ Validate output
    └─▶ AIAdvisory[]
            │
            ▼
Logger
    │
    └─▶ Log all events
```

### Remediation Data Flow

```
ScanResult[] + EvaluationResult[] + AIAdvisory[]
    │
    ▼
RemediationEngine
    │
    ├─▶ Validate approvals
    ├─▶ Create backups
    ├─▶ Validate commands
    ├─▶ Execute commands
    ├─▶ Monitor failures
    └─▶ RemediationResult[]
            │
            ▼
Logger
    │
    └─▶ Log all events
```

## Integration Points

### External Integrations

1. **LLM Providers**
   - OpenAI API
   - Anthropic API
   - OpenRouter API
   - Ollama API
   - Local LLM models

2. **System Resources**
   - File system (for configuration, backups, logs)
   - System commands (for checks and remediation)
   - Services (for service management)
   - Kernel parameters (for sysctl)

3. **Configuration Sources**
   - YAML configuration files
   - Environment variables (.env)
   - Command-line arguments

### Internal Integration Points

1. **Scanner → Engine**
   - Scanner provides ScanResult[]
   - Engine evaluates and returns EvaluationResult[]

2. **Engine → Advisor**
   - Engine determines AI assist required
   - Advisor provides AIAdvisory[]

3. **Advisor → Remediation**
   - Advisor provides AI recommendations
   - Remediation uses recommendations for fixes

4. **All Components → Logger**
   - All components log events
   - Logger provides structured audit trail

5. **All Components → Security Module**
   - All components use security utilities
   - Security module provides safe operations
