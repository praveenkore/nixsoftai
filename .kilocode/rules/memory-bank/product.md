# VulnGuard Product Description

## Why VulnGuard Exists

### The Problem

Organizations operating in regulated environments face significant challenges in maintaining security compliance:

1. **Manual Compliance is Error-Prone**
   - Manual security audits are time-consuming and inconsistent
   - Human error leads to missed compliance issues
   - Difficult to maintain comprehensive audit trails
   - Hard to track compliance over time

2. **Existing Tools Lack Safety**
   - Many security tools use blind automation
   - Insufficient safeguards against dangerous operations
   - Limited or no rollback capabilities
   - Poor audit logging for compliance verification

3. **AI Tools Are Untrusted**
   - AI-powered security tools often execute commands directly
   - Lack of validation for AI-generated commands
   - No confidence thresholds for AI recommendations
   - Risk of AI hallucinations causing system damage

4. **Compliance Standards are Complex**
   - CIS Benchmarks and DISA STIGs are extensive
   - Different severity levels across standards
   - OS-specific requirements complicate implementation
   - Keeping up with rule updates is challenging

5. **Regulated Environments Require Trust**
   - High-trust environments need deterministic behavior
   - Security audits require complete audit trails
   - Fail-safe operation is mandatory
   - Production stability is non-negotiable

## Problems VulnGuard Solves

### 1. Deterministic Security Compliance

**Problem:** Existing tools often use unpredictable AI or inconsistent manual processes.

**VulnGuard Solution:**
- All compliance checks are 100% deterministic and rule-based
- No AI in the scanning pipeline - only advisory
- Every check produces predictable, repeatable results
- Strict rule validation before execution
- Timeout protection prevents hanging operations

### 2. Safe AI-Assisted Remediation

**Problem:** AI tools often execute commands directly without validation, risking system damage.

**VulnGuard Solution:**
- AI provides advisory only, never executes commands directly
- All AI output passes through multiple validation layers:
  - JSON schema validation
  - Command allow-list validation
  - Command block-list validation
  - Confidence threshold checking (default 0.7)
  - Required field verification
- Low-confidence recommendations require manual review
- Multiple LLM provider support for flexibility

### 3. Reversible Changes

**Problem:** Many security tools make changes that cannot be easily undone.

**VulnGuard Solution:**
- Every remediation is reversible by design
- Automatic backup before any changes
- Rollback commands generated for each action
- Automatic rollback on remediation failure
- Dry-run mode shows what will happen without executing
- Complete audit trail of all changes

### 4. Comprehensive Audit Trail

**Problem:** Insufficient logging makes compliance verification difficult.

**VulnGuard Solution:**
- All operations logged in structured JSON-line format
- Complete context in every log entry:
  - Timestamp
  - System information
  - Rule details
  - Scan results
  - AI advisories
  - Remediation actions
  - Rollback operations
  - Error details
- Log rotation prevents disk space issues
- Easy parsing for compliance audits

### 5. Multi-Benchmark Support

**Problem:** Different tools for different standards create complexity.

**VulnGuard Solution:**
- Unified interface for both CIS Benchmarks and DISA STIGs
- Severity normalization across standards:
  - CIS Level 1 → high
  - CIS Level 2 → medium
  - CIS Level 3 → low
  - STIG CAT I → critical
  - STIG CAT II → high
  - STIG CAT III → medium
- OS compatibility filtering ensures rules only run on supported systems
- Easy to add new benchmark rules

### 6. Production-Ready Safety

**Problem:** Tools optimized for speed often sacrifice safety.

**VulnGuard Solution:**
- Production stability prioritized over compliance speed
- Fail-safe design (fail-closed)
- Never leaves system in undefined state
- Approval gating for high-risk changes:
  - STIG CAT I and CAT II rules
  - Critical severity rules
  - Rules marked with approval_required
- Command allow-list restricts dangerous operations
- Command block-list explicitly blocks harmful commands

## How VulnGuard Works

### Operational Pipeline

VulnGuard follows a seven-step operational pipeline:

```
1. Scan (Deterministic)
   └─> Execute rule-based checks
   └─> Validate results against expected states
   └─> Determine compliance status

2. Evaluate (Risk Assessment)
   └─> Normalize severities across benchmarks
   └─> Determine risk levels
   └─> Decide if AI assistance is needed

3. Decide (AI Trigger)
   └─> AI invoked only for:
       - Ambiguous findings
       - Explicit AI assist requests
       - Scan errors

4. Validate (AI Safety)
   └─> JSON schema validation
   └─> Command allow-list validation
   └─> Command block-list validation
   └─> Confidence threshold checking
   └─> Required field verification

5. Apply (Remediation)
   └─> Dry-run mode (default)
   └─> Manual review
   └─> Commit mode (after approval)
   └─> Automatic backup before changes

6. Rollback (Failure Recovery)
   └─> Automatic rollback on failure
   └─> Restore from backup
   └─> Execute rollback commands

7. Log (Audit Trail)
   └─> JSON-line format
   └─> Complete context
   └─> Structured data
```

### Component Architecture

VulnGuard consists of seven core components:

1. **Scanner Module** ([`vulnguard/pkg/scanner/scanner.py`](../vulnguard/pkg/scanner/scanner.py))
   - Loads and validates benchmark rule configurations
   - Executes defined check commands
   - Validates results against expected states
   - Determines compliance status
   - OS compatibility checking

2. **Engine Module** ([`vulnguard/pkg/engine/engine.py`](../vulnguard/pkg/engine/engine.py))
   - Normalizes severities across benchmark standards
   - Determines risk levels based on severity and compliance
   - Decides if AI assistance is required
   - Determines approval requirements
   - Generates compliance summaries

3. **Advisor Module** ([`vulnguard/pkg/advisor/advisor.py`](../vulnguard/pkg/advisor/advisor.py))
   - Provides AI assistance for ambiguous findings
   - Validates all AI output against safety controls
   - Enforces confidence thresholds
   - Validates commands against allow-list/block-list
   - Never executes commands directly

4. **Remediation Module** ([`vulnguard/pkg/remediation/remediation.py`](../vulnguard/pkg/remediation/remediation.py))
   - Applies security fixes with automatic backup
   - Executes remediation commands in dry-run or commit mode
   - Automatic rollback on failure
   - Validates all commands against allow-list/block-list
   - Maintains audit trail of all changes

5. **Logging Module** ([`vulnguard/pkg/logging/logger.py`](../vulnguard/pkg/logging/logger.py))
   - Logs all operations in JSON-line format
   - Provides structured, parseable audit trail
   - Supports log rotation
   - Multiple output formats (JSON, text)

6. **Security Module** ([`vulnguard/pkg/security/`](../vulnguard/pkg/security/))
   - Eliminates command injection vulnerabilities
   - Enforces secure file and directory permissions
   - Prevents TOCTOU vulnerabilities with atomic operations
   - Provides audit logging for all security operations

7. **Main Orchestrator** ([`vulnguard/main.py`](../vulnguard/main.py))
   - Coordinates all components
   - Manages configuration
   - Provides CLI interface
   - Generates compliance reports

### User Workflow

#### Step 1: Configuration

User configures VulnGuard in [`vulnguard/configs/agent/config.yaml`](../vulnguard/configs/agent/config.yaml):
- Set default mode (dry-run or commit)
- Configure logging settings
- Set AI provider and credentials
- Configure command allow-list/block-list
- Set severity mappings
- Configure approval requirements

#### Step 2: Scan

User runs compliance scan:
```bash
python -m vulnguard.main scan
```

VulnGuard:
- Loads all benchmark rules
- Executes deterministic checks
- Evaluates compliance status
- Generates AI advisories for ambiguous findings
- Produces compliance report

#### Step 3: Review

User reviews scan results:
- Compliance status for each rule
- Risk level assessment
- AI recommendations (if applicable)
- Proposed remediation commands
- Rollback commands

#### Step 4: Dry-Run Remediation

User tests remediation in dry-run mode:
```bash
python -m vulnguard.main remediate --mode dry-run
```

VulnGuard:
- Shows what would be done
- Validates all commands
- Checks approval requirements
- Does NOT execute any changes

#### Step 5: Commit Remediation

User approves and commits remediation:
```bash
python -m vulnguard.main remediate --mode commit
```

VulnGuard:
- Creates automatic backup
- Executes remediation commands
- Monitors for failures
- Automatic rollback on failure
- Logs all actions

#### Step 6: Verification

User verifies results:
- Review remediation report
- Check audit logs
- Verify system state
- Re-scan to confirm compliance

## User Experience Goals

### 1. Clarity

**Goal:** Users should always understand what's happening.

**Implementation:**
- Clear, descriptive error messages
- Detailed output for each operation
- Structured reports with summaries
- Progress indicators for long operations
- Contextual help in CLI

### 2. Safety

**Goal:** Users should never accidentally damage their systems.

**Implementation:**
- Dry-run mode by default
- Explicit confirmation for dangerous operations
- Approval gating for high-risk changes
- Automatic backup before changes
- Automatic rollback on failure
- Clear warnings before irreversible actions

### 3. Trust

**Goal:** Users should trust the tool's recommendations.

**Implementation:**
- Deterministic, repeatable results
- AI advisory only, never direct execution
- Multiple validation layers for AI output
- Confidence thresholds for AI recommendations
- Complete audit trail for verification
- Transparent about limitations

### 4. Efficiency

**Goal:** Users should complete compliance tasks quickly.

**Implementation:**
- Fast scanning with parallel execution
- Efficient connection pooling for HTTP requests
- Rate limiting to prevent API quota exhaustion
- Lazy loading to avoid circular dependencies
- Cached results where appropriate

### 5. Flexibility

**Goal:** Users should adapt VulnGuard to their needs.

**Implementation:**
- Configuration-driven behavior
- Multiple output formats (JSON, YAML, text)
- Multiple LLM providers
- Custom benchmark rules
- Extensible command allow-list/block-list
- Custom severity mappings

## Target Users

### Primary Users

1. **Security Engineers**
   - Responsible for maintaining system security
   - Need automated compliance checking
   - Require safe, reversible remediation
   - Value comprehensive audit trails

2. **DevOps Engineers**
   - Manage infrastructure at scale
   - Need efficient compliance automation
   - Require integration with CI/CD pipelines
   - Value deterministic behavior

3. **Compliance Officers**
   - Ensure regulatory compliance
   - Need detailed audit reports
   - Require evidence of compliance actions
   - Value transparency and traceability

### Secondary Users

1. **System Administrators**
   - Day-to-day system management
   - Need easy-to-use security tools
   - Require clear error messages
   - Value helpful documentation

2. **Security Auditors**
   - Conduct periodic security audits
   - Need verifiable compliance evidence
   - Require detailed audit logs
   - Value structured, parseable data

## Use Cases

### Use Case 1: Routine Compliance Scanning

**Scenario:** Organization needs to verify monthly compliance with CIS Benchmarks.

**Workflow:**
1. Configure VulnGuard with CIS benchmark rules
2. Run scheduled scan: `python -m vulnguard.main scan`
3. Review compliance report
4. Address non-compliant findings
5. Re-scan to verify fixes

**Benefits:**
- Automated, consistent compliance checks
- Comprehensive audit trail
- AI-assisted remediation recommendations
- Safe, reversible fixes

### Use Case 2: STIG Compliance for Government Systems

**Scenario:** Government system must comply with DISA STIG requirements.

**Workflow:**
1. Configure VulnGuard with STIG benchmark rules
2. Run scan: `python -m vulnguard.main scan`
3. Review STIG-specific findings
4. Dry-run remediation: `python -m vulnguard.main remediate --mode dry-run`
5. Obtain approval for high-risk changes
6. Commit remediation: `python -m vulnguard.main remediate --mode commit`

**Benefits:**
- STIG-specific severity normalization
- Approval gating for CAT I and CAT II rules
- Complete audit trail for compliance verification
- Automatic rollback on failure

### Use Case 3: Security Hardening New Systems

**Scenario:** New Linux servers need to be hardened before production deployment.

**Workflow:**
1. Install VulnGuard on new system
2. Run full compliance scan
3. Review all non-compliant findings
4. Dry-run remediation for all issues
5. Review proposed changes
6. Commit remediation
7. Verify system state
8. Document compliance status

**Benefits:**
- Comprehensive security hardening
- Safe, reversible changes
- Complete audit trail
- AI-assisted recommendations

### Use Case 4: Incident Response

**Scenario:** Security incident identified; system needs immediate remediation.

**Workflow:**
1. Run targeted scan for affected area
2. Review findings and AI recommendations
3. Dry-run critical remediation
4. Expedite approval process
5. Commit remediation with `--force` flag
6. Monitor for failures
7. Verify system state

**Benefits:**
- Rapid response with safety controls
- AI-assisted analysis
- Automatic rollback on failure
- Complete audit trail for investigation

## Differentiation

### What Makes VulnGuard Unique

1. **Deterministic-First Approach**
   - Unlike AI-heavy security tools, VulnGuard uses deterministic checks
   - AI is advisory only, never in the scanning pipeline
   - Repeatable, predictable results

2. **Multi-Layer AI Validation**
   - Most tools trust AI output blindly
   - VulnGuard validates AI output through 5+ layers
   - Confidence thresholds prevent low-quality recommendations

3. **Reversible by Design**
   - Many security tools make irreversible changes
   - Every VulnGuard remediation is reversible
   - Automatic backup and rollback

4. **Production-Ready Safety**
   - Tools optimized for speed often sacrifice safety
   - VulnGuard prioritizes safety over speed
   - Fail-safe design, never undefined states

5. **Comprehensive Audit Trail**
   - Many tools have minimal logging
   - VulnGuard logs everything in structured JSON-line format
   - Complete context for compliance verification

6. **Multi-Benchmark Support**
   - Many tools focus on single standard
   - VulnGuard supports both CIS and STIG
   - Unified interface, normalized severities
