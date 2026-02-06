# VulnGuard – Frontend V0 Task List (LLM-Driven)

## Goal

Design and implement a **bare-minimum frontend (V0)** for VulnGuard that:
- Provides visibility into agent scan results
- Enables **human approval for remediation**
- Displays audit and compliance reports
- Does NOT perform scanning, evaluation, or remediation logic

The frontend acts strictly as a **control and visibility layer**.

---

## Non-Goals (Important)

❌ No vulnerability scanning logic  
❌ No remediation execution  
❌ No AI reasoning in frontend  
❌ No complex RBAC or multi-tenancy  
❌ No SIEM-style dashboards  

---

## Architecture Constraints

- Frontend communicates ONLY with the **Gateway / Central Server**
- All data is **JSON-based**
- Communication supports **WebSocket (primary)** and **HTTP (secondary)**
- Agent behavior, security rules, and remediation logic remain unchanged

---

## Task Group 1: Frontend Foundations

### TASK 1.1 – Select Frontend Stack
- Choose minimal, production-safe stack:
  - React + Vite OR Next.js
  - TailwindCSS for styling
- Avoid heavy state management libraries

**Deliverable:**
- Stack decision documented in README

---

### TASK 1.2 – Project Scaffolding
- Initialize frontend project
- Configure:
  - Linting
  - Basic folder structure
  - Environment variables support

**Deliverable:**
- Clean project skeleton
- `.env.example`

---

## Task Group 2: Data Contracts (Critical)

### TASK 2.1 – Define Frontend Data Models
Create TypeScript interfaces (or schemas) for:
- Agent / Host summary
- ScanResult
- EvaluationResult
- AIAdvisory (read-only)
- RemediationApprovalRequest
- RemediationResult
- AuditEvent

**Deliverable:**
- `/src/types/*.ts`

---

### TASK 2.2 – Define WebSocket Message Types

Inbound messages:
- `system_info`
- `scan_summary`
- `scan_results`
- `approval_required`
- `audit_event`

Outbound messages:
- `approve_remediation`
- `reject_remediation`
- `request_rescan`
- `request_dry_run`

**Deliverable:**
- Message contract documentation
- Type-safe message handlers

---

## Task Group 3: Core Screens (V0)

### TASK 3.1 – System Overview Screen
**Purpose:** Fleet health snapshot

UI Elements:
- Hostname
- OS
- Last scan time
- Compliance status (pass / warn / critical)

**Deliverable:**
- Table-based overview screen
- Read-only

---

### TASK 3.2 – Host Scan Results Screen
**Purpose:** View vulnerabilities per host

Show:
- Rule ID
- Title
- Severity
- Risk level
- Compliance status
- Requires approval flag

Expandable details:
- Description
- Evidence
- AI advisory (if present)
- Suggested remediation (read-only)

**Deliverable:**
- Host details page
- Expandable rows

---

### TASK 3.3 – Approval Queue Screen (High Priority)
**Purpose:** Human-in-the-loop control

Show:
- Host
- Rule ID
- Severity
- Risk
- Change type
- AI confidence
- Dry-run diff

Actions:
- Approve remediation
- Reject remediation
- Re-run dry-run

**Deliverable:**
- Explicit approval workflow
- Confirmation modal before approval

---

### TASK 3.4 – Audit & Reports Screen
**Purpose:** Compliance & forensic visibility

Show:
- Timestamped audit events
- Event type
- Status
- Related rule / host

Actions:
- Filter by host / rule / event type
- Download JSON report

**Deliverable:**
- Read-only audit log viewer

---

## Task Group 4: Communication Layer

### TASK 4.1 – WebSocket Client
- Implement resilient WebSocket client
- Handle:
  - reconnects
  - heartbeats
  - message validation

**Deliverable:**
- Centralized WebSocket service
- Typed event dispatching

---

### TASK 4.2 – Approval Action Handlers
- On approval:
  - Send `approve_remediation` message
- On rejection:
  - Send `reject_remediation` message
- Display success/failure feedback

**Deliverable:**
- Safe, idempotent action handlers

---

## Task Group 5: UX & Safety

### TASK 5.1 – Read-Only by Default
- All remediation info is non-editable
- No inline command editing
- No config editing

**Deliverable:**
- Enforced read-only UX

---

### TASK 5.2 – Explicit Confirmation
- Require confirmation modal for:
  - Approve remediation
  - Commit mode execution

**Deliverable:**
- Human-in-the-loop safety guard

---

## Task Group 6: Security & Reliability

### TASK 6.1 – Input Validation
- Validate all incoming WebSocket messages
- Reject malformed or unexpected payloads

**Deliverable:**
- Runtime validation layer

---

### TASK 6.2 – Error Handling
- Graceful UI failures
- Clear error states (no silent failures)

**Deliverable:**
- Error boundary components

---

## Task Group 7: Documentation & Handoff

### TASK 7.1 – Frontend README
Include:
- Architecture overview
- Message flow diagram
- How approvals work
- What frontend does NOT do

**Deliverable:**
- `README.md`

---

### TASK 7.2 – LLM Execution Notes
Document:
- Assumptions
- Guardrails
- What an LLM must NOT change

**Deliverable:**
- `LLM_GUIDELINES.md`

---

## Success Criteria

✅ Human approval required for all remediations  
✅ No business logic duplication  
✅ JSON-only communication  
✅ Fully auditable UI actions  
✅ Backend architecture remains untouched  

---

## One-Line Principle

> **If the frontend can break VulnGuard’s security guarantees, it is overbuilt.**
