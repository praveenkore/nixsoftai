# VulnGuard Architecture Upgrade Design
## Capability-Based Plugins & Centralized Gateway

### 1. Overview
This document outlines the architectural design for two major enhancements to VulnGuard:
1.  **Capability-Based Plugin System**: A secure, sandboxed architecture for extending agent functionality (e.g., remote execution, custom backups) without compromising the core security model.
2.  **Centralized Gateway Layer**: A dedicated communication layer for fleet management, enabling the agent to receive commands from and report status to a central server.

---

### 2. Capability-Based Plugin Architecture

The core principle is **Least Privilege**. Plugins are not imported as raw Python modules with full access. Instead, they operate within a sandbox and must explicitly request "Capabilities" which the agent grants or denies.

#### 2.1 Plugin Structure
Each plugin is a directory containing:
*   `manifest.yaml`: Metadata and requested capabilities.
*   `plugin.py`: The entry point implementing the `IPlugin` interface.
*   `requirements.txt`: Dependencies (optional).
*   `signature.sig`: Digital signature of the plugin bundle.

#### 2.2 Manifest (`manifest.yaml`)
```yaml
name: "remote-backup-s3"
version: "1.0.0"
author: "Nixsoft"
description: "Offloads backups to AWS S3"
entry_point: "plugin.BackupPlugin"
capabilities:
  - "NETWORK_OUTBOUND": ["s3.amazonaws.com"]
  - "FILE_READ": ["/var/lib/vulnguard/backups"]
  - "SECRETS_READ": ["AWS_ACCESS_KEY"]
```

#### 2.3 Capability Definitions
| Capability | Description | Parameters |
| :--- | :--- | :--- |
| `EXEC_CMD` | Execute shell commands | Allowed command patterns (regex) |
| `FILE_READ` | Read files | Allowed paths |
| `FILE_WRITE` | Write files | Allowed paths |
| `NETWORK_OUTBOUND` | Outbound network access | Allowed domains/ports |
| `SECRETS_READ` | Access agent secrets | Secret keys |

#### 2.4 Interface (`IPlugin`)
```python
class IPlugin(ABC):
    def initialize(self, context: PluginContext):
        """Called on load. Context provides secure proxies to capabilities."""
        pass

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Main execution entry point."""
        pass

    def shutdown(self):
        """Cleanup."""
        pass
```

#### 2.5 capability Enforcement (The Sandbox)
Plugins interact with the system ONLY via the `PluginContext` object passed during initialization.
*   `context.fs`: Secure file system proxy. Checks `FILE_READ/WRITE` capabilities before delegation.
*   `context.exec`: Secure command proxy. Checks `EXEC_CMD` capability and allow-lists.
*   `context.net`: Secure network proxy. Checks `NETWORK_OUTBOUND`.

**Implementation Note**: Since Python is dynamic, true memory sandboxing is difficult without separate processes.
*   **Level 1 (In-Process)**: Use `sys.modules` restrictions and proxy objects. Good generic protection but bypassable by sophisticated malicious code.
*   **Level 2 (Out-of-Process)**: Run plugins in separate processes (gRPC/IPC). Strong isolation.
*   **Recommendation**: Start with **Level 1** + Review/Signing for trusted internal usage. Move to Level 2 for 3rd party support.

---

### 3. Centralized Gateway Layer

The Gateway Layer sits between the `VulnGuardOrchestrator` and the external world.

#### 3.1 Gateway Components
```
┌───────────────────────────┐      ┌───────────────────────────┐
│    Central Command (C2)   │◄────►│      Agent Gateway        │
└───────────────────────────┘      └─────────────┬─────────────┘
                                                 │
                                                 ▼
                                   ┌───────────────────────────┐
                                   │   VulnGuard Orchestrator  │
                                   └───────────────────────────┘
```

#### 3.2 Protocol & Transport
*   **Transport**: WebSocket (persistent) or gRPC (efficient).
*   **Security**: mTLS (Mutual TLS) for device authentication.
*   **Payload**: JSON or Protobuf.

#### 3.3 Gateway Interface
```python
class AgentGateway:
    def __init__(self, orchestrator: VulnGuardOrchestrator, config: GatewayConfig):
        self.orchestrator = orchestrator
        self.client = ...

    async def connect(self):
        """Establish connection to C2."""
        pass

    async def listen(self):
        """Main loop: receive commands."""
        while True:
            cmd = await self.client.recv()
            await self.dispatch(cmd)

    async def dispatch(self, cmd: Command):
        if cmd.type == "START_SCAN":
            result = self.orchestrator.run_scan(cmd.params)
            await self.client.send(Result(id=cmd.id, data=result))
        elif cmd.type == "REMEDIATE":
            # ...
```

#### 3.4 Command Dispatching
The Gateway maps remote commands to Orchestrator methods:
1.  **SCAN**: Triggers `orchestrator.run_scan`.
2.  **REMEDIATE**: Triggers `orchestrator.run_remediation` (Subject to approval policy).
3.  **UPDATE_RULES**: Updates local benchmark YAMLs.
4.  **PLUGIN_ACTION**: Dispatches payload to specific plugin.

---

### 4. Integration Plan

#### Phase 1: Core Interfaces
1.  Define `vulnguard/pkg/plugins/interface.py`.
2.  Define `vulnguard/pkg/plugins/capabilities.py`.

#### Phase 2: Plugin Manager
1.  Implement `PluginLoader` to read manifests and verify signatures.
2.  Implement `PluginContext` (The Sandbox proxies).

#### Phase 3: Gateway
1.  Implement `vulnguard/pkg/gateway/client.py`.
2.  Update `main.py` to start the gateway if configured (`--connect`).

### 5. Deployment & Security
*   **Signing**: All plugins must be signed by the private key of the central authority. The agent holds the public key.
*   **Audit**: Every action taken by a plugin (via `PluginContext`) is automatically logged to `AuditLogger` with the plugin's ID.

### 6. Security Threat Model & Mitigations

Plugins introduce third-party code into the agent, creating specific attack vectors.

| Threat | Description | Mitigation Strategy |
| :--- | :--- | :--- |
| **Malicious Code** | Plugin contains malware or backdoors. | **Digital Signatures**: Agent refuses to load any plugin not signed by the trusted central authority. Code review required before signing. |
| **Privilege Escalation** | Plugin attempts to gain root or modify agent core. | **Capability System**: Plugins have NO access to core agent objects. They only hold restricted proxies (`PluginContext`) that enforce "Least Privilege". |
| **Runtime Tampering** | "Monkey patching" core Python objects in memory. | **Module-Level Isolation**: Plugins are loaded with restricted `__builtins__` and custom `sys.modules`. (Future: Process isolation). |
| **Data Exfiltration** | Reading sensitive files and sending them out. | **Network Allow-listing**: `NETWORK_OUTBOUND` capability restricts destination IPs/Domains. `FILE_READ` restricts accessible paths. |
| **Command Injection** | Using `EXEC_CMD` to run arbitrary commands. | **Strict Regex Allow-lists**: Plugins can only request specific command patterns (e.g., `zip /var/log/*`), not `bash -c`. |
| **Resource Exhaustion** | Plugin consumes 100% CPU or Memory. | **Resource Limits**: (Process Isolation only) cgroups/ulimits. In-process: Heartbeat monitoring and timeouts. |

**Critical Rule**: The agent's core `Security Module` (Command Executor, Path Validator) always sits *below* the plugin. A plugin cannot bypass the `SecureCommandExecutor` logic; it merely requests usage of it.
