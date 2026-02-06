# VulnGuard Frontend Architecture

## Enterprise Scale Architecture for 100s of Agents

**Version:** 1.0  
**Date:** 2026-02-02  
**Status:** Draft

---

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Database Design](#database-design)
- [Redis Cluster Configuration](#redis-cluster-configuration)
- [S3 Archive Strategy](#s3-archive-strategy)
- [Frontend Implementation](#frontend-implementation)
- [Data Flow Patterns](#data-flow-patterns)
- [API Design](#api-design)
- [Deployment Architecture](#deployment-architecture)
- [Monitoring & Alerting](#monitoring--alerting)

---

## Overview

This document outlines the architecture for a scalable VulnGuard frontend capable of managing **hundreds of agents** with the following infrastructure stack:

| Component | Technology |
|-----------|------------|
| **Frontend** | Next.js 14 + React + TypeScript |
| **Primary Database** | PostgreSQL 15 (Primary + Read Replica) |
| **Time-Series Database** | TimescaleDB Cluster |
| **Cache Layer** | Redis Cluster (3 masters + 3 replicas) |
| **Archive Storage** | S3 with Parquet format |
| **Container Platform** | AWS ECS/EKS or equivalent |

### Key Design Principles

1. **Read-First UI**: All remediation data is read-only by default
2. **Safety-First**: Explicit confirmation for all write operations
3. **Scalability**: Support 500+ agents with sub-2s response times
4. **Compliance**: 7-year audit retention with queryable history
5. **Real-time**: WebSocket-based updates for critical events

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                      CLIENT LAYER                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         Next.js Frontend (Vercel/EC2)                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │    │
│  │  │   Dashboard │  │ Host Management│ │ Approvals  │  │   Audit & Reports      │ │    │
│  │  │   (SSR/ISR) │  │  (CSR + Virtual)│ │  (Realtime)│  │   (Time-range queries) │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                    │
└────────────────────────────────────┼────────────────────────────────────────────────────┘
                                     │ HTTPS/WSS
┌────────────────────────────────────┼────────────────────────────────────────────────────┐
│                              API GATEWAY LAYER                                         │
│  ┌─────────────────────────────────▼───────────────────────────────────────────────┐    │
│  │                         Next.js API Routes (BFF)                               │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │    │
│  │  │  Auth/ACL   │  │  Query Opt  │  │ Aggregation │  │   WebSocket Handler     │ │    │
│  │  │  Middleware │  │   Engine    │  │   Service   │  │   (Socket.io/ws)        │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                    │
│                          ┌─────────┴─────────┐                                          │
│                          ▼                   ▼                                          │
│  ┌─────────────────────────────┐   ┌─────────────────────────────┐                      │
│  │   GraphQL API (Optional)    │   │    REST API (Primary)       │                      │
│  │   - Flexible queries        │   │    - CRUD operations        │                      │
│  │   - Field selection         │   │    - WebSocket fallback     │                      │
│  └─────────────────────────────┘   └─────────────────────────────┘                      │
└────────────────────────────────────┼────────────────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┼────────────────────────────────────────────────────┐
│                              DATA LAYER                                                │
│                          ┌─────────┴─────────┐                                         │
│                          ▼                   ▼                                         │
│  ┌─────────────────────────────┐   ┌─────────────────────────────┐                      │
│  │      REDIS CLUSTER          │   │    POSTGRESQL CLUSTER       │                      │
│  │  ┌─────┐ ┌─────┐ ┌─────┐   │   │  ┌─────────┐   ┌─────────┐  │                      │
│  │  │ M1  │ │ M2  │ │ M3  │   │   │  │ Primary │──►│ Replica │  │                      │
│  │  └──┬──┘ └──┬──┘ └──┬──┘   │   │  │  (RW)   │   │  (RO)   │  │                      │
│  │     └──►└──┬──┘◄───┘       │   │  └────┬────┘   └────┬────┘  │                      │
│  │        │ R1 │ R2 │ R3 │     │   │       │             │       │                      │
│  │        └────┴────┴────┘     │   │       └──────┬──────┘       │                      │
│  │                             │   │              │                │                      │
│  │  • Session Store            │   │  • Agents, Users, Approvals   │                      │
│  │  • Real-time Pub/Sub        │   │  • Current scan results       │                      │
│  │  • Rate Limiting            │   │  • Configuration              │                      │
│  │  • Query Result Cache       │   │  • Compliance state           │                      │
│  │  • Write-behind Queue       │   │                               │                      │
│  └─────────────────────────────┘   └─────────────────────────────┘                      │
│                                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      TIMESCALEDB CLUSTER (Time-Series)                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │   │
│  │  │ Access Node │  │ Data Node 1 │  │ Data Node 2 │  │      Data Node N        │  │   │
│  │  │  (Router)   │  │  (Chunk 1)  │  │  (Chunk 2)  │  │      (Chunk N)          │  │   │
│  │  └──────┬──────┘  └─────────────┘  └─────────────┘  └─────────────────────────┘  │   │
│  │         │                                                                         │   │
│  │  • Audit logs (partitioned by time)                                               │   │
│  │  • Scan history (90 days hot, archive cold)                                       │   │
│  │  • Metrics & trends                                                               │   │
│  │  • Compressed chunks (90% storage savings)                                        │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                         OBJECT STORAGE (S3/MINIO)                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │   │
│  │  │ audit-logs/ │  │  backups/   │  │  exports/   │  │   archived-scans/       │  │   │
│  │  │  (Parquet)  │  │  (pg_dump)  │  │  (CSV/JSON) │  │   (>90 days)            │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┼────────────────────────────────────────────────────┐
│                           AGENT LAYER (VulnGuard Agents)                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐        │
│  │  Agent #1   │  │  Agent #2   │  │  Agent #3   │  │      Agent #N           │        │
│  │  (Ubuntu)   │  │   (RHEL)    │  │  (Debian)   │  │     (CentOS)            │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘        │
│         └─────────────────┴─────────────────┘                     │                    │
│                           │                                       │                    │
│                           ▼                                       │                    │
│              ┌─────────────────────────┐                          │                    │
│              │      MQTT/NATS          │◄─────────────────────────┘                    │
│              │   (Agent Messaging)     │                                               │
│              └─────────────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Database Design

### PostgreSQL (Primary + Replica) - Operational Data

```sql
-- ============================================
-- CORE TABLES (PostgreSQL Primary)
-- ============================================

-- Agents table (relatively static)
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    os VARCHAR(50) NOT NULL CHECK (os IN ('ubuntu', 'rhel', 'centos', 'debian', 'amazon_linux')),
    os_version VARCHAR(50) NOT NULL,
    os_codename VARCHAR(50),
    architecture VARCHAR(20),
    kernel_version VARCHAR(100),
    ip_address INET,
    mac_address MACADDR,
    agent_version VARCHAR(20),
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'pending' 
        CHECK (status IN ('online', 'offline', 'error', 'updating', 'pending')),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    
    -- Grouping & metadata
    environment VARCHAR(50) DEFAULT 'production' 
        CHECK (environment IN ('production', 'staging', 'development', 'testing')),
    team VARCHAR(100),
    datacenter VARCHAR(100),
    labels JSONB DEFAULT '{}',
    
    -- Configuration
    config JSONB DEFAULT '{}',
    
    -- Indexes
    CONSTRAINT valid_hostname CHECK (hostname ~ '^[a-zA-Z0-9][-a-zA-Z0-9.]*$')
);

CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_environment ON agents(environment);
CREATE INDEX idx_agents_team ON agents(team);
CREATE INDEX idx_agents_last_seen ON agents(last_seen);
CREATE INDEX idx_agents_labels ON agents USING GIN (labels);

-- Users table (for audit trail)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    role VARCHAR(50) DEFAULT 'viewer' 
        CHECK (role IN ('admin', 'operator', 'viewer', 'auditor')),
    permissions JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true
);

-- Benchmark rules (static reference data)
CREATE TABLE rules (
    id VARCHAR(100) PRIMARY KEY,
    benchmark VARCHAR(20) NOT NULL CHECK (benchmark IN ('CIS', 'STIG')),
    benchmark_version VARCHAR(20),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    rationale TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    original_severity VARCHAR(20),
    check_type VARCHAR(50) NOT NULL,
    
    -- Remediation info
    remediation_commands TEXT[],
    rollback_commands TEXT[],
    requires_restart BOOLEAN DEFAULT false,
    requires_reboot BOOLEAN DEFAULT false,
    
    -- Metadata
    os_compatibility VARCHAR[] NOT NULL,
    cis_control VARCHAR(50),
    cis_subcontrol VARCHAR(50),
    stig_id VARCHAR(50),
    nist_mapping VARCHAR[],
    
    -- Configuration
    ai_assist BOOLEAN DEFAULT false,
    approval_required BOOLEAN DEFAULT false,
    exception_allowed BOOLEAN DEFAULT true,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_rules_benchmark ON rules(benchmark);
CREATE INDEX idx_rules_severity ON rules(severity);
CREATE INDEX idx_rules_os_compat ON rules USING GIN (os_compatibility);

-- Scan sessions (groups scan results)
CREATE TABLE scan_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    
    -- Scan metadata
    initiated_by VARCHAR(100) DEFAULT 'system',
    initiated_via VARCHAR(50) DEFAULT 'scheduled',
    
    -- Timing
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    
    -- Results summary
    total_rules INTEGER DEFAULT 0,
    compliant_count INTEGER DEFAULT 0,
    non_compliant_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    
    -- Status
    status VARCHAR(20) DEFAULT 'running' 
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    
    -- Error info
    error_message TEXT,
    
    -- Compliance score
    compliance_percentage DECIMAL(5,2),
    
    -- For pagination/cursor
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scan_sessions_agent ON scan_sessions(agent_id);
CREATE INDEX idx_scan_sessions_status ON scan_sessions(status);
CREATE INDEX idx_scan_sessions_time ON scan_sessions(started_at DESC);
CREATE INDEX idx_scan_sessions_compliance ON scan_sessions(compliance_percentage);

-- Current scan results (latest state per agent/rule)
CREATE TABLE current_scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL REFERENCES rules(id),
    session_id UUID REFERENCES scan_sessions(id),
    
    -- Result data
    compliant BOOLEAN NOT NULL,
    expected_state TEXT,
    actual_state TEXT,
    check_output TEXT,
    error_message TEXT,
    
    -- Evaluation
    severity VARCHAR(20),
    risk_level VARCHAR(20),
    ai_assist_required BOOLEAN DEFAULT false,
    approval_required BOOLEAN DEFAULT false,
    
    -- Timestamps
    first_detected TIMESTAMPTZ DEFAULT NOW(),
    last_scanned TIMESTAMPTZ DEFAULT NOW(),
    scan_count INTEGER DEFAULT 1,
    
    -- Unique constraint: one result per agent+rule
    UNIQUE(agent_id, rule_id)
);

CREATE INDEX idx_current_results_agent ON current_scan_results(agent_id);
CREATE INDEX idx_current_results_rule ON current_scan_results(rule_id);
CREATE INDEX idx_current_results_compliant ON current_scan_results(compliant) WHERE compliant = false;
CREATE INDEX idx_current_results_risk ON current_scan_results(risk_level);
CREATE INDEX idx_current_results_approval ON current_scan_results(approval_required) WHERE approval_required = true;

-- Approvals (audit-critical, must be durable)
CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- References
    scan_result_id UUID REFERENCES current_scan_results(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    rule_id VARCHAR(100) NOT NULL REFERENCES rules(id),
    session_id UUID REFERENCES scan_sessions(id),
    
    -- Request details
    request_type VARCHAR(50) DEFAULT 'remediation' 
        CHECK (request_type IN ('remediation', 'exception', 'override')),
    status VARCHAR(20) DEFAULT 'pending' 
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
    
    -- AI advisory data
    ai_analysis TEXT,
    ai_confidence DECIMAL(3,2),
    recommended_commands TEXT[],
    rollback_commands TEXT[],
    requires_restart BOOLEAN,
    requires_reboot BOOLEAN,
    
    -- Dry run results
    dry_run_output TEXT,
    dry_run_success BOOLEAN,
    
    -- Approval workflow
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    requested_by VARCHAR(100),
    expires_at TIMESTAMPTZ,
    
    -- Decision
    decided_at TIMESTAMPTZ,
    decided_by UUID REFERENCES users(id),
    decision_notes TEXT,
    
    -- Execution tracking
    executed_at TIMESTAMPTZ,
    execution_result JSONB,
    
    -- Audit trail
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_approvals_status ON approvals(status) WHERE status = 'pending';
CREATE INDEX idx_approvals_agent ON approvals(agent_id);
CREATE INDEX idx_approvals_rule ON approvals(rule_id);
CREATE INDEX idx_approvals_time ON approvals(requested_at DESC);
CREATE INDEX idx_approvals_expires ON approvals(expires_at) WHERE status = 'pending';

-- Exceptions (approved deviations)
CREATE TABLE exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id),
    rule_id VARCHAR(100) NOT NULL REFERENCES rules(id),
    
    -- Exception details
    reason TEXT NOT NULL,
    approved_by UUID NOT NULL REFERENCES users(id),
    approved_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Time-bounded
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'active' 
        CHECK (status IN ('active', 'expired', 'revoked')),
    revoked_by UUID REFERENCES users(id),
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT,
    
    -- References
    approval_id UUID REFERENCES approvals(id),
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_exceptions_agent_rule ON exceptions(agent_id, rule_id);
CREATE INDEX idx_exceptions_status ON exceptions(status) WHERE status = 'active';
CREATE INDEX idx_exceptions_valid ON exceptions(valid_until) WHERE status = 'active';

-- System configuration
CREATE TABLE system_config (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);
```

### TimescaleDB (Dedicated Cluster) - Time-Series Data

```sql
-- ============================================
-- TIMESERIES TABLES (TimescaleDB)
-- ============================================

-- Connect to TimescaleDB instance
\c vulnguard_timeseries

-- Enable extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Audit events hypertable (all security events)
CREATE TABLE audit_events (
    time TIMESTAMPTZ NOT NULL,
    event_id UUID DEFAULT gen_random_uuid(),
    
    -- Source
    agent_id UUID,
    user_id UUID,
    session_id UUID,
    
    -- Event classification
    event_type VARCHAR(50) NOT NULL 
        CHECK (event_type IN (
            'scan_start', 'scan_complete', 'scan_result',
            'evaluation', 'ai_advisory',
            'approval_requested', 'approval_decided',
            'remediation_start', 'remediation_complete', 'remediation_failed',
            'rollback_executed', 'backup_created',
            'agent_registered', 'agent_offline', 'agent_updated',
            'config_changed', 'user_login', 'user_action',
            'error', 'warning'
        )),
    severity VARCHAR(20) DEFAULT 'info' 
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    
    -- Event payload
    rule_id VARCHAR(100),
    benchmark VARCHAR(20),
    message TEXT,
    details JSONB,
    
    -- Compliance/audit
    compliance_status VARCHAR(20),
    risk_level VARCHAR(20),
    
    -- Metadata
    source_ip INET,
    user_agent TEXT,
    correlation_id UUID
);

-- Convert to hypertable with daily chunks
SELECT create_hypertable('audit_events', 'time', 
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Create indexes for common queries
CREATE INDEX idx_audit_time ON audit_events(time DESC);
CREATE INDEX idx_audit_agent ON audit_events(agent_id, time DESC);
CREATE INDEX idx_audit_type ON audit_events(event_type, time DESC);
CREATE INDEX idx_audit_severity ON audit_events(severity, time DESC) WHERE severity IN ('critical', 'high');
CREATE INDEX idx_audit_correlation ON audit_events(correlation_id);

-- Enable compression for old data
ALTER TABLE audit_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'agent_id, event_type'
);

-- Auto-compress chunks older than 7 days
SELECT add_compression_policy('audit_events', INTERVAL '7 days');

-- Auto-drop chunks older than 2 years (or archive to S3 first)
SELECT add_retention_policy('audit_events', INTERVAL '2 years');

-- ============================================
-- HISTORICAL SCAN RESULTS (TimescaleDB)
-- ============================================

CREATE TABLE scan_results_history (
    time TIMESTAMPTZ NOT NULL,
    
    agent_id UUID NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    session_id UUID,
    
    compliant BOOLEAN NOT NULL,
    severity VARCHAR(20),
    risk_level VARCHAR(20),
    
    compliance_score DECIMAL(5,2),
    remediation_time_ms INTEGER,
    
    scan_duration_ms INTEGER,
    check_type VARCHAR(50)
);

SELECT create_hypertable('scan_results_history', 'time',
    chunk_time_interval => INTERVAL '7 days'
);

CREATE INDEX idx_history_agent_rule ON scan_results_history(agent_id, rule_id, time DESC);
CREATE INDEX idx_history_compliance ON scan_results_history(compliant, time DESC);

ALTER TABLE scan_results_history SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'agent_id, rule_id'
);

SELECT add_compression_policy('scan_results_history', INTERVAL '14 days');
SELECT add_retention_policy('scan_results_history', INTERVAL '90 days');

-- ============================================
-- METRICS (TimescaleDB)
-- ============================================

CREATE TABLE fleet_metrics (
    time TIMESTAMPTZ NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DOUBLE PRECISION,
    
    agent_id UUID,
    environment VARCHAR(50),
    team VARCHAR(100),
    
    tags JSONB
);

SELECT create_hypertable('fleet_metrics', 'time', chunk_time_interval => INTERVAL '1 hour');

CREATE INDEX idx_metrics_name ON fleet_metrics(metric_name, time DESC);
CREATE INDEX idx_metrics_agent ON fleet_metrics(agent_id, metric_name, time DESC);

ALTER TABLE fleet_metrics SET (timescaledb.compress);
SELECT add_compression_policy('fleet_metrics', INTERVAL '3 days');
SELECT add_retention_policy('fleet_metrics', INTERVAL '1 year');

-- Continuous aggregates for fast dashboard queries
CREATE MATERIALIZED VIEW fleet_daily_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS bucket,
    agent_id,
    count(*) FILTER (WHERE event_type = 'scan_complete') as scans_count,
    count(*) FILTER (WHERE event_type = 'remediation_complete') as remediations_count,
    count(*) FILTER (WHERE severity = 'critical') as critical_events
FROM audit_events
GROUP BY bucket, agent_id;

SELECT add_continuous_aggregate_policy('fleet_daily_summary',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);
```

---

## Redis Cluster Configuration

```yaml
# redis-cluster.yml
cluster:
  nodes: 6
  replicas: 1
  
  masters:
    - name: redis-master-1
      host: redis-node-1.vulnguard.svc
      port: 6379
      slots: "0-5460"
      
    - name: redis-master-2
      host: redis-node-2.vulnguard.svc
      port: 6379
      slots: "5461-10922"
      
    - name: redis-master-3
      host: redis-node-3.vulnguard.svc
      port: 6379
      slots: "10923-16383"

  persistence:
    rdb: true
    aof: true
    appendfsync: everysec
    
  memory:
    maxmemory: 4gb
    maxmemory_policy: allkeys-lru
```

### Redis Key Schema

| Pattern | TTL | Purpose |
|---------|-----|---------|
| `session:{token}` | 24h | User authentication sessions |
| `agent:{id}:status` | 5min | Real-time agent status |
| `agent:{id}:metrics` | 5min | Agent performance metrics |
| `fleet:overview` | 30s | Aggregated fleet statistics |
| `fleet:compliance:trend:{granularity}` | 5min | Compliance trend data |
| `approvals:pending:list` | - | Pending approval queue |
| `approvals:pending:{id}` | - | Individual approval details |
| `query:{hash}` | 5min | Cached query results |
| `ratelimit:{ip}:{endpoint}` | 1min | Rate limiting counters |
| `ws:agent:{id}` | - | WebSocket channels for agents |
| `ws:fleet:{environment}` | - | Environment broadcast channels |
| `ws:user:{id}` | - | User notification channels |

---

## S3 Archive Strategy

```yaml
archive:
  trigger_age_days: 90
  schedule: "0 2 * * *"
  
  tables:
    - name: scan_results_history
      format: parquet
      compression: zstd
      
    - name: audit_events
      format: parquet
      compression: zstd
      partition_by: [year, month]
      
  s3_path_template: |
    s3://vulnguard-archive/
    {table}/
    year={year}/
    month={month}/
    {table}_{date}.parquet
  
  lifecycle:
    - transition_to_glacier: 365 days
    - expire: 2555 days
```

---

## Frontend Implementation

### Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | Next.js 14+ (App Router) | SSR/ISR, API routes, file-based routing |
| Language | TypeScript 5+ | Type safety |
| Styling | TailwindCSS + shadcn/ui | Utility-first CSS, accessible components |
| State (Server) | TanStack Query (React Query) | Server state, caching, synchronization |
| State (Client) | Zustand | Client-side UI state |
| Tables | TanStack Table | Virtualization, sorting, filtering |
| Charts | Recharts | Compliance trends, metrics |
| WebSocket | Socket.io | Real-time updates |
| Validation | Zod | Runtime schema validation |

### Project Structure

```
frontend/
├── src/
│   ├── app/
│   │   ├── (dashboard)/
│   │   │   ├── layout.tsx
│   │   │   ├── page.tsx
│   │   │   ├── loading.tsx
│   │   │   └── error.tsx
│   │   ├── agents/
│   │   │   ├── page.tsx
│   │   │   └── [id]/
│   │   │       ├── page.tsx
│   │   │       ├── scans/
│   │   │       │   └── page.tsx
│   │   │       └── compliance/
│   │   │           └── page.tsx
│   │   ├── approvals/
│   │   │   ├── page.tsx
│   │   │   └── [id]/
│   │   │       └── page.tsx
│   │   ├── audit/
│   │   │   ├── page.tsx
│   │   │   └── export/
│   │   │       └── page.tsx
│   │   ├── api/
│   │   │   ├── agents/
│   │   │   │   └── route.ts
│   │   │   ├── scans/
│   │   │   ├── approvals/
│   │   │   ├── audit/
│   │   │   └── ws/
│   │   │       └── route.ts
│   │   └── layout.tsx
│   ├── components/
│   │   ├── agents/
│   │   ├── approvals/
│   │   ├── audit/
│   │   ├── dashboard/
│   │   └── ui/
│   ├── lib/
│   │   ├── db/
│   │   │   ├── postgres.ts
│   │   │   ├── timescale.ts
│   │   │   └── redis.ts
│   │   ├── queries/
│   │   │   ├── agents.ts
│   │   │   ├── scans.ts
│   │   │   ├── approvals.ts
│   │   │   └── audit.ts
│   │   ├── realtime/
│   │   │   ├── websocket.ts
│   │   │   ├── pubsub.ts
│   │   │   └── handlers.ts
│   │   └── cache/
│   │       ├── cache.ts
│   │       ├── keys.ts
│   │       └── invalidation.ts
│   ├── hooks/
│   │   ├── useAgents.ts
│   │   ├── useScanResults.ts
│   │   ├── useApprovals.ts
│   │   ├── useAuditLog.ts
│   │   ├── useRealtime.ts
│   │   └── useVirtualization.ts
│   └── types/
│       ├── agent.ts
│       ├── scan.ts
│       ├── approval.ts
│       └── api.ts
├── prisma/
│   └── schema.prisma
└── terraform/
    ├── main.tf
    ├── rds.tf
    ├── elasticache.tf
    └── s3.tf
```

---

## Data Flow Patterns

### 1. Fleet Overview (Cached, Fast)

```
Client → Next.js API → Redis Cache → PostgreSQL Read Replica
                ↓
         30s Revalidate (ISR)
```

### 2. Real-time Approvals (WebSocket)

```
Agent → Gateway → PostgreSQL Primary
                      ↓
                Redis Pub/Sub
                      ↓
              WebSocket Server → Clients
```

### 3. Audit Log Query (Time-range)

```
Client → Next.js API → Redis (Query Cache) → TimescaleDB Access Node
                                                    ↓
                                              Data Nodes (Chunks)
```

---

## API Design

### Fleet Overview Endpoint

```typescript
// GET /api/agents?environment={env}&team={team}
interface FleetOverviewResponse {
  totalAgents: number;
  onlineCount: number;
  offlineCount: number;
  complianceRate: number;
  criticalIssues: number;
  highIssues: number;
  pendingApprovals: number;
  recentScans: {
    timestamp: string;
    count: number;
  }[];
}
```

### Audit Log Endpoint

```typescript
// GET /api/audit?start={ISO}&end={ISO}&agentId={id}&cursor={cursor}&limit=50
interface AuditLogResponse {
  events: AuditEvent[];
  nextCursor: string | null;
  hasMore: boolean;
}

interface AuditEvent {
  id: string;
  timestamp: string;
  agentId: string;
  eventType: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  details: Record<string, unknown>;
}
```

### WebSocket Message Types

#### Server → Client

| Message Type | Description |
|--------------|-------------|
| `fleet:overview` | Updated fleet statistics |
| `agent:{id}:status` | Agent status change |
| `agent:{id}:scan_complete` | Scan finished |
| `approval:new` | New approval request |
| `approval:decided` | Approval decision made |
| `alert:critical` | Critical security alert |

#### Client → Server

| Message Type | Description |
|--------------|-------------|
| `subscribe:fleet` | Subscribe to fleet updates |
| `subscribe:agent:{id}` | Subscribe to agent updates |
| `approval:approve` | Approve remediation |
| `approval:reject` | Reject remediation |
| `request:rescan` | Request agent rescan |

---

## Deployment Architecture (AWS Example)

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                      VPC                                                │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                PUBLIC SUBNET                                      │  │
│  │  ┌─────────────┐  ┌─────────────┐                                                │  │
│  │  │   ALB       │  │   NAT GW    │                                                │  │
│  │  │  (HTTPS)    │  │             │                                                │  │
│  │  └──────┬──────┘  └─────────────┘                                                │  │
│  │         │                                                                         │  │
│  └─────────┼─────────────────────────────────────────────────────────────────────────┘  │
│            │                                                                            │
│  ┌─────────┼─────────────────────────────────────────────────────────────────────────┐  │
│  │         ▼                       PRIVATE SUBNET (App)                              │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                     ECS/EKS Cluster (Next.js Frontend)                     │  │  │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                                    │  │  │
│  │  │  │ Pod 1   │  │ Pod 2   │  │ Pod 3   │  (Auto-scaling: 3-20 replicas)    │  │  │
│  │  │  │ Next.js │  │ Next.js │  │ Next.js │                                    │  │  │
│  │  │  └─────────┘  └─────────┘  └─────────┘                                    │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                                   │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │                       PRIVATE SUBNET (Data)                                       │  │
│  │                                                                                   │  │
│  │  ┌─────────────────────────┐  ┌─────────────────────────┐                        │  │
│  │  │   RDS PostgreSQL        │  │   TimescaleDB (EC2)     │                        │  │
│  │  │   ┌─────────┐           │  │   ┌─────────┐           │                        │  │
│  │  │   │Primary  │◄──────────┼──┼──►│ Access  │           │                        │  │
│  │  │   │  (RW)   │           │  │   │  Node   │           │                        │  │
│  │  │   └────┬────┘           │  │   └────┬────┘           │                        │  │
│  │  │        │ Replication     │  │        │                │                        │  │
│  │  │   ┌────▼────┐           │  │   ┌────┴────┐           │                        │  │
│  │  │   │Replica  │           │  │   │ Data    │           │                        │  │
│  │  │   │  (RO)   │◄──────────┼──┼──►│ Nodes   │           │                        │  │
│  │  │   └─────────┘           │  │   │ (3-5x)  │           │                        │  │
│  │  └─────────────────────────┘  └─────────────────────────┘                        │  │
│  │                                                                                   │  │
│  │  ┌─────────────────────────┐  ┌─────────────────────────┐                        │  │
│  │  │   ElastiCache Redis     │  │   S3 VPC Endpoint       │                        │  │
│  │  │   Cluster Mode          │  │   (Archive bucket)      │                        │  │
│  │  │   (3 shards + replicas) │  │                         │                        │  │
│  │  └─────────────────────────┘  └─────────────────────────┘                        │  │
│  │                                                                                   │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Monitoring & Alerting

### Metrics to Monitor

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| API Response Time (p99) | < 500ms | > 2s |
| Database Query Time (p99) | < 100ms | > 500ms |
| Cache Hit Rate | > 85% | < 80% |
| WebSocket Connections | - | > 80% capacity |
| PostgreSQL Replication Lag | < 1s | > 30s |
| Redis Cluster Memory | - | > 80% |
| Error Rate | < 0.1% | > 5% |
| Failed Approvals | - | Any in 5min |

### Alert Priorities

- **P1 (Critical)**: PostgreSQL primary down, Redis cluster unhealthy, API completely down
- **P2 (High)**: Replication lag > 30s, error rate > 5%, single AZ failure
- **P3 (Warning)**: Cache hit rate < 80%, slow queries, disk usage > 80%

---

## Success Metrics

| Metric | Target | Test Scenario |
|--------|--------|---------------|
| Dashboard Load | < 2s | 500 agents, cold cache |
| Table Scroll | 60fps | 10,000 rows virtualized |
| WebSocket Reconnect | < 5s | Network interruption |
| Search Response | < 500ms | Full-text search across fleet |
| Memory Usage | < 200MB | 1,000 visible rows |
| Audit Query | < 2s | 30-day time range |
| Approval Latency | < 1s | End-to-end notification |

---

## Security Considerations

1. **Input Validation**: All incoming data validated with Zod schemas
2. **XSS Prevention**: No `dangerouslySetInnerHTML`; sanitize all outputs
3. **CSRF Protection**: WebSocket authentication tokens, SameSite cookies
4. **Audit Logging**: All UI actions logged to audit trail
5. **Read-Only Default**: No inline command editing, explicit confirmations
6. **Rate Limiting**: Per-user and per-IP rate limits on all endpoints

---

## Next Steps

1. **Phase 1**: Implement PostgreSQL schema and basic Next.js frontend
2. **Phase 2**: Add Redis caching and WebSocket real-time updates
3. **Phase 3**: Integrate TimescaleDB for audit and metrics
4. **Phase 4**: Implement S3 archival and cold storage queries
5. **Phase 5**: Load testing and optimization for 500+ agents

---

*This architecture document should be updated as the system evolves.*
