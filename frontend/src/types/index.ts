export type AssetStatus = 'online' | 'offline' | 'error' | 'updating' | 'pending';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ComplianceStatus = 'compliant' | 'non-compliant' | 'warning' | 'error';

export interface Agent {
    id: string;
    hostname: string;
    displayName?: string;
    os: string;
    osVersion: string;
    ipAddress?: string;
    status: AssetStatus;
    lastSeen: string;
    environment: string;
    team?: string;
    complianceScore?: number;
}

export interface Rule {
    id: string;
    benchmark: string;
    title: string;
    severity: Severity;
    description?: string;
    remediationSteps?: string[];
}

export interface ScanResult {
    id: string;
    agentId: string;
    ruleId: string;
    compliant: boolean;
    actualState?: string;
    expectedState?: string;
    checkOutput?: string;
    severity: Severity;
    lastScanned: string;
}

export interface FleetStats {
    totalAgents: number;
    onlineCount: number;
    offlineCount: number;
    complianceRate: number;
    criticalIssues: number;
    highIssues: number;
    pendingApprovals: number;
}
