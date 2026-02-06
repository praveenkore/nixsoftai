-- CreateTable
CREATE TABLE "Agent" (
    "id" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "displayName" TEXT,
    "os" TEXT NOT NULL,
    "osVersion" TEXT NOT NULL,
    "osCodename" TEXT,
    "architecture" TEXT,
    "kernelVersion" TEXT,
    "ipAddress" TEXT,
    "macAddress" TEXT,
    "agentVersion" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "environment" TEXT NOT NULL DEFAULT 'production',
    "team" TEXT,
    "datacenter" TEXT,
    "labels" JSONB NOT NULL DEFAULT '{}',
    "config" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "Agent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "email" TEXT,
    "role" TEXT NOT NULL DEFAULT 'viewer',
    "permissions" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastLogin" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Rule" (
    "id" TEXT NOT NULL,
    "benchmark" TEXT NOT NULL,
    "benchmarkVersion" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "rationale" TEXT,
    "severity" TEXT NOT NULL,
    "originalSeverity" TEXT,
    "checkType" TEXT NOT NULL,
    "remediationCmds" TEXT[],
    "rollbackCmds" TEXT[],
    "requiresRestart" BOOLEAN NOT NULL DEFAULT false,
    "requiresReboot" BOOLEAN NOT NULL DEFAULT false,
    "osCompatibility" TEXT[],
    "cisControl" TEXT,
    "cisSubcontrol" TEXT,
    "stigId" TEXT,
    "nistMapping" TEXT[],
    "aiAssist" BOOLEAN NOT NULL DEFAULT false,
    "approvalRequired" BOOLEAN NOT NULL DEFAULT false,
    "exceptionAllowed" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Rule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanSession" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "initiatedBy" TEXT NOT NULL DEFAULT 'system',
    "initiatedVia" TEXT NOT NULL DEFAULT 'scheduled',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "durationMs" INTEGER,
    "totalRules" INTEGER NOT NULL DEFAULT 0,
    "compliantCount" INTEGER NOT NULL DEFAULT 0,
    "nonCompliantCount" INTEGER NOT NULL DEFAULT 0,
    "errorCount" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'running',
    "errorMessage" TEXT,
    "compliancePercentage" DECIMAL(65,30),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CurrentScanResult" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "sessionId" TEXT,
    "compliant" BOOLEAN NOT NULL,
    "expectedState" TEXT,
    "actualState" TEXT,
    "checkOutput" TEXT,
    "errorMessage" TEXT,
    "severity" TEXT,
    "riskLevel" TEXT,
    "aiAssistRequired" BOOLEAN NOT NULL DEFAULT false,
    "approvalRequired" BOOLEAN NOT NULL DEFAULT false,
    "firstDetected" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanned" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "scanCount" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "CurrentScanResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Approval" (
    "id" TEXT NOT NULL,
    "scanResultId" TEXT,
    "agentId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "sessionId" TEXT,
    "requestType" TEXT NOT NULL DEFAULT 'remediation',
    "status" TEXT NOT NULL DEFAULT 'pending',
    "aiAnalysis" TEXT,
    "aiConfidence" DECIMAL(65,30),
    "recommendedCmds" TEXT[],
    "rollbackCmds" TEXT[],
    "requiresRestart" BOOLEAN,
    "requiresReboot" BOOLEAN,
    "dryRunOutput" TEXT,
    "dryRunSuccess" BOOLEAN,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "requestedBy" TEXT,
    "expiresAt" TIMESTAMP(3),
    "decidedAt" TIMESTAMP(3),
    "decidedBy" TEXT,
    "decisionNotes" TEXT,
    "executedAt" TIMESTAMP(3),
    "executionResult" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Approval_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Exception" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "approvedBy" TEXT NOT NULL,
    "approvedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "validFrom" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "validUntil" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "revokedBy" TEXT,
    "revokedAt" TIMESTAMP(3),
    "revokeReason" TEXT,
    "approvalId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Exception_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SystemConfig" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "description" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedBy" TEXT,

    CONSTRAINT "SystemConfig_pkey" PRIMARY KEY ("key")
);

-- CreateIndex
CREATE UNIQUE INDEX "Agent_hostname_key" ON "Agent"("hostname");

-- CreateIndex
CREATE INDEX "Agent_status_idx" ON "Agent"("status");

-- CreateIndex
CREATE INDEX "Agent_environment_idx" ON "Agent"("environment");

-- CreateIndex
CREATE INDEX "Agent_team_idx" ON "Agent"("team");

-- CreateIndex
CREATE INDEX "Agent_lastSeen_idx" ON "Agent"("lastSeen");

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "Rule_benchmark_idx" ON "Rule"("benchmark");

-- CreateIndex
CREATE INDEX "Rule_severity_idx" ON "Rule"("severity");

-- CreateIndex
CREATE INDEX "ScanSession_agentId_idx" ON "ScanSession"("agentId");

-- CreateIndex
CREATE INDEX "ScanSession_status_idx" ON "ScanSession"("status");

-- CreateIndex
CREATE INDEX "ScanSession_startedAt_idx" ON "ScanSession"("startedAt" DESC);

-- CreateIndex
CREATE INDEX "ScanSession_compliancePercentage_idx" ON "ScanSession"("compliancePercentage");

-- CreateIndex
CREATE INDEX "CurrentScanResult_agentId_idx" ON "CurrentScanResult"("agentId");

-- CreateIndex
CREATE INDEX "CurrentScanResult_ruleId_idx" ON "CurrentScanResult"("ruleId");

-- CreateIndex
CREATE INDEX "CurrentScanResult_compliant_idx" ON "CurrentScanResult"("compliant");

-- CreateIndex
CREATE INDEX "CurrentScanResult_riskLevel_idx" ON "CurrentScanResult"("riskLevel");

-- CreateIndex
CREATE INDEX "CurrentScanResult_approvalRequired_idx" ON "CurrentScanResult"("approvalRequired");

-- CreateIndex
CREATE UNIQUE INDEX "CurrentScanResult_agentId_ruleId_key" ON "CurrentScanResult"("agentId", "ruleId");

-- CreateIndex
CREATE INDEX "Approval_status_idx" ON "Approval"("status");

-- CreateIndex
CREATE INDEX "Approval_agentId_idx" ON "Approval"("agentId");

-- CreateIndex
CREATE INDEX "Approval_ruleId_idx" ON "Approval"("ruleId");

-- CreateIndex
CREATE INDEX "Approval_requestedAt_idx" ON "Approval"("requestedAt" DESC);

-- CreateIndex
CREATE INDEX "Approval_expiresAt_idx" ON "Approval"("expiresAt");

-- CreateIndex
CREATE INDEX "Exception_agentId_ruleId_idx" ON "Exception"("agentId", "ruleId");

-- CreateIndex
CREATE INDEX "Exception_status_idx" ON "Exception"("status");

-- CreateIndex
CREATE INDEX "Exception_validUntil_idx" ON "Exception"("validUntil");

-- AddForeignKey
ALTER TABLE "ScanSession" ADD CONSTRAINT "ScanSession_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrentScanResult" ADD CONSTRAINT "CurrentScanResult_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrentScanResult" ADD CONSTRAINT "CurrentScanResult_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "Rule"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrentScanResult" ADD CONSTRAINT "CurrentScanResult_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "ScanSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Approval" ADD CONSTRAINT "Approval_scanResultId_fkey" FOREIGN KEY ("scanResultId") REFERENCES "CurrentScanResult"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Approval" ADD CONSTRAINT "Approval_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Approval" ADD CONSTRAINT "Approval_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "Rule"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Approval" ADD CONSTRAINT "Approval_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "ScanSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Approval" ADD CONSTRAINT "Approval_decidedBy_fkey" FOREIGN KEY ("decidedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Exception" ADD CONSTRAINT "Exception_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "Agent"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Exception" ADD CONSTRAINT "Exception_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "Rule"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Exception" ADD CONSTRAINT "Exception_approvedBy_fkey" FOREIGN KEY ("approvedBy") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Exception" ADD CONSTRAINT "Exception_revokedBy_fkey" FOREIGN KEY ("revokedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Exception" ADD CONSTRAINT "Exception_approvalId_fkey" FOREIGN KEY ("approvalId") REFERENCES "Approval"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SystemConfig" ADD CONSTRAINT "SystemConfig_updatedBy_fkey" FOREIGN KEY ("updatedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
