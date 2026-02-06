'use client';

import { useState, useEffect } from 'react';
import { CheckCircle, XCircle, Clock, ShieldAlert, Cpu } from 'lucide-react';

export default function ApprovalQueuePage() {
    const [approvals, setApprovals] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('/api/approvals')
            .then((res) => res.json())
            .then((data) => {
                setApprovals(data);
                setLoading(false);
            });
    }, []);

    const handleDecision = async (approvalId: string, decision: 'approved' | 'rejected') => {
        try {
            const res = await fetch('/api/approvals', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ approvalId, decision, notes: 'Handled via V0 UI' }),
            });
            if (res.ok) {
                setApprovals(approvals.filter((a) => a.id !== approvalId));
            }
        } catch (err) {
            console.error('Failed to update approval:', err);
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-3xl font-bold tracking-tight">Approval Queue</h1>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4" />
                    <span>{approvals.length} Pending Requests</span>
                </div>
            </div>

            <div className="grid gap-6">
                {loading ? (
                    <div className="py-20 text-center text-muted-foreground border rounded-xl bg-card">
                        Loading approval queue...
                    </div>
                ) : approvals.length === 0 ? (
                    <div className="py-20 text-center text-muted-foreground border rounded-xl bg-card">
                        No pending approvals.
                    </div>
                ) : (
                    approvals.map((approval) => (
                        <div key={approval.id} className="rounded-xl border bg-card shadow-sm overflow-hidden flex flex-col md:flex-row">
                            <div className="w-full md:w-1/3 bg-muted/30 p-6 border-b md:border-b-0 md:border-r space-y-4">
                                <div>
                                    <h3 className="font-semibold text-sm">Host</h3>
                                    <p className="text-sm font-mono">{approval.agent.hostname}</p>
                                </div>
                                <div>
                                    <h3 className="font-semibold text-sm">Rule</h3>
                                    <p className="text-sm text-muted-foreground">{approval.rule.title}</p>
                                </div>
                                <div className="flex items-center gap-2 text-xs">
                                    <span className="px-2 py-1 rounded-full bg-red-100 text-red-700 font-semibold uppercase">
                                        {approval.rule.severity}
                                    </span>
                                    <div className="flex items-center gap-1 text-primary">
                                        <Cpu className="h-3 w-3" />
                                        <span>AI Confidence: {(approval.aiConfidence * 100).toFixed(0)}%</span>
                                    </div>
                                </div>
                            </div>

                            <div className="flex-1 p-6 space-y-4">
                                <div>
                                    <h3 className="font-semibold text-sm mb-2">Recommended Remediation</h3>
                                    <div className="bg-slate-950 text-slate-50 p-4 rounded-lg font-mono text-xs overflow-x-auto">
                                        {approval.recommendedCmds?.length > 0
                                            ? approval.recommendedCmds.map((cmd: string, i: number) => <div key={i}>$ {cmd}</div>)
                                            : '# No commands provided'}
                                    </div>
                                </div>

                                <div className="flex gap-4">
                                    <button
                                        onClick={() => handleDecision(approval.id, 'approved')}
                                        className="flex-1 flex items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
                                    >
                                        <CheckCircle className="h-4 w-4" /> Approve & Execute
                                    </button>
                                    <button
                                        onClick={() => handleDecision(approval.id, 'rejected')}
                                        className="flex-1 flex items-center justify-center gap-2 rounded-md border bg-background px-4 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
                                    >
                                        <XCircle className="h-4 w-4" /> Reject
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
