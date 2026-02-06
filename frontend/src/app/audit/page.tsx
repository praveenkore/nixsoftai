'use client';

import { useState, useEffect } from 'react';
import { Search, Filter, Download, Info, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function AuditLogPage() {
    const [events, setEvents] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    // Mock data for V0 since timeseries DB might not be linked yet
    useEffect(() => {
        setTimeout(() => {
            setEvents([
                { id: 1, time: new Date().toISOString(), type: 'scan_complete', severity: 'info', agent: 'prod-web-01', message: 'Full system compliance scan completed' },
                { id: 2, time: new Date().toISOString(), type: 'remediation_complete', severity: 'low', agent: 'db-master-01', message: 'Password complexity rule enforced' },
                { id: 3, time: new Date().toISOString(), type: 'error', severity: 'high', agent: 'app-service-02', message: 'Agent connection lost' },
            ]);
            setLoading(false);
        }, 500);
    }, []);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-3xl font-bold tracking-tight">Audit Log</h1>
                <div className="flex gap-2">
                    <button className="flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm hover:bg-accent shadow-sm">
                        <Download className="h-4 w-4" /> Export JSON
                    </button>
                </div>
            </div>

            <div className="flex items-center gap-2">
                <div className="relative flex-1">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <input
                        type="search"
                        placeholder="Search audit events..."
                        className="w-full rounded-md border bg-background pl-8 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                </div>
                <button className="flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm hover:bg-accent shadow-sm">
                    <Filter className="h-4 w-4" /> Filter
                </button>
            </div>

            <div className="rounded-xl border bg-card shadow-sm overflow-hidden">
                <table className="w-full text-sm text-left">
                    <thead className="bg-muted/50 text-muted-foreground font-medium border-b">
                        <tr>
                            <th className="px-6 py-3">Timestamp</th>
                            <th className="px-6 py-3">Type</th>
                            <th className="px-6 py-3">Agent</th>
                            <th className="px-6 py-3">Message</th>
                            <th className="px-6 py-3">Severity</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y text-xs">
                        {loading ? (
                            <tr><td colSpan={5} className="px-6 py-10 text-center">Loading audit data...</td></tr>
                        ) : (
                            events.map((event) => (
                                <tr key={event.id} className="hover:bg-accent/5">
                                    <td className="px-6 py-4 font-mono text-muted-foreground">
                                        {new Date(event.time).toLocaleString()}
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className="font-semibold uppercase text-[10px] tracking-wider text-muted-foreground">
                                            {event.type.replace('_', ' ')}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 font-medium">{event.agent}</td>
                                    <td className="px-6 py-4">{event.message}</td>
                                    <td className="px-6 py-4">
                                        {event.severity === 'high' ? (
                                            <span className="flex items-center gap-1 text-red-600"><AlertTriangle className="h-3 w-3" /> High</span>
                                        ) : (
                                            <span className="flex items-center gap-1 text-blue-600"><Info className="h-3 w-3" /> {event.severity}</span>
                                        )}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
