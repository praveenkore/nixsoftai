'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { ExternalLink, Search, Filter } from 'lucide-react';
import { Agent } from '@/types';

export default function AgentsPage() {
    const [agents, setAgents] = useState<Agent[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('/api/agents')
            .then((res) => res.json())
            .then((data) => {
                setAgents(data.agents || []);
                setLoading(false);
            });
    }, []);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-3xl font-bold tracking-tight">Agents</h1>
                <div className="flex items-center gap-2">
                    <div className="relative">
                        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                        <input
                            type="search"
                            placeholder="Search agents..."
                            className="rounded-md border bg-background pl-8 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                        />
                    </div>
                    <button className="flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm hover:bg-accent shadow-sm">
                        <Filter className="h-4 w-4" /> Filter
                    </button>
                </div>
            </div>

            <div className="rounded-xl border bg-card shadow-sm overflow-hidden">
                <table className="w-full text-sm text-left">
                    <thead className="bg-muted/50 text-muted-foreground font-medium border-b">
                        <tr>
                            <th className="px-6 py-3">Hostname</th>
                            <th className="px-6 py-3">Status</th>
                            <th className="px-6 py-3">OS</th>
                            <th className="px-6 py-3">IP Address</th>
                            <th className="px-6 py-3">Last Seen</th>
                            <th className="px-6 py-3">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y">
                        {loading ? (
                            <tr>
                                <td colSpan={6} className="px-6 py-10 text-center text-muted-foreground">
                                    Loading agents...
                                </td>
                            </tr>
                        ) : agents.length === 0 ? (
                            <tr>
                                <td colSpan={6} className="px-6 py-10 text-center text-muted-foreground">
                                    No agents found.
                                </td>
                            </tr>
                        ) : (
                            agents.map((agent) => (
                                <tr key={agent.id} className="hover:bg-accent/5 transition-colors">
                                    <td className="px-6 py-4 font-medium">{agent.hostname}</td>
                                    <td className="px-6 py-4">
                                        <span className={`px-2 py-1 rounded-full text-xs font-semibold ${agent.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'
                                            }`}>
                                            {agent.status}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4">{agent.os}</td>
                                    <td className="px-6 py-4 font-mono text-xs">{agent.ipAddress || '---'}</td>
                                    <td className="px-6 py-4 text-muted-foreground">
                                        {new Date(agent.lastSeen).toLocaleString()}
                                    </td>
                                    <td className="px-6 py-4">
                                        <Link
                                            href={`/agents/${agent.id}`}
                                            className="text-primary hover:underline flex items-center gap-1"
                                        >
                                            View Details <ExternalLink className="h-3 w-3" />
                                        </Link>
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
