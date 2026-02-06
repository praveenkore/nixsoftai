'use client';

import { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, ChevronLeft } from 'lucide-react';
import Link from 'next/link';

import { use } from 'react';

export default function AgentDetailsPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const [results, setResults] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch(`/api/scans/${id}`)
            .then((res) => res.json())
            .then((data) => {
                setResults(data);
                setLoading(false);
            });
    }, [id]);

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Link href="/agents" className="p-2 hover:bg-accent rounded-full">
                    <ChevronLeft className="h-5 w-5" />
                </Link>
                <h1 className="text-3xl font-bold tracking-tight">Scan Results</h1>
            </div>

            <div className="grid gap-6">
                {loading ? (
                    <div className="py-20 text-center text-muted-foreground border rounded-xl bg-card">
                        Loading scan results...
                    </div>
                ) : results.length === 0 ? (
                    <div className="py-20 text-center text-muted-foreground border rounded-xl bg-card">
                        No scan data available for this agent.
                    </div>
                ) : (
                    results.map((result) => (
                        <div key={result.id} className="rounded-xl border bg-card shadow-sm overflow-hidden">
                            <div className={`px-6 py-4 flex items-center justify-between border-b ${result.compliant ? 'bg-green-50/50' : 'bg-red-50/50'
                                }`}>
                                <div className="flex items-center gap-3">
                                    {result.compliant ? (
                                        <ShieldCheck className="h-5 w-5 text-green-600" />
                                    ) : (
                                        <ShieldAlert className="h-5 w-5 text-red-600" />
                                    )}
                                    <div>
                                        <h3 className="font-semibold text-sm">{result.rule.title}</h3>
                                        <p className="text-xs text-muted-foreground">{result.rule.id}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-4 text-xs">
                                    <span className={`px-2 py-1 rounded-full font-semibold ${result.compliant ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                                        }`}>
                                        {result.compliant ? 'Compliant' : 'Non-Compliant'}
                                    </span>
                                    <span className="text-muted-foreground">
                                        Severity: <span className="font-medium text-foreground capitalize">{result.rule.severity}</span>
                                    </span>
                                </div>
                            </div>
                            {!result.compliant && (
                                <div className="px-6 py-4 space-y-4">
                                    <div className="grid grid-cols-2 gap-4 text-sm">
                                        <div>
                                            <h4 className="font-medium mb-1 text-muted-foreground uppercase text-[10px] tracking-wider">Expected State</h4>
                                            <pre className="bg-muted p-2 rounded text-xs overflow-x-auto">{result.expectedState || 'N/A'}</pre>
                                        </div>
                                        <div>
                                            <h4 className="font-medium mb-1 text-muted-foreground uppercase text-[10px] tracking-wider">Actual State</h4>
                                            <pre className="bg-red-50 p-2 rounded text-xs overflow-x-auto text-red-900">{result.actualState || 'N/A'}</pre>
                                        </div>
                                    </div>
                                    {result.rule.description && (
                                        <div className="text-sm">
                                            <h4 className="font-medium mb-1">Description</h4>
                                            <p className="text-muted-foreground">{result.rule.description}</p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
