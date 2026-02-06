export default async function OverviewPage() {
    // In a real app, this would be a server component fetching from the API
    // For V0, we can mock or fetch directly from Prisma if needed

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-3xl font-bold tracking-tight">Overview</h1>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <StatsCard title="Total Agents" value="--" description="Connected hosts" />
                <StatsCard title="Online" value="--" description="Active now" color="text-green-500" />
                <StatsCard title="Critical Issues" value="--" description="Immediate remediation" color="text-red-500" />
                <StatsCard title="Compliance" value="-- %" description="Fleet average" />
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
                <div className="col-span-4 rounded-xl border bg-card p-6 shadow-sm">
                    <h3 className="font-semibold leading-none tracking-tight">Agent Distribution</h3>
                    <div className="mt-4 h-[300px] flex items-center justify-center text-muted-foreground">
                        Chart Placeholder (Recharts)
                    </div>
                </div>
                <div className="col-span-3 rounded-xl border bg-card p-6 shadow-sm">
                    <h3 className="font-semibold leading-none tracking-tight">Recent Activity</h3>
                    <div className="mt-4 space-y-4">
                        <p className="text-sm text-muted-foreground text-center py-10">No recent events</p>
                    </div>
                </div>
            </div>
        </div>
    );
}

function StatsCard({ title, value, description, color }: { title: string; value: string; description: string; color?: string }) {
    return (
        <div className="rounded-xl border bg-card p-6 shadow-sm">
            <div className="flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="text-sm font-medium tracking-tight">{title}</h3>
            </div>
            <div>
                <div className={`text-2xl font-bold ${color || ''}`}>{value}</div>
                <p className="text-xs text-muted-foreground">{description}</p>
            </div>
        </div>
    );
}
