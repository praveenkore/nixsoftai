import { NextResponse } from 'next/server';
import getPrismaClient from '@/lib/db/postgres';

export async function GET(request: Request) {
    const prisma = getPrismaClient();
    const { searchParams } = new URL(request.url);
    const environment = searchParams.get('environment');
    const team = searchParams.get('team');

    try {
        const where: any = {};
        if (environment) where.environment = environment;
        if (team) where.team = team;

        const agents = await prisma.agent.findMany({
            where,
            orderBy: { lastSeen: 'desc' },
        });

        // Simple aggregation for stats on the same call for V0
        const stats = {
            totalAgents: agents.length,
            onlineCount: agents.filter((a) => a.status === 'online').length,
            offlineCount: agents.filter((a) => a.status === 'offline').length,
            criticalIssues: 0, // Would require join with CurrentScanResult
            complianceRate: 0,
        };

        return NextResponse.json({ agents, stats });
    } catch (error) {
        console.error('Failed to fetch agents:', error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
