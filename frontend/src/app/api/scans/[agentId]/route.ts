import { NextResponse } from 'next/server';
import getPrismaClient from '@/lib/db/postgres';

export async function GET(
    request: Request,
    { params }: { params: Promise<{ agentId: string }> }
) {
    const prisma = getPrismaClient();
    try {
        const { agentId } = await params;
        const results = await prisma.currentScanResult.findMany({
            where: { agentId },
            include: { rule: true },
            orderBy: { ruleId: 'asc' },
        });

        return NextResponse.json(results);
    } catch (error) {
        console.error('Failed to fetch scan results:', error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
