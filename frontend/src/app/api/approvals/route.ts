import { NextResponse } from 'next/server';
import getPrismaClient from '@/lib/db/postgres';

export async function GET() {
    const prisma = getPrismaClient();
    try {
        const approvals = await prisma.approval.findMany({
            where: { status: 'pending' },
            include: {
                agent: true,
                rule: true,
            },
            orderBy: { requestedAt: 'desc' },
        });

        return NextResponse.json(approvals);
    } catch (error) {
        console.error('Failed to fetch approvals:', error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}

export async function POST(request: Request) {
    const prisma = getPrismaClient();
    try {
        const body = await request.json();
        const { approvalId, decision, notes } = body;

        if (!['approved', 'rejected'].includes(decision)) {
            return NextResponse.json({ error: 'Invalid decision' }, { status: 400 });
        }

        const updatedApproval = await prisma.approval.update({
            where: { id: approvalId },
            data: {
                status: decision,
                decisionNotes: notes,
                decidedAt: new Date(),
            },
        });

        return NextResponse.json(updatedApproval);
    } catch (error) {
        console.error('Failed to update approval:', error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
