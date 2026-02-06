import { Navbar } from '@/components/layout/Navbar';
import { Sidebar } from '@/components/layout/Sidebar';

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <div className="min-h-screen bg-background">
            <Navbar />
            <div className="flex">
                <Sidebar />
                <main className="flex-1 pl-64 pt-16">
                    <div className="container p-8">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
}
