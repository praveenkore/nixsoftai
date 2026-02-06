import Link from 'next/link';

export function Navbar() {
    return (
        <nav className="fixed top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
            <div className="container flex h-16 items-center justify-between px-4 sm:px-8">
                <Link href="/" className="flex items-center space-x-2">
                    <span className="text-xl font-bold tracking-tight text-primary">VulnGuard</span>
                </Link>
                <div className="flex items-center space-x-4 text-sm font-medium">
                    <span className="text-muted-foreground">© 2026 Nixsoft</span>
                </div>
            </div>
        </nav>
    );
}
