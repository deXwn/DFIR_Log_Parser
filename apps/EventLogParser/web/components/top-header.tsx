"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export default function TopHeader() {
  const pathname = usePathname();
  return (
    <header className="flex items-center justify-between px-4 md:px-8 py-4 border-b border-black/50 bg-panelAccent/80 backdrop-blur sticky top-0 z-20 shadow-[0_8px_30px_rgba(0,0,0,0.4)]">
      <div className="text-sm text-muted">
        {pathname === "/" ? "Dashboard" : pathname.replace("/", "")}
      </div>
      <div className="flex items-center gap-3 text-sm">
        <Link
          href="/search"
          className="px-3 py-1 rounded-md bg-black/60 border border-black/40 text-[var(--text)] hover:border-accent/60 transition"
        >
          Search
        </Link>
        <span className="text-muted">EVTX DFIR</span>
      </div>
    </header>
  );
}
