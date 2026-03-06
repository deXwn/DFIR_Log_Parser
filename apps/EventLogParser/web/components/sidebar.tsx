"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "Overview" },
  { href: "/ingest", label: "Ingest" },
  { href: "/events", label: "Events" },
  { href: "/processes", label: "Process Tree" },
  { href: "/stats", label: "Stats" },
  { href: "/timeline", label: "Timeline" },
  { href: "/search", label: "Search" },
  { href: "/report", label: "Report" },
  { href: "/detections", label: "Detections" }
];

export default function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="w-64 hidden md:flex flex-col bg-panel border-r border-black/50 shadow-[2px_0_30px_rgba(0,0,0,0.4)]">
      <div className="p-6 border-b border-black/60">
        <div className="text-xs uppercase tracking-[0.2em] text-muted">
          EVTX Forensics
        </div>
        <div className="text-lg font-semibold text-white">Dashboard</div>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        {links.map((link) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={link.href}
              className={`block rounded-lg px-3 py-2 text-sm transition interactive ${
                active
                  ? "bg-accent/15 text-accent"
                  : "text-[var(--text)] hover:bg-black/40"
              }`}
            >
              {link.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
