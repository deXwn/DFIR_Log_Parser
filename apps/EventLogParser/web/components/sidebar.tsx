"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "Overview" },
  { href: "/ingest", label: "Ingest" },
  { href: "/events", label: "Events" },
  { href: "/processes", label: "Process Tree" },
  { href: "/stats", label: "Statistics" },
  { href: "/timeline", label: "Timeline" },
  { href: "/search", label: "Search" },
  { href: "/report", label: "Report" },
  { href: "/detections", label: "Detections" }
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 hidden h-screen w-72 flex-col border-r border-slate-800/70 bg-panel/90 p-4 backdrop-blur md:flex">
      <div className="rounded-2xl border border-slate-700/60 bg-panelAccent/70 px-4 py-4 shadow-xl shadow-slate-950/40">
        <div className="text-[11px] uppercase tracking-[0.18em] text-muted">
          EVTX Forensics
        </div>
        <div className="mt-1 text-lg font-bold text-white">Analyst Console</div>
        <div className="mt-2 text-xs text-muted">
          Windows event triage, timeline, and threat detection workspace.
        </div>
      </div>

      <nav className="mt-4 flex-1 space-y-1">
        {links.map((link, idx) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={link.href}
              className={`group flex items-center gap-3 rounded-xl border px-3 py-2 text-sm font-medium transition ${
                active
                  ? "border-accent/35 bg-accent/18 text-sky-200"
                  : "border-transparent text-slate-200 hover:border-slate-700/70 hover:bg-panelAccent/55"
              }`}
            >
              <span
                className={`inline-flex h-6 w-6 items-center justify-center rounded-md text-[11px] font-semibold ${
                  active
                    ? "bg-accent/30 text-sky-100"
                    : "bg-slate-900/70 text-muted group-hover:text-slate-200"
                }`}
              >
                {idx + 1}
              </span>
              <span>{link.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="rounded-xl border border-slate-800/70 bg-slate-900/45 px-3 py-2 text-[11px] text-muted">
        Tip: `g` then press page shortcuts (1..9) for quick navigation.
      </div>
    </aside>
  );
}
