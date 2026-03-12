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
    <aside className="sticky top-0 hidden h-screen w-80 flex-col border-r border-slate-800/70 bg-[rgba(5,10,18,0.82)] p-4 backdrop-blur-xl md:flex">
      <div className="glass px-5 py-5 shadow-xl shadow-slate-950/40">
        <div className="eyebrow">EVTX Workspace</div>
        <div className="mt-4 text-xl font-extrabold text-white">Case Review</div>
        <div className="mt-2 text-sm leading-6 text-slate-300">
          Bulk ingest, event review, detections, timeline pivots, and reporting in a
          single investigation surface.
        </div>
      </div>

      <nav className="mt-5 flex-1 space-y-2">
        {links.map((link, idx) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={link.href}
              className={`group flex items-center gap-3 rounded-2xl border px-4 py-3 text-sm font-medium transition ${
                active
                  ? "border-accent/35 bg-accent/12 text-orange-100 shadow-[0_0_0_1px_rgba(251,146,60,0.15)]"
                  : "border-transparent bg-[rgba(8,14,24,0.32)] text-slate-200 hover:border-slate-700/70 hover:bg-panelAccent/55"
              }`}
            >
              <span
                className={`inline-flex h-7 w-7 items-center justify-center rounded-lg text-[11px] font-semibold ${
                  active
                    ? "bg-accent/22 text-orange-100"
                    : "bg-slate-950/70 text-muted group-hover:text-slate-200"
                }`}
              >
                {idx + 1}
              </span>
              <span className="min-w-0 flex-1 truncate">{link.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="glass px-4 py-4 text-xs text-slate-300">
        <div className="metric-label">Workflow</div>
        <div className="mt-2 font-semibold text-white">
          Ingest {"->"} Explore {"->"} Detect {"->"} Report
        </div>
      </div>
    </aside>
  );
}
