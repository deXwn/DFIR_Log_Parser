"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const labels: Record<string, string> = {
  "/": "Overview",
  "/ingest": "EVTX Ingest",
  "/events": "Event Explorer",
  "/processes": "Process Tree",
  "/stats": "Statistics",
  "/timeline": "Timeline Analysis",
  "/search": "Search",
  "/report": "Report Builder",
  "/detections": "Detections"
};

function formatPath(pathname: string) {
  if (labels[pathname]) {
    return labels[pathname];
  }

  return pathname
    .split("/")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" / ");
}

export default function TopHeader() {
  const pathname = usePathname();
  const page = formatPath(pathname);

  return (
    <header className="sticky top-0 z-20 border-b border-slate-800/70 bg-panel/78 backdrop-blur-xl">
      <div className="content-shell flex items-center justify-between gap-3 px-4 py-4 md:px-8">
        <div className="min-w-0">
          <div className="text-[11px] uppercase tracking-[0.18em] text-muted">
            EVTX Forensics Platform
          </div>
          <div className="truncate text-sm font-semibold text-slate-100 md:text-base">
            {page}
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs md:text-sm">
          <Link
            href="/events"
            className="rounded-lg border border-slate-700/70 bg-slate-900/55 px-3 py-1.5 font-medium text-slate-100 transition hover:border-accent/45 hover:text-sky-100"
          >
            Events
          </Link>
          <Link
            href="/search"
            className="rounded-lg border border-accent/35 bg-accent/20 px-3 py-1.5 font-semibold text-sky-100 transition hover:bg-accent/28"
          >
            Search
          </Link>
        </div>
      </div>
    </header>
  );
}
