import Link from "next/link";
import { Card } from "../ui/card";

const quickActions = [
  { href: "/ingest", label: "Open Ingest", meta: "Load EVTX datasets and stage cases" },
  { href: "/events", label: "Explore Events", meta: "Pivot through raw records at speed" },
  { href: "/detections", label: "Run Detections", meta: "Execute rule packs and inspect hits" },
  { href: "/report", label: "Build Report", meta: "Export case-ready findings" }
];

const capabilities = [
  {
    title: "Ingest Pipeline",
    detail:
      "List EVTX folders, select files in bulk, tune parser threads, and push large collections into the workspace."
  },
  {
    title: "Event Explorer",
    detail:
      "Filter by Event ID, identity, IP, SID, channel, and time with a virtualized event table built for high-volume triage."
  },
  {
    title: "Timeline Pivot",
    detail:
      "Walk event bursts over time, isolate investigation windows, and move directly into the matching records."
  },
  {
    title: "Detection Engine",
    detail:
      "Run YAML/JSON rules, inspect correlation hits, and validate suspicious activity with raw event context."
  },
  {
    title: "Search Console",
    detail:
      "Query deeply into parsed event payloads with contextual filters for IP, LogonType, and structured fields."
  },
  {
    title: "Reporting",
    detail:
      "Assemble case files, annotate evidence, and generate polished incident outputs without leaving the workspace."
  }
];

export default function HomePage() {
  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Investigation Workspace</div>
            <h1 className="page-title">EVTX Forensics Command Center</h1>
            <p className="page-subtitle">
              Move from raw Windows event logs to investigation-ready findings with a
              workflow built for ingest, detection, timeline reconstruction, and reporting.
            </p>
          </div>
          <div className="toolbar-cluster">
            <Link href="/ingest" className="action-btn primary">
              Start Ingest
            </Link>
            <Link href="/events" className="action-btn secondary">
              Open Explorer
            </Link>
          </div>
        </div>

        <div className="hero-grid">
          <div className="metric-card">
            <div className="metric-label">Coverage</div>
            <div className="metric-value">Windows EVTX</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Primary Use</div>
            <div className="metric-value">Incident Triage</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Workflow</div>
            <div className="metric-value">Ingest {"->"} Detect {"->"} Report</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Mode</div>
            <div className="metric-value">Case Workspace</div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.25fr_0.95fr]">
        <Card className="p-6">
          <div className="page-copy">
            <div className="eyebrow">Core Workflow</div>
            <h2 className="text-2xl font-bold text-white">Operational Surface</h2>
            <p className="page-subtitle">
              Use these modules as the primary analyst path through collection,
              triage, correlation, and evidence production.
            </p>
          </div>
          <div className="mt-6 grid grid-cols-1 gap-3 md:grid-cols-2">
            {capabilities.map((item) => (
              <div
                key={item.title}
                className="rounded-2xl border border-slate-800/60 bg-[rgba(6,12,20,0.55)] p-4"
              >
                <div className="metric-label">{item.title}</div>
                <p className="mt-3 text-sm leading-7 text-slate-300">{item.detail}</p>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-6">
          <div className="page-copy">
            <div className="eyebrow">Rapid Entry</div>
            <h2 className="text-2xl font-bold text-white">Quick Actions</h2>
            <p className="page-subtitle">
              Jump into the most common investigation tasks without navigating through
              the full menu structure.
            </p>
          </div>
          <div className="mt-6 grid gap-3">
            {quickActions.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="rounded-2xl border border-slate-800/70 bg-[rgba(9,16,28,0.62)] p-4 transition hover:border-accent/35 hover:bg-accent/10"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-base font-semibold text-white">{item.label}</div>
                    <div className="mt-1 text-sm text-slate-300">{item.meta}</div>
                  </div>
                  <div className="text-xs uppercase tracking-[0.18em] text-orange-200">
                    Open
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </Card>
      </div>
    </section>
  );
}
