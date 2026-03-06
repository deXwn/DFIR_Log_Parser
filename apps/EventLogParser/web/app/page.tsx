import { Card } from "../ui/card";

const capabilities = [
  {
    title: "Ingest Pipeline",
    detail:
      "Load EVTX datasets through the UI or API, list files rapidly, and control parser threads for high-volume investigations."
  },
  {
    title: "Event Explorer",
    detail:
      "Use a virtualized event table for large datasets with EventID, user, SID, IP, channel, keyword, and time filters."
  },
  {
    title: "Process Tree",
    detail:
      "Visualize 4688 and Sysmon process relationships to uncover parent-child anomalies and suspicious execution chains."
  },
  {
    title: "Statistics",
    detail:
      "Review event distributions across EventID, source, channel, and user with ingest-path level pivots."
  },
  {
    title: "Timeline Analysis",
    detail:
      "Zoom and pan an interactive timeline, then pivot directly into filtered event windows for triage."
  },
  {
    title: "Full-Text Search",
    detail:
      "Query across parsed event payloads with LogonType/IP filters and inspect structured event data quickly."
  },
  {
    title: "Report Builder",
    detail:
      "Generate structured incident reports (HTML/PDF) with metadata, key findings, timeline context, and analyst notes."
  },
  {
    title: "Detection Engine",
    detail:
      "Run rule-based detections (YAML/JSON) with rich conditions and inspect matched events in context."
  }
];

export default function HomePage() {
  return (
    <section className="space-y-5">
      <Card className="p-6 md:p-8">
        <div className="space-y-4">
          <div className="inline-flex items-center rounded-full border border-accent/30 bg-accent/15 px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-sky-100">
            Investigation Workspace
          </div>
          <h1 className="text-2xl font-bold text-white md:text-3xl">
            EVTX Forensics Dashboard
          </h1>
          <p className="max-w-3xl text-sm leading-relaxed text-slate-300 md:text-base">
            A focused workspace for ingesting, searching, correlating, and reporting on Windows event telemetry.
            Use the modules below to move from raw EVTX files to investigation-ready findings.
          </p>
          <div className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
            <div className="rounded-xl border border-slate-800/70 bg-slate-900/45 px-4 py-3">
              <div className="text-xs uppercase tracking-[0.14em] text-muted">Coverage</div>
              <div className="mt-1 text-lg font-semibold text-white">Windows EVTX</div>
            </div>
            <div className="rounded-xl border border-slate-800/70 bg-slate-900/45 px-4 py-3">
              <div className="text-xs uppercase tracking-[0.14em] text-muted">Primary Use</div>
              <div className="mt-1 text-lg font-semibold text-white">Incident Triage</div>
            </div>
            <div className="rounded-xl border border-slate-800/70 bg-slate-900/45 px-4 py-3">
              <div className="text-xs uppercase tracking-[0.14em] text-muted">Workflow</div>
              <div className="mt-1 text-lg font-semibold text-white">Ingest → Detect → Report</div>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {capabilities.map((item) => (
          <Card key={item.title} className="p-4 md:p-5">
            <h2 className="text-base font-semibold text-slate-100">{item.title}</h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">{item.detail}</p>
          </Card>
        ))}
      </div>
    </section>
  );
}
