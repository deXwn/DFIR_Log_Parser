"use client";

import { useMemo, useState } from "react";
import { Card } from "../../ui/card";
import { api } from "../../lib/api";
import { useCaseFileStore } from "../../hooks/useCaseFileStore";

const now = new Date().toISOString().slice(0, 16);
const yesterday = new Date(Date.now() - 24 * 3600 * 1000)
  .toISOString()
  .slice(0, 16);

export default function ReportPage() {
  const [form, setForm] = useState({
    case_name: "Investigation",
    analyst: "Analyst",
    case_number: "CASE-001",
    from: yesterday,
    to: now,
    host: "",
    user: "",
    ioc: "",
    ioc_list: "",
    query: "",
    limit: 300,
    executive_summary: "This report summarizes key findings and notable events for the current investigation."
  });
  const [report, setReport] = useState<any | null>(null);
  const [results, setResults] = useState<any[]>([]);
  const [summaryOutput, setSummaryOutput] = useState<string>("");
  const {
    items: caseMap,
    toggle,
    remove,
    setNotes,
    clear
  } = useCaseFileStore();
  const caseItems = useMemo(() => Array.from(caseMap.values()), [caseMap]);
  const [caseOpen, setCaseOpen] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const markdownSections: string[] = [];

  const fetchReport = async () => {
    setError(null);
    setLoading(true);
    setSummaryOutput("");
    try {
      const payload = {
        ...form,
        from: form.from ? new Date(form.from).toISOString() : undefined,
        to: form.to ? new Date(form.to).toISOString() : undefined
      };
      const data = await api.report(payload);
      setReport(data);
      const iocTerms = form.ioc_list
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      const queries = form.query.trim() ? [form.query.trim(), ...iocTerms] : iocTerms;

      if (queries.length > 0) {
        const chunks = await Promise.all(
          queries.map((q) =>
            api.search(q, { limit: form.limit }).catch(() => ({ data: [] }))
          )
        );
        const merged: any[] = [];
        const seen = new Set<number>();
        queries.forEach((q, idx) => {
          const list = (chunks[idx] as any)?.data ?? (chunks[idx] as any) ?? [];
          list.forEach((ev: any) => {
            if (!seen.has(ev.id)) {
              merged.push({ ...ev, hit: q });
              seen.add(ev.id);
            }
          });
        });
        setResults(merged);
      } else {
        setResults([]);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const exportPdf = () => {
    window.print();
  };

  return (
    <section className="space-y-4 print:space-y-3 print-wrapper">
      <Card className="hero-panel print-avoid">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Reporting Suite</div>
            <h1 className="page-title">Case Reporting and Evidence Assembly</h1>
            <p className="page-subtitle">
              Combine timeline context, IOC search results, selected events, and analyst notes into
              a structured investigation output.
            </p>
          </div>
          {report && (
            <button onClick={exportPdf} className="action-btn primary">
              PDF
            </button>
          )}
        </div>
      </Card>
      <Card className="p-4 space-y-3 print-card print-avoid">
        <div className="page-copy">
          <h2 className="text-xl font-semibold text-white">Report Parameters</h2>
          <p className="status-text">Set metadata, search pivots, and time range before generating output.</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          <input
            className="input"
            value={form.case_name}
            onChange={(e) => setForm({ ...form, case_name: e.target.value })}
            placeholder="Case name"
          />
          <input
            className="input"
            value={form.analyst}
            onChange={(e) => setForm({ ...form, analyst: e.target.value })}
            placeholder="Analyst"
          />
          <input
            className="input"
            value={form.case_number}
            onChange={(e) => setForm({ ...form, case_number: e.target.value })}
            placeholder="Case number"
          />
          <input
            className="input"
            value={form.host}
            onChange={(e) => setForm({ ...form, host: e.target.value })}
            placeholder="Host"
          />
          <input
            className="input"
            value={form.user}
            onChange={(e) => setForm({ ...form, user: e.target.value })}
            placeholder="User"
          />
          <input
            className="input"
            value={form.ioc}
            onChange={(e) => setForm({ ...form, ioc: e.target.value })}
            placeholder="IOC (hash, ip, domain)"
          />
          <textarea
            className="input min-h-[80px]"
            value={form.executive_summary}
            onChange={(e) => setForm({ ...form, executive_summary: e.target.value })}
            placeholder="Executive summary"
          />
          <textarea
            className="input min-h-[120px]"
            value={form.ioc_list}
            onChange={(e) => setForm({ ...form, ioc_list: e.target.value })}
            placeholder="IOC list for search (one per line: IP, domain, hash, user...)"
          />
          <input
            className="input"
            value={form.query}
            onChange={(e) => setForm({ ...form, query: e.target.value })}
            placeholder="Search query (IP, user, process...)"
          />
          <input
            className="input"
            type="number"
            min={10}
            max={2000}
            value={form.limit}
            onChange={(e) => setForm({ ...form, limit: Number(e.target.value) })}
            placeholder="Result limit"
          />
          <div className="flex gap-2">
            <input
              className="input w-full"
              type="datetime-local"
              value={form.from}
              onChange={(e) => setForm({ ...form, from: e.target.value })}
            />
            <input
              className="input w-full"
              type="datetime-local"
              value={form.to}
              onChange={(e) => setForm({ ...form, to: e.target.value })}
            />
          </div>
        </div>
        <button
          onClick={fetchReport}
          className="px-4 py-2 rounded-lg bg-primary text-white font-semibold"
          disabled={loading}
        >
          {loading ? "Generating…" : "Generate"}
        </button>
        {error && <div className="text-danger text-sm">{error}</div>}
      </Card>

      <Card className="p-4 space-y-3 print-card print-avoid">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold">Case File</h3>
            <span className="px-2 py-1 text-xs rounded bg-panelAccent border border-slate-800/60">
              {caseItems.length} items
            </span>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted">
            <button
              className="px-2 py-1 rounded bg-panelAccent border border-slate-800/60"
              onClick={() => setCaseOpen((o) => !o)}
            >
              {caseOpen ? "Hide" : "Show"}
            </button>
            <button
              className="px-2 py-1 rounded bg-panelAccent border border-slate-800/60"
              onClick={clear}
            >
              Clear
            </button>
          </div>
        </div>
        {caseOpen && (
          <>
            <div className="flex flex-wrap gap-2">
              {caseItems.slice(0, 10).map((i) => (
                <span
                  key={i.event.id}
                  className="text-xs px-2 py-1 rounded border border-slate-800/60 bg-black/30"
                >
                  #{i.event.id} • {i.event.event_id}
                </span>
              ))}
              {caseItems.length > 10 && (
                <span className="text-xs text-muted">+{caseItems.length - 10} more</span>
              )}
            </div>
            {caseItems.length === 0 && (
              <div className="text-muted text-sm">
                No selected events yet. Add from search results.
              </div>
            )}
            <div className="space-y-3 max-h-80 overflow-auto pr-1">
              {caseItems.map((i) => (
                <div
                  key={i.event.id}
                  className="p-3 rounded border border-slate-800/60 bg-panelAccent"
                >
                  <div className="flex items-center justify-between text-sm">
                    <div className="font-semibold">
                      {i.event.id} • {i.event.event_id} • {i.event.timestamp}
                    </div>
                    <button
                      className="text-danger text-xs"
                      onClick={() => remove(i.event.id)}
                    >
                      Remove
                    </button>
                  </div>
                  <div className="text-xs text-muted">
                    {i.event.user || "—"} @ {i.event.computer} | {i.event.channel}
                  </div>
                  <textarea
                    className="input mt-2"
                    placeholder="Analyst notes"
                    value={i.notes}
                    onChange={(e) => setNotes(i.event.id, e.target.value)}
                  />
                </div>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={async () => {
                  setError(null);
                  setLoading(true);
                  try {
                    const payload = {
                      title: form.case_name || "Report",
                      analyst: form.analyst || "Analyst",
                      summary: form.ioc || form.executive_summary || "",
                      items: caseItems.map((c) => ({
                        event_id: c.event.id,
                        notes: c.notes || undefined
                      }))
                    };
                    const res = (await api.customReport(payload)) as {
                      markdown: string;
                    };
                    setReport(null);
                    setResults([]);
                    setLoading(false);
                    setSummaryOutput(res.markdown);
                  } catch (e: any) {
                    setLoading(false);
                    setError(e.message);
                  }
                }}
                disabled={loading || caseItems.length === 0}
                className="px-4 py-2 rounded bg-primary text-white font-semibold disabled:opacity-50"
              >
                {loading ? "Building…" : "Create Custom Report"}
              </button>
              <button
                onClick={async () => {
                  setError(null);
                  try {
                    const payload = {
                      title: form.case_name || "Report",
                      analyst: form.analyst || "Analyst",
                      summary: form.ioc || form.executive_summary || "",
                      items: caseItems.map((c) => ({
                        event_id: c.event.id,
                        notes: c.notes || undefined
                      }))
                    };
                    const res = (await api.customReportHtml(payload)) as {
                      html: string;
                    };
                    const blob = new Blob([res.html], { type: "text/html" });
                    const url = URL.createObjectURL(blob);
                    window.open(url, "_blank", "noopener,noreferrer");
                  } catch (e: any) {
                    setError(e.message);
                  }
                }}
                className="px-4 py-2 rounded bg-panelAccent border border-slate-800/60 text-white"
                disabled={caseItems.length === 0}
              >
                Open HTML report
              </button>
            </div>
          </>
        )}
      </Card>

      {report && (
        <Card className="p-6 space-y-4 print:bg-white print:text-black print-report print-card print-avoid">
          <div className="cover">
            <div className="text-xs uppercase tracking-[0.2em] text-muted">EVTX Forensics Report</div>
            <div className="text-2xl font-bold text-accent">{report.metadata.case_name}</div>
            <div className="text-sm font-semibold">Case No: {form.case_number}</div>
            <div className="text-sm">Analyst: {report.metadata.analyst}</div>
            <div className="text-sm text-muted">Generated: {report.metadata.generated_at}</div>
          </div>
          <div className="toc">
            <h3 className="report-title">Contents</h3>
            <ol className="toc-list">
              <li>Executive Summary</li>
              <li>Case Summary</li>
              <li>Timeline Overview</li>
              <li>Key Events</li>
              <li>Suspicious Findings</li>
              {results.length > 0 && <li>Search Results</li>}
            </ol>
          </div>

          <section className="report-section">
            <h3 className="report-title">Executive Summary</h3>
            <p className="text-sm leading-relaxed">{form.executive_summary}</p>
          </section>

          <section className="report-section">
            <h3 className="report-title">Case Summary</h3>
            <div className="report-grid">
              <div className="pill">Total events: {report.summary.total_events}</div>
              <div className="pill">Unique users: {report.summary.unique_users}</div>
              <div className="pill">Unique hosts: {report.summary.unique_hosts}</div>
              <div className="pill">Logons (4624/4625): {report.summary.logons}</div>
              <div className="pill">Process creations (4688): {report.summary.process_creations}</div>
              <div className="pill">Service installs (7045): {report.summary.services}</div>
              <div className="pill">Log clears (1102): {report.summary.clear_logs}</div>
            </div>
          </section>

          <section className="report-section">
            <h3 className="report-title">Timeline Overview (hourly)</h3>
            <div className="flex gap-2 overflow-x-auto text-xs">
              {report.timeline.map((b: any) => (
                <div key={b.bucket} className="timeline-card">
                  <div className="text-muted">{b.bucket}</div>
                  <div className="font-semibold text-accent">{b.count}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="report-section">
            <h3 className="report-title">Key Events</h3>
            <div className="text-xs space-y-2">
              {report.key_events.map((ev: any) => (
                <div key={ev.id} className="report-card">
                  <div className="font-semibold">
                    {ev.event_id} • {ev.timestamp} • {ev.channel}
                  </div>
                  <div>User: {ev.user || "—"} | Host: {ev.computer}</div>
                  <div className="text-muted">Keywords: {ev.keywords || "—"}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="report-section">
            <h3 className="report-title">Suspicious Findings</h3>
            <div className="text-xs space-y-2">
              {report.suspicious.map((ev: any) => (
                <div key={ev.id} className="report-card border-danger/60">
                  <div className="font-semibold text-danger">
                    {ev.event_id} • {ev.timestamp}
                  </div>
                  <div>Computer: {ev.computer}</div>
                  <div>{ev.description}</div>
                </div>
              ))}
            </div>
          </section>

          {results.length > 0 && (
            <section className="report-section">
              <h3 className="report-title">Search Results ({results.length})</h3>
              <div className="flex items-center gap-3 text-xs text-muted mb-2">
                <button
                  className="px-2 py-1 rounded bg-panelAccent border border-slate-800/60"
                  onClick={() => {
                    results.forEach((r) => toggle(r));
                  }}
                >
                  Select all
                </button>
                <button
                  className="px-2 py-1 rounded bg-panelAccent border border-slate-800/60"
                  onClick={() => clear()}
                >
                  Clear case file
                </button>
                <span>Case items: {caseItems.length}</span>
              </div>
              <div className="space-y-2 text-xs pr-1">
                {results.map((ev: any) => {
                  const ed =
                    ev.event_data_json?.Event?.EventData ||
                    ev.event_data_json?.EventData ||
                    {};
                  const cmd =
                    ed.CommandLine ||
                    ed.NewProcessName ||
                    ed.Image ||
                    ed.ProcessName;
                  return (
                    <div
                      key={ev.id}
                      className="p-2 bg-panelAccent rounded border border-slate-800/60 break-inside-avoid-page report-card"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <input
                          type="checkbox"
                          checked={caseMap.has(ev.id)}
                          onChange={(e) => {
                            toggle(ev);
                          }}
                        />
                        <span className="text-muted">Hit: {ev.hit || "query"}</span>
                      </div>
                      <div className="font-semibold">
                        {ev.event_id} • {ev.timestamp} • {ev.channel}
                      </div>
                      <div>User: {ev.user || "—"} | Host: {ev.computer}</div>
                      {cmd && (
                        <div className="text-muted">
                          Cmd/Image: {cmd}
                        </div>
                      )}
                      <pre className="mt-2 bg-slate-900/60 p-2 rounded border border-slate-800 text-[11px] whitespace-pre-wrap break-all max-h-[400px] overflow-auto print:max-h-none print:overflow-visible">
{JSON.stringify(ev.event_data_json, null, 2)}
                      </pre>
                    </div>
                  );
                })}
              </div>
            </section>
          )}
        </Card>
      )}

      {summaryOutput && (
        <Card className="p-4 space-y-2 print-card print-avoid">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Markdown Output</h2>
            <button
              className="px-3 py-1 rounded bg-panelAccent border border-slate-800/60 text-sm"
              onClick={() => navigator.clipboard.writeText(summaryOutput)}
            >
              Copy
            </button>
          </div>
          <pre className="whitespace-pre-wrap break-words text-xs bg-slate-900/60 p-3 rounded border border-slate-800 max-h-64 overflow-auto print:max-h-none print:overflow-visible">
{summaryOutput}
          </pre>
          <div className="text-right">
            <button
              onClick={exportPdf}
              className="px-3 py-2 rounded-lg bg-accent text-black font-semibold"
            >
              Print PDF
            </button>
          </div>
        </Card>
      )}

      <style jsx global>{`
        .print-report {
          background: linear-gradient(180deg, rgba(17,17,17,0.9) 0%, rgba(12,12,12,0.9) 100%);
          border: 1px solid #1f2937;
        }
        .print-card {
          box-shadow: none !important;
        }
        .print-avoid {
          page-break-inside: avoid;
        }
        .report-section {
          border: 1px solid #1f2937;
          border-left: 4px solid #cc0000;
          border-radius: 10px;
          padding: 12px;
          background: linear-gradient(180deg, rgba(26,32,44,0.5) 0%, rgba(17,24,39,0.5) 100%);
          margin-top: 12px;
        }
        .report-title {
          margin-bottom: 8px;
          font-size: 1.05rem;
          font-weight: 700;
          color: #cc0000;
          letter-spacing: 0.02em;
        }
        .report-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
          gap: 8px;
        }
        .pill {
          border: 1px solid #1f2937;
          background: rgba(255,255,255,0.04);
          padding: 8px 10px;
          border-radius: 8px;
          color: #e5e5e5;
          font-weight: 600;
        }
        .timeline-card {
          min-width: 120px;
          border: 1px solid #1f2937;
          background: rgba(12, 74, 110, 0.25);
          color: #e5e5e5;
          padding: 10px;
          border-radius: 10px;
        }
        .report-card {
          border: 1px solid #1f2937;
          background: rgba(255,255,255,0.04);
          border-radius: 10px;
          padding: 10px;
        }
        @media print {
          body { background: #fff; color: #000; margin: 0; }
          nav, header, aside, .sidebar, .print-hide { display: none !important; }
          .print-wrapper { padding: 0 !important; margin: 0 !important; }
          .print-report { background: #fff !important; border: 1px solid #e5e7eb; }
          .print-card { border: 1px solid #e5e7eb !important; background: #fff !important; }
          .report-section {
            background: #f8fafc !important;
            border-color: #e5e7eb;
            border-left-color: #cc0000;
          }
          .timeline-card, .pill, .report-card {
            background: #fff !important;
            border: 1px solid #e5e7eb;
            color: #000;
          }
          .report-title {
            color: #b91c1c !important;
          }
          pre {
            background: #f1f5f9 !important;
            color: #0f172a !important;
          }
        }
      `}</style>
    </section>
  );
}
