"use client";

import { useState } from "react";
import { Card } from "../../ui/card";
import { api } from "../../lib/api";

export default function DetectionsPage() {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<any | null>(null);

  const load = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await api.get("/detections");
      setData(res as any[]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Detections</h1>
        <button
          onClick={load}
          className="px-3 py-2 rounded-lg bg-primary text-white font-semibold"
          disabled={loading}
        >
          {loading ? "Running…" : "Run Rules"}
        </button>
      </div>
      {error && <div className="text-danger text-sm">{error}</div>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="p-4 space-y-2">
          <h2 className="text-sm uppercase tracking-[0.2em] text-muted">
            Rules
          </h2>
          <div className="divide-y divide-black/40">
            {data.map((d: any) => (
              <div
                key={d.rule.id}
                className={`p-2 cursor-pointer hover:bg-black/30 ${
                  selectedRule?.rule?.id === d.rule.id ? "bg-accent/15" : ""
                }`}
                onClick={() => setSelectedRule(d)}
              >
                <div className="flex justify-between text-sm">
                  <span className="font-semibold">{d.rule.name}</span>
                  <span
                    className={`badge ${
                      d.rule.severity === "high"
                        ? "badge-danger"
                        : d.rule.severity === "medium"
                        ? "badge-accent"
                        : "badge-muted"
                    }`}
                  >
                    {d.rule.severity || "info"}
                  </span>
                </div>
                <div className="text-xs text-muted">{d.rule.description || ""}</div>
                <div className="text-xs">Hits: {d.hits}</div>
              </div>
            ))}
          </div>
        </Card>
        <Card className="p-4 space-y-2">
          <h2 className="text-sm uppercase tracking-[0.2em] text-muted">
            Matches
          </h2>
          {!selectedRule && <div className="text-muted text-sm">Select a rule</div>}
          {selectedRule && (
            <div className="space-y-2 text-xs">
              {selectedRule.events.map((ev: any) => (
                <details
                  key={ev.id}
                  className="p-2 bg-panelAccent rounded border border-black/40"
                >
                  <summary className="cursor-pointer">
                    <div className="flex items-center gap-2 text-sm font-semibold">
                      <span className="badge badge-accent">{ev.event_id}</span>
                      <span className="text-muted">{ev.timestamp}</span>
                    </div>
                    <div className="text-xs">
                      User: {ev.user || "—"} | Host: {ev.computer} | Channel: {ev.channel} | Source:{" "}
                      {ev.source || "—"}
                    </div>
                    <div className="text-xs text-muted">
                      Keywords: {ev.keywords || "—"} | Path: {ev.ingest_path || "—"}
                    </div>
                  </summary>
                  <div className="mt-2 space-y-1">
                    <div className="text-xs uppercase tracking-[0.2em] text-muted">
                      Event Data
                    </div>
                    <pre className="bg-slate-900/80 p-2 rounded border border-black/40 text-[11px] overflow-auto max-h-[300px]">
                      {JSON.stringify(ev.event_data_json, null, 2)}
                    </pre>
                    <div className="text-xs uppercase tracking-[0.2em] text-muted">
                      Raw XML
                    </div>
                    <pre className="bg-slate-900/80 p-2 rounded border border-black/40 text-[11px] overflow-auto max-h-[200px]">
                      {ev.raw_xml}
                    </pre>
                  </div>
                </details>
              ))}
              {selectedRule.events.length === 0 && (
                <div className="text-muted">No events matched.</div>
              )}
            </div>
          )}
        </Card>
      </div>
    </section>
  );
}
