"use client";

import { useApi } from "../../hooks/useApi";
import { Card } from "../../ui/card";
import { useState } from "react";

export default function StatsPage() {
  const [pathFilter, setPathFilter] = useState<string | undefined>(undefined);
  const { data, isLoading, error } = useApi<any>(
    ["stats", pathFilter],
    () => import("../../lib/api").then((m) => m.api.stats(pathFilter)),
    { staleTime: 10_000 }
  );

  const renderList = (title: string, list: any[] = []) => (
    <Card className="p-4 max-h-96 overflow-y-auto">
      <h2 className="text-sm uppercase tracking-[0.2em] text-muted mb-2">
        {title}
      </h2>
      <ul className="space-y-1 text-sm">
        {list.map((item, idx) => (
          <li key={idx} className="flex justify-between">
            <span className="text-slate-200">
              {item.key === null ? "N/A" : item.key}
            </span>
            <span className="text-muted">{item.count}</span>
          </li>
        ))}
      </ul>
    </Card>
  );

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Data Distribution</div>
            <h1 className="page-title">Statistical Overview of the Current Case</h1>
            <p className="page-subtitle">
              Review event density across IDs, channels, sources, users, and network fields to
              understand dataset shape before deeper triage.
            </p>
          </div>
        </div>
      </Card>

      <div className="page-intro gap-4">
        <div className="page-copy">
          <h2 className="text-xl font-semibold text-white">Distribution Panels</h2>
          <p className="status-text">Filter by ingest path to isolate a specific collection source.</p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted">Ingest Path:</span>
          <select
            className="input"
            value={pathFilter || ""}
            onChange={(e) =>
              setPathFilter(e.target.value ? e.target.value : undefined)
            }
          >
            <option value="">All</option>
            {(data?.ingest_paths || []).map((p: string) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>
      </div>
      {isLoading && <div className="text-slate-400">Loading…</div>}
      {error && (
        <div className="text-danger text-sm">
          {(error as Error).message || "Failed to load stats"}
        </div>
      )}
      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {renderList("By Event ID", data.by_event_id)}
          {renderList("By Channel", data.by_channel)}
          {renderList("By Source", data.by_source)}
          {renderList("By User", data.by_user)}
          {renderList("By Source IP", data.by_source_ip)}
          {renderList("By Destination IP", data.by_dest_ip)}
        </div>
      )}
    </section>
  );
}
