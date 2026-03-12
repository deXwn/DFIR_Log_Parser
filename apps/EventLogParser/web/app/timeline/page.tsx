"use client";

import { useMemo, useState } from "react";
import { useApi } from "../../hooks/useApi";
import { Card } from "../../ui/card";
import { TimelineChart } from "../../components/timeline-chart";

function toLocalDateTimeInputValue(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

function toIsoOrNull(value: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

const localNow = toLocalDateTimeInputValue(new Date());
const localYesterday = toLocalDateTimeInputValue(
  new Date(Date.now() - 24 * 3600 * 1000)
);

export default function TimelinePage() {
  const [bucketSize, setBucketSize] = useState<"minute" | "hour">("hour");
  const [from, setFrom] = useState(localYesterday);
  const [to, setTo] = useState(localNow);
  const [pathFilter, setPathFilter] = useState<string>("");
  const fromIso = useMemo(() => toIsoOrNull(from), [from]);
  const toIso = useMemo(() => toIsoOrNull(to), [to]);
  const hasValidRange = Boolean(fromIso && toIso);

  const { data: statsData } = useApi<any>(
    ["timeline-ingest-paths"],
    () => import("../../lib/api").then((m) => m.api.stats()),
    { staleTime: 60_000 }
  );

  const { data, isLoading, error, refetch, isFetching } = useApi<any>(
    ["timeline", fromIso, toIso, bucketSize, pathFilter],
    () =>
      import("../../lib/api").then((m) =>
        m.api.timeline(fromIso!, toIso!, bucketSize, pathFilter || undefined)
      ),
    { enabled: hasValidRange }
  );

  const max = useMemo(
    () => Math.max(...(((data as any[])?.map((d: any) => Number(d.count))) || [1])),
    [data]
  );

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Temporal Analysis</div>
            <h1 className="page-title">Timeline Reconstruction</h1>
            <p className="page-subtitle">
              Walk event density over time, isolate suspicious windows, and pivot straight into
              the relevant records for sequence validation.
            </p>
          </div>
        </div>
      </Card>
      <Card className="p-6 md:p-8 space-y-4">
        <div className="page-intro">
          <div className="page-copy">
            <h2 className="text-xl font-semibold text-white">Timeline Controls</h2>
            <p className="status-text">Set the time window, bucket size, and ingest source before plotting.</p>
          </div>
        <div className="flex items-center gap-2 text-sm">
          <input
            type="datetime-local"
            className="input"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
          <input
            type="datetime-local"
            className="input"
            value={to}
            onChange={(e) => setTo(e.target.value)}
          />
          <select
            className="input"
            value={bucketSize}
            onChange={(e) => setBucketSize(e.target.value as "minute" | "hour")}
          >
            <option value="minute">Minute</option>
            <option value="hour">Hour</option>
          </select>
          <select
            className="input"
            value={pathFilter}
            onChange={(e) => setPathFilter(e.target.value)}
          >
            <option value="">All sources</option>
            {(statsData?.ingest_paths || []).map((p: string) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <button
            onClick={() => refetch()}
            className="px-3 py-2 rounded-lg bg-accent/80 text-slate-900 font-semibold"
            disabled={!hasValidRange}
          >
            Refresh
          </button>
        </div>
      </div>
      {!hasValidRange && (
        <div className="text-amber-300 text-sm">
          Enter a valid start and end date to load the timeline.
        </div>
      )}
      {(isLoading || isFetching) && <div className="text-slate-400">Loading…</div>}
      {error && (
        <div className="text-danger text-sm">
          {(error as Error).message || "Failed to load timeline"}
        </div>
      )}
      {data && data.length > 0 && (
        <>
          <div className="text-sm text-slate-400">
            Source: {pathFilter || "All ingest paths"}
          </div>
          <TimelineChart data={data as any} from={fromIso!} bucketSize={bucketSize} />
        </>
      )}
      </Card>
    </section>
  );
}
