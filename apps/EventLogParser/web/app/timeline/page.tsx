"use client";

import { useMemo, useState } from "react";
import { useApi } from "../../hooks/useApi";
import { Card } from "../../ui/card";
import { TimelineChart } from "../../components/timeline-chart";

const isoNow = new Date().toISOString();
const isoYesterday = new Date(Date.now() - 24 * 3600 * 1000).toISOString();

export default function TimelinePage() {
  const [bucketSize, setBucketSize] = useState<"minute" | "hour">("hour");
  const [from, setFrom] = useState(isoYesterday);
  const [to, setTo] = useState(isoNow);
  const [pathFilter, setPathFilter] = useState<string>("");

  const { data: statsData } = useApi<any>(
    ["timeline-ingest-paths"],
    () => import("../../lib/api").then((m) => m.api.stats()),
    { staleTime: 60_000 }
  );

  const { data, isLoading, error, refetch, isFetching } = useApi<any>(
    ["timeline", from, to, bucketSize, pathFilter],
    () =>
      import("../../lib/api").then((m) =>
        m.api.timeline(from, to, bucketSize, pathFilter || undefined)
      )
  );

  const max = useMemo(
    () => Math.max(...(((data as any[])?.map((d: any) => Number(d.count))) || [1])),
    [data]
  );

  return (
    <Card className="p-6 md:p-8 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold">Timeline</h1>
        <div className="flex items-center gap-2 text-sm">
          <input
            type="datetime-local"
            className="input"
            value={from.slice(0, 16)}
            onChange={(e) => setFrom(new Date(e.target.value).toISOString())}
          />
          <input
            type="datetime-local"
            className="input"
            value={to.slice(0, 16)}
            onChange={(e) => setTo(new Date(e.target.value).toISOString())}
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
          >
            Refresh
          </button>
        </div>
      </div>
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
          <TimelineChart data={data as any} from={from} bucketSize={bucketSize} />
        </>
      )}
    </Card>
  );
}
