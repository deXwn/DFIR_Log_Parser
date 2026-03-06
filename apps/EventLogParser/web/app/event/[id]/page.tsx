"use client";

import { useParams } from "next/navigation";
import { useApi } from "../../../hooks/useApi";
import { Card } from "../../../ui/card";

export default function EventDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const { data, isLoading, error } = useApi<any>(
    ["event", id],
    () => import("../../../lib/api").then((m) => m.api.event(id)),
    { enabled: Boolean(id) }
  );

  return (
    <Card className="p-6 md:p-8 space-y-4">
      <h1 className="text-xl font-semibold">Event {id}</h1>
      {isLoading && <div className="text-slate-400">Loading…</div>}
      {error && (
        <div className="text-danger text-sm">
          {(error as Error).message || "Failed to load event"}
        </div>
      )}
      {data && (
        <>
          <div className="text-sm text-slate-300 grid grid-cols-2 md:grid-cols-3 gap-2">
            <div><span className="text-muted">Event ID:</span> {data.event_id}</div>
            <div><span className="text-muted">Time:</span> {data.timestamp}</div>
            <div><span className="text-muted">Channel:</span> {data.channel}</div>
            <div><span className="text-muted">Computer:</span> {data.computer}</div>
            <div><span className="text-muted">User:</span> {data.user || "—"}</div>
          </div>
          <div>
            <h2 className="text-sm uppercase tracking-[0.2em] text-muted mb-2">Event Data (JSON)</h2>
            <pre className="bg-slate-900/80 p-4 rounded-lg text-xs overflow-auto">
              {JSON.stringify(data.event_data_json, null, 2)}
            </pre>
          </div>
          <div>
            <h2 className="text-sm uppercase tracking-[0.2em] text-muted mb-2">Raw XML</h2>
            <pre className="bg-slate-900/80 p-4 rounded-lg text-xs overflow-auto">{data.raw_xml}</pre>
          </div>
        </>
      )}
    </Card>
  );
}
