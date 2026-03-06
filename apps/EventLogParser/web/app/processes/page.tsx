"use client";

import { useMemo } from "react";
import { useApi } from "../../hooks/useApi";
import { Card } from "../../ui/card";
import ProcessTree from "../../components/process-tree";

export default function ProcessesPage() {
  const { data, isLoading, error } = useApi<any>(
    ["proc-events"],
    () => import("../../lib/api").then((m) => m.api.processes({ limit: 5000 })),
    { staleTime: 60_000 }
  );

  const events = useMemo<any[]>(() => {
    const all = (data as any)?.data ?? (data as any) ?? [];
    return all;
  }, [data]);

  return (
    <Card className="p-6 md:p-8 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Process Tree</h1>
        <div className="text-muted text-sm">
          Based on recent process creation events (4688)
        </div>
      </div>
      {isLoading && <div className="text-slate-400">Loading…</div>}
      {error && (
        <div className="text-danger text-sm">
          {(error as Error).message || "Failed to load process events"}
        </div>
      )}
      {events.length === 0 && !isLoading && (
        <div className="text-muted text-sm">
          No process creation events found. Try ingesting Security/Sysmon logs or increase limit.
        </div>
      )}
      {events.length > 0 && <ProcessTree events={events} />}
    </Card>
  );
}
