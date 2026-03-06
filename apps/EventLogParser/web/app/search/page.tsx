"use client";

import { useState } from "react";
import { useApi } from "../../hooks/useApi";
import { Card } from "../../ui/card";

export default function SearchPage() {
  const [term, setTerm] = useState("failed logon");
  const [logonType, setLogonType] = useState<string>("");
  const [ip, setIp] = useState<string>("");
  const [exclude, setExclude] = useState<string>("");
  const { data, isFetching, refetch, error } = useApi<any>(
    ["search", term, logonType, ip, exclude],
    () =>
      import("../../lib/api").then((m) =>
        m.api.search(term, {
          logon_type: logonType ? Number(logonType) : undefined,
          ip: ip || undefined,
          exclude: exclude || undefined
        })
      ),
    { enabled: false }
  );

  return (
    <Card className="p-6 md:p-8 space-y-4">
      <div className="space-y-2">
        <div className="text-xs text-muted">
          Use commas for multiple values in exclude:{" "}
          <span className="font-mono">a,b</span>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
        <input
          value={term}
          onChange={(e) => setTerm(e.target.value)}
          placeholder="Search events..."
          className="flex-1 min-w-[240px] bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-accent/50"
        />
        <input
          value={logonType}
          onChange={(e) => setLogonType(e.target.value)}
          placeholder="LogonType (e.g., 10)"
          className="w-32 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-accent/50"
        />
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP include"
          className="w-40 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-accent/50"
        />
        <input
          value={exclude}
          onChange={(e) => setExclude(e.target.value)}
          placeholder="Exclude (global, a,b)"
          className="w-44 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-accent/50"
        />
        <button
          onClick={() => refetch()}
          className="px-4 py-2 rounded-lg bg-accent/80 text-slate-900 text-sm font-semibold hover:bg-accent transition"
        >
          Search
        </button>
        </div>
      </div>
      {isFetching && <div className="text-slate-400 text-sm">Searching…</div>}
      {error && (
        <div className="text-danger text-sm">
          {(error as Error).message || "Search failed"}
        </div>
      )}
      <div className="space-y-3">
        {(data as any)?.data?.map((ev: any) => (
          <details
            key={ev.id}
            className="glass p-3 border border-slate-800/60 rounded-lg group"
          >
            <summary className="cursor-pointer space-y-1">
              <div className="text-xs text-muted mb-1">{ev.timestamp}</div>
              <div className="flex items-center gap-2 text-sm font-semibold flex-wrap">
                <span className="badge badge-accent">{ev.event_id}</span>
                <span className="badge badge-muted">{ev.channel}</span>
                <span className="badge badge-muted">{ev.computer}</span>
              </div>
              <div className="text-sm text-slate-300 line-clamp-1 group-open:line-clamp-none transition-all">
                {JSON.stringify(ev.event_data_json)}
              </div>
            </summary>
            <div className="mt-2 text-xs text-slate-200 overflow-auto max-h-[300px] bg-slate-900/70 p-2 rounded">
              <pre className="whitespace-pre-wrap break-all">
                {JSON.stringify(ev.event_data_json, null, 2)}
              </pre>
            </div>
          </details>
        ))}
      </div>
    </Card>
  );
}
