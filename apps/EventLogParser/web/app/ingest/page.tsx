"use client";

import { useState } from "react";
import { Card } from "../../ui/card";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";

export default function IngestPage() {
  const [path, setPath] = useState("event_log");
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [channel, setChannel] = useState<string>("");
  const [threads, setThreads] = useState<number | undefined>(undefined);

  const listQuery = useQuery<{ path: string; files: string[] }>({
    queryKey: ["list-evtx", path],
    queryFn: () => api.post("/list-evtx", { path }),
    enabled: false
  });

  const ingestMutation = useMutation<{
    ingested: number;
    duration_ms: number;
    parsed: number;
  }>({
    mutationFn: () =>
      api.post("/ingest", {
        path: selectedFile,
        channel: channel || undefined,
        threads
      })
  });

  const handleList = () => {
    setSelectedFile(null);
    listQuery.refetch();
  };

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">EVTX Ingest</h1>
        <div className="flex gap-2">
          <button
            onClick={() => {
              if (!confirm("Delete all records?")) return;
              api
                .deleteEvents({})
                .then((res: { deleted: number }) =>
                  alert(`All records deleted: ${res.deleted}`)
                )
                .catch((e: Error) => alert(`Delete error: ${e.message}`));
            }}
            className="px-3 py-2 rounded-lg bg-danger text-white text-sm font-semibold"
          >
            Delete All
          </button>
        </div>
      </div>

      <Card className="p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input
            className="input"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="EVTX folder path (e.g., event_log or /data/evtx)"
          />
          <div className="flex gap-2">
            <input
              className="input flex-1"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              placeholder="Channel (optional)"
            />
            <input
              className="input w-28"
              type="number"
              min={0}
              value={threads ?? ""}
              onChange={(e) =>
                setThreads(e.target.value ? Number(e.target.value) : undefined)
              }
              placeholder="Threads"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleList}
            className="px-4 py-2 rounded-lg bg-primary text-white font-semibold interactive"
          >
            List
          </button>
          <button
            disabled={!selectedFile || ingestMutation.isPending}
            onClick={() => ingestMutation.mutate()}
            className={`px-4 py-2 rounded-lg font-semibold ${
              selectedFile
                ? "bg-accent text-black interactive"
                : "bg-gray-700 text-gray-400 cursor-not-allowed"
            }`}
          >
            {ingestMutation.isPending ? "Processing..." : "Ingest"}
          </button>
        </div>
        {listQuery.isFetching && (
          <div className="text-muted text-sm">Loading files...</div>
        )}
        {listQuery.error && (
          <div className="text-danger text-sm">
            {(listQuery.error as Error).message}
          </div>
        )}
        {ingestMutation.error && (
          <div className="text-danger text-sm">
            {(ingestMutation.error as Error).message}
          </div>
        )}
        {ingestMutation.data && (
          <div className="text-sm text-accent">
            {ingestMutation.data.ingested} records ingested (
            {ingestMutation.data.duration_ms} ms) - {ingestMutation.data.parsed} parsed
          </div>
        )}
      </Card>

      {(() => {
        const files = listQuery.data?.files ?? [];
        return files.length > 0 ? (
        <Card className="p-4">
          <div className="text-sm text-muted mb-2">
            {files.length} EVTX files found. Select one file.
          </div>
          <div className="max-h-[400px] overflow-auto border border-black/40 rounded-lg">
            <table className="w-full text-sm">
              <tbody>
                {files.map((f: string) => (
                  <tr
                    key={f}
                    className={`cursor-pointer border-b border-black/30 hover:bg-black/30 ${
                      selectedFile === f ? "bg-accent/15" : ""
                    }`}
                    onClick={() => setSelectedFile(f)}
                  >
                    <td className="px-3 py-2">{f}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        ) : null;
      })()}
    </section>
  );
}
