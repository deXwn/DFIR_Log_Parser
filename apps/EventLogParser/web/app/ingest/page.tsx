"use client";

import { useState } from "react";
import { Card } from "../../ui/card";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";

type IngestApiResponse = {
  ingested: number;
  duration_ms: number;
  parsed: number;
};

type EvtxListItem = {
  path: string;
  size_bytes: number;
};

type IngestBatchResult = {
  totalFiles: number;
  successCount: number;
  failed: { file: string; error: string }[];
  totalIngested: number;
  totalParsed: number;
  totalDurationMs: number;
};

export default function IngestPage() {
  const [path, setPath] = useState("event_log");
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [channel, setChannel] = useState<string>("");
  const [threads, setThreads] = useState<number | undefined>(undefined);

  const listQuery = useQuery<{ path: string; files: EvtxListItem[] }>({
    queryKey: ["list-evtx", path],
    queryFn: () => api.post("/list-evtx", { path }),
    enabled: false
  });

  const ingestMutation = useMutation<IngestBatchResult, Error, string[]>({
    mutationFn: async (files) => {
      let totalIngested = 0;
      let totalParsed = 0;
      let totalDurationMs = 0;
      const failed: { file: string; error: string }[] = [];

      for (const file of files) {
        try {
          const result = await api.post<IngestApiResponse>("/ingest", {
            path: file,
            channel: channel || undefined,
            threads
          });
          totalIngested += result.ingested;
          totalParsed += result.parsed;
          totalDurationMs += result.duration_ms;
        } catch (err) {
          failed.push({
            file,
            error: err instanceof Error ? err.message : "Unknown ingest error"
          });
        }
      }

      return {
        totalFiles: files.length,
        successCount: files.length - failed.length,
        failed,
        totalIngested,
        totalParsed,
        totalDurationMs
      };
    }
  });

  const handleList = () => {
    setSelectedFiles([]);
    listQuery.refetch();
  };

  const toggleFile = (file: string) => {
    setSelectedFiles((prev) =>
      prev.includes(file) ? prev.filter((f) => f !== file) : [...prev, file]
    );
  };

  const toggleAll = (files: string[]) => {
    if (files.length === 0) return;
    setSelectedFiles((prev) =>
      prev.length === files.length ? [] : [...files]
    );
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let size = bytes / 1024;
    let unitIdx = 0;
    while (size >= 1024 && unitIdx < units.length - 1) {
      size /= 1024;
      unitIdx += 1;
    }
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unitIdx]}`;
  };

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Collection Intake</div>
            <h1 className="page-title">Bulk EVTX Ingest and File Staging</h1>
            <p className="page-subtitle">
              Enumerate EVTX folders, select files by size, and push large Windows event
              collections into the analyst workspace with controlled parser concurrency.
            </p>
          </div>
        </div>
      </Card>

      <div className="page-intro">
        <div className="page-copy">
          <h2 className="text-xl font-semibold text-white">Ingest Controls</h2>
          <p className="status-text">List candidate files, choose the dataset, then run a staged ingest.</p>
        </div>
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
            disabled={selectedFiles.length === 0 || ingestMutation.isPending}
            onClick={() => ingestMutation.mutate([...selectedFiles])}
            className={`px-4 py-2 rounded-lg font-semibold ${
              selectedFiles.length > 0
                ? "bg-accent text-black interactive"
                : "bg-gray-700 text-gray-400 cursor-not-allowed"
            }`}
          >
            {ingestMutation.isPending
              ? "Processing..."
              : `Ingest Selected (${selectedFiles.length})`}
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
          <div className="space-y-1 text-sm">
            <div className="text-accent">
              Ingest completed: {ingestMutation.data.successCount}/
              {ingestMutation.data.totalFiles} files succeeded.
            </div>
            <div className="text-slate-300">
              {ingestMutation.data.totalIngested} records ingested (
              {ingestMutation.data.totalDurationMs} ms) -{" "}
              {ingestMutation.data.totalParsed} parsed
            </div>
            {ingestMutation.data.failed.length > 0 && (
              <div className="text-danger">
                Failed files:{" "}
                {ingestMutation.data.failed
                  .map((f) => `${f.file} (${f.error})`)
                  .join(", ")}
              </div>
            )}
          </div>
        )}
      </Card>

      {(() => {
        const files = listQuery.data?.files ?? [];
        const filePaths = files.map((f) => f.path);
        const allSelected = files.length > 0 && selectedFiles.length === files.length;
        return files.length > 0 ? (
        <Card className="p-4">
          <div className="text-sm text-muted mb-2">
            {files.length} EVTX files found. Select one or more files. Sorted by
            size (largest to smallest).
          </div>
          <div className="max-h-[400px] overflow-auto border border-black/40 rounded-lg">
            <table className="w-full text-sm">
              <thead className="border-b border-black/40">
                <tr className="text-left text-xs uppercase tracking-[0.08em] text-muted">
                  <th className="w-12 px-3 py-2">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={() => toggleAll(filePaths)}
                      aria-label="Select all EVTX files"
                    />
                  </th>
                  <th className="px-3 py-2">File</th>
                  <th className="w-36 px-3 py-2 text-right">Size</th>
                </tr>
              </thead>
              <tbody>
                {files.map((file) => (
                  <tr
                    key={file.path}
                    className={`cursor-pointer border-b border-black/30 hover:bg-black/30 ${
                      selectedFiles.includes(file.path) ? "bg-accent/15" : ""
                    }`}
                    onClick={() => toggleFile(file.path)}
                  >
                    <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedFiles.includes(file.path)}
                        onChange={() => toggleFile(file.path)}
                        aria-label={`Select ${file.path}`}
                      />
                    </td>
                    <td className="px-3 py-2">{file.path}</td>
                    <td className="px-3 py-2 text-right">
                      <span className="badge badge-muted">{formatBytes(file.size_bytes)}</span>
                    </td>
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
