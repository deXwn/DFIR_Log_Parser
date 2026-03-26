const envApiBase = process.env.NEXT_PUBLIC_API_BASE?.trim();

export const API_BASE =
  envApiBase ||
  (typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname}:8080`
    : "http://127.0.0.1:8080");

type Query = Record<string, string | number | boolean | undefined>;

const buildUrl = (path: string, query?: Query) => {
  if (!query) return `${API_BASE}${path}`;
  const q = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => {
    if (v !== undefined) q.append(k, String(v));
  });
  const qs = q.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ""}`;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {})
    },
    cache: "no-cache"
  });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(msg || res.statusText);
  }
  return res.json();
}

export const api = {
  get: <T>(path: string, query?: Query) =>
    request<T>(buildUrl(path, query)),
  post: <T>(path: string, body?: unknown) =>
    request<T>(buildUrl(path), {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined
    }),
  listEvtx: (path: string) => api.post("/list-evtx", { path }),
  events: (query?: Query) => api.get("/events", query),
  event: (id: string) => api.get(`/event/${id}`),
  stats: (ingest_path?: string) => api.get("/stats", ingest_path ? { ingest_path } : undefined),
  timeline: (from: string, to: string, bucket?: string, ingest_path?: string) =>
    api.get("/timeline", { from, to, bucket, ingest_path }),
  processes: (params?: Query) => api.get("/processes", params),
  search: (query: string, params?: Query) =>
    api.get("/search", { query, ...(params || {}) }),
  deleteEvents: (body: any) => api.post<{ deleted: number }>("/delete", body),
  report: (body: any) => api.post("/report", body),
  customReport: (body: any) => api.post("/reports/custom", body),
  customReportHtml: (body: any) => api.post("/reports/custom/html", body),
  // Forensics
  forensics: () => api.get<any[]>("/forensics"),
  forensicStats: () => api.get<any>("/forensics/stats"),
  addForensic: (body: any) => api.post<any>("/forensics", body),
  updateForensic: (id: number, body: any) =>
    request<any>(buildUrl(`/forensics/${id}`), {
      method: "PUT",
      body: JSON.stringify(body)
    }),
  deleteForensic: (id: number) =>
    request<any>(buildUrl(`/forensics/${id}`), { method: "DELETE" }),
  clearForensics: () => api.post<any>("/forensics/clear")
};
