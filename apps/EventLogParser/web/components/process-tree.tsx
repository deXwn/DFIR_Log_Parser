"use client";

import * as d3 from "d3";
import { useEffect, useMemo, useRef, useState } from "react";
import { Drawer } from "../ui/drawer";

type ProcNode = {
  id: string; // primary identity (guid or pid string)
  pid?: number;
  ppid?: number;
  guid?: string;
  parent_guid?: string;
  name: string;
  cmd?: string;
  timestamp?: string;
  channel?: string;
  computer?: string;
  data?: any;
  suspicious?: boolean;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
};

type ProcLink = { source: string; target: string };
type GraphStats = {
  totalEvents: number;
  process4688: number;
  sysmonProcessCreate: number;
  withParentField: number;
  uniqueHosts: number;
};

const LOLBINS = [
  "powershell.exe",
  "powershell",
  "cmd.exe",
  "wmic.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "certutil.exe",
  "bitsadmin.exe",
  "cscript.exe",
  "wscript.exe"
];

function parsePid(v: any): number | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v === "number") {
    return Number.isFinite(v) && v >= 0 ? v : undefined;
  }
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (!s) return undefined;
    const hex = s.startsWith("0x") ? s.slice(2) : undefined;
    if (hex) {
      const n = parseInt(hex, 16);
      return Number.isNaN(n) ? undefined : n;
    }
    const n = parseInt(s, 10);
    return Number.isNaN(n) ? undefined : n;
  }
  return undefined;
}

function firstPid(ed: any, keys: string[]): number | undefined {
  for (const k of keys) {
    if (k in ed) {
      const v = parsePid(ed[k]);
      if (v !== undefined) return v;
    }
  }
  return undefined;
}

function normalizeEventData(rawEventData: any): Record<string, any> {
  if (!rawEventData) return {};
  if (Array.isArray(rawEventData.Data)) {
    const normalized: Record<string, any> = {};
    for (const item of rawEventData.Data) {
      if (!item || typeof item !== "object") continue;
      const attrs = item["#attributes"] || {};
      const name = attrs.Name || item["@Name"];
      const value = item["#text"] ?? item["value"] ?? item["_text"] ?? "";
      if (name) normalized[name] = value;
    }
    return normalized;
  }
  return rawEventData;
}

function buildGraph(events: any[]): { nodes: ProcNode[]; links: ProcLink[]; stats: GraphStats } {
  const nodeMap = new Map<string, ProcNode>();
  const links: ProcLink[] = [];
  const degree = new Map<string, number>();
  const hostSet = new Set<string>();
  let process4688 = 0;
  let sysmonProcessCreate = 0;
  let withParentField = 0;

  for (const ev of events) {
    const ed = normalizeEventData(
      ev.event_data_json?.Event?.EventData || ev.event_data_json?.EventData || {}
    );
    const channel = String(ev.channel || "").toLowerCase();
    const source = String(ev.source || "").toLowerCase();
    if (ev.event_id === 4688 && channel === "security") process4688 += 1;
    if (ev.event_id === 1 && (channel.includes("sysmon") || source.includes("sysmon"))) {
      sysmonProcessCreate += 1;
    }

    const guid = ed.ProcessGuid || ed.ProcessGUID;
    const parentGuid = ed.ParentProcessGuid || ed.ParentProcessGUID;
    const pidRaw = firstPid(ed, [
      "ProcessId",
      "NewProcessId",
      "ProcessID",
      "NewProcessID",
      "TargetProcessId"
    ]);
    const ppidRaw = firstPid(ed, [
      "ParentProcessId",
      "ParentProcessID",
      "ParentProcessGuid",
      "ParentProcessGUID"
    ]);
    const name =
      ed.NewProcessName ||
      ed.Image ||
      ed.Application ||
      (typeof ev.event_data_json?.Image === "string"
        ? ev.event_data_json.Image
        : undefined) ||
      ed.ProcessName ||
      (ed.CommandLine ? (ed.CommandLine as string).split(" ")[0] : undefined) ||
      "unknown";

    const pid = pidRaw ?? Number(ev.record_id || ev.id);
    const ppid = ppidRaw;
    const nodeId = (guid as string | undefined) || String(pid);
    const parentId = (parentGuid as string | undefined) || (ppid !== undefined ? String(ppid) : undefined);
    if (ev.computer) hostSet.add(String(ev.computer));

    if (!nodeMap.has(nodeId)) {
      const suspicious =
        LOLBINS.some((bin) => name.toLowerCase().includes(bin)) ||
        (ed.CommandLine && /-enc|downloadstring|invoke-webrequest/i.test(ed.CommandLine));
      nodeMap.set(nodeId, {
        id: nodeId,
        pid,
        ppid,
        guid: guid as string | undefined,
        parent_guid: parentGuid as string | undefined,
        name,
        cmd: ed.CommandLine,
        timestamp: ev.timestamp,
        channel: ev.channel,
        computer: ev.computer,
        data: ev,
        suspicious
      });
    }

    if (parentId) {
      links.push({ source: parentId, target: nodeId });
      degree.set(nodeId, (degree.get(nodeId) || 0) + 1);
      degree.set(parentId, (degree.get(parentId) || 0) + 1);
      withParentField += 1;
    }
  }

  // ensure parents exist for linking
  for (const l of links) {
    if (!nodeMap.has(l.source)) {
      nodeMap.set(l.source, {
        id: l.source,
        pid: Number(l.source),
        name: "parent",
        ppid: undefined
      });
    }
    if (!nodeMap.has(l.target)) {
      nodeMap.set(l.target, {
        id: l.target,
        pid: Number(l.target),
        name: "child",
        ppid: Number(l.source)
      });
    }
  }

  // Keep only nodes that have at least one edge (or are suspicious)
  const filteredNodes = Array.from(nodeMap.values()).filter((n) => {
    const deg = degree.get(n.id) || 0;
    return deg > 0 || n.suspicious || !!n.cmd;
  });
  const filteredIds = new Set(filteredNodes.map((n) => n.id));
  const filteredLinks = links.filter(
    (l) => filteredIds.has(String(l.source)) && filteredIds.has(String(l.target))
  );

  return {
    nodes: filteredNodes,
    links: filteredLinks,
    stats: {
      totalEvents: events.length,
      process4688,
      sysmonProcessCreate,
      withParentField,
      uniqueHosts: hostSet.size
    }
  };
}

export default function ProcessTree({ events }: { events: any[] }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ProcNode | null>(null);

  const { nodes, links, stats } = useMemo(() => buildGraph(events), [events]);
  const hasGraph = nodes.length > 0;

  const filtered = useMemo(() => {
    if (!search.trim()) return nodes;
    const term = search.toLowerCase();
    const keep = new Set(
      nodes
        .filter(
          (n) =>
            n.name.toLowerCase().includes(term) ||
            String(n.pid).includes(term) ||
            (n.cmd || "").toLowerCase().includes(term)
        )
        .map((n) => n.id)
    );
    return nodes.filter((n) => keep.has(n.id));
  }, [nodes, search]);
  const filteredIds = useMemo(() => new Set(filtered.map((n) => n.id)), [filtered]);
  const visibleLinks = useMemo(
    () =>
      links.filter(
        (l) => filteredIds.has(String(l.source)) && filteredIds.has(String(l.target))
      ),
    [links, filteredIds]
  );

  useEffect(() => {
    if (!svgRef.current || filtered.length === 0) return;
    const width = svgRef.current.clientWidth || 960;
    const height = 620;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const simulation = d3
      .forceSimulation(filtered as any)
      .force(
        "link",
        d3.forceLink(visibleLinks as any).id((d: any) => d.id).distance(80)
      )
      .force("charge", d3.forceManyBody().strength(-180))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .alphaDecay(0.05);

    const zoomLayer = svg.append("g");

    const link = zoomLayer
      .append("g")
      .attr("stroke", "#334155")
      .attr("stroke-width", 1)
      .selectAll("line")
      .data(visibleLinks)
      .enter()
      .append("line");

    const node = zoomLayer
      .append("g")
      .selectAll("circle")
      .data(filtered)
      .enter()
      .append("circle")
      .attr("r", 10)
      .attr("fill", (d) => (d.suspicious ? "#cc0000" : "#00b7ff"))
      .attr("stroke", "#0f172a")
      .attr("stroke-width", 1.5)
      .call(
        d3
          .drag<SVGCircleElement, ProcNode>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on("click", (_e, d) => setSelected(d))
      .append("title")
      .text((d) => `${d.name} (${d.pid})`);

    const labels = zoomLayer
      .append("g")
      .selectAll("text")
      .data(filtered)
      .enter()
      .append("text")
      .text((d) => d.name.split("\\").pop() || d.name)
      .attr("fill", "#cbd5e1")
      .attr("font-size", 10)
      .attr("dx", 12)
      .attr("dy", 4);

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node.attr("cx", (d: any) => d.x).attr("cy", (d: any) => d.y);
      labels
        .attr("x", (d: any) => d.x)
        .attr("y", (d: any) => d.y);
    });

    const zoomed = (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
      zoomLayer.attr("transform", event.transform.toString());
    };
    svg.call(
      d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.4, 6])
        .on("zoom", zoomed)
    );

    return () => {
      simulation.stop();
    };
  }, [filtered, visibleLinks]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by process name or PID"
          className="input flex-1"
        />
        <div className="text-xs text-muted">
          Nodes: {filtered.length} | Edges: {visibleLinks.length}
        </div>
      </div>
      <div className="text-xs text-muted grid grid-cols-2 md:grid-cols-5 gap-2">
        <div>Total events: {stats.totalEvents}</div>
        <div>Security 4688: {stats.process4688}</div>
        <div>Sysmon EID 1: {stats.sysmonProcessCreate}</div>
        <div>With parent fields: {stats.withParentField}</div>
        <div>Hosts: {stats.uniqueHosts}</div>
      </div>
      {hasGraph ? (
        <svg
          ref={svgRef}
          className="w-full h-[640px] bg-slate-900/70 rounded-lg border border-slate-800/60"
        />
      ) : (
        <div className="text-muted text-sm space-y-1">
          <div>No process relationships to show from current dataset.</div>
          <div>
            Process Tree needs Security `4688` or Sysmon Process Create (`EventID=1`) logs
            that include parent-child fields.
          </div>
        </div>
      )}
      <Drawer open={!!selected} onClose={() => setSelected(null)}>
        {selected && (
          <div className="space-y-2 text-sm">
            <div className="text-xs text-muted">{selected.timestamp}</div>
            <div className="text-lg font-semibold">
              {selected.name} ({selected.pid})
            </div>
            <div>Parent PID: {selected.ppid ?? "—"}</div>
            <div>Computer: {selected.computer ?? "—"}</div>
            <div>Channel: {selected.channel ?? "—"}</div>
            <div className="text-danger">
              {selected.suspicious ? "Suspicious" : ""}
            </div>
            {selected.cmd && (
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-muted mb-1">
                  Command Line
                </div>
                <div className="bg-slate-900/80 p-2 rounded border border-slate-800 text-xs">
                  {selected.cmd}
                </div>
              </div>
            )}
            <div>
              <div className="text-xs uppercase tracking-[0.2em] text-muted mb-1">
                Event Data
              </div>
              <pre className="bg-slate-900/80 p-2 rounded border border-slate-800 text-xs overflow-auto">
                {JSON.stringify(selected.data?.event_data_json ?? {}, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
