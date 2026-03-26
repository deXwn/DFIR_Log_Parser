"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { createPortal } from "react-dom";
import { Drawer } from "../ui/drawer";
import { api } from "../lib/api";
import { EventFilters } from "./event-filters";
import { Card } from "../ui/card";
import { EventContextMenu } from "./context-menu";
import { useForensicsStore } from "../hooks/useForensicsStore";

const PAGE_SIZE = 500;
const CRITICAL_EVENT_IDS = new Set([
  1100, 1102, 4625, 4719, 4724, 4726, 4740
]);
const HIGH_RISK_EVENT_IDS = new Set([
  4648, 4672, 4697, 4698, 4702, 7045, 4728, 4729, 4732, 4733, 4756, 4757
]);
const SUCCESS_EVENT_IDS = new Set([4624, 4720, 4722, 5140]);
const TELEMETRY_EVENT_IDS = new Set([1, 4103, 4104, 4616, 4688]);

const SECURITY_EVENT_INFO: Record<number, string> = {
  1102: "The Security event log was cleared.",
  4616: "System time was changed.",
  4624: "An account was successfully logged on.",
  4625: "An account failed to log on.",
  4648: "A logon was attempted using explicit credentials.",
  4672: "Special privileges assigned to a new logon.",
  4688: "A new process has been created (Security audit).",
  4697: "A service was installed in the system.",
  4698: "A scheduled task was created.",
  4702: "A scheduled task was updated.",
  4719: "System audit policy was changed.",
  4720: "A user account was created.",
  4722: "A user account was enabled.",
  4724: "An attempt was made to reset an account password.",
  4725: "A user account was disabled.",
  4726: "A user account was deleted.",
  4728: "A member was added to a privileged global group.",
  4729: "A member was removed from a privileged global group.",
  4732: "A member was added to a privileged local group.",
  4733: "A member was removed from a privileged local group.",
  4740: "A user account was locked out.",
  4756: "A member was added to a privileged universal group.",
  4757: "A member was removed from a privileged universal group.",
  5140: "A network share object was accessed."
};

const SYSTEM_EVENT_INFO: Record<number, string> = {
  1: "System configuration/time change (provider-specific).",
  1100: "Windows Event Log service was shut down.",
  6005: "The Event Log service was started.",
  6006: "The Event Log service was stopped.",
  7045: "A new Windows service was installed."
};

const APPLICATION_EVENT_INFO: Record<number, string> = {
  1000: "Application Error (faulting application/crash).",
  1001: "Windows Error Reporting event.",
  1026: ".NET Runtime exception."
};

const SYSMON_EVENT_INFO: Record<number, string> = {
  1: "Sysmon process creation event.",
  3: "Sysmon network connection event.",
  7: "Sysmon image loaded event.",
  8: "Sysmon CreateRemoteThread event.",
  10: "Sysmon process access event.",
  11: "Sysmon file create event.",
  12: "Sysmon registry object create/delete event.",
  13: "Sysmon registry value set event.",
  22: "Sysmon DNS query event."
};

type EventSummaryInput = {
  event_id?: number;
  channel?: string;
  source?: string;
};

function eventIdSummary(event: EventSummaryInput) {
  const eventId = event.event_id;
  if (!eventId) return "No Event ID.";

  const channel = (event.channel || "").toLowerCase();
  const source = (event.source || "").toLowerCase();
  const isSysmon =
    channel.includes("sysmon") ||
    source.includes("sysmon") ||
    source.includes("sysmon64");

  if (isSysmon) {
    return (
      SYSMON_EVENT_INFO[eventId] ||
      "Sysmon event (provider-specific). No short summary is defined yet."
    );
  }

  if (source.includes("kernel-general") && eventId === 1) {
    return "System time was changed (Kernel-General).";
  }

  if (channel.includes("security")) {
    return (
      SECURITY_EVENT_INFO[eventId] ||
      "Security event. No short summary is defined yet."
    );
  }

  if (channel.includes("system")) {
    return (
      SYSTEM_EVENT_INFO[eventId] ||
      "System event. No short summary is defined yet."
    );
  }

  if (channel.includes("application")) {
    return (
      APPLICATION_EVENT_INFO[eventId] ||
      "Application event. No short summary is defined yet."
    );
  }

  return "Windows event (channel/provider-specific). No short summary is defined yet.";
}

export default function EventTable({ filters }: { filters: EventFilters }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selected, setSelected] = useState<number>(-1);
  const [detail, setDetail] = useState<any | null>(null);
  const [eventIdPopup, setEventIdPopup] = useState<{
    id: number;
    text: string;
    left: number;
    top: number;
  } | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    event: any;
  } | null>(null);
  const { addWithEvent: addToForensics, has: hasInForensics } = useForensicsStore();

  const queryFilters = useMemo(() => filters, [filters]);

  const eventsQuery = useInfiniteQuery({
    queryKey: ["events", queryFilters],
    initialPageParam: 0,
    queryFn: ({ pageParam = 0 }) =>
      api.events({ ...queryFilters, limit: PAGE_SIZE, offset: pageParam }),
    getNextPageParam: (last: any, all) =>
      last?.data?.length === PAGE_SIZE ? all.length * PAGE_SIZE : undefined,
    refetchOnWindowFocus: false
  });

  const items = useMemo(
    () => eventsQuery.data?.pages.flatMap((p: any) => p.data) ?? [],
    [eventsQuery.data]
  );

  const closeDetail = useCallback(() => {
    setDetail(null);
    setSelected(-1);
  }, []);

  const eventBadgeClass = (eventId?: number) => {
    if (!eventId) return "badge badge-muted";
    if (CRITICAL_EVENT_IDS.has(eventId)) return "badge badge-critical";
    if (HIGH_RISK_EVENT_IDS.has(eventId)) return "badge badge-warning";
    if (SUCCESS_EVENT_IDS.has(eventId)) return "badge badge-success";
    if (TELEMETRY_EVENT_IDS.has(eventId)) return "badge badge-accent";
    return "badge badge-muted";
  };

  const rowVirtualizer = useVirtualizer({
    count: eventsQuery.hasNextPage ? items.length + 1 : items.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => 44,
    overscan: 12
  });

  useEffect(() => {
    if (
      eventsQuery.hasNextPage &&
      rowVirtualizer.getVirtualItems().some((v) => v.index >= items.length - 1)
    ) {
      eventsQuery.fetchNextPage();
    }
  }, [eventsQuery, items.length, rowVirtualizer]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        closeDetail();
        setContextMenu(null);
        return;
      }
      if (
        (e.key === "f" || e.key === "F") &&
        selected >= 0 &&
        items[selected] &&
        !(e.target as HTMLElement)?.closest("input,textarea,select")
      ) {
        e.preventDefault();
        const ev = items[selected];
        if (!hasInForensics(ev.id)) {
          addToForensics(ev);
        }
        return;
      }
      if (!["ArrowDown", "ArrowUp", "Enter"].includes(e.key) || items.length === 0)
        return;
      if (e.key === "ArrowDown") {
        setSelected((s) => Math.min(items.length - 1, s + 1));
      } else if (e.key === "ArrowUp") {
        setSelected((s) => Math.max(0, s - 1));
      } else if (e.key === "Enter" && selected >= 0) {
        setDetail(items[selected]);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [closeDetail, items, selected]);

  const eventPopupPortal =
    eventIdPopup && typeof window !== "undefined"
      ? createPortal(
          <div
            className="fixed inset-0 z-50"
            onClick={() => setEventIdPopup(null)}
            role="presentation"
          >
            <div
              className="absolute rounded-lg border border-slate-700 bg-slate-950/95 p-3 shadow-2xl"
              style={{
                left: `${eventIdPopup.left}px`,
                top: `${eventIdPopup.top}px`,
                width: "320px"
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="text-xs uppercase tracking-[0.14em] text-muted mb-1">
                Event ID {eventIdPopup.id}
              </div>
              <div className="text-sm text-slate-200">{eventIdPopup.text}</div>
            </div>
          </div>,
          document.body
        )
      : null;

  return (
    <Card
      className={detail ? "overflow-hidden xl:grid xl:grid-cols-[minmax(0,1fr)_420px]" : "overflow-hidden"}
    >
      <div className="min-w-0">
        <div className="sticky top-0 z-10 grid grid-cols-[180px,80px,160px,160px,140px,120px,120px] gap-2 border-b border-black/40 bg-panel px-3 py-2 text-xs uppercase tracking-[0.1em] text-muted">
          <span>Timestamp</span>
          <span>Event ID</span>
          <span>User</span>
          <span>Computer</span>
          <span>Channel</span>
          <span>Opcode</span>
          <span>Keywords</span>
        </div>
        <div
          ref={containerRef}
          className="relative h-[70vh] overflow-auto font-mono text-xs focus:outline-none"
          tabIndex={0}
        >
          <div
            style={{
              height: `${rowVirtualizer.getTotalSize()}px`,
              width: "100%",
              position: "relative"
            }}
          >
            {rowVirtualizer.getVirtualItems().map((virtualRow) => {
              const isLoaderRow = virtualRow.index > items.length - 1;
              const event = items[virtualRow.index];
              return (
                <div
                  key={virtualRow.key}
                  onClick={() => {
                    if (!event) return;
                    const sameEvent = detail === event;
                    setSelected(sameEvent ? -1 : virtualRow.index);
                    setDetail(sameEvent ? null : event);
                  }}
                  onContextMenu={(e) => {
                    if (!event) return;
                    e.preventDefault();
                    setSelected(virtualRow.index);
                    setContextMenu({ x: e.clientX, y: e.clientY, event });
                  }}
                  className={`absolute left-0 right-0 cursor-pointer border-b border-black/30 px-3 py-2 transition ${
                    selected === virtualRow.index
                      ? "bg-accent/15 shadow-inner"
                      : "hover:bg-black/30"
                  }`}
                  style={{
                    transform: `translateY(${virtualRow.start}px)`
                  }}
                >
                  {isLoaderRow ? (
                    eventsQuery.isFetchingNextPage ? (
                      <div className="text-slate-400">Loading more…</div>
                    ) : (
                      <div className="text-slate-400">No more results</div>
                    )
                  ) : (
                    <div className="grid grid-cols-[180px,80px,160px,160px,140px,120px,120px] gap-2">
                      <span className="truncate">{event.timestamp}</span>
                      <span>
                        <button
                          type="button"
                          className={eventBadgeClass(event.event_id)}
                          onClick={(e) => {
                            e.stopPropagation();
                            const popupWidth = 320;
                            const popupHeight = 96;
                            const margin = 12;
                            const offset = 10;

                            let left = e.clientX + offset;
                            if (left + popupWidth > window.innerWidth - margin) {
                              left = Math.max(
                                margin,
                                e.clientX - popupWidth - offset
                              );
                            }

                            let top = e.clientY + offset;
                            if (top + popupHeight > window.innerHeight - margin) {
                              top = Math.max(
                                margin,
                                e.clientY - popupHeight - offset
                              );
                            }
                            setEventIdPopup({
                              id: event.event_id,
                              text: eventIdSummary({
                                event_id: event.event_id,
                                channel: event.channel,
                                source: event.source
                              }),
                              left,
                              top
                            });
                          }}
                        >
                          {event.event_id}
                        </button>
                      </span>
                      <span className="truncate">
                        {event.user ? (
                          <span className="badge badge-muted">{event.user}</span>
                        ) : (
                          "—"
                        )}
                      </span>
                      <span className="truncate">{event.computer}</span>
                      <span className="truncate">
                        <span className="badge badge-muted">{event.channel}</span>
                      </span>
                      <span className="truncate">
                        {event.opcode ?? event.level ?? "—"}
                      </span>
                      <span className="truncate">{event.keywords ?? "—"}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {detail ? (
        <aside className="hidden h-[calc(70vh+41px)] flex-col border-l border-black/50 bg-panelAccent/90 xl:flex">
          <div className="border-b border-black/40 px-4 py-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em] text-muted">
                  Event Detail
                </div>
                <div className="mt-2 text-lg font-semibold text-white">
                  {detail.event_id} • {detail.channel}
                </div>
                <div className="mt-1 text-xs text-muted">{detail.timestamp}</div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    if (!hasInForensics(detail.id)) addToForensics(detail);
                  }}
                  disabled={hasInForensics(detail.id)}
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold transition ${
                    hasInForensics(detail.id)
                      ? "border-green-700/40 bg-green-950/30 text-green-300 cursor-not-allowed"
                      : "border-accent/40 bg-accent/10 text-orange-100 hover:bg-accent/20"
                  }`}
                >
                  {hasInForensics(detail.id) ? "In Forensics" : "+ Forensics"}
                </button>
                <button
                  onClick={closeDetail}
                  className="rounded-lg border border-slate-700/70 bg-slate-950/50 px-3 py-2 text-xs font-semibold text-slate-200 transition hover:border-accent/35 hover:text-white"
                >
                  Back to results
                </button>
              </div>
            </div>
            <div className="mt-3 text-sm text-slate-300">{eventIdSummary(detail)}</div>
          </div>

          <div className="flex-1 space-y-4 overflow-y-auto p-4 text-sm">
            <div className="grid grid-cols-2 gap-2 text-slate-200">
              <div>User: {detail.user || "—"}</div>
              <div>SID: {detail.sid || "—"}</div>
              <div>Computer: {detail.computer || "—"}</div>
              <div>Opcode: {detail.opcode ?? detail.level ?? "—"}</div>
              <div>Keywords: {detail.keywords ?? "—"}</div>
              <div>Source: {detail.source || "—"}</div>
            </div>
            <div>
              <div className="mb-1 text-xs uppercase tracking-[0.2em] text-muted">
                Event Data
              </div>
              <pre className="overflow-auto rounded border border-slate-800 bg-slate-950/80 p-3 text-xs">
                {JSON.stringify(detail.event_data_json, null, 2)}
              </pre>
            </div>
            <div>
              <div className="mb-1 text-xs uppercase tracking-[0.2em] text-muted">
                Raw XML
              </div>
              <pre className="overflow-auto rounded border border-slate-800 bg-slate-950/80 p-3 text-xs">
                {detail.raw_xml}
              </pre>
            </div>
          </div>
        </aside>
      ) : null}

      <div className="xl:hidden">
        <Drawer open={!!detail} onClose={closeDetail}>
          {detail ? (
            <div className="space-y-4 text-sm">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-[11px] uppercase tracking-[0.18em] text-muted">
                    Event Detail
                  </div>
                  <div className="mt-2 text-lg font-semibold text-white">
                    {detail.event_id} • {detail.channel}
                  </div>
                  <div className="mt-1 text-xs text-muted">{detail.timestamp}</div>
                </div>
                <button
                  onClick={closeDetail}
                  className="rounded-lg border border-slate-700/70 bg-slate-950/50 px-3 py-2 text-xs font-semibold text-slate-200 transition hover:border-accent/35 hover:text-white"
                >
                  Back to results
                </button>
              </div>
              <div className="text-sm text-slate-300">{eventIdSummary(detail)}</div>
              <div className="grid grid-cols-2 gap-2 text-slate-200">
                <div>User: {detail.user || "—"}</div>
                <div>SID: {detail.sid || "—"}</div>
                <div>Computer: {detail.computer || "—"}</div>
                <div>Opcode: {detail.opcode ?? detail.level ?? "—"}</div>
                <div>Keywords: {detail.keywords ?? "—"}</div>
                <div>Source: {detail.source || "—"}</div>
              </div>
              <div>
                <div className="mb-1 text-xs uppercase tracking-[0.2em] text-muted">
                  Event Data
                </div>
                <pre className="overflow-auto rounded border border-slate-800 bg-slate-950/80 p-3 text-xs">
                  {JSON.stringify(detail.event_data_json, null, 2)}
                </pre>
              </div>
              <div>
                <div className="mb-1 text-xs uppercase tracking-[0.2em] text-muted">
                  Raw XML
                </div>
                <pre className="overflow-auto rounded border border-slate-800 bg-slate-950/80 p-3 text-xs">
                  {detail.raw_xml}
                </pre>
              </div>
            </div>
          ) : null}
        </Drawer>
      </div>
      {eventPopupPortal}
      {contextMenu && (
        <EventContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          event={contextMenu.event}
          onClose={() => setContextMenu(null)}
        />
      )}
    </Card>
  );
}
