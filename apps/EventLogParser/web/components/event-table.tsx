"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Drawer } from "../ui/drawer";
import { api } from "../lib/api";
import { EventFilters } from "./event-filters";
import { Card } from "../ui/card";

const PAGE_SIZE = 500;
const EVENT_ID_INFO: Record<number, string> = {
  1: "Sysmon process creation event.",
  1100: "Windows Event Log service was shut down.",
  1102: "The Security event log was cleared.",
  1104: "The Security event log is full.",
  4103: "PowerShell module logging event.",
  4104: "PowerShell script block logging event.",
  4616: "System time was changed.",
  4624: "An account was successfully logged on.",
  4625: "An account failed to log on.",
  4648: "A logon was attempted using explicit credentials.",
  4672: "Special privileges assigned to a new logon.",
  4688: "A new process has been created.",
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
  5140: "A network share object was accessed.",
  7045: "A new Windows service was installed."
};

function eventIdSummary(eventId?: number) {
  if (!eventId) return "No Event ID.";
  return EVENT_ID_INFO[eventId] || "Known Windows event. No short summary is defined yet.";
}

export default function EventTable({ filters }: { filters: EventFilters }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selected, setSelected] = useState<number>(-1);
  const [detail, setDetail] = useState<any | null>(null);
  const detailRef = useRef<HTMLDivElement | null>(null);
  const [eventIdPopup, setEventIdPopup] = useState<{
    id: number;
    text: string;
    left: number;
    top: number;
  } | null>(null);

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

  const eventBadgeClass = (eventId?: number) => {
    if (!eventId) return "badge badge-muted";
    if (eventId === 4625 || eventId === 1102) return "badge badge-danger";
    if (eventId === 4688 || eventId === 7045) return "badge badge-accent";
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
        setDetail(null);
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
  }, [items, selected]);

  return (
    <Card className="overflow-hidden">
      <div className="grid grid-cols-[180px,80px,160px,160px,140px,120px,120px] gap-2 px-3 py-2 text-xs uppercase tracking-[0.1em] text-muted border-b border-black/40 sticky top-0 z-10 bg-panel">
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
        className="h-[70vh] overflow-auto font-mono text-xs focus:outline-none relative"
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
                  setSelected(virtualRow.index);
                  setDetail(event);
                }}
                className={`absolute left-0 right-0 border-b border-black/30 px-3 py-2 cursor-pointer transition ${
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
                            const rect = (
                              e.currentTarget as HTMLButtonElement
                            ).getBoundingClientRect();
                            const popupWidth = 320;
                            const margin = 12;
                            const left = Math.min(
                              Math.max(
                                margin,
                                rect.left + rect.width / 2 - popupWidth / 2
                              ),
                              window.innerWidth - popupWidth - margin
                            );
                            const top = Math.min(
                              rect.bottom + 10,
                              window.innerHeight - 110
                            );
                            setEventIdPopup({
                              id: event.event_id,
                              text: eventIdSummary(event.event_id),
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
      {detail && (
        <div
          ref={detailRef}
          className="hidden xl:block absolute top-[64px] right-4 w-[420px] h-[82%] bg-panelAccent border border-black/50 rounded-lg shadow-2xl overflow-auto p-4"
        >
          <div className="flex items-start justify-between mb-2">
            <div className="text-xs text-muted">{detail.timestamp}</div>
            <button
              onClick={() => setDetail(null)}
              className="text-muted hover:text-accent transition text-sm"
              aria-label="Close details"
            >
              ×
            </button>
          </div>
          <div className="text-lg font-semibold">
            {detail.event_id} • {detail.channel}
          </div>
          <div className="text-sm grid grid-cols-2 gap-2 my-2">
            <div>User: {detail.user || "—"}</div>
            <div>SID: {detail.sid || "—"}</div>
            <div>Computer: {detail.computer}</div>
            <div>Opcode: {detail.opcode ?? "—"}</div>
            <div>Keywords: {detail.keywords ?? "—"}</div>
          </div>
          <div className="text-xs uppercase tracking-[0.2em] text-muted mb-1">
            Event Data
          </div>
          <pre className="bg-slate-900/80 p-3 rounded border border-slate-800 text-xs overflow-auto">
            {JSON.stringify(detail.event_data_json, null, 2)}
          </pre>
        </div>
      )}
      <Drawer open={!!detail} onClose={() => setDetail(null)}>
        {detail ? (
          <div className="space-y-3 text-sm">
            <div className="text-xs text-muted">{detail.timestamp}</div>
            <div className="text-lg font-semibold">
              {detail.event_id} • {detail.channel}
            </div>
            <div className="grid grid-cols-2 gap-2 text-slate-200">
              <div>User: {detail.user || "—"}</div>
              <div>SID: {detail.sid || "—"}</div>
              <div>Computer: {detail.computer}</div>
              <div>Opcode: {detail.opcode ?? "—"}</div>
              <div>Keywords: {detail.keywords ?? "—"}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.2em] text-muted mb-1">
                Event Data
              </div>
              <pre className="bg-slate-900/80 p-3 rounded border border-slate-800 text-xs overflow-auto">
                {JSON.stringify(detail.event_data_json, null, 2)}
              </pre>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.2em] text-muted mb-1">
                Raw XML
              </div>
              <pre className="bg-slate-900/80 p-3 rounded border border-slate-800 text-xs overflow-auto">
                {detail.raw_xml}
              </pre>
            </div>
          </div>
        ) : null}
      </Drawer>
      {eventIdPopup && (
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
        </div>
      )}
    </Card>
  );
}
