"use client";

import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { useForensicsStore } from "../hooks/useForensicsStore";

type ContextMenuProps = {
  x: number;
  y: number;
  event: any;
  onClose: () => void;
};

export function EventContextMenu({ x, y, event, onClose }: ContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const { addWithEvent, has } = useForensicsStore();
  const alreadyAdded = has(event.id);

  useEffect(() => {
    const handler = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent && e.key === "Escape") {
        onClose();
        return;
      }
      if (
        e instanceof MouseEvent &&
        menuRef.current &&
        !menuRef.current.contains(e.target as Node)
      ) {
        onClose();
      }
    };
    window.addEventListener("mousedown", handler);
    window.addEventListener("keydown", handler);
    return () => {
      window.removeEventListener("mousedown", handler);
      window.removeEventListener("keydown", handler);
    };
  }, [onClose]);

  const menuStyle: React.CSSProperties = {
    position: "fixed",
    left: Math.min(x, window.innerWidth - 240),
    top: Math.min(y, window.innerHeight - 200),
    zIndex: 100,
    minWidth: 220
  };

  const handleAddForensics = async () => {
    if (!alreadyAdded) {
      await addWithEvent(event);
    }
    onClose();
  };

  const handleCopyEventId = () => {
    navigator.clipboard.writeText(String(event.event_id));
    onClose();
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(
      JSON.stringify(event.event_data_json, null, 2)
    );
    onClose();
  };

  const handleCopyAll = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    onClose();
  };

  return createPortal(
    <div ref={menuRef} style={menuStyle}>
      <div className="rounded-xl border border-slate-700/80 bg-slate-950/95 shadow-2xl backdrop-blur-md overflow-hidden">
        <div className="border-b border-slate-800/60 px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-muted">
            Event {event.event_id} / ID {event.id}
          </div>
        </div>
        <div className="py-1">
          <button
            onClick={handleAddForensics}
            disabled={alreadyAdded}
            className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition ${
              alreadyAdded
                ? "text-slate-500 cursor-not-allowed"
                : "text-orange-100 hover:bg-accent/15"
            }`}
          >
            <span className="w-5 text-center text-xs">{alreadyAdded ? "+" : "+"}</span>
            {alreadyAdded ? "Already in Forensics" : "Add to Forensics"}
          </button>
          <div className="mx-2 my-1 border-t border-slate-800/50" />
          <button
            onClick={handleCopyEventId}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-slate-200 hover:bg-accent/15 transition"
          >
            <span className="w-5 text-center text-xs">#</span>
            Copy Event ID
          </button>
          <button
            onClick={handleCopyJson}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-slate-200 hover:bg-accent/15 transition"
          >
            <span className="w-5 text-center text-xs">{"{}"}</span>
            Copy Event Data (JSON)
          </button>
          <button
            onClick={handleCopyAll}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-slate-200 hover:bg-accent/15 transition"
          >
            <span className="w-5 text-center text-xs">*</span>
            Copy Full Event
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
