"use client";

import { useEffect, useState } from "react";

export type EventFilters = {
  event_id?: string;
  user?: string;
  sid?: string;
  ip?: string;
  channel?: string;
  keyword?: string;
  exclude?: string;
  from?: string;
  to?: string;
};

const UTC_PLUS_THREE_MS = 3 * 60 * 60 * 1000;

function pad2(v: number) {
  return String(v).padStart(2, "0");
}

function formatUtcPlusThree(value?: string) {
  if (!value) return "";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return value;

  const shifted = new Date(dt.getTime() + UTC_PLUS_THREE_MS);
  return `${shifted.getUTCFullYear()}-${pad2(shifted.getUTCMonth() + 1)}-${pad2(
    shifted.getUTCDate()
  )} ${pad2(shifted.getUTCHours())}:${pad2(shifted.getUTCMinutes())}:${pad2(
    shifted.getUTCSeconds()
  )}`;
}

function parseUtcPlusThree(value: string) {
  const raw = value.trim();
  if (!raw) return "";

  const m = raw.match(
    /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/
  );
  if (!m) {
    return null;
  }

  const [, y, mo, d, h, mi, s] = m;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s || "00"}+03:00`;
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) {
    return null;
  }

  return iso;
}

function maskUtcPlusThreeInput(value: string) {
  const digits = value.replace(/\D/g, "").slice(0, 14);
  if (digits.length <= 4) return digits;

  let out = digits.slice(0, 4);
  if (digits.length > 4) out += `-${digits.slice(4, Math.min(6, digits.length))}`;
  if (digits.length > 6) out += `-${digits.slice(6, Math.min(8, digits.length))}`;
  if (digits.length > 8) out += ` ${digits.slice(8, Math.min(10, digits.length))}`;
  if (digits.length > 10) out += `:${digits.slice(10, Math.min(12, digits.length))}`;
  if (digits.length > 12) out += `:${digits.slice(12, Math.min(14, digits.length))}`;
  return out;
}

export default function EventFilters({
  value,
  onChange
}: {
  value: EventFilters;
  onChange: (f: EventFilters) => void;
}) {
  const [open, setOpen] = useState(true);
  const [filters, setFilters] = useState<EventFilters>(value);
  const [fromInput, setFromInput] = useState(formatUtcPlusThree(value.from));
  const [toInput, setToInput] = useState(formatUtcPlusThree(value.to));

  useEffect(() => {
    setFilters(value);
    setFromInput(formatUtcPlusThree(value.from));
    setToInput(formatUtcPlusThree(value.to));
  }, [value]);

  const update = (k: keyof EventFilters, v: string) => {
    const next = { ...filters, [k]: v || undefined };
    setFilters(next);
    onChange(next);
  };

  const commitTime = (k: "from" | "to", raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) {
      update(k, "");
      return;
    }

    const parsed = parseUtcPlusThree(trimmed);
    if (!parsed) {
      return;
    }

    update(k, parsed);
    const formatted = formatUtcPlusThree(parsed);
    if (k === "from") {
      setFromInput(formatted);
    } else {
      setToInput(formatted);
    }
  };

  return (
    <div className="glass p-4 border border-slate-800/60 mb-3">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-semibold">Filters</div>
        <button
          onClick={() => setOpen((o) => !o)}
          className="text-xs text-muted hover:text-accent transition"
        >
          {open ? "Hide" : "Show"}
        </button>
      </div>
      {open && (
        <div className="space-y-3 text-sm">
          <div className="text-xs text-muted">
            Use commas for multiple values: <span className="font-mono">a,b</span>
          </div>
          <div className="text-xs text-muted">
            Time format: <span className="font-mono">YYYY-MM-DD HH:mm:ss</span> (UTC+3, 24h)
          </div>
          <div className="text-xs text-muted">
            You can type only digits; separators are inserted automatically.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="number"
              min={0}
              placeholder="Event ID"
              className="input"
              value={filters.event_id || ""}
              onChange={(e) => update("event_id", e.target.value)}
            />
            <input
              placeholder="Username (include)"
              className="input"
              value={filters.user || ""}
              onChange={(e) => update("user", e.target.value)}
            />
            <input
              placeholder="SID (include)"
              className="input"
              value={filters.sid || ""}
              onChange={(e) => update("sid", e.target.value)}
            />
            <input
              placeholder="IP (include)"
              className="input"
              value={filters.ip || ""}
              onChange={(e) => update("ip", e.target.value)}
            />
            <input
              placeholder="Channel (include)"
              className="input"
              value={filters.channel || ""}
              onChange={(e) => update("channel", e.target.value)}
            />
            <input
              placeholder="Keyword (include)"
              className="input"
              value={filters.keyword || ""}
              onChange={(e) => update("keyword", e.target.value)}
            />
            <input
              type="text"
              className="input"
              placeholder="Start (UTC+3): ....-..-.. ..:..:.."
              value={fromInput}
              onChange={(e) => setFromInput(maskUtcPlusThreeInput(e.target.value))}
              onBlur={() => commitTime("from", fromInput)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commitTime("from", fromInput);
                }
              }}
            />
            <input
              type="text"
              className="input"
              placeholder="End (UTC+3): ....-..-.. ..:..:.."
              value={toInput}
              onChange={(e) => setToInput(maskUtcPlusThreeInput(e.target.value))}
              onBlur={() => commitTime("to", toInput)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commitTime("to", toInput);
                }
              }}
            />
          </div>
          <input
            placeholder="Exclude (global, a,b)"
            className="input"
            value={filters.exclude || ""}
            onChange={(e) => update("exclude", e.target.value)}
          />
        </div>
      )}
    </div>
  );
}
