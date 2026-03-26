import { create } from "zustand";
import { api } from "../lib/api";

export type ForensicItem = {
  id: number;
  event_id: number;
  notes: string;
  tags: string[];
  severity: string;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  created_at: string;
  event: any | null;
};

// Event ID -> auto severity mapping
const CRITICAL_EVENT_IDS = new Set([1100, 1102, 4625, 4719, 4724, 4726, 4740]);
const HIGH_RISK_EVENT_IDS = new Set([
  4648, 4672, 4697, 4698, 4702, 7045, 4728, 4729, 4732, 4733, 4756, 4757
]);
const SUCCESS_EVENT_IDS = new Set([4624, 4720, 4722, 5140]);

function inferSeverityFromEventId(eventId?: number): string {
  if (!eventId) return "medium";
  if (CRITICAL_EVENT_IDS.has(eventId)) return "critical";
  if (HIGH_RISK_EVENT_IDS.has(eventId)) return "high";
  if (SUCCESS_EVENT_IDS.has(eventId)) return "low";
  return "medium";
}

type State = {
  items: ForensicItem[];
  loading: boolean;
  fetch: () => Promise<void>;
  add: (eventId: number, extra?: Partial<ForensicItem>) => Promise<void>;
  addWithEvent: (event: any, extra?: Partial<ForensicItem>) => Promise<void>;
  update: (id: number, data: Partial<ForensicItem>) => Promise<void>;
  remove: (id: number) => Promise<void>;
  clear: () => Promise<void>;
  has: (eventId: number) => boolean;
};

export const useForensicsStore = create<State>((set, get) => ({
  items: [],
  loading: false,

  fetch: async () => {
    set({ loading: true });
    try {
      const items = (await api.forensics()) as ForensicItem[];
      set({ items });
    } finally {
      set({ loading: false });
    }
  },

  add: async (eventId: number, extra?: Partial<ForensicItem>) => {
    // If no severity provided, fetch event to infer
    let severity = extra?.severity;
    if (!severity) {
      try {
        const ev = (await api.event(String(eventId))) as any;
        severity = inferSeverityFromEventId(ev?.event_id);
      } catch {
        severity = "medium";
      }
    }

    const item = (await api.addForensic({
      event_id: eventId,
      notes: extra?.notes || "",
      tags: extra?.tags || [],
      severity,
      mitre_tactic: extra?.mitre_tactic || "",
      mitre_technique_id: extra?.mitre_technique_id || "",
      mitre_technique_name: extra?.mitre_technique_name || ""
    })) as ForensicItem;
    set((s) => ({ items: [item, ...s.items] }));
  },

  // Add with event object already available (avoids extra fetch)
  addWithEvent: async (event: any, extra?: Partial<ForensicItem>) => {
    const severity =
      extra?.severity || inferSeverityFromEventId(event?.event_id);

    const item = (await api.addForensic({
      event_id: event.id,
      notes: extra?.notes || "",
      tags: extra?.tags || [],
      severity,
      mitre_tactic: extra?.mitre_tactic || "",
      mitre_technique_id: extra?.mitre_technique_id || "",
      mitre_technique_name: extra?.mitre_technique_name || ""
    })) as ForensicItem;
    set((s) => ({ items: [item, ...s.items] }));
  },

  update: async (id: number, data: Partial<ForensicItem>) => {
    const updated = (await api.updateForensic(id, data)) as ForensicItem;
    set((s) => ({
      items: s.items.map((i) => (i.id === id ? updated : i))
    }));
  },

  remove: async (id: number) => {
    await api.deleteForensic(id);
    set((s) => ({ items: s.items.filter((i) => i.id !== id) }));
  },

  clear: async () => {
    await api.clearForensics();
    set({ items: [] });
  },

  has: (eventId: number) => get().items.some((i) => i.event_id === eventId)
}));
