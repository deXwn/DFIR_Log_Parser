import { create } from "zustand";
import { api } from "../lib/api";

type CaseItem = {
  event: any;
  notes: string;
};

type State = {
  items: Map<number, CaseItem>;
  addById: (id: number) => Promise<void>;
  toggle: (item: any) => void;
  remove: (id: number) => void;
  setNotes: (id: number, notes: string) => void;
  clear: () => void;
};

export const useCaseFileStore = create<State>((set, get) => ({
  items: new Map(),
  addById: async (id: number) => {
    const exists = get().items.has(id);
    if (exists) return;
    const ev = await api.event(String(id));
    set((state) => {
      const next = new Map(state.items);
      next.set(id, { event: ev, notes: "" });
      return { items: next };
    });
  },
  toggle: (event: any) =>
    set((state) => {
      const next = new Map(state.items);
      if (next.has(event.id)) {
        next.delete(event.id);
      } else {
        next.set(event.id, { event, notes: "" });
      }
      return { items: next };
    }),
  remove: (id: number) =>
    set((state) => {
      const next = new Map(state.items);
      next.delete(id);
      return { items: next };
    }),
  setNotes: (id: number, notes: string) =>
    set((state) => {
      const next = new Map(state.items);
      const found = next.get(id);
      if (found) {
        next.set(id, { ...found, notes });
      }
      return { items: next };
    }),
  clear: () => set({ items: new Map() })
}));
