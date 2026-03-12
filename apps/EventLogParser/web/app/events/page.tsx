"use client";

import { useApi } from "../../hooks/useApi";
import { Card } from "../../ui/card";
import EventFilters, { type EventFilters as FilterType } from "../../components/event-filters";
import EventTable from "../../components/event-table";
import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

export default function EventsPage() {
  const search = useSearchParams();
  const [filters, setFilters] = useState<FilterType>({});

  useEffect(() => {
    const params: FilterType = {
      from: search.get("from") || undefined,
      to: search.get("to") || undefined
    };
    setFilters((prev) => ({ ...prev, ...params }));
  }, [search]);

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Event Explorer</div>
            <h1 className="page-title">Interactive EVTX Record Review</h1>
            <p className="page-subtitle">
              Filter by identity, channel, IP, keyword, and time to inspect high-volume event
              collections without losing raw record fidelity.
            </p>
          </div>
        </div>
      </Card>
      <EventFilters value={filters} onChange={setFilters} />
      <EventTable filters={filters} />
    </section>
  );
}
