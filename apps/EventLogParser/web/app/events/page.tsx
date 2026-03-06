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
    <section className="space-y-3">
      <EventFilters value={filters} onChange={setFilters} />
      <EventTable filters={filters} />
    </section>
  );
}
