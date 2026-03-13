"use client";

import { useState } from "react";
import { Card } from "../../ui/card";
import { api } from "../../lib/api";

function MatchEventCard({
  ev,
  step,
  stepLabel,
  matchedRuleNames
}: {
  ev: any;
  step?: number | null;
  stepLabel?: string | null;
  matchedRuleNames?: string[];
}) {
  return (
    <details className="rounded border border-black/40 bg-panelAccent p-2">
      <summary className="cursor-pointer">
        <div className="flex flex-wrap items-center gap-2 text-sm font-semibold">
          <span className="badge badge-accent">{ev.event_id}</span>
          {step ? <span className="badge badge-muted">Step {step}</span> : null}
          {stepLabel ? <span className="badge badge-muted">{stepLabel}</span> : null}
          <span className="text-muted">{ev.timestamp}</span>
        </div>
        <div className="mt-1 text-xs">
          User: {ev.user || "—"} | Host: {ev.computer} | Channel: {ev.channel} | Source:{" "}
          {ev.source || "—"}
        </div>
        <div className="text-xs text-muted">
          Keywords: {ev.keywords || "—"} | Path: {ev.ingest_path || "—"}
        </div>
        {matchedRuleNames && matchedRuleNames.length > 0 ? (
          <div className="mt-1 text-xs text-orange-100/80">
            Matched by: {matchedRuleNames.join(", ")}
          </div>
        ) : null}
      </summary>
      <div className="mt-2 space-y-1">
        <div className="text-xs uppercase tracking-[0.2em] text-muted">
          Event Data
        </div>
        <pre className="max-h-[300px] overflow-auto rounded border border-black/40 bg-slate-900/80 p-2 text-[11px]">
          {JSON.stringify(ev.event_data_json, null, 2)}
        </pre>
        <div className="text-xs uppercase tracking-[0.2em] text-muted">
          Raw XML
        </div>
        <pre className="max-h-[200px] overflow-auto rounded border border-black/40 bg-slate-900/80 p-2 text-[11px]">
          {ev.raw_xml}
        </pre>
      </div>
    </details>
  );
}

export default function DetectionsPage() {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<any | null>(null);

  const load = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await api.get("/detections");
      setData(res as any[]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const selectedCorrelationGroups = Array.isArray(selectedRule?.correlation_groups)
    ? selectedRule.correlation_groups
    : [];
  const isCorrelationRule = Boolean(selectedRule?.rule?.correlation);

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Detection Console</div>
            <h1 className="page-title">Rule Execution and Hit Review</h1>
            <p className="page-subtitle">
              Launch the current rule pack, inspect severity-ranked matches, and validate
              suspicious chains against raw event context.
            </p>
          </div>
        </div>
        <div className="hero-grid">
          <div className="metric-card">
            <div className="metric-label">Source</div>
            <div className="metric-value">YAML / JSON rules</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Primary Use</div>
            <div className="metric-value">Threat triage</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Workflow</div>
            <div className="metric-value">Run {"->"} Review {"->"} Validate</div>
          </div>
        </div>
      </Card>

      <div className="page-intro">
        <div className="page-copy">
          <h2 className="text-xl font-semibold text-white">Detection Results</h2>
          <p className="status-text">Load the current ruleset and select a rule to inspect matched events.</p>
        </div>
        <button
          onClick={load}
          className="action-btn primary"
          disabled={loading}
        >
          {loading ? "Running…" : "Run Rules"}
        </button>
      </div>
      {error && <div className="text-danger text-sm">{error}</div>}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[0.88fr_1.12fr] xl:items-stretch">
        <Card className="flex min-h-[620px] min-h-0 flex-col overflow-hidden p-4 xl:h-[74vh] xl:max-h-[920px] xl:min-h-0">
          <div className="flex items-center justify-between gap-3 border-b border-black/40 pb-3">
            <h2 className="text-sm uppercase tracking-[0.2em] text-muted">
              Rules
            </h2>
            <span className="badge badge-muted">{data.length} loaded</span>
          </div>
          <div className="mt-3 min-h-0 flex-1 overflow-y-auto pr-1">
            <div className="space-y-2">
              {data.map((d: any) => (
                <div
                  key={d.rule.id}
                  className={`rounded-xl border border-black/30 p-3 cursor-pointer transition hover:bg-black/20 ${
                    selectedRule?.rule?.id === d.rule.id ? "bg-accent/15 border-accent/25" : "bg-black/10"
                  }`}
                  onClick={() => setSelectedRule(d)}
                >
                  <div className="flex justify-between gap-3 text-sm">
                    <span className="font-semibold">{d.rule.name}</span>
                    <span
                      className={`badge ${
                        d.rule.severity === "high"
                          ? "badge-danger"
                          : d.rule.severity === "medium"
                          ? "badge-accent"
                          : "badge-muted"
                      }`}
                    >
                      {d.rule.severity || "info"}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-muted">{d.rule.description || ""}</div>
                  <div className="mt-2 text-xs text-orange-100/80">Hits: {d.hits}</div>
                </div>
              ))}
              {!loading && data.length === 0 && (
                <div className="rounded-xl border border-dashed border-slate-700/70 bg-black/10 px-4 py-8 text-center text-sm text-muted">
                  No rules loaded yet. Run the current ruleset to populate this panel.
                </div>
              )}
            </div>
          </div>
        </Card>
        <Card className="flex min-h-[620px] min-h-0 flex-col overflow-hidden p-4 xl:h-[74vh] xl:max-h-[920px] xl:min-h-0">
          <div className="flex items-center justify-between gap-3 border-b border-black/40 pb-3">
            <h2 className="text-sm uppercase tracking-[0.2em] text-muted">
              Matches
            </h2>
            {selectedRule ? (
              <span className="badge badge-muted">
                {isCorrelationRule
                  ? `${selectedRule.hits} groups / ${selectedRule.events.length} events`
                  : `${selectedRule.events.length} events`}
              </span>
            ) : null}
          </div>
          {!selectedRule && (
            <div className="mt-3 rounded-xl border border-dashed border-slate-700/70 bg-black/10 px-4 py-8 text-center text-sm text-muted">
              Select a rule to review matching events.
            </div>
          )}
          {selectedRule && (
            <div className="mt-3 min-h-0 flex-1 overflow-y-auto pr-1">
              {isCorrelationRule && selectedCorrelationGroups.length > 0 ? (
                <div className="space-y-3">
                  {selectedCorrelationGroups.map((group: any, index: number) => (
                    <div
                      key={`${group.group_key || "all"}-${group.window_start || index}-${index}`}
                      className="rounded-xl border border-slate-800/70 bg-black/10 p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-black/30 pb-3">
                        <div>
                          <div className="text-xs uppercase tracking-[0.18em] text-muted">
                            Correlation Hit {index + 1}
                          </div>
                          <div className="mt-1 text-sm text-slate-200">
                            {group.window_start || "—"}{" "}
                            {group.window_end && group.window_end !== group.window_start
                              ? `-> ${group.window_end}`
                              : ""}
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          {group.group_key ? (
                            <span className="badge badge-muted">{group.group_key}</span>
                          ) : null}
                          <span className="badge badge-accent">
                            {group.events?.length || 0} linked events
                          </span>
                        </div>
                      </div>
                      <div className="mt-3 space-y-2 text-xs">
                        {(group.events || []).map((item: any) => (
                          <MatchEventCard
                            key={item.event.id}
                            ev={item.event}
                            step={item.step}
                            stepLabel={item.step_label}
                            matchedRuleNames={item.matched_rule_names}
                          />
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="space-y-2 text-xs">
                  {selectedRule.events.map((ev: any) => (
                    <MatchEventCard key={ev.id} ev={ev} />
                  ))}
                  {selectedRule.events.length === 0 && (
                    <div className="rounded-xl border border-dashed border-slate-700/70 bg-black/10 px-4 py-8 text-center text-sm text-muted">
                      No events matched.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </section>
  );
}
