"use client";

import { useMemo, useState } from "react";
import { Card } from "../../ui/card";
import { api } from "../../lib/api";
import { useForensicsStore } from "../../hooks/useForensicsStore";

// ── MITRE TTP parser: "T1078 - Valid Accounts" -> { id, name } ──
function parseMitre(raw: string): { id: string; name: string } {
  const m = raw.match(/^(T\d+(?:\.\d+)?)\s*[-–]\s*(.+)$/);
  if (m) return { id: m[1], name: m[2].trim() };
  return { id: raw.trim(), name: "" };
}

function parseMitreList(list?: string[]): { id: string; name: string }[] {
  return (list || []).map(parseMitre);
}

// Guess tactic from technique ID (best effort)
function guessTacticFromTechniqueId(techId: string): string {
  const map: Record<string, string> = {
    T1078: "Initial Access",
    T1133: "Initial Access",
    T1566: "Initial Access",
    T1190: "Initial Access",
    T1195: "Initial Access",
    T1059: "Execution",
    T1053: "Execution",
    T1047: "Execution",
    T1569: "Execution",
    T1204: "Execution",
    T1543: "Persistence",
    T1547: "Persistence",
    T1136: "Persistence",
    T1098: "Persistence",
    T1548: "Privilege Escalation",
    T1134: "Privilege Escalation",
    T1068: "Privilege Escalation",
    T1070: "Defense Evasion",
    T1562: "Defense Evasion",
    T1036: "Defense Evasion",
    T1112: "Defense Evasion",
    T1218: "Defense Evasion",
    T1027: "Defense Evasion",
    T1110: "Credential Access",
    T1003: "Credential Access",
    T1558: "Credential Access",
    T1552: "Credential Access",
    T1087: "Discovery",
    T1082: "Discovery",
    T1083: "Discovery",
    T1069: "Discovery",
    T1018: "Discovery",
    T1049: "Discovery",
    T1021: "Lateral Movement",
    T1570: "Lateral Movement",
    T1563: "Lateral Movement",
    T1560: "Collection",
    T1005: "Collection",
    T1039: "Collection",
    T1114: "Collection",
    T1071: "Command and Control",
    T1105: "Command and Control",
    T1572: "Command and Control",
    T1090: "Command and Control",
    T1219: "Command and Control",
    T1041: "Exfiltration",
    T1048: "Exfiltration",
    T1567: "Exfiltration",
    T1486: "Impact",
    T1490: "Impact",
    T1489: "Impact",
    T1529: "Impact"
  };
  // Try exact, then parent technique
  const parent = techId.split(".")[0];
  return map[techId] || map[parent] || "";
}

function severityOrder(s?: string): number {
  switch (s) {
    case "critical": return 0;
    case "high": return 1;
    case "medium": return 2;
    case "low": return 3;
    default: return 4;
  }
}

function compareBySeverityThenHits(a: any, b: any): number {
  const aHasHits = a.hits > 0;
  const bHasHits = b.hits > 0;

  if (aHasHits !== bHasHits) {
    return aHasHits ? -1 : 1;
  }

  const severityDiff =
    severityOrder(a.rule.severity) - severityOrder(b.rule.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  const hitsDiff = b.hits - a.hits;
  if (hitsDiff !== 0) {
    return hitsDiff;
  }

  return a.rule.name.localeCompare(b.rule.name);
}

function severityBadge(s?: string) {
  switch (s) {
    case "critical": return "badge badge-critical";
    case "high": return "badge badge-danger";
    case "medium": return "badge badge-accent";
    case "low": return "badge badge-muted";
    default: return "badge badge-muted";
  }
}

// ── Match Event Card ──

function MatchEventCard({
  ev,
  step,
  stepLabel,
  matchedRuleNames,
  ruleSeverity,
  ruleMitre
}: {
  ev: any;
  step?: number | null;
  stepLabel?: string | null;
  matchedRuleNames?: string[];
  ruleSeverity?: string;
  ruleMitre?: string[];
}) {
  const { addWithEvent, has: hasInForensics } = useForensicsStore();

  const handleAddForensics = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (hasInForensics(ev.id)) return;

    // Auto-fill MITRE from the detection rule
    const mitreParsed = parseMitreList(ruleMitre);
    const firstMitre = mitreParsed[0];
    const tactic = firstMitre
      ? guessTacticFromTechniqueId(firstMitre.id)
      : "";

    await addWithEvent(ev, {
      severity: ruleSeverity || "medium",
      mitre_tactic: tactic,
      mitre_technique_id: firstMitre?.id || "",
      mitre_technique_name: firstMitre?.name || "",
      tags: ruleMitre ? ruleMitre.map((m) => parseMitre(m).id) : []
    });
  };

  return (
    <details className="rounded-xl border border-black/40 bg-panelAccent p-3">
      <summary className="cursor-pointer">
        <div className="flex flex-wrap items-center gap-2 text-sm font-semibold">
          <span className="badge badge-accent">{ev.event_id}</span>
          <button
            onClick={handleAddForensics}
            disabled={hasInForensics(ev.id)}
            className={`badge transition ${
              hasInForensics(ev.id)
                ? "badge-success cursor-not-allowed"
                : "badge-muted hover:border-orange-400/40 cursor-pointer"
            }`}
          >
            {hasInForensics(ev.id) ? "In Forensics" : "+ Forensics"}
          </button>
          {step ? <span className="badge badge-muted">Step {step}</span> : null}
          {stepLabel ? (
            <span className="badge badge-muted">{stepLabel}</span>
          ) : null}
          <span className="text-muted text-xs">{ev.timestamp}</span>
        </div>
        <div className="mt-1 text-xs text-slate-300">
          User: {ev.user || "—"} | Host: {ev.computer} | Channel: {ev.channel}{" "}
          | Source: {ev.source || "—"}
        </div>
        <div className="text-xs text-muted">
          Keywords: {ev.keywords || "—"} | SID: {ev.sid || "—"}
        </div>
        {matchedRuleNames && matchedRuleNames.length > 0 ? (
          <div className="mt-1 text-xs text-orange-100/80">
            Matched by: {matchedRuleNames.join(", ")}
          </div>
        ) : null}
      </summary>
      <div className="mt-3 space-y-2">
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

// ── Main Page ──

type SortMode = "severity" | "hits" | "name";

export default function DetectionsPage() {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<any | null>(null);
  const { addWithEvent, has: hasInForensics } = useForensicsStore();

  // Filters
  const [searchTerm, setSearchTerm] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterMitre, setFilterMitre] = useState("");
  const [sortMode, setSortMode] = useState<SortMode>("severity");
  const [hideZeroHits, setHideZeroHits] = useState(false);

  const load = async () => {
    setError(null);
    setLoading(true);
    setSelectedRule(null);
    try {
      const res = await api.get("/detections");
      setData(res as any[]);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  // ── Computed stats ──
  const stats = useMemo(() => {
    const totalRules = data.length;
    const totalHits = data.reduce((sum: number, d: any) => sum + d.hits, 0);
    const bySeverity: Record<string, number> = {};
    const mitreSet = new Set<string>();
    data.forEach((d: any) => {
      const s = d.rule.severity || "info";
      bySeverity[s] = (bySeverity[s] || 0) + 1;
      (d.rule.mitre || []).forEach((m: string) => {
        mitreSet.add(parseMitre(m).id);
      });
    });
    const rulesWithHits = data.filter((d: any) => d.hits > 0).length;
    return { totalRules, totalHits, bySeverity, rulesWithHits, mitreCount: mitreSet.size };
  }, [data]);

  // ── All unique MITRE tags for filter dropdown ──
  const allMitreTags = useMemo(() => {
    const tags = new Set<string>();
    data.forEach((d: any) => {
      (d.rule.mitre || []).forEach((m: string) => tags.add(m));
    });
    return Array.from(tags).sort();
  }, [data]);

  // ── Filtered & sorted rules ──
  const filteredRules = useMemo(() => {
    let result = [...data];

    if (searchTerm) {
      const lower = searchTerm.toLowerCase();
      result = result.filter(
        (d: any) =>
          d.rule.name.toLowerCase().includes(lower) ||
          d.rule.id.toLowerCase().includes(lower) ||
          (d.rule.description || "").toLowerCase().includes(lower)
      );
    }

    if (filterSeverity) {
      result = result.filter((d: any) => d.rule.severity === filterSeverity);
    }

    if (filterMitre) {
      result = result.filter((d: any) =>
        (d.rule.mitre || []).some((m: string) => m === filterMitre)
      );
    }

    if (hideZeroHits) {
      result = result.filter((d: any) => d.hits > 0);
    }

    result.sort((a: any, b: any) => {
      if (sortMode === "severity") {
        return compareBySeverityThenHits(a, b);
      }
      if (sortMode === "hits") return b.hits - a.hits;
      return a.rule.name.localeCompare(b.rule.name);
    });

    return result;
  }, [data, searchTerm, filterSeverity, filterMitre, sortMode, hideZeroHits]);

  const selectedCorrelationGroups = Array.isArray(
    selectedRule?.correlation_groups
  )
    ? selectedRule.correlation_groups
    : [];
  const isCorrelationRule = Boolean(selectedRule?.rule?.correlation);

  const handleAddAllToForensics = async () => {
    if (!selectedRule) return;
    const events = selectedRule.events || [];
    for (const ev of events) {
      if (!hasInForensics(ev.id)) {
        const mitreParsed = parseMitreList(selectedRule.rule.mitre);
        const firstMitre = mitreParsed[0];
        const tactic = firstMitre
          ? guessTacticFromTechniqueId(firstMitre.id)
          : "";
        await addWithEvent(ev, {
          severity: selectedRule.rule.severity || "medium",
          mitre_tactic: tactic,
          mitre_technique_id: firstMitre?.id || "",
          mitre_technique_name: firstMitre?.name || "",
          tags: (selectedRule.rule.mitre || []).map(
            (m: string) => parseMitre(m).id
          )
        });
      }
    }
  };

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Detection Console</div>
            <h1 className="page-title">Rule Execution and Hit Review</h1>
            <p className="page-subtitle">
              Launch the current rule pack, inspect severity-ranked matches, and
              validate suspicious chains against raw event context.
            </p>
          </div>
        </div>
        <div className="hero-grid">
          <div className="metric-card">
            <div className="metric-label">Total Rules</div>
            <div className="metric-value">{stats.totalRules}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Rules with Hits</div>
            <div className="metric-value">{stats.rulesWithHits}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Total Hits</div>
            <div className="metric-value">{stats.totalHits}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">MITRE Techniques</div>
            <div className="metric-value">{stats.mitreCount}</div>
          </div>
          {stats.bySeverity["critical"] ? (
            <div className="metric-card">
              <div className="metric-label">Critical</div>
              <div className="metric-value text-red-300">
                {stats.bySeverity["critical"]}
              </div>
            </div>
          ) : null}
          {stats.bySeverity["high"] ? (
            <div className="metric-card">
              <div className="metric-label">High</div>
              <div className="metric-value text-orange-300">
                {stats.bySeverity["high"]}
              </div>
            </div>
          ) : null}
        </div>
      </Card>

      {/* Toolbar */}
      <div className="page-intro">
        <div className="page-copy">
          <h2 className="text-xl font-semibold text-white">
            Detection Results
          </h2>
          <p className="status-text">
            {data.length > 0
              ? `${filteredRules.length} of ${data.length} rules shown`
              : "Load the current ruleset and select a rule to inspect matched events."}
          </p>
        </div>
        <button
          onClick={load}
          className="action-btn primary"
          disabled={loading}
        >
          {loading ? "Running..." : "Run Rules"}
        </button>
      </div>

      {error && <div className="text-danger text-sm">{error}</div>}

      {/* Filter bar */}
      {data.length > 0 && (
        <Card className="p-4">
          <div className="flex items-center gap-3 flex-wrap">
            <input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search rules..."
              className="input flex-1 min-w-[200px]"
            />
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="input w-32"
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              value={filterMitre}
              onChange={(e) => setFilterMitre(e.target.value)}
              className="input w-56"
            >
              <option value="">All MITRE</option>
              {allMitreTags.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <select
              value={sortMode}
              onChange={(e) => setSortMode(e.target.value as SortMode)}
              className="input w-36"
            >
              <option value="severity">Sort: Severity</option>
              <option value="hits">Sort: Hits</option>
              <option value="name">Sort: Name</option>
            </select>
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={hideZeroHits}
                onChange={(e) => setHideZeroHits(e.target.checked)}
                className="accent-orange-500"
              />
              Hide 0 hits
            </label>
          </div>
        </Card>
      )}

      {/* Two-panel layout */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[0.88fr_1.12fr] xl:items-stretch">
        {/* Rules Panel */}
        <Card className="flex min-h-[620px] min-h-0 flex-col overflow-hidden p-4 xl:h-[74vh] xl:max-h-[920px] xl:min-h-0">
          <div className="flex items-center justify-between gap-3 border-b border-black/40 pb-3">
            <h2 className="text-sm uppercase tracking-[0.2em] text-muted">
              Rules
            </h2>
            <span className="badge badge-muted">
              {filteredRules.length} shown
            </span>
          </div>
          <div className="mt-3 min-h-0 flex-1 overflow-y-auto pr-1">
            <div className="space-y-2">
              {filteredRules.map((d: any) => {
                const mitreTags = parseMitreList(d.rule.mitre);
                return (
                  <div
                    key={d.rule.id}
                    className={`rounded-xl border border-black/30 p-3 cursor-pointer transition hover:bg-black/20 ${
                      selectedRule?.rule?.id === d.rule.id
                        ? "bg-accent/15 border-accent/25"
                        : "bg-black/10"
                    }`}
                    onClick={() => setSelectedRule(d)}
                  >
                    <div className="flex justify-between gap-3 text-sm">
                      <span className="font-semibold text-slate-100">
                        {d.rule.name}
                      </span>
                      <span className={severityBadge(d.rule.severity)}>
                        {d.rule.severity || "info"}
                      </span>
                    </div>
                    {d.rule.description && (
                      <div className="mt-1.5 text-xs text-muted line-clamp-2">
                        {d.rule.description}
                      </div>
                    )}
                    {/* MITRE Tags */}
                    {mitreTags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {mitreTags.map((m) => (
                          <span
                            key={m.id}
                            className="inline-flex items-center gap-1 rounded-md bg-slate-900/60 border border-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-300"
                          >
                            <span className="font-semibold text-orange-200/80">
                              {m.id}
                            </span>
                            {m.name && (
                              <span className="text-slate-400">{m.name}</span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="mt-2 flex items-center gap-3">
                      <span
                        className={`text-xs font-semibold ${
                          d.hits > 0 ? "text-orange-100" : "text-slate-500"
                        }`}
                      >
                        {d.hits} hit{d.hits !== 1 ? "s" : ""}
                      </span>
                      {d.hits > 0 && (
                        <span className="text-[10px] text-slate-500">
                          {d.events.length} events
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
              {!loading && filteredRules.length === 0 && data.length > 0 && (
                <div className="empty-state text-center">
                  No rules match current filters.
                </div>
              )}
              {!loading && data.length === 0 && (
                <div className="empty-state text-center">
                  No rules loaded yet. Run the current ruleset to populate this
                  panel.
                </div>
              )}
            </div>
          </div>
        </Card>

        {/* Matches Panel */}
        <Card className="flex min-h-[620px] min-h-0 flex-col overflow-hidden p-4 xl:h-[74vh] xl:max-h-[920px] xl:min-h-0">
          <div className="flex items-center justify-between gap-3 border-b border-black/40 pb-3">
            <h2 className="text-sm uppercase tracking-[0.2em] text-muted">
              Matches
            </h2>
            {selectedRule ? (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="badge badge-muted">
                  {isCorrelationRule
                    ? `${selectedRule.hits} groups / ${selectedRule.events.length} events`
                    : `${selectedRule.events.length} events`}
                </span>
                {selectedRule.events.length > 0 && (
                  <button
                    onClick={handleAddAllToForensics}
                    className="badge badge-accent cursor-pointer hover:bg-accent/30 transition"
                  >
                    + All to Forensics
                  </button>
                )}
              </div>
            ) : null}
          </div>

          {/* Selected rule info header */}
          {selectedRule && (
            <div className="mt-3 rounded-xl border border-slate-800/50 bg-black/20 p-3 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-bold text-white">
                  {selectedRule.rule.name}
                </span>
                <span className={severityBadge(selectedRule.rule.severity)}>
                  {selectedRule.rule.severity || "info"}
                </span>
              </div>
              {selectedRule.rule.description && (
                <div className="text-xs text-slate-300">
                  {selectedRule.rule.description}
                </div>
              )}
              {selectedRule.rule.mitre && selectedRule.rule.mitre.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {parseMitreList(selectedRule.rule.mitre).map((m) => (
                    <span
                      key={m.id}
                      className="badge badge-accent text-[10px]"
                    >
                      {m.id} {m.name ? `- ${m.name}` : ""}
                    </span>
                  ))}
                </div>
              )}
              {/* Event ID targets */}
              {selectedRule.rule.event_id &&
                selectedRule.rule.event_id.length > 0 && (
                  <div className="flex items-center gap-2 text-xs text-muted">
                    <span>Target Event IDs:</span>
                    {selectedRule.rule.event_id.map((eid: number) => (
                      <span key={eid} className="badge badge-muted text-[10px]">
                        {eid}
                      </span>
                    ))}
                  </div>
                )}
            </div>
          )}

          {!selectedRule && (
            <div className="mt-3 empty-state text-center">
              Select a rule to review matching events.
            </div>
          )}
          {selectedRule && (
            <div className="mt-3 min-h-0 flex-1 overflow-y-auto pr-1">
              {isCorrelationRule && selectedCorrelationGroups.length > 0 ? (
                <div className="space-y-3">
                  {selectedCorrelationGroups.map(
                    (group: any, index: number) => (
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
                              {group.window_end &&
                              group.window_end !== group.window_start
                                ? `-> ${group.window_end}`
                                : ""}
                            </div>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            {group.group_key ? (
                              <span className="badge badge-muted">
                                {group.group_key}
                              </span>
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
                              ruleSeverity={selectedRule.rule.severity}
                              ruleMitre={selectedRule.rule.mitre}
                            />
                          ))}
                        </div>
                      </div>
                    )
                  )}
                </div>
              ) : (
                <div className="space-y-2 text-xs">
                  {selectedRule.events.map((ev: any) => (
                    <MatchEventCard
                      key={ev.id}
                      ev={ev}
                      ruleSeverity={selectedRule.rule.severity}
                      ruleMitre={selectedRule.rule.mitre}
                    />
                  ))}
                  {selectedRule.events.length === 0 && (
                    <div className="empty-state text-center">
                      No events matched this rule.
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
