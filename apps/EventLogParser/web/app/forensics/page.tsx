"use client";

import { useEffect, useState } from "react";
import { Card } from "../../ui/card";
import {
  useForensicsStore,
  type ForensicItem
} from "../../hooks/useForensicsStore";

const MITRE_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact"
];

const MITRE_TECHNIQUES: Record<string, { id: string; name: string }[]> = {
  "Initial Access": [
    { id: "T1078", name: "Valid Accounts" },
    { id: "T1133", name: "External Remote Services" },
    { id: "T1566", name: "Phishing" },
    { id: "T1190", name: "Exploit Public-Facing Application" },
    { id: "T1195", name: "Supply Chain Compromise" }
  ],
  Execution: [
    { id: "T1059", name: "Command and Scripting Interpreter" },
    { id: "T1059.001", name: "PowerShell" },
    { id: "T1059.003", name: "Windows Command Shell" },
    { id: "T1053", name: "Scheduled Task/Job" },
    { id: "T1047", name: "WMI" },
    { id: "T1569", name: "System Services" },
    { id: "T1204", name: "User Execution" }
  ],
  Persistence: [
    { id: "T1543", name: "Create or Modify System Process" },
    { id: "T1543.003", name: "Windows Service" },
    { id: "T1053.005", name: "Scheduled Task" },
    { id: "T1547", name: "Boot or Logon Autostart Execution" },
    { id: "T1547.001", name: "Registry Run Keys" },
    { id: "T1136", name: "Create Account" },
    { id: "T1098", name: "Account Manipulation" }
  ],
  "Privilege Escalation": [
    { id: "T1548", name: "Abuse Elevation Control Mechanism" },
    { id: "T1134", name: "Access Token Manipulation" },
    { id: "T1068", name: "Exploitation for Privilege Escalation" },
    { id: "T1078", name: "Valid Accounts" }
  ],
  "Defense Evasion": [
    { id: "T1070", name: "Indicator Removal" },
    { id: "T1070.001", name: "Clear Windows Event Logs" },
    { id: "T1562", name: "Impair Defenses" },
    { id: "T1562.001", name: "Disable or Modify Tools" },
    { id: "T1036", name: "Masquerading" },
    { id: "T1112", name: "Modify Registry" },
    { id: "T1218", name: "System Binary Proxy Execution" },
    { id: "T1027", name: "Obfuscated Files or Information" }
  ],
  "Credential Access": [
    { id: "T1110", name: "Brute Force" },
    { id: "T1003", name: "OS Credential Dumping" },
    { id: "T1003.001", name: "LSASS Memory" },
    { id: "T1558", name: "Steal or Forge Kerberos Tickets" },
    { id: "T1552", name: "Unsecured Credentials" }
  ],
  Discovery: [
    { id: "T1087", name: "Account Discovery" },
    { id: "T1082", name: "System Information Discovery" },
    { id: "T1083", name: "File and Directory Discovery" },
    { id: "T1069", name: "Permission Groups Discovery" },
    { id: "T1018", name: "Remote System Discovery" },
    { id: "T1049", name: "System Network Connections Discovery" }
  ],
  "Lateral Movement": [
    { id: "T1021", name: "Remote Services" },
    { id: "T1021.001", name: "Remote Desktop Protocol" },
    { id: "T1021.002", name: "SMB/Windows Admin Shares" },
    { id: "T1021.006", name: "Windows Remote Management" },
    { id: "T1570", name: "Lateral Tool Transfer" },
    { id: "T1563", name: "Remote Service Session Hijacking" }
  ],
  Collection: [
    { id: "T1560", name: "Archive Collected Data" },
    { id: "T1005", name: "Data from Local System" },
    { id: "T1039", name: "Data from Network Shared Drive" },
    { id: "T1114", name: "Email Collection" }
  ],
  "Command and Control": [
    { id: "T1071", name: "Application Layer Protocol" },
    { id: "T1105", name: "Ingress Tool Transfer" },
    { id: "T1572", name: "Protocol Tunneling" },
    { id: "T1090", name: "Proxy" },
    { id: "T1219", name: "Remote Access Software" }
  ],
  Exfiltration: [
    { id: "T1041", name: "Exfiltration Over C2 Channel" },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
    { id: "T1567", name: "Exfiltration Over Web Service" }
  ],
  Impact: [
    { id: "T1486", name: "Data Encrypted for Impact" },
    { id: "T1490", name: "Inhibit System Recovery" },
    { id: "T1489", name: "Service Stop" },
    { id: "T1529", name: "System Shutdown/Reboot" }
  ],
  Reconnaissance: [
    { id: "T1595", name: "Active Scanning" },
    { id: "T1592", name: "Gather Victim Host Information" },
    { id: "T1589", name: "Gather Victim Identity Information" }
  ],
  "Resource Development": [
    { id: "T1583", name: "Acquire Infrastructure" },
    { id: "T1588", name: "Obtain Capabilities" },
    { id: "T1587", name: "Develop Capabilities" }
  ]
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

function severityBadgeClass(s: string) {
  switch (s) {
    case "critical":
      return "badge badge-critical";
    case "high":
      return "badge badge-danger";
    case "medium":
      return "badge badge-warning";
    case "low":
      return "badge badge-accent";
    default:
      return "badge badge-muted";
  }
}

function EditModal({
  item,
  onClose
}: {
  item: ForensicItem;
  onClose: () => void;
}) {
  const { update } = useForensicsStore();
  const [notes, setNotes] = useState(item.notes);
  const [severity, setSeverity] = useState(item.severity);
  const [tactic, setTactic] = useState(item.mitre_tactic);
  const [techId, setTechId] = useState(item.mitre_technique_id);
  const [techName, setTechName] = useState(item.mitre_technique_name);
  const [tags, setTags] = useState(item.tags.join(", "));
  const [saving, setSaving] = useState(false);

  const techniques = MITRE_TECHNIQUES[tactic] || [];

  const handleTacticChange = (val: string) => {
    setTactic(val);
    setTechId("");
    setTechName("");
  };

  const handleTechChange = (val: string) => {
    const tech = techniques.find((t) => t.id === val);
    if (tech) {
      setTechId(tech.id);
      setTechName(tech.name);
    } else {
      setTechId(val);
      setTechName("");
    }
  };

  const save = async () => {
    setSaving(true);
    try {
      await update(item.id, {
        notes,
        severity,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        mitre_tactic: tactic,
        mitre_technique_id: techId,
        mitre_technique_name: techName
      });
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl rounded-2xl border border-slate-700/70 bg-slate-950 p-6 shadow-2xl space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold text-white">Edit Evidence</h3>
          <button
            onClick={onClose}
            className="text-sm text-muted hover:text-white transition"
          >
            Close
          </button>
        </div>

        <div className="text-xs text-muted">
          Event {item.event?.event_id} | {item.event?.timestamp} |{" "}
          {item.event?.computer}
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-xs uppercase tracking-[0.14em] text-muted block mb-1">
              Analyst Notes
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              className="input w-full resize-y"
              placeholder="Investigation notes..."
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs uppercase tracking-[0.14em] text-muted block mb-1">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="input w-full"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs uppercase tracking-[0.14em] text-muted block mb-1">
                Tags (comma separated)
              </label>
              <input
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                className="input w-full"
                placeholder="e.g. IOC, suspicious, lateral"
              />
            </div>
          </div>

          <div className="border-t border-slate-800/50 pt-3">
            <div className="text-xs uppercase tracking-[0.14em] text-orange-100/80 mb-2">
              MITRE ATT&CK Mapping
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted block mb-1">Tactic</label>
                <select
                  value={tactic}
                  onChange={(e) => handleTacticChange(e.target.value)}
                  className="input w-full"
                >
                  <option value="">-- Select Tactic --</option>
                  {MITRE_TACTICS.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-muted block mb-1">
                  Technique
                </label>
                {techniques.length > 0 ? (
                  <select
                    value={techId}
                    onChange={(e) => handleTechChange(e.target.value)}
                    className="input w-full"
                  >
                    <option value="">-- Select Technique --</option>
                    {techniques.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.id} - {t.name}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    value={techId}
                    onChange={(e) => {
                      setTechId(e.target.value);
                      setTechName("");
                    }}
                    className="input w-full"
                    placeholder="e.g. T1059.001"
                  />
                )}
              </div>
            </div>
            {techId && (
              <div className="mt-2 text-xs text-slate-300">
                <span className="badge badge-accent">
                  {techId}
                  {techName ? ` - ${techName}` : ""}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="action-btn secondary">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving}
            className="action-btn primary"
          >
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ForensicsPage() {
  const { items, loading, fetch, remove, clear } = useForensicsStore();
  const [editing, setEditing] = useState<ForensicItem | null>(null);
  const [filterTactic, setFilterTactic] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");

  useEffect(() => {
    fetch();
  }, [fetch]);

  const filtered = items.filter((item) => {
    if (filterTactic && item.mitre_tactic !== filterTactic) return false;
    if (filterSeverity && item.severity !== filterSeverity) return false;
    return true;
  });

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensics_evidence_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCsv = () => {
    const headers = [
      "ID",
      "Event ID",
      "Event Type",
      "Timestamp",
      "Computer",
      "User",
      "Channel",
      "Severity",
      "MITRE Tactic",
      "MITRE Technique",
      "Tags",
      "Notes",
      "Created At"
    ];
    const rows = filtered.map((i) => [
      i.id,
      i.event?.event_id || "",
      i.event?.event_id || "",
      i.event?.timestamp || "",
      i.event?.computer || "",
      i.event?.user || "",
      i.event?.channel || "",
      i.severity,
      i.mitre_tactic,
      `${i.mitre_technique_id} ${i.mitre_technique_name}`.trim(),
      i.tags.join("; "),
      `"${(i.notes || "").replace(/"/g, '""')}"`,
      i.created_at
    ]);
    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensics_evidence_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const tacticCounts: Record<string, number> = {};
  const severityCounts: Record<string, number> = {};
  items.forEach((i) => {
    if (i.mitre_tactic) tacticCounts[i.mitre_tactic] = (tacticCounts[i.mitre_tactic] || 0) + 1;
    severityCounts[i.severity] = (severityCounts[i.severity] || 0) + 1;
  });

  return (
    <section className="panel-stack">
      <Card className="hero-panel">
        <div className="page-intro">
          <div className="page-copy">
            <div className="eyebrow">Evidence Collection</div>
            <h1 className="page-title">Forensics Workspace</h1>
            <p className="page-subtitle">
              Collected evidence items with MITRE ATT&CK TTP mapping, severity
              classification, analyst notes, and export capabilities.
            </p>
          </div>
        </div>
        <div className="hero-grid">
          <div className="metric-card">
            <div className="metric-label">Total Evidence</div>
            <div className="metric-value">{items.length}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Tactics Mapped</div>
            <div className="metric-value">
              {Object.keys(tacticCounts).length}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Critical/High</div>
            <div className="metric-value">
              {(severityCounts["critical"] || 0) +
                (severityCounts["high"] || 0)}
            </div>
          </div>
        </div>
      </Card>

      {/* MITRE Tactic Overview */}
      {Object.keys(tacticCounts).length > 0 && (
        <Card className="p-5">
          <div className="text-xs uppercase tracking-[0.14em] text-muted mb-3">
            MITRE ATT&CK Coverage
          </div>
          <div className="flex flex-wrap gap-2">
            {MITRE_TACTICS.map((t) =>
              tacticCounts[t] ? (
                <button
                  key={t}
                  onClick={() =>
                    setFilterTactic(filterTactic === t ? "" : t)
                  }
                  className={`badge transition cursor-pointer ${
                    filterTactic === t
                      ? "badge-accent"
                      : "badge-muted hover:border-orange-400/40"
                  }`}
                >
                  {t} ({tacticCounts[t]})
                </button>
              ) : null
            )}
            {filterTactic && (
              <button
                onClick={() => setFilterTactic("")}
                className="text-xs text-muted hover:text-white transition ml-2"
              >
                Clear filter
              </button>
            )}
          </div>
        </Card>
      )}

      {/* Toolbar */}
      <div className="page-intro">
        <div className="toolbar-cluster">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="input w-36"
          >
            <option value="">All Severity</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
          <span className="text-xs text-muted">
            {filtered.length} / {items.length} items
          </span>
        </div>
        <div className="toolbar-cluster">
          <button onClick={exportJson} className="action-btn ghost">
            Export JSON
          </button>
          <button onClick={exportCsv} className="action-btn ghost">
            Export CSV
          </button>
          {items.length > 0 && (
            <button
              onClick={() => {
                if (confirm("Clear all forensic evidence?")) clear();
              }}
              className="action-btn secondary"
            >
              Clear All
            </button>
          )}
        </div>
      </div>

      {/* Items List */}
      {loading && <div className="text-slate-400 text-sm">Loading...</div>}
      <div className="space-y-3">
        {filtered.map((item) => (
          <Card key={item.id} className="p-4 space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={severityBadgeClass(item.severity)}>
                    {item.severity}
                  </span>
                  {item.event && (
                    <span className="badge badge-accent">
                      Event {item.event.event_id}
                    </span>
                  )}
                  {item.mitre_tactic && (
                    <span className="badge badge-muted">
                      {item.mitre_tactic}
                    </span>
                  )}
                  {item.mitre_technique_id && (
                    <span className="badge badge-muted">
                      {item.mitre_technique_id}
                      {item.mitre_technique_name
                        ? ` - ${item.mitre_technique_name}`
                        : ""}
                    </span>
                  )}
                  {item.tags.map((tag) => (
                    <span
                      key={tag}
                      className="badge badge-muted text-[10px]"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
                {item.event && (
                  <div className="mt-2 text-xs text-slate-300">
                    <span>{item.event.timestamp}</span>
                    <span className="mx-2 text-slate-600">|</span>
                    <span>{item.event.computer}</span>
                    <span className="mx-2 text-slate-600">|</span>
                    <span>{item.event.user || "—"}</span>
                    <span className="mx-2 text-slate-600">|</span>
                    <span>{item.event.channel}</span>
                  </div>
                )}
                {item.notes && (
                  <div className="mt-2 text-sm text-slate-200 bg-slate-900/50 rounded-lg p-2 border border-slate-800/40">
                    {item.notes}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setEditing(item)}
                  className="rounded-lg border border-slate-700/60 bg-slate-900/50 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:border-accent/40 hover:text-white transition"
                >
                  Edit
                </button>
                <button
                  onClick={() => remove(item.id)}
                  className="rounded-lg border border-slate-700/60 bg-slate-900/50 px-3 py-1.5 text-xs font-semibold text-red-300 hover:border-red-500/40 hover:text-red-200 transition"
                >
                  Remove
                </button>
              </div>
            </div>

            {/* Event Data Preview */}
            {item.event && (
              <details className="text-xs">
                <summary className="cursor-pointer text-muted hover:text-slate-200 transition">
                  Show Event Data
                </summary>
                <pre className="mt-2 max-h-[200px] overflow-auto rounded border border-slate-800 bg-slate-950/80 p-3 text-[11px]">
                  {JSON.stringify(item.event.event_data_json, null, 2)}
                </pre>
              </details>
            )}
          </Card>
        ))}
        {!loading && filtered.length === 0 && (
          <div className="empty-state text-center">
            {items.length === 0
              ? "No evidence collected yet. Right-click events and select \"Add to Forensics\" or press F on a selected event."
              : "No items match current filters."}
          </div>
        )}
      </div>

      {editing && (
        <EditModal item={editing} onClose={() => setEditing(null)} />
      )}
    </section>
  );
}
