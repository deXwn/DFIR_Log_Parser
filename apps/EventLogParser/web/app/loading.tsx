export default function Loading() {
  return (
    <div className="glass hero-panel">
      <div className="eyebrow">Workspace Status</div>
      <div className="page-copy">
        <h1 className="page-title">Preparing EVTX workspace</h1>
        <p className="page-subtitle">
          Loading modules, hydrating query state, and restoring the analyst surface.
        </p>
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="metric-card">
          <div className="metric-label">State</div>
          <div className="metric-value">Loading data</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Query Layer</div>
          <div className="metric-value">Reconnecting</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Interface</div>
          <div className="metric-value">Bootstrapping</div>
        </div>
      </div>
    </div>
  );
}
