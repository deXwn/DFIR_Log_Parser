"use client";

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset
}: {
  error: Error;
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <html>
      <body className="app-body p-6 md:p-10">
        <div className="ambient-orbs" aria-hidden="true">
          <div className="ambient-orb one" />
          <div className="ambient-orb two" />
          <div className="ambient-orb three" />
        </div>
        <div className="mx-auto max-w-3xl glass hero-panel">
          <div className="eyebrow">System Fault</div>
          <div className="page-copy">
            <h1 className="page-title">The EVTX workspace hit an unrecoverable error</h1>
            <p className="page-subtitle">
              The UI is still responsive, but the current route could not complete. Review the
              error below and retry the module.
            </p>
          </div>
          <div className="empty-state">
            <div className="metric-label">Error Message</div>
            <div className="mt-3 text-sm text-danger">{error.message}</div>
          </div>
          <button
            onClick={reset}
            className="action-btn primary w-fit"
          >
            Try again
          </button>
        </div>
      </body>
    </html>
  );
}
