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
      <body className="bg-slate-950 text-slate-100 p-8">
        <div className="max-w-xl mx-auto glass p-6 border border-slate-800/60">
          <h1 className="text-lg font-semibold mb-2">Something went wrong</h1>
          <div className="text-sm text-danger">{error.message}</div>
          <button
            onClick={reset}
            className="mt-4 px-4 py-2 rounded-lg bg-accent/80 text-slate-900 text-sm font-semibold hover:bg-accent transition"
          >
            Try again
          </button>
        </div>
      </body>
    </html>
  );
}
