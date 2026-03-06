import { ReactNode } from "react";

export function Card({
  children,
  className = ""
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`glass border border-slate-800/60 ${className}`.trim()}
    >
      {children}
    </div>
  );
}
