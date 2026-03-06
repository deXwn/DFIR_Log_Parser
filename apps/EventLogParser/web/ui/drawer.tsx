import { ReactNode } from "react";

export function Drawer({
  open,
  onClose,
  children
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex">
      <div
        className="flex-1 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        role="presentation"
      />
      <div className="w-full max-w-xl h-full bg-panel border-l border-slate-800/80 p-6 overflow-y-auto shadow-2xl">
        {children}
      </div>
    </div>
  );
}
