"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

const shortcuts: Record<string, string> = {
  ge: "/events",
  gp: "/processes",
  gt: "/timeline",
  gs: "/stats",
  gq: "/search",
  gf: "/forensics",
  gd: "/"
};

export default function NavHotkeys() {
  const router = useRouter();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target && (e.target as HTMLElement).tagName === "INPUT") return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const key = `${e.key}${e.code === "KeyG" ? "" : ""}`; // placeholder
      // Simple two-key nav: press g then another key
      if (e.key.toLowerCase() === "g") {
        let buffer = "g";
        const listener = (ev: KeyboardEvent) => {
          const combo = `${buffer}${ev.key.toLowerCase()}`;
          const dest = shortcuts[combo];
          if (dest) {
            ev.preventDefault();
            router.push(dest);
          }
          window.removeEventListener("keydown", listener);
        };
        window.addEventListener("keydown", listener, { once: true });
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [router]);

  return null;
}
