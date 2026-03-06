import "./globals.css";
import "../styles/print.css";
import Sidebar from "../components/sidebar";
import { ReactQueryProvider } from "../components/react-query-provider";
import TopHeader from "../components/top-header";
import NavHotkeys from "../components/nav-hotkeys";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "EVTX Forensics",
  description: "High-speed Windows event log analysis"
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100">
        <ReactQueryProvider>
          <div className="min-h-screen flex">
            <Sidebar />
            <div className="flex-1 flex flex-col">
              <NavHotkeys />
              <TopHeader />
              <main className="flex-1 p-6 md:p-10 space-y-6">{children}</main>
            </div>
          </div>
        </ReactQueryProvider>
      </body>
    </html>
  );
}
