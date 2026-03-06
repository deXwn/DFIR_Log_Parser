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
      <body className="app-body">
        <ReactQueryProvider>
          <div className="app-shell">
            <Sidebar />
            <div className="app-main">
              <NavHotkeys />
              <TopHeader />
              <main className="flex-1 px-4 pb-8 pt-6 md:px-8 md:pb-10">
                <div className="content-shell space-y-6">{children}</div>
              </main>
            </div>
          </div>
        </ReactQueryProvider>
      </body>
    </html>
  );
}
