import { Card } from "../ui/card";

export default function HomePage() {
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold">EVTX DFIR Dashboard</h1>
      <Card className="p-6 md:p-8 space-y-4">
        <p className="text-slate-300">
          Ingest Windows EVTX logs, search them, and accelerate DFIR investigations
          with timeline and detection rules. Available capabilities:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
          <div className="space-y-2">
            <h3 className="font-semibold">Ingest</h3>
            <p>Load EVTX files from the UI or the `/ingest` API; fast listing and thread selection.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Events</h3>
            <p>Virtualized table for 100k+ records; EventID, user, SID, IP, channel, keyword, and time filters with side details.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Process Tree</h3>
            <p>4688/Sysmon process relationships; LOLBin/suspicious nodes are highlighted with click-to-inspect details.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Stats</h3>
            <p>EventID/Channel/Source/User distributions; filter by ingest path to view log-specific statistics.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Timeline</h3>
            <p>D3 histogram with zoom/pan; click a bar to apply a time-range filter in Events.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Search</h3>
            <p>FTS5 full-text search; LogonType/IP filters; expandable cards show JSON/Raw XML.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Report</h3>
            <p>Generate HTML/PDF reports with summary, timeline, key events, and suspicious findings including case/analyst metadata.</p>
          </div>
          <div className="space-y-2">
            <h3 className="font-semibold">Detections</h3>
            <p>YAML/JSON rule engine; EventID/channel/user/ip/process/logon_type conditions with detailed matched events.</p>
          </div>
        </div>
      </Card>
    </section>
  );
}
