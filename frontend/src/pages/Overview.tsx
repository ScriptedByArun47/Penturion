import { mockDashboard as d } from "../data/mockData";
import OverviewCard from "../components/dashboard/OverviewCard";
import SeverityChart from "../components/dashboard/SeverityChart";
import RecentScans from "../components/dashboard/RecentScans";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

export default function Overview() {
  return (
    <>
      <div className="grid4">
        <OverviewCard label="Total projects" value={d.projects} />
        <OverviewCard label="Total targets" value={d.targets} />
        <OverviewCard label="Total scans" value={d.scans} />
        <OverviewCard label="Total findings" value={d.findings} />
      </div>

      <div className="grid2">
        <SeverityChart data={d.severity} />
        <RecentScans scans={d.recentScans} />
      </div>

      <div className="card">
        <h2>Recent findings</h2>
        <DataTable
          rows={d.recentFindings}
          columns={[
            { header: "Title", render: (f) => f.title },
            { header: "Severity", render: (f) => <StatusBadge label={f.severity} /> },
            { header: "Target", render: (f) => f.target },
          ]}
        />
      </div>
    </>
  );
}