import type { Scan } from "../../types";
import DataTable from "../common/DataTable";
import StatusBadge from "../common/StatusBadge";

export default function RecentScans({ scans }: { scans: Scan[] }) {
  return (
    <div className="card">
      <h2>Recent scans</h2>
      <DataTable
        rows={scans}
        columns={[
          { header: "ID", render: (s) => s.id },
          { header: "Target", render: (s) => s.target },
          { header: "Status", render: (s) => <StatusBadge label={s.status} /> },
          { header: "Findings", render: (s) => s.findings },
        ]}
      />
    </div>
  );
}