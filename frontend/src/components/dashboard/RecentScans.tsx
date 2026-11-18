import type { MockScan, Scan } from "../../types";
import DataTable from "../common/DataTable";
import StatusBadge from "../common/StatusBadge";

export default function RecentScans({
  scans,
  targetMap,
}: {
  scans: (Scan | MockScan)[];
  targetMap?: Map<string, string>;
}) {
  return (
    <div className="card">
      <h2>Recent scans</h2>
      <DataTable
        rows={scans}
        columns={[
          { header: "ID", render: (s) => s.id.slice(0, 8) },
          {
            header: "Target",
            render: (s) =>
              "target" in s
                ? s.target
                : (targetMap?.get(s.target_id) ?? s.target_id.slice(0, 8)),
          },
          { header: "Status", render: (s) => <StatusBadge label={s.status} /> },
          {
            header: "Info",
            render: (s) =>
              "findings" in s
                ? `${s.findings} findings`
                : s.scan_type,
          },
        ]}
      />
    </div>
  );
}
