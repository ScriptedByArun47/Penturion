import { scans } from "../data/mockData";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

export default function Scans() {
  return (
    <div className="card">
      <div className="toolbar">
        <button
          onClick={() =>
            alert("Simulated: scan start is not connected to the backend yet.")
          }
        >
          Start scan
        </button>
        <span className="muted">Simulated action</span>
      </div>
      <DataTable
        rows={scans}
        columns={[
          { header: "ID", render: (s) => s.id },
          { header: "Target", render: (s) => s.target },
          { header: "Status", render: (s) => <StatusBadge label={s.status} /> },
          { header: "Findings", render: (s) => s.findings },
          { header: "Started", render: (s) => s.started },
          { header: "Ended", render: (s) => s.ended ?? "-" },
        ]}
      />
    </div>
  );
}