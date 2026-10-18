import { findings } from "../data/mockData";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

export default function Findings() {
  return (
    <div className="card">
      <DataTable
        rows={findings}
        columns={[
          { header: "ID", render: (f) => f.id },
          { header: "Title", render: (f) => f.title },
          { header: "Severity", render: (f) => <StatusBadge label={f.severity} /> },
          { header: "Target", render: (f) => f.target },
          { header: "Status", render: (f) => <StatusBadge label={f.status} /> },
        ]}
      />
    </div>
  );
}