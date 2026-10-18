import { targets } from "../data/mockData";
import DataTable from "../components/common/DataTable";

export default function Targets() {
  return (
    <div className="card">
      <DataTable
        rows={targets}
        columns={[
          { header: "ID", render: (t) => t.id },
          { header: "Host", render: (t) => t.host },
          { header: "Project", render: (t) => t.project },
          { header: "Type", render: (t) => t.type },
        ]}
      />
    </div>
  );
}