import { reports } from "../data/mockData";
import DataTable from "../components/common/DataTable";

export default function Reports() {
  return (
    <div className="card">
      <DataTable
        rows={reports}
        columns={[
          { header: "ID", render: (r) => r.id },
          { header: "Name", render: (r) => r.name },
          { header: "Project", render: (r) => r.project },
          { header: "Generated", render: (r) => r.generated },
          {
            header: "",
            render: () => (
              <button onClick={() => alert("Simulated download")}>Download</button>
            ),
          },
        ]}
      />
    </div>
  );
}