import { useState } from "react";
import { projects as seed } from "../data/mockData";
import type { Project } from "../types";
import DataTable from "../components/common/DataTable";

export default function Projects() {
  const [rows, setRows] = useState<Project[]>(seed);
  const [name, setName] = useState("");

  const add = () => {
    if (!name.trim()) return;
    const id = `PRJ-${String(rows.length + 1).padStart(3, "0")}`;
    setRows([
      ...rows,
      { id, name, owner: "You", targets: 0, created: new Date().toISOString().slice(0, 10) },
    ]);
    setName("");
  };

  return (
    <div className="card">
      <div className="toolbar">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="New project name"
        />
        <button onClick={add}>Create project</button>
        <span className="muted">Simulated: not saved to the backend</span>
      </div>
      <DataTable
        rows={rows}
        columns={[
          { header: "ID", render: (p) => p.id },
          { header: "Name", render: (p) => p.name },
          { header: "Owner", render: (p) => p.owner },
          { header: "Targets", render: (p) => p.targets },
          { header: "Created", render: (p) => p.created },
        ]}
      />
    </div>
  );
}