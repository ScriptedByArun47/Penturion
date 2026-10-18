import type { ReactNode } from "react";
import EmptyState from "./EmptyState";

export interface Column<T> {
  header: string;
  render: (row: T) => ReactNode;
}

export default function DataTable<T extends { id: string }>({
  columns,
  rows,
}: {
  columns: Column<T>[];
  rows: T[];
}) {
  if (rows.length === 0) return <EmptyState message="Nothing here yet." />;

  return (
    <table className="table">
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c.header}>{c.header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id}>
            {columns.map((c) => (
              <td key={c.header}>{c.render(r)}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}