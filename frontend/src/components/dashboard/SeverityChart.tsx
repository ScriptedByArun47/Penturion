import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const colors: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#3b82f6",
  Informational: "#94a3b8",
};

export default function SeverityChart({
  data,
}: {
  data: { name: string; value: number }[];
}) {
  return (
    <div className="card">
      <h2>Findings by severity</h2>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2a3441" />
          <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
          <YAxis allowDecimals={false} stroke="#94a3b8" fontSize={12} />
          <Tooltip
            contentStyle={{ background: "#151c26", border: "1px solid #2a3441" }}
          />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {data.map((d) => (
              <Cell key={d.name} fill={colors[d.name]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}