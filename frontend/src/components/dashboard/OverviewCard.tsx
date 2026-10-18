export default function OverviewCard({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="card stat">
      <span className="muted">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}