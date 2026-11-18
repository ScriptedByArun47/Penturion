export default function OverviewCard({
  label,
  value,
}: {
  label: string;
  value: number | string;
}) {
  return (
    <div className="card stat">
      <span className="muted">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}