export default function StatusBadge({ label }: { label: string }) {
  return (
    <span className={`badge badge-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      {label}
    </span>
  );
}