import { useEffect, useState } from "react";

const base = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

export default function Settings() {
  const [status, setStatus] = useState("Checking...");

  useEffect(() => {
    fetch(base.replace(/\/api\/v1$/, "") + "/docs", { method: "HEAD" })
      .then((r) => setStatus(r.ok ? "Reachable" : `Responded ${r.status}`))
      .catch(() => setStatus("Not reachable"));
  }, []);

  return (
    <div className="card">
      <h2>API connection</h2>
      <p>
        <span className="muted">Base URL:</span> {base}
      </p>
      <p>
        <span className="muted">Status:</span> {status}
      </p>
    </div>
  );
}