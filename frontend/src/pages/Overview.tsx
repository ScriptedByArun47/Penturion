import { useEffect, useState } from "react";
import { listProjects } from "../api/projects";
import { listTargets } from "../api/targets";
import { listAuthorizationRequests } from "../api/authorization";
import { mockDashboard as sample } from "../data/mockData";
import type { AuthorizationRequest, Project, Target } from "../types";
import OverviewCard from "../components/dashboard/OverviewCard";
import SeverityChart from "../components/dashboard/SeverityChart";
import RecentScans from "../components/dashboard/RecentScans";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

export default function Overview() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [requests, setRequests] = useState<AuthorizationRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [projectList, requestList] = await Promise.all([
          listProjects(),
          listAuthorizationRequests(),
        ]);
        const targetLists = await Promise.all(projectList.map((p) => listTargets(p.id)));
        if (cancelled) return;
        setProjects(projectList);
        setTargets(targetLists.flat());
        setRequests(requestList);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load dashboard.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <div className="card"><div className="empty">Loading dashboard...</div></div>;

  const pending = requests.filter((r) => r.status === "pending").length;
  const approvedTargets = targets.filter((t) => t.authorization_status === "approved").length;
  const recent = [...requests]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 5);

  return (
    <>
      {error && <div className="error" role="alert">{error}</div>}

      <div className="grid4">
        <OverviewCard label="Projects" value={projects.length} />
        <OverviewCard label="Targets" value={targets.length} />
        <OverviewCard label="Pending authorization requests" value={pending} />
        <OverviewCard label="Authorized targets" value={approvedTargets} />
      </div>

      <div className="card">
        <h2>Recent authorization requests</h2>
        <DataTable
          rows={recent}
          columns={[
            {
              header: "Target",
              render: (r) => targets.find((t) => t.id === r.target_id)?.value ?? r.target_id,
            },
            { header: "Status", render: (r) => <StatusBadge label={r.status} /> },
            { header: "Requested by", render: (r) => r.requested_by },
            { header: "Created", render: (r) => r.created_at.slice(0, 10) },
          ]}
        />
      </div>

      <p className="muted">
        Sample data below: scans and findings are not connected to the backend yet.
      </p>
      <div className="grid2 sample">
        <SeverityChart data={sample.severity} />
        <RecentScans scans={sample.recentScans} />
      </div>
    </>
  );
}