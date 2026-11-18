import { useEffect, useMemo, useState } from "react";
import { listProjects } from "../api/projects";
import { listTargets } from "../api/targets";
import { listAuthorizationRequests } from "../api/authorization";
import { listScans } from "../api/scans";
import { mockDashboard as sample } from "../data/mockData";
import type { AuthorizationRequest, Project, Scan, Target } from "../types";
import OverviewCard from "../components/dashboard/OverviewCard";
import SeverityChart from "../components/dashboard/SeverityChart";
import RecentScans from "../components/dashboard/RecentScans";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

export default function Overview() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [requests, setRequests] = useState<AuthorizationRequest[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [projectList, requestList, scanList] = await Promise.all([
          listProjects(),
          listAuthorizationRequests(),
          listScans().catch(() => [] as Scan[]),
        ]);
        const targetLists = await Promise.all(
          projectList.map((p) => listTargets(p.id).catch(() => [] as Target[])),
        );
        if (cancelled) return;
        setProjects(projectList);
        setTargets(targetLists.flat());
        setRequests(requestList);
        setScans(scanList);
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

  const targetMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const t of targets) {
      map.set(t.id, t.value);
    }
    return map;
  }, [targets]);

  if (loading) return <div className="card"><div className="empty">Loading dashboard...</div></div>;

  const pending = requests.filter((r) => r.status === "pending").length;
  const authorizedTargets = targets.filter((t) => t.authorization_status === "approved").length;
  const recentRequests = [...requests]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 5);

  const displayScans = scans.length > 0 ? scans.slice(0, 5) : sample.recentScans;

  return (
    <>
      {error && <div className="error" role="alert">{error}</div>}

      <div className="grid4">
        <OverviewCard label="Projects" value={projects.length} />
        <OverviewCard label="Authorized Targets" value={`${authorizedTargets} / ${targets.length}`} />
        <OverviewCard label="Pending Authorizations" value={pending} />
        <OverviewCard label="Total Scans" value={scans.length} />
      </div>

      <div className="card">
        <h2>Recent authorization requests</h2>
        <DataTable
          rows={recentRequests}
          columns={[
            {
              header: "Target",
              render: (r) => targetMap.get(r.target_id) ?? r.target_id,
            },
            { header: "Status", render: (r) => <StatusBadge label={r.status} /> },
            { header: "Requested by", render: (r) => r.requested_by },
            { header: "Created", render: (r) => r.created_at.slice(0, 10) },
          ]}
        />
      </div>

      <p className="muted">
        Vulnerability findings and severity distributions remain simulated until findings integration (Roadmap Module 22).
      </p>
      <div className="grid2">
        <div className="sample">
          <SeverityChart data={sample.severity} />
        </div>
        <RecentScans scans={displayScans} targetMap={targetMap} />
      </div>
    </>
  );
}
