import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { createScan, listScans } from "../api/scans";
import { listProjects } from "../api/projects";
import { listTargets } from "../api/targets";
import { listAuthorizationRequests } from "../api/authorization";
import type { AuthorizationRequest, Project, Scan, Target } from "../types";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong.";
}

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [requests, setRequests] = useState<AuthorizationRequest[]>([]);

  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [selectedRequestId, setSelectedRequestId] = useState<string>("");

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [scanList, projectList, requestList] = await Promise.all([
        listScans(),
        listProjects(),
        listAuthorizationRequests(),
      ]);

      const targetLists = await Promise.all(
        projectList.map((p) => listTargets(p.id).catch(() => [] as Target[])),
      );
      const allTargets = targetLists.flat();

      setScans(scanList);
      setProjects(projectList);
      setTargets(allTargets);
      setRequests(requestList);

      const approved = requestList.filter((r) => r.status === "approved");
      setSelectedRequestId((prev) => (prev && approved.some((r) => r.id === prev) ? prev : approved[0]?.id ?? ""));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const approvedRequests = useMemo(() => {
    return requests.filter((r) => r.status === "approved");
  }, [requests]);

  const targetMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const t of targets) {
      const proj = projects.find((p) => p.id === t.project_id)?.name ?? "unknown project";
      map.set(t.id, `${t.value} (${proj})`);
    }
    return map;
  }, [targets, projects]);

  const onStartScan = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedRequestId) return;

    const authReq = approvedRequests.find((r) => r.id === selectedRequestId);
    if (!authReq) {
      setError("Please select a valid approved authorization.");
      return;
    }

    setCreating(true);
    setError(null);
    setNotice(null);

    try {
      const newScan = await createScan({
        target_id: authReq.target_id,
        authorization_request_id: authReq.id,
        scan_type: "web",
      });

      setScans((prev) => [newScan, ...prev]);
      setNotice(`Scan successfully queued (ID: ${newScan.id.slice(0, 8)}).`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="empty">Loading scans...</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Authorized Scans</h2>

      <form className="toolbar" onSubmit={onStartScan}>
        {approvedRequests.length > 0 ? (
          <>
            <select
              value={selectedRequestId}
              onChange={(e) => setSelectedRequestId(e.target.value)}
              aria-label="Approved authorization target"
              disabled={creating}
            >
              {approvedRequests.map((req) => (
                <option key={req.id} value={req.id}>
                  Target: {targetMap.get(req.target_id) ?? req.target_id} — Scope: {req.requested_scope}
                </option>
              ))}
            </select>
            <button type="submit" disabled={creating || !selectedRequestId}>
              {creating ? "Queueing..." : "Start scan"}
            </button>
          </>
        ) : (
          <span className="muted">
            No approved authorizations available. Authorize a target before launching a scan.
          </span>
        )}
      </form>

      {notice && <div className="notice" role="status">{notice}</div>}
      {error && <div className="error" role="alert">{error}</div>}

      <DataTable
        rows={scans}
        columns={[
          { header: "ID", render: (s) => s.id.slice(0, 8) },
          { header: "Target", render: (s) => targetMap.get(s.target_id) ?? s.target_id },
          { header: "Type", render: (s) => s.scan_type },
          { header: "Status", render: (s) => <StatusBadge label={s.status} /> },
          {
            header: "Created",
            render: (s) => (s.created_at ? s.created_at.slice(0, 16).replace("T", " ") : "-"),
          },
          {
            header: "Started",
            render: (s) => (s.started_at ? s.started_at.slice(0, 16).replace("T", " ") : "-"),
          },
          {
            header: "Completed",
            render: (s) => (s.completed_at ? s.completed_at.slice(0, 16).replace("T", " ") : "-"),
          },
          {
            header: "Error",
            render: (s) => s.error_message ?? "-",
          },
        ]}
      />
    </div>
  );
}
