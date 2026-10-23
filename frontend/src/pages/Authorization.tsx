import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { listProjects } from "../api/projects";
import { listTargets } from "../api/targets";
import {
  createAuthorizationRequest,
  listAuthorizationRequests,
  reviewAuthorizationRequest,
} from "../api/authorization";
import type { AuthorizationRequest, Project, Target } from "../types";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong.";
}

export default function Authorization() {
  const { user, isReviewer } = useAuth();

  const [projects, setProjects] = useState<Project[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [requests, setRequests] = useState<AuthorizationRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [targetId, setTargetId] = useState("");
  const [evidence, setEvidence] = useState("");
  const [scope, setScope] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [projectList, requestList] = await Promise.all([
        listProjects(),
        listAuthorizationRequests(),
      ]);
      const targetLists = await Promise.all(projectList.map((p) => listTargets(p.id)));
      const allTargets = targetLists.flat();
      setProjects(projectList);
      setTargets(allTargets);
      setRequests(requestList);
      setTargetId((prev) => prev || allTargets[0]?.id || "");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const targetLabels = useMemo(() => {
    const map = new Map<string, string>();
    for (const t of targets) {
      const project = projects.find((p) => p.id === t.project_id)?.name ?? "unknown project";
      map.set(t.id, `${t.value} (${project})`);
    }
    return map;
  }, [targets, projects]);

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    if (!user || !targetId) return;
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      const created = await createAuthorizationRequest({
        target_id: targetId,
        evidence_reference: evidence.trim(),
        requested_scope: scope.trim(),
        requested_by: user.email, // TODO: remove once the backend derives it from the token
      });
      setRequests((prev) => [...prev, created]);
      setEvidence("");
      setScope("");
      setNotice("Authorization request submitted. It is pending review.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  const onReview = async (request: AuthorizationRequest, status: "approved" | "rejected") => {
    const reason = window.prompt(`Reason for marking this request as ${status}:`);
    if (!reason || !reason.trim()) return;
    setError(null);
    setNotice(null);
    try {
      await reviewAuthorizationRequest(request.id, { status, review_reason: reason.trim() });
      setNotice(`Request ${status}.`);
      await load(); // refresh so the target's authorization status is current too
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  if (loading) return <div className="card"><div className="empty">Loading...</div></div>;

  return (
    <div className="card">
      {targets.length === 0 ? (
        <div className="empty">Add a target first, then request authorization for it.</div>
      ) : (
        <form className="toolbar" onSubmit={onCreate}>
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)} aria-label="Target">
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{targetLabels.get(t.id)}</option>
            ))}
          </select>
          <input
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            placeholder="Evidence reference (e.g. signed scope letter ID)"
            maxLength={500}
            required
          />
          <input
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="Requested scope"
            maxLength={10000}
            required
          />
          <button type="submit" disabled={submitting}>
            {submitting ? "Submitting..." : "Request authorization"}
          </button>
        </form>
      )}

      {notice && <div className="notice" role="status">{notice}</div>}
      {error && <div className="error" role="alert">{error}</div>}

      <DataTable
        rows={requests}
        columns={[
          { header: "Target", render: (r) => targetLabels.get(r.target_id) ?? r.target_id },
          { header: "Status", render: (r) => <StatusBadge label={r.status} /> },
          { header: "Scope", render: (r) => r.requested_scope },
          { header: "Evidence", render: (r) => r.evidence_reference },
          { header: "Requested by", render: (r) => r.requested_by },
          { header: "Review", render: (r) => r.review_reason ?? "-" },
          {
            header: "",
            render: (r) =>
              isReviewer && r.status === "pending" ? (
                <span className="toolbar">
                  <button onClick={() => void onReview(r, "approved")}>Approve</button>
                  <button className="btn-danger" onClick={() => void onReview(r, "rejected")}>
                    Reject
                  </button>
                </span>
              ) : null,
          },
        ]}
      />
    </div>
  );
}