import { useEffect, useState, type FormEvent } from "react";
import { listProjects } from "../api/projects";
import { createTarget, deleteTarget, listTargets } from "../api/targets";
import type { Project, Target, TargetType } from "../types";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";

const TYPES: TargetType[] = ["domain", "ip", "url"];

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong.";
}

export default function Targets() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [targets, setTargets] = useState<Target[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [loadingTargets, setLoadingTargets] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [value, setValue] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("domain");
  const [notes, setNotes] = useState("");
  const [creating, setCreating] = useState(false);

  // Load projects once, then select the first one.
  useEffect(() => {
    let cancelled = false;
    listProjects()
      .then((list) => {
        if (cancelled) return;
        setProjects(list);
        if (list.length > 0) setProjectId(list[0].id);
      })
      .catch((err) => !cancelled && setError(errorMessage(err)))
      .finally(() => !cancelled && setLoadingProjects(false));
    return () => {
      cancelled = true;
    };
  }, []);

  // Load targets whenever the selected project changes.
  useEffect(() => {
    if (!projectId) return;
    let cancelled = false;
    setLoadingTargets(true);
    setError(null);
    listTargets(projectId)
      .then((list) => !cancelled && setTargets(list))
      .catch((err) => !cancelled && setError(errorMessage(err)))
      .finally(() => !cancelled && setLoadingTargets(false));
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    if (!value.trim() || !projectId) return;
    setCreating(true);
    setError(null);
    setNotice(null);
    try {
      const created = await createTarget(projectId, {
        value: value.trim(),
        target_type: targetType,
        notes: notes.trim() || null,
      });
      setTargets((prev) => [...prev, created]);
      setValue("");
      setNotes("");
      setNotice(`Target "${created.value}" added. Its authorization status is ${created.authorization_status}.`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  const onDelete = async (target: Target) => {
    if (!window.confirm(`Delete target "${target.value}"? This cannot be undone.`)) return;
    setError(null);
    setNotice(null);
    try {
      await deleteTarget(target.id);
      setTargets((prev) => prev.filter((t) => t.id !== target.id));
      setNotice(`Target "${target.value}" deleted.`);
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  if (loadingProjects) return <div className="card"><div className="empty">Loading...</div></div>;

  if (projects.length === 0) {
    return (
      <div className="card">
        {error && <div className="error" role="alert">{error}</div>}
        <div className="empty">Create a project first, then add targets to it.</div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="toolbar">
        <label className="muted" htmlFor="project-select">Project</label>
        <select id="project-select" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
      </div>

      <form className="toolbar" onSubmit={onCreate}>
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="example.com, 203.0.113.10 or https://..."
          maxLength={253}
          required
        />
        <select
          value={targetType}
          onChange={(e) => setTargetType(e.target.value as TargetType)}
          aria-label="Target type"
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Notes (optional)"
          maxLength={5000}
        />
        <button type="submit" disabled={creating}>{creating ? "Adding..." : "Add target"}</button>
      </form>

      {notice && <div className="notice" role="status">{notice}</div>}
      {error && <div className="error" role="alert">{error}</div>}

      {loadingTargets ? (
        <div className="empty">Loading targets...</div>
      ) : (
        <DataTable
          rows={targets}
          columns={[
            { header: "Value", render: (t) => t.value },
            { header: "Type", render: (t) => t.target_type },
            { header: "Authorization", render: (t) => <StatusBadge label={t.authorization_status} /> },
            { header: "Notes", render: (t) => t.notes ?? "-" },
            { header: "Added", render: (t) => t.created_at.slice(0, 10) },
            {
              header: "",
              render: (t) => (
                <button className="btn-danger" onClick={() => void onDelete(t)}>Delete</button>
              ),
            },
          ]}
        />
      )}
    </div>
  );
}