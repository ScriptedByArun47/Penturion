import { useCallback, useEffect, useState, type FormEvent } from "react";
import { createProject, deleteProject, listProjects, updateProject, USE_MOCK } from "../api/projects";
import type { Project, ProjectStatus } from "../types";
import DataTable from "../components/common/DataTable";

const STATUSES: ProjectStatus[] = ["active", "inactive", "archived"];

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong.";
}

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setProjects(await listProjects());
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setError(null);
    setNotice(null);
    try {
      const created = await createProject({
        name: name.trim(),
        description: description.trim() || null,
      });
      setProjects((prev) => [...prev, created]);
      setName("");
      setDescription("");
      setNotice(`Project "${created.name}" created.`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  const onStatusChange = async (project: Project, status: ProjectStatus) => {
    setError(null);
    setNotice(null);
    try {
      const updated = await updateProject(project.id, { status });
      setProjects((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
      setNotice(`"${updated.name}" is now ${updated.status}.`);
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const onDelete = async (project: Project) => {
    if (!window.confirm(`Delete project "${project.name}"? This cannot be undone.`)) return;
    setError(null);
    setNotice(null);
    try {
      await deleteProject(project.id);
      setProjects((prev) => prev.filter((p) => p.id !== project.id));
      setNotice(`Project "${project.name}" deleted.`);
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  return (
    <div className="card">
      <form className="toolbar" onSubmit={onCreate}>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Project name"
          maxLength={150}
          required
        />
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Description (optional)"
          maxLength={5000}
        />
        <button type="submit" disabled={creating}>
          {creating ? "Creating..." : "Create project"}
        </button>
        {USE_MOCK && <span className="muted">Mock mode: nothing is saved to the backend</span>}
      </form>

      {notice && <div className="notice" role="status">{notice}</div>}
      {error && (
        <div className="error" role="alert">
          {error} <button className="btn-ghost" onClick={() => void load()}>Retry</button>
        </div>
      )}

      {loading ? (
        <div className="empty">Loading projects...</div>
      ) : (
        <DataTable
          rows={projects}
          columns={[
            { header: "Name", render: (p) => p.name },
            { header: "Description", render: (p) => p.description ?? "-" },
            {
              header: "Status",
              render: (p) => (
                <select
                  value={p.status}
                  onChange={(e) => void onStatusChange(p, e.target.value as ProjectStatus)}
                  aria-label={`Status of ${p.name}`}
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              ),
            },
            { header: "Created", render: (p) => p.created_at.slice(0, 10) },
            {
              header: "",
              render: (p) => (
                <button className="btn-danger" onClick={() => void onDelete(p)}>Delete</button>
              ),
            },
          ]}
        />
      )}
    </div>
  );
}