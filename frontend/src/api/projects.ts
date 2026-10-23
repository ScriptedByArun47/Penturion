import { apiRequest } from "./client";
import { projects as mockProjects } from "../data/mockData";
import type { Project, ProjectCreate, ProjectUpdate } from "../types";

// Optional dev fallback: set VITE_USE_MOCK=true in .env to work without the backend.
export const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";

let mockStore: Project[] = [...mockProjects];

export async function listProjects(): Promise<Project[]> {
  if (USE_MOCK) return [...mockStore];
  return apiRequest<Project[]>("/projects");
}

export async function createProject(input: ProjectCreate): Promise<Project> {
  if (USE_MOCK) {
    const now = new Date().toISOString();
    const project: Project = {
      id: `mock-${Date.now()}`,
      name: input.name,
      description: input.description ?? null,
      status: "active",
      created_at: now,
      updated_at: now,
    };
    mockStore = [...mockStore, project];
    return project;
  }
  return apiRequest<Project>("/projects", { method: "POST", json: input });
}

export async function updateProject(id: string, input: ProjectUpdate): Promise<Project> {
  if (USE_MOCK) {
    const current = mockStore.find((p) => p.id === id);
    if (!current) throw new Error("Project not found.");
    const updated: Project = { ...current, ...input, updated_at: new Date().toISOString() } as Project;
    mockStore = mockStore.map((p) => (p.id === id ? updated : p));
    return updated;
  }
  return apiRequest<Project>(`/projects/${id}`, { method: "PATCH", json: input });
}

export async function deleteProject(id: string): Promise<void> {
  if (USE_MOCK) {
    mockStore = mockStore.filter((p) => p.id !== id);
    return;
  }
  return apiRequest<void>(`/projects/${id}`, { method: "DELETE" });
}