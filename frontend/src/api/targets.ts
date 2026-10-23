import { apiRequest } from "./client";
import { USE_MOCK } from "./projects";
import { targets as mockTargets } from "../data/mockData";
import type { Target, TargetCreate } from "../types";

let mockStore: Target[] = [...mockTargets];

export async function listTargets(projectId: string): Promise<Target[]> {
  if (USE_MOCK) return mockStore.filter((t) => t.project_id === projectId);
  return apiRequest<Target[]>(`/projects/${projectId}/targets`);
}

export async function createTarget(projectId: string, input: TargetCreate): Promise<Target> {
  if (USE_MOCK) {
    const target: Target = {
      id: `mock-${Date.now()}`,
      project_id: projectId,
      value: input.value,
      target_type: input.target_type,
      authorization_status: "pending",
      notes: input.notes ?? null,
      created_at: new Date().toISOString(),
    };
    mockStore = [...mockStore, target];
    return target;
  }
  return apiRequest<Target>(`/projects/${projectId}/targets`, { method: "POST", json: input });
}

export async function deleteTarget(id: string): Promise<void> {
  if (USE_MOCK) {
    mockStore = mockStore.filter((t) => t.id !== id);
    return;
  }
  return apiRequest<void>(`/targets/${id}`, { method: "DELETE" });
}