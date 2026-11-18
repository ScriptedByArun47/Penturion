import { apiRequest } from "./client";
import type { Scan, ScanCreate } from "../types";

export const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";

let mockScans: Scan[] = [
  {
    id: "scan-mock-1",
    target_id: "tgt-001",
    requested_by: "usr-001",
    status: "completed",
    scan_type: "web",
    error_message: null,
    created_at: new Date(Date.now() - 3600000).toISOString(),
    started_at: new Date(Date.now() - 3500000).toISOString(),
    completed_at: new Date(Date.now() - 3000000).toISOString(),
  },
  {
    id: "scan-mock-2",
    target_id: "tgt-002",
    requested_by: "usr-001",
    status: "queued",
    scan_type: "web",
    error_message: null,
    created_at: new Date().toISOString(),
    started_at: null,
    completed_at: null,
  },
];

export async function listScans(): Promise<Scan[]> {
  if (USE_MOCK) return [...mockScans];
  return apiRequest<Scan[]>("/scans");
}

export async function createScan(input: ScanCreate): Promise<Scan> {
  if (USE_MOCK) {
    const newScan: Scan = {
      id: `scan-mock-${Date.now()}`,
      target_id: input.target_id,
      requested_by: "usr-current",
      status: "queued",
      scan_type: input.scan_type ?? "web",
      error_message: null,
      created_at: new Date().toISOString(),
      started_at: null,
      completed_at: null,
    };
    mockScans = [newScan, ...mockScans];
    return newScan;
  }
  return apiRequest<Scan>("/scans", {
    method: "POST",
    json: input,
  });
}

export async function getScan(id: string): Promise<Scan> {
  if (USE_MOCK) {
    const found = mockScans.find((s) => s.id === id);
    if (!found) throw new Error("Scan not found.");
    return found;
  }
  return apiRequest<Scan>(`/scans/${id}`);
}
