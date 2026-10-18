import { apiRequest } from "./client";
import { scans } from "../data/mockData";
import type { Scan } from "../types";

const USE_MOCK = true; // set to false once /scans exists

export async function listScans(): Promise<Scan[]> {
  return USE_MOCK ? scans : apiRequest<Scan[]>("/scans");
}