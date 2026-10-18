import { apiRequest } from "./client";
import { targets } from "../data/mockData";
import type { Target } from "../types";

const USE_MOCK = true; // set to false once /targets exists

export async function listTargets(): Promise<Target[]> {
  return USE_MOCK ? targets : apiRequest<Target[]>("/targets");
}