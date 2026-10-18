import { apiRequest } from "./client";
import { findings } from "../data/mockData";
import type { Finding } from "../types";

const USE_MOCK = true; // set to false once /findings exists

export async function listFindings(): Promise<Finding[]> {
  return USE_MOCK ? findings : apiRequest<Finding[]>("/findings");
}