import { apiRequest } from "./client";
import { reports } from "../data/mockData";
import type { Report } from "../types";

const USE_MOCK = true; // set to false once /reports exists

export async function listReports(): Promise<Report[]> {
  return USE_MOCK ? reports : apiRequest<Report[]>("/reports");
}