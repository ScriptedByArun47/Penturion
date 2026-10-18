import { apiRequest } from "./client";
import { projects } from "../data/mockData";
import type { Project } from "../types";

const USE_MOCK = true; // set to false once /projects exists

export async function listProjects(): Promise<Project[]> {
  return USE_MOCK ? projects : apiRequest<Project[]>("/projects");
}