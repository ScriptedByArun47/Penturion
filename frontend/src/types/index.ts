//This file defines the data shapes every other file imports.

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type ScanStatus = "Completed" | "Running" | "Failed" | "Queued";
export type FindingStatus = "Open" | "In Review" | "Resolved";

export interface Project {
  id: string;
  name: string;
  owner: string;
  targets: number;
  created: string;
}

export interface Target {
  id: string;
  host: string;
  project: string;
  type: string;
}

export interface Scan {
  id: string;
  target: string;
  status: ScanStatus;
  findings: number;
  started: string;
  ended?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  target: string;
  status: FindingStatus;
}

export interface Report {
  id: string;
  name: string;
  project: string;
  generated: string;
}