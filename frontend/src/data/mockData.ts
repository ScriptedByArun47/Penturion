// Illustrative mock data only, not real scan results.
import type { Finding, Project, Report, Scan, Severity, Target } from "../types";

export const projects: Project[] = [
  { id: "PRJ-001", name: "Internal Web Apps", owner: "Alex", targets: 5, created: "2026-09-01" },
  { id: "PRJ-002", name: "Customer Portal", owner: "Sam", targets: 4, created: "2026-09-14" },
  { id: "PRJ-003", name: "Lab Network", owner: "Alex", targets: 3, created: "2026-10-02" },
];

export const targets: Target[] = [
  { id: "TGT-001", host: "demo.example.com", project: "Internal Web Apps", type: "Web" },
  { id: "TGT-002", host: "staging.example.com", project: "Customer Portal", type: "Web" },
  { id: "TGT-003", host: "10.0.0.15", project: "Lab Network", type: "Host" },
];

export const scans: Scan[] = [
  { id: "SCAN-001", target: "demo.example.com", status: "Completed", findings: 5, started: "2026-10-18 09:00", ended: "2026-10-18 09:42" },
  { id: "SCAN-002", target: "staging.example.com", status: "Running", findings: 2, started: "2026-10-18 10:10" },
  { id: "SCAN-003", target: "10.0.0.15", status: "Failed", findings: 0, started: "2026-10-17 15:30", ended: "2026-10-17 15:31" },
  { id: "SCAN-004", target: "demo.example.com", status: "Queued", findings: 0, started: "-" },
];

export const findings: Finding[] = [
  { id: "FND-001", title: "SQL injection in search parameter", severity: "Critical", target: "demo.example.com", status: "Open" },
  { id: "FND-002", title: "Outdated TLS configuration", severity: "High", target: "staging.example.com", status: "In Review" },
  { id: "FND-003", title: "Missing security headers", severity: "Medium", target: "demo.example.com", status: "Open" },
  { id: "FND-004", title: "Verbose server banner", severity: "Low", target: "10.0.0.15", status: "Resolved" },
  { id: "FND-005", title: "robots.txt exposes paths", severity: "Informational", target: "staging.example.com", status: "Open" },
];

export const reports: Report[] = [
  { id: "RPT-001", name: "Internal Web Apps - Q3", project: "Internal Web Apps", generated: "2026-10-01" },
  { id: "RPT-002", name: "Customer Portal - Initial", project: "Customer Portal", generated: "2026-10-10" },
];

export const severityOrder: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];

export const mockDashboard = {
  projects: projects.length,
  targets: targets.length,
  scans: scans.length,
  findings: findings.length,
  severity: severityOrder.map((name) => ({
    name,
    value: findings.filter((f) => f.severity === name).length,
  })),
  recentScans: scans.slice(0, 3),
  recentFindings: findings.slice(0, 3),
};