// Illustrative mock data only, not real scan results.
import type { Finding, Project, Report, Scan, Severity, Target } from "../types";

export const projects: Project[] = [
  { id: "prj-001", name: "Internal Web Apps", description: "Quarterly assessment of internal tools", status: "active", created_at: "2026-09-01T09:00:00Z", updated_at: "2026-09-01T09:00:00Z" },
  { id: "prj-002", name: "Customer Portal", description: null, status: "active", created_at: "2026-09-14T09:00:00Z", updated_at: "2026-09-14T09:00:00Z" },
  { id: "prj-003", name: "Lab Network", description: "Practice environment", status: "archived", created_at: "2026-10-02T09:00:00Z", updated_at: "2026-10-02T09:00:00Z" },
];

export const targets: Target[] = [
  { id: "tgt-001", project_id: "prj-001", value: "demo.example.com", target_type: "domain", authorization_status: "approved", notes: null, created_at: "2026-09-02T09:00:00Z" },
  { id: "tgt-002", project_id: "prj-002", value: "staging.example.com", target_type: "domain", authorization_status: "pending", notes: "Awaiting written approval", created_at: "2026-09-15T09:00:00Z" },
  { id: "tgt-003", project_id: "prj-003", value: "10.0.0.15", target_type: "ip", authorization_status: "rejected", notes: null, created_at: "2026-10-03T09:00:00Z" },
];

// Scans, findings and reports have no backend yet, so they stay mock-only.
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