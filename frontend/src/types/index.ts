// ---------- Auth ----------
export interface User {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}
export interface LoginInput { email: string; password: string }
export interface RegisterInput { email: string; password: string } // password min 12 chars

// ---------- Projects ----------
export type ProjectStatus = "active" | "inactive" | "archived";
export interface Project {
  id: string;
  name: string;
  description: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}
export interface ProjectCreate { name: string; description?: string | null }
export interface ProjectUpdate { name?: string; description?: string | null; status?: ProjectStatus }

// ---------- Targets ----------
export type TargetType = "domain" | "ip" | "url";
export type AuthorizationStatus = "pending" | "approved" | "rejected";
export interface Target {
  id: string;
  project_id: string;
  value: string;
  target_type: string;
  authorization_status: AuthorizationStatus;
  notes: string | null;
  created_at: string;
}
export interface TargetCreate { value: string; target_type: TargetType; notes?: string | null }
export interface TargetUpdate { value?: string; notes?: string | null }

// ---------- Authorization requests ----------
export interface AuthorizationRequest {
  id: string;
  target_id: string;
  status: AuthorizationStatus;
  evidence_reference: string;
  requested_scope: string;
  requested_by: string;
  reviewed_by: string | null;
  review_reason: string | null;
  reviewed_at: string | null;
  created_at: string;
}
export interface AuthorizationRequestCreate {
  target_id: string;
  evidence_reference: string;
  requested_scope: string;
  requested_by: string; // TODO: remove once the backend derives it from the token
}
export interface AuthorizationReview {
  status: "approved" | "rejected";
  review_reason: string;
}

// ---------- API errors ----------
export interface ApiValidationError { loc: (string | number)[]; msg: string; type: string }

// ---------- Mock-only (no backend yet) ----------
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type ScanStatus = "Completed" | "Running" | "Failed" | "Queued";
export type FindingStatus = "Open" | "In Review" | "Resolved";

export interface Scan { id: string; target: string; status: ScanStatus; findings: number; started: string; ended?: string }
export interface Finding { id: string; title: string; severity: Severity; target: string; status: FindingStatus }
export interface Report { id: string; name: string; project: string; generated: string }