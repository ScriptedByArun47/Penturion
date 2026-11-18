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
export type AuthorizationStatus = "pending" | "approved" | "rejected" | "revoked" | "expired";
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
  expires_at?: string | null;
  revoked_by?: string | null;
  revoked_at?: string | null;
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
  validity_days?: number;
}

// ---------- Scans (real backend) ----------
export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface Scan {
  id: string;
  target_id: string;
  requested_by: string;
  status: ScanStatus | string;
  scan_type: string;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanCreate {
  target_id: string;
  authorization_request_id: string;
  scan_type?: "web";
}

// ---------- API errors ----------
export interface ApiValidationError { loc: (string | number)[]; msg: string; type: string }

// ---------- Mock-only (Findings & Reports pending backend) ----------
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type FindingStatus = "Open" | "In Review" | "Resolved";

export interface Finding { id: string; title: string; severity: Severity; target: string; status: FindingStatus }
export interface Report { id: string; name: string; project: string; generated: string }

// Mock scan definition for fallback and sample dashboard
export interface MockScan {
  id: string;
  target: string;
  status: string;
  findings: number;
  started: string;
  ended?: string;
}
