import { apiRequest } from "./client";
import type {
  AuthorizationRequest,
  AuthorizationRequestCreate,
  AuthorizationReview,
} from "../types";

export function listAuthorizationRequests(targetId?: string): Promise<AuthorizationRequest[]> {
  const query = targetId ? `?target_id=${encodeURIComponent(targetId)}` : "";
  return apiRequest<AuthorizationRequest[]>(`/authorization-requests${query}`);
}

export function createAuthorizationRequest(
  input: AuthorizationRequestCreate,
): Promise<AuthorizationRequest> {
  return apiRequest<AuthorizationRequest>("/authorization-requests", {
    method: "POST",
    json: input,
  });
}

export function reviewAuthorizationRequest(
  id: string,
  input: AuthorizationReview,
): Promise<AuthorizationRequest> {
  return apiRequest<AuthorizationRequest>(`/authorization-requests/${id}/review`, {
    method: "PATCH",
    json: input,
  });
}