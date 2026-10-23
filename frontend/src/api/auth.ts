import { apiRequest } from "./client";
import type { LoginInput, RegisterInput, TokenResponse, User } from "../types";

export function login(input: LoginInput): Promise<TokenResponse> {
  return apiRequest<TokenResponse>("/auth/login", { method: "POST", json: input });
}

export function register(input: RegisterInput): Promise<User> {
  return apiRequest<User>("/auth/register", { method: "POST", json: input });
}

export function getCurrentUser(): Promise<User> {
  return apiRequest<User>("/auth/me");
}