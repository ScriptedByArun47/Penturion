const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

const TOKEN_KEY = "penturion_token";
const TIMEOUT_MS = 15000;

export const tokenStore = {
  get(): string | null {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set(token: string): void {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch {
      /* storage unavailable */
    }
  },
  clear(): void {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* storage unavailable */
    }
  },
};

// The auth layer registers this so an expired token sends the user to login.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function messageFromDetail(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const joined = detail
      .map((d) => (d && typeof d === "object" && "msg" in d ? String(d.msg) : ""))
      .filter(Boolean)
      .join("; ");
    return joined || fallback;
  }
  return fallback;
}

interface ApiOptions extends Omit<RequestInit, "body" | "headers"> {
  json?: unknown;
  headers?: Record<string, string>;
}

export async function apiRequest<T>(
  endpoint: string,
  { json, headers, ...options }: ApiOptions = {},
): Promise<T> {
  const token = tokenStore.get();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      signal: controller.signal,
      body: json !== undefined ? JSON.stringify(json) : undefined,
      headers: {
        Accept: "application/json",
        ...(json !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(0, "The request timed out. Please try again.");
    }
    throw new ApiError(0, "Cannot reach the API. Is the backend running, and is CORS enabled?");
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    let detail: unknown;
    try {
      detail = (await response.json()).detail;
    } catch {
      /* response had no JSON body */
    }
    if (response.status === 401 && token) {
      tokenStore.clear();
      onUnauthorized?.();
    }
    throw new ApiError(
      response.status,
      messageFromDetail(detail, `${response.status} ${response.statusText}`),
    );
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}