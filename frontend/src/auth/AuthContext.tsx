import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { getCurrentUser, login as loginRequest } from "../api/auth";
import { setUnauthorizedHandler, tokenStore } from "../api/client";
import type { User } from "../types";

interface AuthState {
  user: User | null;
  loading: boolean; // true while a saved session is being restored
  isReviewer: boolean; // reviewer or admin (UI convenience only, the backend enforces it)
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(() => tokenStore.get() !== null);

  // Restore the session if a token is already stored for this tab.
  useEffect(() => {
    if (tokenStore.get() === null) return;
    let cancelled = false;
    getCurrentUser()
      .then((u) => {
        if (!cancelled) setUser(u);
      })
      .catch(() => tokenStore.clear())
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // If the backend rejects our token (expired or invalid), drop the session.
  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    return () => setUnauthorizedHandler(null);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const { access_token } = await loginRequest({ email, password });
    tokenStore.set(access_token);
    try {
      setUser(await getCurrentUser());
    } catch (err) {
      tokenStore.clear();
      throw err;
    }
  }, []);

  const logout = useCallback(() => {
    tokenStore.clear();
    setUser(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading,
      isReviewer: user?.role === "reviewer" || user?.role === "admin",
      login,
      logout,
    }),
    [user, loading, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}