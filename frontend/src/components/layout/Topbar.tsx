import { useLocation } from "react-router-dom";
import { LogOut } from "lucide-react";
import { useAuth } from "../../auth/AuthContext";

// Pages that still show sample data. Pages not listed here use the real backend.
const sampleLabels: Record<string, string> = {
  "/": "Partly sample data",
  "/scans": "Sample data",
  "/findings": "Sample data",
  "/reports": "Sample data",
};

export default function Topbar() {
  const { pathname } = useLocation();
  const { user, logout } = useAuth();
  const title =
    pathname === "/"
      ? "Overview"
      : pathname.slice(1).replace(/^./, (c) => c.toUpperCase());

  return (
    <header className="topbar">
      <h1>{title}</h1>
      <div className="topbar-right">
        {sampleLabels[pathname] && <span className="pill">{sampleLabels[pathname]}</span>}
        {user && (
          <>
            <span className="user-info">
              {user.email} <span className="pill">{user.role}</span>
            </span>
            <button className="btn-ghost" onClick={logout}>
              <LogOut size={16} /> Logout
            </button>
          </>
        )}
      </div>
    </header>
  );
}