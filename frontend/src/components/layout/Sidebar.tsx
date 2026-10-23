import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  FolderKanban,
  Crosshair,
  ScanSearch,
  Bug,
  FileText,
  Settings,
  ShieldCheck,
} from "lucide-react";

const items = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/projects", label: "Projects", icon: FolderKanban },
  { to: "/targets", label: "Targets", icon: Crosshair },
  { to: "/authorization", label: "Authorization", icon: ShieldCheck },
  { to: "/scans", label: "Scans", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
  
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">Penturion</div>
      <nav>
        {items.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
          >
            <Icon size={18} /> <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}