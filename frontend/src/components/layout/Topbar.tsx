import { useLocation } from "react-router-dom";

export default function Topbar() {
  const { pathname } = useLocation();
  const title =
    pathname === "/"
      ? "Overview"
      : pathname.slice(1).replace(/^./, (c) => c.toUpperCase());

  return (
    <header className="topbar">
      <h1>{title}</h1>
      <span className="pill">Mock data</span>
    </header>
  );
}