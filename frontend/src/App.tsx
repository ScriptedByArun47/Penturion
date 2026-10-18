import { Route, Routes } from "react-router-dom";
import AppLayout from "./components/layout/AppLayout";
import Overview from "./pages/Overview";
import Projects from "./pages/Projects";
import Targets from "./pages/Targets";
import Scans from "./pages/Scans";
import Findings from "./pages/Findings";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Overview />} />
        <Route path="projects" element={<Projects />} />
        <Route path="targets" element={<Targets />} />
        <Route path="scans" element={<Scans />} />
        <Route path="findings" element={<Findings />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}