import React, { useEffect, useRef, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { Menu } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { alertApi } from "../../api/alerts";
import Sidebar from "./Sidebar";
import TopBar from "./TopBar";
import LoadingSpinner from "../ui/LoadingSpinner";

/** Map route pathnames to human-readable page titles. */
const PAGE_TITLES = {
  "/dashboard": "Dashboard",
  "/scan": "New Scan",
  "/history": "Scan History",
  "/alerts": "Alerts",
  "/settings": "Settings",
};

function getPageTitle(pathname) {
  return PAGE_TITLES[pathname] ?? "MyCyber DLP";
}

/**
 * Wrapper layout for all authenticated pages.
 *
 * Renders:
 *   - Fixed left Sidebar (desktop) / slide-in drawer (mobile)
 *   - TopBar with page title and alert badge
 *   - Scrollable main content area for children
 *
 * Redirects unauthenticated users to /login.
 */
export default function DashboardLayout({ children }) {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [alertCount, setAlertCount] = useState(0);
  const intervalRef = useRef(null);

  const pageTitle = getPageTitle(location.pathname);

  function fetchAlertCount() {
    alertApi
      .getAlertCount()
      .then((res) => {
        const count = res.data?.unacknowledged ?? 0;
        setAlertCount(Number(count));
      })
      .catch(() => {});
  }

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchAlertCount();
    intervalRef.current = setInterval(fetchAlertCount, 30_000);
    return () => clearInterval(intervalRef.current);
  }, [isAuthenticated]);

  // Show spinner while auth state is being restored from localStorage
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <LoadingSpinner size="lg" text="Loading…" />
      </div>
    );
  }

  // Redirect unauthenticated users — preserve intended destination
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return (
    <div className="flex min-h-screen bg-gray-950">
      {/* Sidebar */}
      <Sidebar
        mobileOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main content — offset by sidebar width on md+ */}
      <div className="flex flex-1 flex-col md:ml-64 min-w-0">
        {/* Mobile hamburger row */}
        <div className="flex items-center gap-3 px-4 h-14 bg-gray-900 border-b border-gray-800 md:hidden">
          <button
            type="button"
            onClick={() => setSidebarOpen(true)}
            className="flex items-center justify-center h-9 w-9 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
            aria-label="Open navigation menu"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="text-white font-semibold text-sm">{pageTitle}</span>
        </div>

        {/* TopBar — visible on md+ */}
        <div className="hidden md:block">
          <TopBar
            pageTitle={pageTitle}
            alertCount={alertCount}
            onAlertsClick={() => navigate("/alerts")}
          />
        </div>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto scrollbar-thin p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
