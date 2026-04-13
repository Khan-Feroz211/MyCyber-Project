import React, { useEffect, useRef, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  Bell,
  Clock,
  CreditCard,
  LayoutDashboard,
  LogOut,
  Search,
  Settings,
  Shield,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { alertApi } from "../../api/alerts";


const NAV_ITEMS = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan", icon: Search, label: "New Scan" },
  { to: "/history", icon: Clock, label: "Scan History" },
  { to: "/alerts", icon: Bell, label: "Alerts", badge: true },
  { to: "/billing", icon: CreditCard, label: "Billing" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

/** Derive up-to-two initials from an email address. */
function getInitials(email) {
  if (!email) return "?";
  const local = email.split("@")[0];
  const parts = local.split(/[._-]/);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return local.slice(0, 2).toUpperCase();
}

export default function Sidebar({ mobileOpen, onClose }) {
  const { user, logout } = useAuth();
  const [alertCount, setAlertCount] = useState(0);
  const intervalRef = useRef(null);

  function fetchCount() {
    alertApi
      .getAlertCount()
      .then((res) => {
        const count = res.data?.unacknowledged ?? 0;
        setAlertCount(Number(count));
      })
      .catch(() => {});
  }

  useEffect(() => {
    fetchCount();
    intervalRef.current = setInterval(fetchCount, 30_000);
    return () => clearInterval(intervalRef.current);
  }, []);

  function handleLogout() {
    logout();
  }

  const email = user?.email ?? localStorage.getItem("mycyber_email") ?? "";
  const initials = getInitials(email);

  const sidebarContent = (
    <div className="flex flex-col h-full py-5 px-3">
      {/* Brand */}
      <div className="flex items-center gap-2.5 px-3 mb-8">
        <Shield className="h-7 w-7 text-cyan-400 shrink-0" strokeWidth={1.5} />
        <div className="min-w-0">
          <p className="text-white font-bold text-base leading-tight truncate">
            MyCyber DLP
          </p>
          <p className="text-gray-500 text-xs leading-tight">
            Security Platform
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1">
        {NAV_ITEMS.map(({ to, icon: Icon, label, badge }) => (
          <NavLink
            key={to}
            to={to}
            onClick={onClose}
            className={({ isActive }) =>
              [
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-cyber-700 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-800",
              ].join(" ")
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span className="flex-1">{label}</span>
            {badge && alertCount > 0 && (
              <span className="inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-red-600 text-white text-xs font-bold px-1">
                {alertCount > 99 ? "99+" : alertCount}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User section */}
      <div className="mt-4 pt-4 border-t border-gray-800">
        <div className="flex items-center gap-3 px-3 mb-3">
          <div className="flex items-center justify-center h-8 w-8 rounded-full bg-cyber-700 text-white text-xs font-bold shrink-0">
            {initials}
          </div>
          <span className="text-sm text-gray-300 truncate min-w-0">{email}</span>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          className="w-full flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
        >
          <LogOut className="h-4 w-4 shrink-0" />
          <span>Sign out</span>
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="hidden md:flex fixed inset-y-0 left-0 z-30 w-64 flex-col bg-gray-900">
        {sidebarContent}
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 flex md:hidden"
          role="dialog"
          aria-modal="true"
        >
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-sm"
            onClick={onClose}
            aria-hidden="true"
          />
          {/* Drawer */}
          <aside className="relative z-50 w-64 flex flex-col bg-gray-900 shadow-2xl">
            {sidebarContent}
          </aside>
        </div>
      )}
    </>
  );
}
