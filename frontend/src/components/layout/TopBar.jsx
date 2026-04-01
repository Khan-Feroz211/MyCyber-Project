import React from "react";
import { Bell, Search } from "lucide-react";
import { useAuth } from "../../context/AuthContext";

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

/**
 * Top navigation bar for the dashboard layout.
 *
 * @param {string}   pageTitle          - Current page label displayed on the left
 * @param {number}   [alertCount=0]     - Unacknowledged alert count for the bell badge
 * @param {() => void} [onSearchClick]  - Handler for the search icon button
 * @param {() => void} [onAlertsClick]  - Handler for the bell icon button
 */
export default function TopBar({
  pageTitle,
  alertCount = 0,
  onSearchClick,
  onAlertsClick,
}) {
  const { user } = useAuth();
  const email = user?.email ?? localStorage.getItem("mycyber_email") ?? "";
  const initials = getInitials(email);

  return (
    <header className="flex items-center justify-between h-16 px-6 bg-gray-900 border-b border-gray-800 shrink-0">
      {/* Page title */}
      <h1 className="text-base font-semibold text-white truncate">
        {pageTitle}
      </h1>

      {/* Actions */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <button
          type="button"
          onClick={onSearchClick}
          className="flex items-center justify-center h-9 w-9 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
          aria-label="Search"
        >
          <Search className="h-4 w-4" />
        </button>

        {/* Bell with badge */}
        <button
          type="button"
          onClick={onAlertsClick}
          className="relative flex items-center justify-center h-9 w-9 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
          aria-label={`Alerts${alertCount > 0 ? ` (${alertCount} unread)` : ""}`}
        >
          <Bell className="h-4 w-4" />
          {alertCount > 0 && (
            <span className="absolute top-1 right-1 flex items-center justify-center min-w-[1rem] h-4 rounded-full bg-red-600 text-white text-[10px] font-bold px-0.5 leading-none">
              {alertCount > 99 ? "99+" : alertCount}
            </span>
          )}
        </button>

        {/* User avatar */}
        <div
          className="flex items-center justify-center h-8 w-8 rounded-full bg-cyber-700 text-white text-xs font-bold select-none cursor-default"
          title={email}
        >
          {initials}
        </div>
      </div>
    </header>
  );
}
