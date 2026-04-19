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
    <header className="surface-panel-strong flex h-16 shrink-0 items-center justify-between border-b px-6">
      {/* Page title */}
      <div className="min-w-0">
        <p className="font-mono-ui text-[10px] uppercase tracking-[0.24em] text-cyan-300/70">
          Secure Workspace
        </p>
        <h1 className="truncate text-base font-semibold text-white">
          {pageTitle}
        </h1>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <button
          type="button"
          onClick={onSearchClick}
          className="hover-lift flex h-9 w-9 items-center justify-center rounded-lg border border-white/5 bg-white/[0.02] text-gray-400"
          aria-label="Search"
        >
          <Search className="h-4 w-4" />
        </button>

        {/* Bell with badge */}
        <button
          type="button"
          onClick={onAlertsClick}
          className="hover-lift relative flex h-9 w-9 items-center justify-center rounded-lg border border-white/5 bg-white/[0.02] text-gray-400"
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
          className="flex h-9 w-9 cursor-default items-center justify-center rounded-full border border-cyan-400/20 bg-gradient-to-br from-cyan-500 to-sky-600 text-xs font-bold text-white shadow-[0_10px_24px_rgba(14,165,233,0.28)] select-none"
          title={email}
        >
          {initials}
        </div>
      </div>
    </header>
  );
}
