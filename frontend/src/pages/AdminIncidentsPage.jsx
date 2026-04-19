import React, { useEffect, useMemo, useState } from "react";
import DashboardLayout from "../components/layout/DashboardLayout";
import { adminSecurityApi } from "../api/adminSecurity";

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

export default function AdminIncidentsPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("");
  const [eventType, setEventType] = useState("");
  const [actionUserId, setActionUserId] = useState("");
  const [reason, setReason] = useState("Incident response action");
  const [lockMinutes, setLockMinutes] = useState(60);
  const [actionBusy, setActionBusy] = useState(false);

  async function loadIncidents() {
    setLoading(true);
    setError("");
    try {
      const response = await adminSecurityApi.listIncidents({
        severity: severity || undefined,
        event_type: eventType || undefined,
        page_size: 50,
      });
      const nextItems = Array.isArray(response.data?.items)
        ? response.data.items
        : [];
      setItems(nextItems);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          "Failed to load incidents. Ensure you are signed in as admin."
      );
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents();
  }, []);

  const distinctEventTypes = useMemo(() => {
    const set = new Set(items.map((i) => i.event_type).filter(Boolean));
    return Array.from(set);
  }, [items]);

  async function runAction(action) {
    const userIdNum = Number(actionUserId);
    if (!Number.isFinite(userIdNum) || userIdNum <= 0) {
      setError("Provide a valid numeric user ID for response actions.");
      return;
    }

    setActionBusy(true);
    setError("");
    try {
      if (action === "lock") {
        await adminSecurityApi.lockUser(userIdNum, reason, Number(lockMinutes) || 60);
      } else if (action === "unlock") {
        await adminSecurityApi.unlockUser(userIdNum, reason);
      } else if (action === "deactivate") {
        await adminSecurityApi.deactivateUser(userIdNum, reason);
      } else if (action === "reactivate") {
        await adminSecurityApi.reactivateUser(userIdNum, reason);
      }
      await loadIncidents();
    } catch (err) {
      setError(err?.response?.data?.message || "Action failed.");
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <DashboardLayout>
      <div className="mx-auto w-full max-w-7xl space-y-6">
        <div className="rounded-xl border border-gray-800 bg-gray-900/80 p-5">
          <h1 className="text-xl font-semibold text-white">Admin Security Incidents</h1>
          <p className="mt-1 text-sm text-gray-400">
            Review audit events and execute incident response actions.
          </p>
        </div>

        <div className="grid gap-3 rounded-xl border border-gray-800 bg-gray-900/80 p-4 md:grid-cols-3">
          <label className="text-sm text-gray-300">
            Severity
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            >
              <option value="">All</option>
              <option value="INFO">INFO</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </label>

          <label className="text-sm text-gray-300">
            Event Type
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            >
              <option value="">All</option>
              {distinctEventTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>

          <div className="flex items-end">
            <button
              type="button"
              onClick={loadIncidents}
              className="w-full rounded-md bg-cyan-600 px-3 py-2 text-sm font-semibold text-white hover:bg-cyan-500"
            >
              Refresh
            </button>
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900/80 p-4">
          <h2 className="text-base font-semibold text-white">Response Actions</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <input
              value={actionUserId}
              onChange={(e) => setActionUserId(e.target.value)}
              placeholder="User ID"
              className="rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            />
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason"
              className="rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            />
            <input
              type="number"
              min="1"
              max="10080"
              value={lockMinutes}
              onChange={(e) => setLockMinutes(e.target.value)}
              placeholder="Lock minutes"
              className="rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            />
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4 md:col-span-1">
              <button
                type="button"
                onClick={() => runAction("lock")}
                disabled={actionBusy}
                className="rounded-md bg-amber-600 px-3 py-2 text-xs font-semibold text-white hover:bg-amber-500 disabled:opacity-60"
              >
                Lock
              </button>
              <button
                type="button"
                onClick={() => runAction("unlock")}
                disabled={actionBusy}
                className="rounded-md bg-emerald-600 px-3 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-60"
              >
                Unlock
              </button>
              <button
                type="button"
                onClick={() => runAction("deactivate")}
                disabled={actionBusy}
                className="rounded-md bg-red-700 px-3 py-2 text-xs font-semibold text-white hover:bg-red-600 disabled:opacity-60"
              >
                Deactivate
              </button>
              <button
                type="button"
                onClick={() => runAction("reactivate")}
                disabled={actionBusy}
                className="rounded-md bg-sky-700 px-3 py-2 text-xs font-semibold text-white hover:bg-sky-600 disabled:opacity-60"
              >
                Reactivate
              </button>
            </div>
          </div>
        </div>

        {error && (
          <div className="rounded-md border border-red-800 bg-red-900/30 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900/80">
          <table className="min-w-full divide-y divide-gray-800 text-sm">
            <thead className="bg-gray-950/80 text-left text-gray-300">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Event</th>
                <th className="px-4 py-3">User ID</th>
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 text-gray-200">
              {!loading && items.length === 0 && (
                <tr>
                  <td className="px-4 py-6 text-gray-400" colSpan={6}>
                    No incidents found.
                  </td>
                </tr>
              )}
              {items.map((item) => (
                <tr key={item.event_id || `${item.id}`}>
                  <td className="px-4 py-3 whitespace-nowrap">{formatDate(item.created_at)}</td>
                  <td className="px-4 py-3">{item.severity}</td>
                  <td className="px-4 py-3">{item.event_type}</td>
                  <td className="px-4 py-3">{item.user_id ?? "-"}</td>
                  <td className="px-4 py-3">{item.ip_address ?? "-"}</td>
                  <td className="px-4 py-3 max-w-[28rem] truncate">
                    {JSON.stringify(item.details || {})}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
}
