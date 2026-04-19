import React, { useEffect, useMemo, useState } from "react";
import { Download, Eye, RefreshCw, ShieldAlert, X } from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import { adminSecurityApi } from "../api/adminSecurity";
import { useAuth } from "../context/AuthContext";
import { isAdminUser } from "../utils/access";

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

function severityTone(severity) {
  const tone = String(severity || "").toUpperCase();
  if (tone === "CRITICAL") return "bg-red-950/50 text-red-200 border-red-700";
  if (tone === "HIGH") return "bg-orange-950/40 text-orange-200 border-orange-700";
  if (tone === "MEDIUM") return "bg-amber-950/40 text-amber-200 border-amber-700";
  if (tone === "LOW") return "bg-sky-950/40 text-sky-200 border-sky-700";
  return "bg-gray-800 text-gray-200 border-gray-700";
}

function downloadCsv(rows) {
  const header = [
    "created_at",
    "severity",
    "event_type",
    "user_id",
    "tenant_id",
    "ip_address",
    "user_agent",
    "details",
  ];
  const body = rows.map((row) =>
    [
      row.created_at,
      row.severity,
      row.event_type,
      row.user_id ?? "",
      row.tenant_id ?? "",
      row.ip_address ?? "",
      row.user_agent ?? "",
      JSON.stringify(row.details || {}),
    ]
      .map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`)
      .join(",")
  );
  const blob = new Blob([[header.join(","), ...body].join("\n")], {
    type: "text/csv;charset=utf-8;",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `security-incidents-${new Date().toISOString().slice(0, 19)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

function IncidentDetailModal({ item, onClose, onSeedAction }) {
  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <aside className="relative z-10 h-full w-full max-w-xl overflow-y-auto border-l border-gray-800 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Incident Detail</h2>
            <p className="text-sm text-gray-400">{item.event_id || item.id}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg text-gray-400 hover:bg-gray-800 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${severityTone(item.severity)}`}>
            {item.severity || "INFO"}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-xs text-gray-500">Time</p>
              <p className="text-sm text-white">{formatDate(item.created_at)}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Event Type</p>
              <p className="text-sm text-white break-all">{item.event_type || "-"}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">User ID</p>
              <p className="text-sm text-white">{item.user_id ?? "-"}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Tenant ID</p>
              <p className="text-sm text-white break-all">{item.tenant_id ?? "-"}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">IP Address</p>
              <p className="text-sm text-white">{item.ip_address ?? "-"}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">User Agent</p>
              <p className="text-sm text-white break-all">{item.user_agent ?? "-"}</p>
            </div>
          </div>

          <div>
            <p className="mb-2 text-xs text-gray-500">Incident Details</p>
            <pre className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-300">
              {JSON.stringify(item.details || {}, null, 2)}
            </pre>
          </div>

          {item.user_id ? (
            <button
              type="button"
              onClick={() => {
                onSeedAction(item.user_id);
                onClose();
              }}
              className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500"
            >
              Use this user in response actions
            </button>
          ) : null}
        </div>
      </aside>
    </div>
  );
}

export default function AdminIncidentsPage() {
  const { user } = useAuth();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("");
  const [eventType, setEventType] = useState("");
  const [search, setSearch] = useState("");
  const [userIdFilter, setUserIdFilter] = useState("");
  const [selectedIncident, setSelectedIncident] = useState(null);
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
        page_size: 200,
      });
      setItems(Array.isArray(response.data?.items) ? response.data.items : []);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.response?.data?.detail ||
          "Failed to load incidents. Ensure you are signed in as admin."
      );
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents();
  }, [severity, eventType]);

  const distinctEventTypes = useMemo(() => {
    const set = new Set(items.map((i) => i.event_type).filter(Boolean));
    return Array.from(set).sort();
  }, [items]);

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    const numericUserId = userIdFilter.trim();
    return items.filter((item) => {
      if (numericUserId && String(item.user_id ?? "") !== numericUserId) {
        return false;
      }
      if (!q) return true;
      const haystack = [
        item.event_id,
        item.event_type,
        item.severity,
        item.ip_address,
        item.user_agent,
        item.tenant_id,
        JSON.stringify(item.details || {}),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [items, search, userIdFilter]);

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
      setError(err?.response?.data?.message || err?.response?.data?.detail || "Action failed.");
    } finally {
      setActionBusy(false);
    }
  }

  if (!isAdminUser(user)) {
    return (
      <DashboardLayout>
        <div className="mx-auto max-w-3xl rounded-xl border border-red-900 bg-red-950/20 p-6">
          <h1 className="text-lg font-semibold text-white">Admin access required</h1>
          <p className="mt-2 text-sm text-red-200">
            This page is restricted to admin users. Frontend access is blocked and the backend route remains protected.
          </p>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="mx-auto w-full max-w-7xl space-y-6">
        <div className="rounded-xl border border-gray-800 bg-gray-900/80 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-xl font-semibold text-white">Admin Security Incidents</h1>
              <p className="mt-1 text-sm text-gray-400">
                Review live audit events, filter by incident characteristics, export results, and trigger response actions.
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => downloadCsv(filteredItems)}
                className="inline-flex items-center gap-2 rounded-md border border-gray-700 px-3 py-2 text-sm font-semibold text-gray-200 hover:bg-gray-800"
              >
                <Download className="h-4 w-4" />
                Export CSV
              </button>
              <button
                type="button"
                onClick={loadIncidents}
                className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3 py-2 text-sm font-semibold text-white hover:bg-cyan-500"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>
        </div>

        <div className="grid gap-3 rounded-xl border border-gray-800 bg-gray-900/80 p-4 md:grid-cols-4">
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

          <label className="text-sm text-gray-300">
            User ID
            <input
              value={userIdFilter}
              onChange={(e) => setUserIdFilter(e.target.value.replace(/\D/g, ""))}
              placeholder="Filter by user ID"
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            />
          </label>

          <label className="text-sm text-gray-300">
            Search
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="IP, event, tenant, details"
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
            />
          </label>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900/80 p-4">
          <h2 className="text-base font-semibold text-white">Response Actions</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <input
              value={actionUserId}
              onChange={(e) => setActionUserId(e.target.value.replace(/\D/g, ""))}
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
                <th className="px-4 py-3">Summary</th>
                <th className="px-4 py-3">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 text-gray-200">
              {!loading && filteredItems.length === 0 && (
                <tr>
                  <td className="px-4 py-10 text-center text-gray-400" colSpan={7}>
                    <div className="flex flex-col items-center gap-3">
                      <ShieldAlert className="h-8 w-8 text-gray-600" />
                      <span>No incidents found for the current filters.</span>
                    </div>
                  </td>
                </tr>
              )}
              {filteredItems.map((item) => (
                <tr key={item.event_id || `${item.id}`} className="hover:bg-gray-800/50">
                  <td className="px-4 py-3 whitespace-nowrap">{formatDate(item.created_at)}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${severityTone(item.severity)}`}>
                      {item.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">{item.event_type}</td>
                  <td className="px-4 py-3">{item.user_id ?? "-"}</td>
                  <td className="px-4 py-3">{item.ip_address ?? "-"}</td>
                  <td className="px-4 py-3 max-w-[26rem] truncate">
                    {JSON.stringify(item.details || {})}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={() => setSelectedIncident(item)}
                      className="inline-flex items-center gap-2 rounded-md border border-gray-700 px-3 py-1.5 text-xs font-semibold text-gray-200 hover:bg-gray-800"
                    >
                      <Eye className="h-3.5 w-3.5" />
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <IncidentDetailModal
        item={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onSeedAction={(nextUserId) => setActionUserId(String(nextUserId))}
      />
    </DashboardLayout>
  );
}
