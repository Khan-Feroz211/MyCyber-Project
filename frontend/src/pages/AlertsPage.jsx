import React, { useCallback, useEffect, useState } from "react";
import { RefreshCw, Shield, ShieldAlert, Sparkles } from "lucide-react";
import { alertApi } from "../api/alerts";
import DashboardLayout from "../components/layout/DashboardLayout";
import SeverityBadge from "../components/ui/SeverityBadge";
import EmptyState from "../components/ui/EmptyState";
import LoadingSpinner from "../components/ui/LoadingSpinner";

function timeAgo(isoString) {
  if (!isoString) return "-";
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const LEFT_BORDER_COLORS = {
  CRITICAL: "border-l-red-500",
  HIGH: "border-l-orange-500",
  MEDIUM: "border-l-yellow-500",
  LOW: "border-l-sky-500",
  SAFE: "border-l-emerald-400",
};

function leftBorderColor(severity) {
  return LEFT_BORDER_COLORS[(severity ?? "").toUpperCase()] ?? "border-l-slate-600";
}

function normalizeAlerts(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  if (Array.isArray(payload.alerts)) return payload.alerts;
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.results)) return payload.results;
  return [];
}

export default function AlertsPage() {
  const [allAlerts, setAllAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showAcknowledged, setShowAcknowledged] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [query, setQuery] = useState("");
  const [ackingIds, setAckingIds] = useState(new Set());
  const [ackedIds, setAckedIds] = useState(new Set());
  const [deletingIds, setDeletingIds] = useState(new Set());
  const [updatingReviewIds, setUpdatingReviewIds] = useState(new Set());
  const [ackAllLoading, setAckAllLoading] = useState(false);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await alertApi.getAlerts(true, 1, 100);
      setAllAlerts(normalizeAlerts(res.data));
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Failed to load alerts.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  async function handleAcknowledge(alertId) {
    setAckingIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.acknowledge(alertId);
      setAckedIds((prev) => new Set(prev).add(alertId));
      setAllAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? { ...a, is_acknowledged: true } : a))
      );
    } finally {
      setAckingIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }

  async function handleAcknowledgeAll() {
    setAckAllLoading(true);
    try {
      await alertApi.acknowledgeAll();
      setAllAlerts((prev) => prev.map((a) => ({ ...a, is_acknowledged: true })));
    } finally {
      setAckAllLoading(false);
    }
  }

  async function handleDelete(alertId) {
    setDeletingIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.deleteAlert(alertId);
      setAllAlerts((prev) => prev.filter((a) => a.alert_id !== alertId));
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to delete alert.");
    } finally {
      setDeletingIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }

  async function handleUpdateReviewStatus(alertId, newStatus) {
    setUpdatingReviewIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.updateReviewStatus(alertId, newStatus);
      setAllAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? { ...a, review_status: newStatus } : a))
      );
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to update review status.");
    } finally {
      setUpdatingReviewIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }

  const acknowledged = allAlerts.filter((a) => a.is_acknowledged || ackedIds.has(a.alert_id));
  const unacknowledged = allAlerts.filter((a) => !a.is_acknowledged && !ackedIds.has(a.alert_id));

  const baseAlerts = showAcknowledged ? allAlerts : unacknowledged;
  const visibleAlerts = baseAlerts.filter((alert) => {
    if (severityFilter !== "ALL" && (alert.severity ?? "").toUpperCase() !== severityFilter) return false;
    const haystack = `${alert.title ?? ""} ${alert.description ?? ""}`.toLowerCase();
    if (query.trim() && !haystack.includes(query.trim().toLowerCase())) return false;
    return true;
  });

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <section className="surface-panel-strong rounded-[30px] p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                Incident Queue
              </div>
              <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                Alerts should feel triage-ready, not like generic notifications.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Analysts need immediate context, clean actions, and a surface that supports quick review under pressure.
              </p>
            </div>
            <button
              type="button"
              onClick={fetchAlerts}
              className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.06]"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh alerts
            </button>
          </div>

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="surface-panel rounded-2xl px-5 py-4 flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-red-500/15">
                <span className="h-2.5 w-2.5 rounded-full bg-red-500 animate-pulse" />
              </span>
              <div>
                <p className="text-2xl font-bold text-white tabular-nums">{unacknowledged.length}</p>
                <p className="text-xs text-slate-400">Unacknowledged</p>
              </div>
            </div>
            <div className="surface-panel rounded-2xl px-5 py-4 flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-800">
                <ShieldAlert className="h-4 w-4 text-slate-300" />
              </span>
              <div>
                <p className="text-2xl font-bold text-white tabular-nums">{allAlerts.length}</p>
                <p className="text-xs text-slate-400">Total alerts</p>
              </div>
            </div>
            <div className="surface-panel rounded-2xl px-5 py-4 flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-500/15">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
              </span>
              <div>
                <p className="text-2xl font-bold text-white tabular-nums">{acknowledged.length}</p>
                <p className="text-xs text-slate-400">Acknowledged</p>
              </div>
            </div>
          </div>
        </section>

        <section className="surface-panel rounded-[28px] p-4 sm:p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <label className="flex cursor-pointer select-none items-center gap-2.5">
              <div className="relative">
                <input
                  type="checkbox"
                  className="sr-only"
                  checked={showAcknowledged}
                  onChange={(e) => setShowAcknowledged(e.target.checked)}
                />
                <div className={`h-5 w-10 rounded-full transition-colors ${showAcknowledged ? "bg-cyan-600" : "bg-slate-700"}`} />
                <div className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${showAcknowledged ? "translate-x-5" : "translate-x-0"}`} />
              </div>
              <span className="text-sm text-slate-400">Show acknowledged</span>
            </label>

            <div className="flex flex-wrap items-center gap-2">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-300 outline-none focus:border-cyan-500"
              >
                <option value="ALL">All severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <input
                type="text"
                placeholder="Search alerts"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-300 placeholder-slate-500 outline-none focus:border-cyan-500"
              />
              {!showAcknowledged && unacknowledged.length > 1 && (
                <button
                  type="button"
                  onClick={handleAcknowledgeAll}
                  disabled={ackAllLoading}
                  className="rounded-xl border border-white/10 px-3 py-2 text-xs font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:opacity-60"
                >
                  {ackAllLoading ? "Acknowledging all..." : "Acknowledge all"}
                </button>
              )}
            </div>
          </div>
        </section>

        {error && <div className="rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">{error}</div>}

        {loading ? (
          <div className="surface-panel rounded-[28px] p-10">
            <LoadingSpinner size="lg" text="Loading alerts" />
          </div>
        ) : visibleAlerts.length === 0 ? (
          <EmptyState
            icon={<Shield />}
            title="No active security alerts"
            message="You are clear for now. New detections will appear here when the platform needs attention."
          />
        ) : (
          <ul className="space-y-3">
            {visibleAlerts.map((alert) => {
              const alertId = alert.alert_id;
              const isAcked = alert.is_acknowledged || ackedIds.has(alertId);
              const isAcking = ackingIds.has(alertId);
              return (
                <li
                  key={alertId}
                  className={`surface-panel hover-lift rounded-[24px] border-l-4 px-5 py-4 ${leftBorderColor(alert.severity)} ${isAcked ? "opacity-60" : ""}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="mb-1 flex items-center gap-2">
                        <p className="truncate text-sm font-semibold text-white">
                          {alert.title ?? alert.message ?? "Security Alert"}
                        </p>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                      {(alert.description ?? alert.message) && (
                        <p className="line-clamp-2 text-sm leading-7 text-slate-400">
                          {(alert.description ?? alert.message ?? "").slice(0, 180)}
                        </p>
                      )}
                      <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                        {alert.scan_id && <span className="font-mono-ui">scan:{String(alert.scan_id).slice(0, 8)}...</span>}
                        <span>{timeAgo(alert.created_at)}</span>
                      </div>
                    </div>

                    <div className="flex shrink-0 flex-col items-end gap-2">
                      <select
                        value={alert.review_status ?? "pending"}
                        onChange={(e) => handleUpdateReviewStatus(alertId, e.target.value)}
                        disabled={updatingReviewIds.has(alertId)}
                        className={`rounded-lg border px-2 py-1 text-xs font-medium outline-none transition ${
                          (alert.review_status ?? "pending") === "pending"
                            ? "border-slate-600 bg-slate-800 text-slate-300"
                            : (alert.review_status ?? "pending") === "reviewed"
                            ? "border-cyan-600/50 bg-cyan-900/20 text-cyan-300"
                            : (alert.review_status ?? "pending") === "dismissed"
                            ? "border-amber-600/50 bg-amber-900/20 text-amber-300"
                            : "border-emerald-600/50 bg-emerald-900/20 text-emerald-300"
                        } disabled:opacity-50`}
                      >
                        <option value="pending">Pending</option>
                        <option value="reviewed">Reviewed</option>
                        <option value="dismissed">Dismissed</option>
                        <option value="resolved">Resolved</option>
                      </select>

                      {!isAcked ? (
                        <div className="flex shrink-0 items-center gap-2">
                          <button
                            type="button"
                            disabled={isAcking}
                            onClick={() => handleAcknowledge(alertId)}
                            className="rounded-xl border border-white/10 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:cursor-wait disabled:opacity-60"
                          >
                            {isAcking ? "Acknowledging..." : "Acknowledge"}
                          </button>
                          <button
                            type="button"
                            disabled={deletingIds.has(alertId)}
                            onClick={() => handleDelete(alertId)}
                            className="rounded-xl border border-red-700/50 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-600 hover:text-white disabled:cursor-wait disabled:opacity-60"
                          >
                            {deletingIds.has(alertId) ? "Deleting..." : "Delete"}
                          </button>
                        </div>
                      ) : (
                        <span className="shrink-0 text-xs font-medium text-emerald-300">Acknowledged</span>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </DashboardLayout>
  );
}
