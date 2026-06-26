import React, { useCallback, useEffect, useState } from "react";
import { RefreshCw, Shield, ShieldAlert, Sparkles, X } from "lucide-react";
import { alertApi } from "../api/alerts";
import DashboardLayout from "../components/layout/DashboardLayout";
import SeverityBadge from "../components/ui/SeverityBadge";
import EmptyState from "../components/ui/EmptyState";
import LoadingSpinner from "../components/ui/LoadingSpinner";
 
/**
 * Format time difference in human-readable format
 */
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
 
/**
 * Map severity levels to border colors
 */
const LEFT_BORDER_COLORS = {
  CRITICAL: "border-l-red-500",
  HIGH: "border-l-orange-500",
  MEDIUM: "border-l-yellow-500",
  LOW: "border-l-sky-500",
  SAFE: "border-l-emerald-400",
};
 
/**
 * Get border color based on severity
 */
function leftBorderColor(severity) {
  return LEFT_BORDER_COLORS[(severity ?? "").toUpperCase()] ?? "border-l-slate-600";
}
 
/**
 * Normalize various alert payload formats
 */
function normalizeAlerts(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  if (Array.isArray(payload.alerts)) return payload.alerts;
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.results)) return payload.results;
  return [];
}
 
/**
 * File Details Modal Component
 */
function FileDetailsModal({ isOpen, isLoading, file, onClose }) {
  if (!isOpen) return null;
 
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
        role="presentation"
      />
      <div className="relative z-10 w-[90%] max-w-3xl rounded-2xl bg-slate-900 p-6">
        {/* Modal Header */}
        <div className="flex items-start justify-between">
          <h3 className="text-lg font-semibold text-white">File details</h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-300 transition"
            aria-label="Close modal"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
 
        {/* Modal Content */}
        <div className="mt-4 max-h-[60vh] overflow-auto text-sm text-slate-300">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner size="sm" text="Loading file details" />
            </div>
          ) : file ? (
            <div className="space-y-3">
              {/* Scan ID */}
              <p className="font-mono-ui text-xs text-slate-400">
                scan:{file.scan_id}
              </p>
 
              {/* Filename */}
              <p className="text-sm font-semibold text-white">
                {file.filename ?? "(no filename)"}
              </p>
 
              {/* Timestamp */}
              <p className="text-xs text-slate-500">
                {new Date(file.created_at).toLocaleString()}
              </p>
 
              {/* Preview Section */}
              <div className="mt-2 rounded-md border border-white/5 bg-slate-800 p-3">
                <div className="text-xs text-slate-400 font-medium">Preview</div>
                <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap text-xs text-slate-300">
                  {file.input_preview ?? "(no preview stored)"}
                </pre>
              </div>
 
              {/* Detected Entities Section */}
              <div>
                <div className="text-xs text-slate-400 font-medium">
                  Detected entities
                </div>
                {file.entities && file.entities.length > 0 ? (
                  <ul className="mt-2 space-y-2">
                    {file.entities.map((entity, idx) => (
                      <li
                        key={idx}
                        className="rounded-md border border-white/5 bg-slate-800 p-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="text-xs text-slate-300 font-medium">
                            {entity.entity_type}
                          </div>
                          <div className="text-xs text-slate-400">
                            {Math.round((entity.confidence || 0) * 100)}%
                          </div>
                        </div>
                        <div className="mt-1 font-mono-ui text-xs text-slate-200 break-all">
                          {entity.value}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-2 text-xs text-slate-500">
                    No detected entities stored for this scan.
                  </p>
                )}
              </div>
            </div>
          ) : (
            <p className="text-sm text-rose-400">
              File details not available.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
 
/**
 * Alert Stats Card Component
 */
function StatsCard({ count, label, icon: Icon, color }) {
  const bgColors = {
    red: "bg-red-500/15",
    emerald: "bg-emerald-500/15",
    slate: "bg-slate-800",
  };
 
  const dotColors = {
    red: "bg-red-500",
    emerald: "bg-emerald-400",
  };
 
  return (
    <div className="surface-panel rounded-2xl px-5 py-4 flex items-center gap-3">
      <span className={`flex h-10 w-10 items-center justify-center rounded-2xl ${bgColors[color]}`}>
        {color !== "slate" ? (
          <span className={`h-2.5 w-2.5 rounded-full ${dotColors[color]} ${color === "red" ? "animate-pulse" : ""}`} />
        ) : (
          <Icon className="h-4 w-4 text-slate-300" />
        )}
      </span>
      <div>
        <p className="text-2xl font-bold text-white tabular-nums">{count}</p>
        <p className="text-xs text-slate-400">{label}</p>
      </div>
    </div>
  );
}
 
/**
 * Alert Item Component
 */
function AlertItem({
  alert,
  isAcked,
  isAcking,
  isDeletingIds,
  isUpdatingReviewIds,
  onAcknowledge,
  onDelete,
  onUpdateReviewStatus,
  onOpenFile,
}) {
  const alertId = alert.alert_id;
 
  return (
    <li
      className={`surface-panel hover-lift rounded-[24px] border-l-4 px-5 py-4 ${leftBorderColor(
        alert.severity
      )} ${isAcked ? "opacity-60" : ""}`}
    >
      <div className="flex items-start justify-between gap-3">
        {/* Left Content - Title & Details */}
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
            {alert.scan_id && (
              <span className="font-mono-ui">
                scan:{String(alert.scan_id).slice(0, 8)}...
              </span>
            )}
            <span>{timeAgo(alert.created_at)}</span>
          </div>
        </div>
 
        {/* Right Content - Actions & Status */}
        <div className="flex shrink-0 flex-col items-end gap-2">
          {/* Review Status Dropdown */}
          <select
            value={alert.review_status ?? "pending"}
            onChange={(e) => onUpdateReviewStatus(alertId, e.target.value)}
            disabled={isUpdatingReviewIds.has(alertId)}
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
 
          {/* Action Buttons */}
          {!isAcked ? (
            <div className="flex shrink-0 items-center gap-2">
              <button
                type="button"
                disabled={isAcking}
                onClick={() => onAcknowledge(alertId)}
                className="rounded-xl border border-white/10 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:cursor-wait disabled:opacity-60"
              >
                {isAcking ? "Acknowledging..." : "Acknowledge"}
              </button>
              <button
                type="button"
                disabled={isDeletingIds.has(alertId)}
                onClick={() => onDelete(alertId)}
                className="rounded-xl border border-red-700/50 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-600 hover:text-white disabled:cursor-wait disabled:opacity-60"
              >
                {isDeletingIds.has(alertId) ? "Deleting..." : "Delete"}
              </button>
              <button
                type="button"
                onClick={() => onOpenFile(alertId)}
                className="rounded-xl border border-white/10 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/[0.05]"
              >
                Details
              </button>
            </div>
          ) : (
            <span className="shrink-0 text-xs font-medium text-emerald-300">
              Acknowledged
            </span>
          )}
        </div>
      </div>
    </li>
  );
}
 
/**
 * Main Alerts Page Component
 */
export default function AlertsPage() {
  // Alert data state
  const [allAlerts, setAllAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
 
  // Filter state
  const [showAcknowledged, setShowAcknowledged] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [query, setQuery] = useState("");
 
  // UI state for actions
  const [ackingIds, setAckingIds] = useState(new Set());
  const [ackedIds, setAckedIds] = useState(new Set());
  const [deletingIds, setDeletingIds] = useState(new Set());
  const [updatingReviewIds, setUpdatingReviewIds] = useState(new Set());
  const [ackAllLoading, setAckAllLoading] = useState(false);
 
  // File modal state
  const [fileLoading, setFileLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileModalOpen, setFileModalOpen] = useState(false);
 
  /**
   * Fetch all alerts from API
   */
  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await alertApi.getAlerts(true, 1, 100);
      setAllAlerts(normalizeAlerts(res.data));
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to load alerts."
      );
    } finally {
      setLoading(false);
    }
  }, []);
 
  /**
   * Fetch alerts on mount
   */
  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);
 
  /**
   * Handle acknowledge single alert
   */
  async function handleAcknowledge(alertId) {
    setAckingIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.acknowledge(alertId);
      setAckedIds((prev) => new Set(prev).add(alertId));
      setAllAlerts((prev) =>
        prev.map((a) =>
          a.alert_id === alertId ? { ...a, is_acknowledged: true } : a
        )
      );
    } catch (err) {
      setError(
        err?.response?.data?.detail || "Failed to acknowledge alert."
      );
    } finally {
      setAckingIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }
 
  /**
   * Handle acknowledge all alerts
   */
  async function handleAcknowledgeAll() {
    setAckAllLoading(true);
    try {
      await alertApi.acknowledgeAll();
      setAllAlerts((prev) =>
        prev.map((a) => ({ ...a, is_acknowledged: true }))
      );
    } catch (err) {
      setError(
        err?.response?.data?.detail || "Failed to acknowledge all alerts."
      );
    } finally {
      setAckAllLoading(false);
    }
  }
 
  /**
   * Handle delete alert
   */
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
 
  /**
   * Open alert file modal
   */
  async function openAlertFile(alertId) {
    setFileLoading(true);
    setFileModalOpen(true);
    setSelectedFile(null);
    try {
      const res = await alertApi.getAlertFile(alertId);
      setSelectedFile(res.data);
    } catch (err) {
      setError(
        err?.response?.data?.detail || "Failed to load file details."
      );
      setFileModalOpen(false);
    } finally {
      setFileLoading(false);
    }
  }
 
  /**
   * Handle update review status
   */
  async function handleUpdateReviewStatus(alertId, newStatus) {
    setUpdatingReviewIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.updateReviewStatus(alertId, newStatus);
      setAllAlerts((prev) =>
        prev.map((a) =>
          a.alert_id === alertId
            ? { ...a, review_status: newStatus }
            : a
        )
      );
    } catch (err) {
      setError(
        err?.response?.data?.detail || "Failed to update review status."
      );
    } finally {
      setUpdatingReviewIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }
 
  /**
   * Filter alerts based on acknowledgment status
   */
  const acknowledged = allAlerts.filter(
    (a) => a.is_acknowledged || ackedIds.has(a.alert_id)
  );
  const unacknowledged = allAlerts.filter(
    (a) => !a.is_acknowledged && !ackedIds.has(a.alert_id)
  );
 
  /**
   * Apply filters to alerts
   */
  const baseAlerts = showAcknowledged ? allAlerts : unacknowledged;
  const visibleAlerts = baseAlerts.filter((alert) => {
    if (
      severityFilter !== "ALL" &&
      (alert.severity ?? "").toUpperCase() !== severityFilter
    )
      return false;
    const haystack = `${alert.title ?? ""} ${alert.description ?? ""}`.toLowerCase();
    if (query.trim() && !haystack.includes(query.trim().toLowerCase()))
      return false;
    return true;
  });
 
  return (
    <>
      <DashboardLayout>
        <div className="space-y-6">
          {/* Header Section */}
          <section className="surface-panel-strong rounded-[30px] p-6 sm:p-8">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              {/* Title & Description */}
              <div className="max-w-3xl">
                <div className="eyebrow">
                  <Sparkles className="h-3.5 w-3.5" />
                  Incident Queue
                </div>
                <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                  Alerts should feel triage-ready, not like generic
                  notifications.
                </h1>
                <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                  Analysts need immediate context, clean actions, and a surface
                  that supports quick review under pressure.
                </p>
              </div>
 
              {/* Refresh Button */}
              <button
                type="button"
                onClick={fetchAlerts}
                className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.06]"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh alerts
              </button>
            </div>
 
            {/* Stats Cards */}
            <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
              <StatsCard
                count={unacknowledged.length}
                label="Unacknowledged"
                color="red"
              />
              <StatsCard
                count={allAlerts.length}
                label="Total alerts"
                icon={ShieldAlert}
                color="slate"
              />
              <StatsCard
                count={acknowledged.length}
                label="Acknowledged"
                color="emerald"
              />
            </div>
          </section>
 
          {/* Filters Section */}
          <section className="surface-panel rounded-[28px] p-4 sm:p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              {/* Toggle Acknowledged */}
              <label className="flex cursor-pointer select-none items-center gap-2.5">
                <div className="relative">
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={showAcknowledged}
                    onChange={(e) => setShowAcknowledged(e.target.checked)}
                  />
                  <div
                    className={`h-5 w-10 rounded-full transition-colors ${
                      showAcknowledged ? "bg-cyan-600" : "bg-slate-700"
                    }`}
                  />
                  <div
                    className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${
                      showAcknowledged ? "translate-x-5" : "translate-x-0"
                    }`}
                  />
                </div>
                <span className="text-sm text-slate-400">
                  Show acknowledged
                </span>
              </label>
 
              {/* Severity Filter & Search */}
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
 
                {/* Acknowledge All Button */}
                {!showAcknowledged && unacknowledged.length > 1 && (
                  <button
                    type="button"
                    onClick={handleAcknowledgeAll}
                    disabled={ackAllLoading}
                    className="rounded-xl border border-white/10 px-3 py-2 text-xs font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:opacity-60"
                  >
                    {ackAllLoading
                      ? "Acknowledging all..."
                      : "Acknowledge all"}
                  </button>
                )}
              </div>
            </div>
          </section>
 
          {/* Error Message */}
          {error && (
            <div className="rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          )}
 
          {/* Alerts List or Loading/Empty State */}
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
                const isAcked =
                  alert.is_acknowledged || ackedIds.has(alertId);
                const isAcking = ackingIds.has(alertId);
 
                return (
                  <AlertItem
                    key={alertId}
                    alert={alert}
                    isAcked={isAcked}
                    isAcking={isAcking}
                    isDeletingIds={deletingIds}
                    isUpdatingReviewIds={updatingReviewIds}
                    onAcknowledge={handleAcknowledge}
                    onDelete={handleDelete}
                    onUpdateReviewStatus={handleUpdateReviewStatus}
                    onOpenFile={openAlertFile}
                  />
                );
              })}
            </ul>
          )}
        </div>
      </DashboardLayout>
 
      {/* File Details Modal */}
      <FileDetailsModal
        isOpen={fileModalOpen}
        isLoading={fileLoading}
        file={selectedFile}
        onClose={() => setFileModalOpen(false)}
      />
    </>
  );
}
 
