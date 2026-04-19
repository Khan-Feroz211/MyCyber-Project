import React, { useCallback, useEffect, useState } from "react";
import { RefreshCw, Shield } from "lucide-react";
import { alertApi } from "../api/alerts";
import DashboardLayout from "../components/layout/DashboardLayout";
import SeverityBadge from "../components/ui/SeverityBadge";
import EmptyState from "../components/ui/EmptyState";

/* ─── helpers ──────────────────────────────────────────────────────── */

function timeAgo(isoString) {
  if (!isoString) return "—";
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60_000);
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
  LOW: "border-l-blue-500",
  SAFE: "border-l-green-500",
};

function leftBorderColor(severity) {
  return LEFT_BORDER_COLORS[(severity ?? "").toUpperCase()] ?? "border-l-gray-600";
}

function normalizeAlerts(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  if (Array.isArray(payload.alerts)) return payload.alerts;
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.results)) return payload.results;
  return [];
}

/* ─── Main page ────────────────────────────────────────────────────── */
export default function AlertsPage() {
  const [allAlerts, setAllAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showAcknowledged, setShowAcknowledged] = useState(false);
  const [ackingIds, setAckingIds] = useState(new Set());
  const [ackedIds, setAckedIds] = useState(new Set());

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await alertApi.getAlerts(true, 1, 100);
      setAllAlerts(normalizeAlerts(res.data));
    } catch (err) {
      setError(
        err?.response?.data?.detail || err?.message || "Failed to load alerts."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  async function handleAcknowledge(alertId) {
    // Optimistic update
    setAckingIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.acknowledge(alertId);
      setAckedIds((prev) => new Set(prev).add(alertId));
      setAllAlerts((prev) =>
        prev.map((a) =>
          a.id === alertId ? { ...a, acknowledged: true } : a
        )
      );
    } catch {
      // revert optimistic if needed — badge will stay as before
    } finally {
      setAckingIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }

  /* Counts */
  const acknowledged = allAlerts.filter(
    (a) => a.acknowledged || ackedIds.has(a.id)
  );
  const unacknowledged = allAlerts.filter(
    (a) => !a.acknowledged && !ackedIds.has(a.id)
  );

  /* Filtered list */
  const visibleAlerts = showAcknowledged ? allAlerts : unacknowledged;

  return (
    <DashboardLayout>
      <div className="space-y-5">
        {/* ── Stats row ── */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 flex items-center gap-3">
            <span className="flex items-center justify-center h-9 w-9 rounded-full bg-red-900/50">
              <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
            </span>
            <div>
              <p className="text-2xl font-bold text-white tabular-nums">
                {unacknowledged.length}
              </p>
              <p className="text-xs text-gray-400">Unacknowledged</p>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 flex items-center gap-3">
            <span className="flex items-center justify-center h-9 w-9 rounded-full bg-gray-800">
              <span className="h-2 w-2 rounded-full bg-gray-400" />
            </span>
            <div>
              <p className="text-2xl font-bold text-white tabular-nums">
                {allAlerts.length}
              </p>
              <p className="text-xs text-gray-400">Total alerts</p>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 flex items-center gap-3">
            <span className="flex items-center justify-center h-9 w-9 rounded-full bg-green-900/50">
              <span className="h-2 w-2 rounded-full bg-green-500" />
            </span>
            <div>
              <p className="text-2xl font-bold text-white tabular-nums">
                {acknowledged.length}
              </p>
              <p className="text-xs text-gray-400">Acknowledged</p>
            </div>
          </div>
        </div>

        {/* ── Toolbar ── */}
        <div className="flex items-center justify-between">
          {/* Toggle: show acknowledged */}
          <label className="flex items-center gap-2.5 cursor-pointer select-none">
            <div className="relative">
              <input
                type="checkbox"
                className="sr-only"
                checked={showAcknowledged}
                onChange={(e) => setShowAcknowledged(e.target.checked)}
              />
              <div
                className={`w-10 h-5 rounded-full transition-colors ${
                  showAcknowledged ? "bg-cyber-600" : "bg-gray-700"
                }`}
              />
              <div
                className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${
                  showAcknowledged ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </div>
            <span className="text-sm text-gray-400">Show acknowledged</span>
          </label>

          <button
            type="button"
            onClick={fetchAlerts}
            className="flex items-center gap-1.5 rounded-lg text-xs text-gray-400 hover:text-white hover:bg-gray-800 px-3 py-1.5 transition"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        {/* ── Error ── */}
        {error && (
          <div className="rounded-lg bg-red-950 border border-red-700 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* ── Loading skeleton ── */}
        {loading && (
          <div className="space-y-3">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className="h-24 animate-pulse bg-gray-800 rounded-xl"
              />
            ))}
          </div>
        )}

        {/* ── Alert cards ── */}
        {!loading && visibleAlerts.length === 0 && (
          <EmptyState
            icon={<Shield />}
            title="No active security alerts"
            message="You're all clear. Alerts will appear here when MyCyber DLP detects a threat."
          />
        )}

        {!loading && visibleAlerts.length > 0 && (
          <ul className="space-y-3">
            {visibleAlerts.map((alert) => {
              const isAcked = alert.acknowledged || ackedIds.has(alert.id);
              const isAcking = ackingIds.has(alert.id);
              return (
                <li
                  key={alert.id}
                  className={`bg-gray-900 border border-gray-800 border-l-4 ${leftBorderColor(
                    alert.severity
                  )} rounded-xl px-5 py-4 ${isAcked ? "opacity-60" : ""}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-sm font-semibold text-white truncate">
                          {alert.title ?? alert.message ?? "Security Alert"}
                        </p>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                      {(alert.description ?? alert.message) && (
                        <p className="text-sm text-gray-400 leading-relaxed line-clamp-2">
                          {(alert.description ?? alert.message ?? "").slice(0, 150)}
                        </p>
                      )}
                      <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-gray-500">
                        {alert.scan_id && (
                          <span className="font-mono">
                            scan:{String(alert.scan_id).slice(0, 8)}…
                          </span>
                        )}
                        <span>{timeAgo(alert.created_at)}</span>
                      </div>
                    </div>

                    {!isAcked && (
                      <button
                        type="button"
                        disabled={isAcking}
                        onClick={() => handleAcknowledge(alert.id)}
                        className={`shrink-0 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                          isAcking
                            ? "border-green-600 text-green-400 opacity-60 cursor-wait"
                            : "border-gray-600 text-gray-300 hover:border-green-500 hover:text-green-400"
                        }`}
                      >
                        {isAcking ? "Acknowledging…" : "Acknowledge"}
                      </button>
                    )}
                    {isAcked && (
                      <span className="shrink-0 text-xs text-green-500 font-medium">
                        ✓ Acknowledged
                      </span>
                    )}
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
