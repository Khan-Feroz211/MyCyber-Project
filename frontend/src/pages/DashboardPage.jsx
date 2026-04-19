import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Search,
  Shield,
} from "lucide-react";
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { useAuth } from "../context/AuthContext";
import { alertApi } from "../api/alerts";
import { scanApi } from "../api/scans";
import DashboardLayout from "../components/layout/DashboardLayout";
import StatCard from "../components/ui/StatCard";
import SeverityBadge from "../components/ui/SeverityBadge";
import ActionBadge from "../components/ui/ActionBadge";
import LoadingSpinner from "../components/ui/LoadingSpinner";

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

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  SAFE: "#22c55e",
};

function riskBarColor(score) {
  if (score > 70) return "bg-red-500";
  if (score > 40) return "bg-amber-500";
  return "bg-green-500";
}

function normalizeList(payload, candidateKeys = []) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];

  for (const key of candidateKeys) {
    const value = payload[key];
    if (Array.isArray(value)) return value;
  }

  return [];
}

/* ─── Skeleton loader ──────────────────────────────────────────────── */
function SkeletonBlock({ className = "" }) {
  return (
    <div className={`animate-pulse bg-gray-800 rounded-lg ${className}`} />
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <SkeletonBlock key={i} className="h-32" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonBlock className="h-72" />
        <SkeletonBlock className="h-72" />
      </div>
      <SkeletonBlock className="h-64" />
    </div>
  );
}

/* ─── Pie chart custom legend ──────────────────────────────────────── */
function PieLegend({ data }) {
  return (
    <div className="flex flex-wrap justify-center gap-3 mt-3">
      {data.map((entry) => (
        <div key={entry.name} className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-xs text-gray-400">
            {entry.name} ({entry.value})
          </span>
        </div>
      ))}
    </div>
  );
}

/* ─── Main page ────────────────────────────────────────────────────── */
export default function DashboardPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [ackingIds, setAckingIds] = useState(new Set());

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [statsRes, alertsRes, historyRes] = await Promise.all([
        scanApi.getStats(),
        alertApi.getAlerts(false, 1, 5),
        scanApi.getHistory(1, 5),
      ]);
      setStats(statsRes.data);
      setAlerts(normalizeList(alertsRes.data, ["alerts", "items", "results", "data"]));
      setHistory(normalizeList(historyRes.data, ["scans", "items", "results", "data"]));
    } catch (err) {
      setError(
        err?.response?.data?.detail || err?.message || "Failed to load dashboard data."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  async function handleAcknowledge(alertId) {
    setAckingIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.acknowledge(alertId);
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
    } finally {
      setAckingIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }

  /* Build pie chart data from stats */
  const pieData = stats
    ? [
        { name: "CRITICAL", value: stats.critical_scans ?? 0, color: SEVERITY_COLORS.CRITICAL },
        { name: "HIGH", value: stats.high_scans ?? 0, color: SEVERITY_COLORS.HIGH },
        { name: "MEDIUM", value: stats.medium_scans ?? 0, color: SEVERITY_COLORS.MEDIUM },
        { name: "LOW", value: stats.low_scans ?? 0, color: SEVERITY_COLORS.LOW },
        { name: "SAFE", value: stats.safe_scans ?? 0, color: SEVERITY_COLORS.SAFE },
      ].filter((d) => d.value > 0)
    : [];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* ── Error ── */}
        {error && (
          <div className="flex items-center justify-between rounded-lg bg-red-950 border border-red-700 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
            <button
              type="button"
              onClick={fetchData}
              className="flex items-center gap-1.5 text-xs text-red-300 hover:text-white transition"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Retry
            </button>
          </div>
        )}

        {loading ? (
          <DashboardSkeleton />
        ) : (
          <>
            {/* ── Stat cards ── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <StatCard
                title="Total Scans"
                value={stats?.total_scans ?? 0}
                icon={<Search />}
                color="bg-cyber-700"
              />
              <StatCard
                title="Critical Threats"
                value={stats?.critical_scans ?? 0}
                icon={<AlertTriangle />}
                color="bg-red-700"
              />
              <StatCard
                title="Scans This Month"
                value={stats?.scans_this_month ?? 0}
                icon={<Activity />}
                color="bg-cyan-700"
              />
              <StatCard
                title="Plan"
                value={(user?.plan ?? "FREE").toUpperCase()}
                icon={<Shield />}
                color="bg-purple-700"
              />
            </div>

            {/* ── Middle row ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Recent Alerts */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-semibold text-white">Recent Alerts</h2>
                  <Link
                    to="/alerts"
                    className="text-xs text-cyan-400 hover:text-cyan-300 transition"
                  >
                    View all →
                  </Link>
                </div>

                {alerts.length === 0 ? (
                  <div className="flex flex-col items-center py-10 gap-2 text-center">
                    <CheckCircle className="h-10 w-10 text-green-500" />
                    <p className="text-sm font-medium text-white">All clear</p>
                    <p className="text-xs text-gray-500">No unacknowledged alerts</p>
                  </div>
                ) : (
                  <ul className="space-y-2">
                    {alerts.map((alert) => (
                      <li
                        key={alert.id}
                        className="flex items-center gap-3 rounded-lg bg-gray-800/60 px-3 py-2.5"
                      >
                        <SeverityBadge severity={alert.severity} />
                        <span className="flex-1 min-w-0 text-sm text-gray-200 truncate">
                          {alert.title ?? alert.message ?? "Alert"}
                        </span>
                        <span className="text-xs text-gray-500 shrink-0">
                          {timeAgo(alert.created_at)}
                        </span>
                        <button
                          type="button"
                          disabled={ackingIds.has(alert.id)}
                          onClick={() => handleAcknowledge(alert.id)}
                          className="shrink-0 rounded px-2 py-1 text-xs font-medium bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white transition disabled:opacity-50"
                        >
                          Ack
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Scan Distribution */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <h2 className="text-sm font-semibold text-white mb-4">
                  Scan Distribution
                </h2>
                {pieData.length === 0 ? (
                  <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
                    No scan data yet
                  </div>
                ) : (
                  <>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={pieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={55}
                          outerRadius={85}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {pieData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#1f2937",
                            border: "1px solid #374151",
                            borderRadius: "8px",
                            color: "#f9fafb",
                            fontSize: "12px",
                          }}
                          itemStyle={{ color: "#d1d5db" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <PieLegend data={pieData} />
                  </>
                )}
              </div>
            </div>

            {/* ── Recent scan history ── */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Recent Scan History</h2>
                <Link
                  to="/history"
                  className="text-xs text-cyan-400 hover:text-cyan-300 transition"
                >
                  View full history →
                </Link>
              </div>

              {history.length === 0 ? (
                <div className="py-12 text-center text-gray-500 text-sm">
                  No scans yet. <Link to="/scan" className="text-cyan-400 hover:text-cyan-300">Run your first scan →</Link>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-gray-500 border-b border-gray-800">
                        <th className="px-5 py-3 font-medium">Time</th>
                        <th className="px-4 py-3 font-medium">Type</th>
                        <th className="px-4 py-3 font-medium">Severity</th>
                        <th className="px-4 py-3 font-medium">Risk Score</th>
                        <th className="px-4 py-3 font-medium">Action</th>
                        <th className="px-4 py-3 font-medium">Entities</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {history.map((scan) => {
                        const risk = Math.round(scan.risk_score ?? 0);
                        return (
                          <tr
                            key={scan.id}
                            className="hover:bg-gray-800/50 transition"
                          >
                            <td className="px-5 py-3 text-gray-400 whitespace-nowrap">
                              {timeAgo(scan.created_at)}
                            </td>
                            <td className="px-4 py-3 text-gray-300 capitalize">
                              {scan.scan_type ?? "—"}
                            </td>
                            <td className="px-4 py-3">
                              <SeverityBadge severity={scan.severity} />
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <div className="w-20 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${riskBarColor(risk)}`}
                                    style={{ width: `${Math.min(risk, 100)}%` }}
                                  />
                                </div>
                                <span className="text-xs text-gray-400 tabular-nums">
                                  {risk}
                                </span>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <ActionBadge action={scan.recommended_action} />
                            </td>
                            <td className="px-4 py-3 text-gray-300 tabular-nums">
                              {scan.total_entities ?? 0}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
