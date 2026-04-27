import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  RefreshCw,
  Search,
  Shield,
  Sparkles,
} from "lucide-react";
import { Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useAuth } from "../context/AuthContext";
import { alertApi } from "../api/alerts";
import { scanApi } from "../api/scans";
import DashboardLayout from "../components/layout/DashboardLayout";
import StatCard from "../components/ui/StatCard";
import SeverityBadge from "../components/ui/SeverityBadge";
import ActionBadge from "../components/ui/ActionBadge";
import EmptyState from "../components/ui/EmptyState";

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

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#38bdf8",
  SAFE: "#34d399",
};

function riskBarColor(score) {
  if (score > 70) return "bg-red-500";
  if (score > 40) return "bg-amber-500";
  return "bg-emerald-400";
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

function SkeletonBlock({ className = "" }) {
  return <div className={`surface-panel animate-pulse rounded-[24px] ${className}`} />;
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <SkeletonBlock className="h-44" />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <SkeletonBlock key={i} className="h-36" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <SkeletonBlock className="h-80" />
        <SkeletonBlock className="h-80" />
      </div>
      <SkeletonBlock className="h-80" />
    </div>
  );
}

function PieLegend({ data }) {
  return (
    <div className="mt-4 flex flex-wrap justify-center gap-3">
      {data.map((entry) => (
        <div key={entry.name} className="surface-panel inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs text-slate-300">
          <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
          {entry.name} ({entry.value})
        </div>
      ))}
    </div>
  );
}

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
      setError(err?.response?.data?.detail || err?.message || "Failed to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Auto-refresh every 30 seconds for real-time data
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [fetchData]);

  async function handleAcknowledge(alertId) {
    setAckingIds((prev) => new Set(prev).add(alertId));
    try {
      await alertApi.acknowledge(alertId);
      setAlerts((prev) => prev.filter((a) => (a.alert_id ?? a.id) !== alertId));
    } finally {
      setAckingIds((prev) => {
        const next = new Set(prev);
        next.delete(alertId);
        return next;
      });
    }
  }

  const pieData = stats
    ? [
        { name: "CRITICAL", value: stats.critical_scans ?? 0, color: SEVERITY_COLORS.CRITICAL },
        { name: "HIGH", value: stats.high_scans ?? 0, color: SEVERITY_COLORS.HIGH },
        { name: "MEDIUM", value: stats.medium_scans ?? 0, color: SEVERITY_COLORS.MEDIUM },
        { name: "LOW", value: stats.low_scans ?? 0, color: SEVERITY_COLORS.LOW },
        { name: "SAFE", value: stats.safe_scans ?? 0, color: SEVERITY_COLORS.SAFE },
      ].filter((d) => d.value > 0)
    : [];

  // Calculate trend data for last 7 days
  const trendData = React.useMemo(() => {
    const days = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateStr = date.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" });
      days.push({
        date: dateStr,
        scans: history.filter((h) => {
          const scanDate = new Date(h.created_at);
          return scanDate.toDateString() === date.toDateString();
        }).length,
      });
    }
    return days;
  }, [history]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <section className="surface-panel-strong overflow-hidden rounded-[30px] p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                Control Center
              </div>
              <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                Security posture, scan volume, and incidents in one operating view.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                This is the product surface buyers should see: current risk, live activity, and a clean path to action.
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <Link
                to="/scan"
                className="inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px]"
              >
                Start scan
                <ArrowRight className="h-4 w-4" />
              </Link>
              <button
                type="button"
                onClick={fetchData}
                className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.06]"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-3">
            <div className="surface-panel rounded-2xl px-4 py-4">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Current plan</p>
              <p className="mt-2 text-xl font-semibold text-white uppercase">{user?.plan ?? "free"}</p>
            </div>
            <div className="surface-panel rounded-2xl px-4 py-4">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Scans this month</p>
              <p className="mt-2 text-xl font-semibold text-white tabular-nums">{stats?.scans_this_month ?? 0}</p>
            </div>
            <div className="surface-panel rounded-2xl px-4 py-4">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Open alerts</p>
              <p className="mt-2 text-xl font-semibold text-white tabular-nums">{alerts.length}</p>
            </div>
          </div>
        </section>

        {error && (
          <div className="rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {loading ? (
          <DashboardSkeleton />
        ) : (
          <>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard title="Total Scans" value={stats?.total_scans ?? 0} icon={<Search />} color="bg-cyan-700" />
              <StatCard title="Critical Threats" value={stats?.critical_scans ?? 0} icon={<AlertTriangle />} color="bg-red-700" />
              <StatCard title="Scans This Month" value={stats?.scans_this_month ?? 0} icon={<Activity />} color="bg-emerald-700" />
              <StatCard title="Plan" value={(user?.plan ?? "FREE").toUpperCase()} icon={<Shield />} color="bg-sky-700" />
            </div>

            <div className="surface-panel rounded-[28px] p-5">
              <div className="mb-4">
                <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Activity</p>
                <h2 className="mt-1 text-sm font-semibold text-white">Scan activity (last 7 days)</h2>
              </div>
              {trendData.every((d) => d.scans === 0) ? (
                <EmptyState
                  icon={<Activity />}
                  title="No recent activity"
                  message="Scan activity will appear here once you start using the platform."
                />
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={trendData}>
                    <XAxis
                      dataKey="date"
                      stroke="#64748b"
                      fontSize={12}
                      tickLine={false}
                      axisLine={false}
                    />
                    <YAxis
                      stroke="#64748b"
                      fontSize={12}
                      tickLine={false}
                      axisLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#09131d",
                        border: "1px solid rgba(120,145,168,0.18)",
                        borderRadius: "16px",
                        color: "#f8fafc",
                        fontSize: "12px",
                      }}
                      itemStyle={{ color: "#dbe7f3" }}
                    />
                    <Line
                      type="monotone"
                      dataKey="scans"
                      stroke="#22d3ee"
                      strokeWidth={2}
                      dot={{ fill: "#22d3ee", r: 4 }}
                      activeDot={{ r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <div className="surface-panel rounded-[28px] p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Alerts</p>
                    <h2 className="mt-1 text-sm font-semibold text-white">Recent alerts</h2>
                  </div>
                  <Link to="/alerts" className="text-xs font-medium text-cyan-300 transition hover:text-cyan-200">
                    View all
                  </Link>
                </div>

                {alerts.length === 0 ? (
                  <EmptyState
                    icon={<CheckCircle />}
                    title="No active alerts"
                    message="Current detections are under control. New incidents will appear here."
                  />
                ) : (
                  <ul className="space-y-3">
                    {alerts.map((alert) => {
                      const alertId = alert.alert_id ?? alert.id;
                      return (
                        <li key={alertId} className="hover-lift rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-4">
                          <div className="flex items-start gap-3">
                            <SeverityBadge severity={alert.severity} />
                            <div className="min-w-0 flex-1">
                              <p className="truncate text-sm font-semibold text-white">{alert.title ?? alert.message ?? "Alert"}</p>
                              <p className="mt-1 text-sm leading-6 text-slate-400">
                                {(alert.description ?? alert.message ?? "").slice(0, 110) || "No additional description."}
                              </p>
                              <div className="mt-3 flex items-center justify-between gap-3">
                                <span className="text-xs text-slate-500">{timeAgo(alert.created_at)}</span>
                                <button
                                  type="button"
                                  disabled={ackingIds.has(alertId)}
                                  onClick={() => handleAcknowledge(alertId)}
                                  className="rounded-xl border border-white/10 px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:bg-white/[0.06] disabled:opacity-50"
                                >
                                  {ackingIds.has(alertId) ? "Acknowledging..." : "Acknowledge"}
                                </button>
                              </div>
                            </div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>

              <div className="surface-panel rounded-[28px] p-5">
                <div className="mb-4">
                  <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Distribution</p>
                  <h2 className="mt-1 text-sm font-semibold text-white">Scan severity mix</h2>
                </div>
                {pieData.length === 0 ? (
                  <EmptyState
                    icon={<Activity />}
                    title="No scan data yet"
                    message="Run scans to populate severity distribution and trends."
                  />
                ) : (
                  <>
                    <ResponsiveContainer width="100%" height={240}>
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={92} paddingAngle={4} dataKey="value">
                          {pieData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#09131d",
                            border: "1px solid rgba(120,145,168,0.18)",
                            borderRadius: "16px",
                            color: "#f8fafc",
                            fontSize: "12px",
                          }}
                          itemStyle={{ color: "#dbe7f3" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <PieLegend data={pieData} />
                  </>
                )}
              </div>
            </div>

            <div className="surface-panel overflow-hidden rounded-[28px]">
              <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
                <div>
                  <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">History</p>
                  <h2 className="mt-1 text-sm font-semibold text-white">Recent scan history</h2>
                </div>
                <Link to="/history" className="text-xs font-medium text-cyan-300 transition hover:text-cyan-200">
                  Open history
                </Link>
              </div>

              {history.length === 0 ? (
                <div className="p-6">
                  <EmptyState
                    icon={<Search />}
                    title="No scans yet"
                    message="Run your first scan to start building history and audit evidence."
                    actionLabel="Open scanner"
                    onAction={() => {
                      window.location.href = "/scan";
                    }}
                  />
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/10 text-left text-xs text-slate-500">
                        <th className="px-5 py-3 font-medium">Time</th>
                        <th className="px-4 py-3 font-medium">Type</th>
                        <th className="px-4 py-3 font-medium">Severity</th>
                        <th className="px-4 py-3 font-medium">Risk Score</th>
                        <th className="px-4 py-3 font-medium">Action</th>
                        <th className="px-4 py-3 font-medium">Entities</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/10">
                      {history.map((scan, index) => {
                        const risk = Math.round(scan.risk_score ?? 0);
                        return (
                          <tr key={scan.scan_id ?? scan.id ?? index} className="hover:bg-white/[0.03]">
                            <td className="px-5 py-3 whitespace-nowrap text-slate-400">{timeAgo(scan.created_at)}</td>
                            <td className="px-4 py-3 capitalize text-slate-200">{scan.scan_type ?? "-"}</td>
                            <td className="px-4 py-3">
                              <SeverityBadge severity={scan.severity} />
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800">
                                  <div className={`h-full rounded-full ${riskBarColor(risk)}`} style={{ width: `${Math.min(risk, 100)}%` }} />
                                </div>
                                <span className="text-xs tabular-nums text-slate-400">{risk}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <ActionBadge action={scan.recommended_action} />
                            </td>
                            <td className="px-4 py-3 text-slate-300 tabular-nums">{scan.total_entities ?? 0}</td>
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
