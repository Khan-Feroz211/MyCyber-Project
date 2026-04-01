import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  Eye,
  EyeOff,
  File,
  FileText,
  Filter,
  Globe,
  RefreshCw,
  X,
} from "lucide-react";
import { scanApi } from "../api/scans";
import DashboardLayout from "../components/layout/DashboardLayout";
import SeverityBadge from "../components/ui/SeverityBadge";
import ActionBadge from "../components/ui/ActionBadge";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import EmptyState from "../components/ui/EmptyState";

/* ─── helpers ──────────────────────────────────────────────────────── */

function formatDate(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString);
  return d.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function riskBarColor(score) {
  if (score > 70) return "bg-red-500";
  if (score > 40) return "bg-amber-500";
  return "bg-green-500";
}

function ScanTypeIcon({ type }) {
  const t = (type ?? "").toLowerCase();
  if (t === "file") return <File className="h-3.5 w-3.5 text-gray-400" />;
  if (t === "network") return <Globe className="h-3.5 w-3.5 text-gray-400" />;
  return <FileText className="h-3.5 w-3.5 text-gray-400" />;
}

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];
const SCAN_TYPES = ["ALL", "TEXT", "FILE", "NETWORK"];
const PAGE_SIZES = [10, 20, 50];

function SkeletonBlock({ className = "" }) {
  return <div className={`animate-pulse bg-gray-800 rounded-lg ${className}`} />;
}

/* ─── Detail modal (slide-in from right) ──────────────────────────── */
function ScanDetailModal({ scan, onClose }) {
  if (!scan) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      {/* Panel */}
      <aside className="relative z-10 w-full max-w-sm bg-gray-900 border-l border-gray-800 h-full overflow-y-auto p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-base font-semibold text-white">Scan Details</h2>
          <button
            type="button"
            onClick={onClose}
            className="flex items-center justify-center h-8 w-8 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <dl className="space-y-4">
          <div>
            <dt className="text-xs text-gray-500 mb-1">Date / Time</dt>
            <dd className="text-sm text-white">{formatDate(scan.created_at)}</dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 mb-1">Scan Type</dt>
            <dd className="text-sm text-white capitalize">{scan.scan_type ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 mb-1">Severity</dt>
            <dd><SeverityBadge severity={scan.severity} /></dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 mb-1">Risk Score</dt>
            <dd className="text-sm text-white tabular-nums">
              {Math.round(scan.risk_score ?? 0)} / 100
            </dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 mb-1">Recommended Action</dt>
            <dd><ActionBadge action={scan.recommended_action} /></dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 mb-1">Summary</dt>
            <dd className="text-sm text-gray-300 leading-relaxed">
              {scan.summary ?? "—"}
            </dd>
          </div>
          {scan.input_preview && (
            <div>
              <dt className="text-xs text-gray-500 mb-1">Preview</dt>
              <dd className="text-xs text-gray-400 font-mono bg-gray-800 rounded p-2 break-words">
                {scan.input_preview}
              </dd>
            </div>
          )}
          {Array.isArray(scan.entities) && scan.entities.length > 0 && (
            <div>
              <dt className="text-xs text-gray-500 mb-2">
                Entities ({scan.entities.length})
              </dt>
              <dd>
                <ul className="space-y-2">
                  {scan.entities.map((ent, idx) => (
                    <li
                      key={idx}
                      className="rounded-lg bg-gray-800 px-3 py-2 text-xs"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-gray-400 font-medium uppercase tracking-wide">
                          {ent.entity_type ?? ent.type ?? "—"}
                        </span>
                        <SeverityBadge severity={ent.severity} />
                      </div>
                      <p className="text-gray-300 font-mono break-all">
                        {ent.redacted_value ?? ent.value ?? "—"}
                      </p>
                    </li>
                  ))}
                </ul>
              </dd>
            </div>
          )}
        </dl>
      </aside>
    </div>
  );
}

/* ─── Main page ────────────────────────────────────────────────────── */
export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedScan, setSelectedScan] = useState(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await scanApi.getHistory(
        page,
        pageSize,
        severityFilter !== "ALL" ? severityFilter : undefined,
        typeFilter !== "ALL" ? typeFilter.toLowerCase() : undefined
      );
      const data = res.data;
      setScans(data?.scans ?? data ?? []);
      setTotal(data?.total ?? (data?.scans ?? data ?? []).length);
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Failed to load history.");
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severityFilter, typeFilter]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  /* Reset to page 1 when filters change */
  function handleSeverityFilter(val) {
    setSeverityFilter(val);
    setPage(1);
  }
  function handleTypeFilter(val) {
    setTypeFilter(val);
    setPage(1);
  }

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <DashboardLayout>
      <div className="space-y-4">
        {/* ── Filter bar ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 space-y-3">
          {/* Severity pills */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-gray-500 font-medium mr-1 flex items-center gap-1">
              <Filter className="h-3 w-3" /> Severity
            </span>
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => handleSeverityFilter(s)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  severityFilter === s
                    ? "bg-cyber-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Type pills + refresh */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-gray-500 font-medium mr-1">Type</span>
              {SCAN_TYPES.map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => handleTypeFilter(t)}
                  className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                    typeFilter === t
                      ? "bg-cyber-600 text-white"
                      : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={fetchScans}
              className="flex items-center gap-1.5 rounded-lg text-xs text-gray-400 hover:text-white hover:bg-gray-800 px-3 py-1.5 transition"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
          </div>
        </div>

        {/* ── Error ── */}
        {error && (
          <div className="rounded-lg bg-red-950 border border-red-700 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* ── Table ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          {loading ? (
            <div className="p-6 space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-10 animate-pulse bg-gray-800 rounded-lg" />
              ))}
            </div>
          ) : scans.length === 0 ? (
            <EmptyState
              icon={<Clock />}
              title="No scans found"
              message="No scans match your current filters. Try adjusting them or run a new scan."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-500 border-b border-gray-800">
                    <th className="px-5 py-3 font-medium">Date / Time</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 font-medium">Severity</th>
                    <th className="px-4 py-3 font-medium">Risk</th>
                    <th className="px-4 py-3 font-medium">Action</th>
                    <th className="px-4 py-3 font-medium">Entities</th>
                    <th className="px-4 py-3 font-medium">Preview</th>
                    <th className="px-4 py-3 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {scans.map((scan) => {
                    const risk = Math.round(scan.risk_score ?? 0);
                    return (
                      <tr
                        key={scan.id}
                        className="hover:bg-gray-800/50 transition"
                      >
                        <td className="px-5 py-3 text-gray-400 whitespace-nowrap text-xs">
                          {formatDate(scan.created_at)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5 text-gray-300 capitalize text-xs">
                            <ScanTypeIcon type={scan.scan_type} />
                            {scan.scan_type ?? "—"}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={scan.severity} />
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${riskBarColor(risk)}`}
                                style={{ width: `${Math.min(risk, 100)}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-400 tabular-nums">{risk}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <ActionBadge action={scan.recommended_action} />
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center justify-center min-w-[1.5rem] h-5 rounded-full bg-gray-800 text-gray-300 text-xs font-medium tabular-nums px-1.5">
                            {scan.total_entities ?? 0}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400 max-w-[160px]">
                          <span className="truncate block" title={scan.input_preview ?? ""}>
                            {(scan.input_preview ?? "").slice(0, 60) || "—"}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={() => setSelectedScan(scan)}
                            className="flex items-center justify-center h-7 w-7 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
                            aria-label="View details"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Pagination ── */}
        {!loading && scans.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 px-1">
            <p className="text-xs text-gray-500">
              Showing {start}–{end} of {total} scans
            </p>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="rounded-lg px-3 py-1.5 text-xs font-medium bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition"
              >
                Previous
              </button>
              <span className="text-xs text-gray-500">
                {page} / {totalPages}
              </span>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="rounded-lg px-3 py-1.5 text-xs font-medium bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition"
              >
                Next
              </button>

              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="rounded-lg bg-gray-800 border border-gray-700 text-gray-300 text-xs px-2 py-1.5 focus:outline-none focus:border-cyan-500"
              >
                {PAGE_SIZES.map((s) => (
                  <option key={s} value={s}>
                    {s} / page
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Detail modal */}
      {selectedScan && (
        <ScanDetailModal scan={selectedScan} onClose={() => setSelectedScan(null)} />
      )}
    </DashboardLayout>
  );
}
