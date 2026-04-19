import React, { useCallback, useEffect, useState } from "react";
import {
  Clock,
  Eye,
  File,
  FileText,
  Filter,
  Globe,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import { scanApi } from "../api/scans";
import DashboardLayout from "../components/layout/DashboardLayout";
import SeverityBadge from "../components/ui/SeverityBadge";
import ActionBadge from "../components/ui/ActionBadge";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import EmptyState from "../components/ui/EmptyState";

function formatDate(isoString) {
  if (!isoString) return "-";
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
  return "bg-emerald-400";
}

function normalizeScans(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  if (Array.isArray(payload.scans)) return payload.scans;
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.results)) return payload.results;
  return [];
}

function ScanTypeIcon({ type }) {
  const t = (type ?? "").toLowerCase();
  if (t === "file") return <File className="h-3.5 w-3.5 text-slate-400" />;
  if (t === "network") return <Globe className="h-3.5 w-3.5 text-slate-400" />;
  return <FileText className="h-3.5 w-3.5 text-slate-400" />;
}

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];
const SCAN_TYPES = ["ALL", "TEXT", "FILE", "NETWORK"];
const PAGE_SIZES = [10, 20, 50];

function ScanDetailModal({ scan, onClose }) {
  if (!scan) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <aside className="surface-panel-strong relative z-10 h-full w-full max-w-sm overflow-y-auto border-l p-6 shadow-2xl">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Scan Details</h2>
          <button
            type="button"
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-white/[0.05] hover:text-white"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <dl className="space-y-4">
          <div>
            <dt className="mb-1 text-xs text-slate-500">Date / Time</dt>
            <dd className="text-sm text-white">{formatDate(scan.created_at)}</dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-slate-500">Scan Type</dt>
            <dd className="text-sm capitalize text-white">{scan.scan_type ?? "-"}</dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-slate-500">Severity</dt>
            <dd><SeverityBadge severity={scan.severity} /></dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-slate-500">Risk Score</dt>
            <dd className="text-sm text-white tabular-nums">{Math.round(scan.risk_score ?? 0)} / 100</dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-slate-500">Recommended Action</dt>
            <dd><ActionBadge action={scan.recommended_action} /></dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-slate-500">Summary</dt>
            <dd className="text-sm leading-relaxed text-slate-300">{scan.summary ?? "-"}</dd>
          </div>
          {scan.input_preview && (
            <div>
              <dt className="mb-1 text-xs text-slate-500">Preview</dt>
              <dd className="font-mono-ui rounded-xl border border-white/10 bg-white/[0.03] p-3 text-xs break-words text-slate-300">
                {scan.input_preview}
              </dd>
            </div>
          )}
          {Array.isArray(scan.entities) && scan.entities.length > 0 && (
            <div>
              <dt className="mb-2 text-xs text-slate-500">Entities ({scan.entities.length})</dt>
              <dd>
                <ul className="space-y-2">
                  {scan.entities.map((ent, idx) => (
                    <li key={idx} className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs">
                      <div className="mb-1 flex items-center justify-between">
                        <span className="font-medium uppercase tracking-wide text-slate-400">
                          {ent.entity_type ?? ent.type ?? "-"}
                        </span>
                        <SeverityBadge severity={ent.severity} />
                      </div>
                      <p className="font-mono-ui break-all text-slate-300">{ent.redacted_value ?? ent.value ?? "-"}</p>
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
      const normalizedScans = normalizeScans(data);
      setScans(normalizedScans);
      setTotal(typeof data?.total === "number" ? data.total : normalizedScans.length);
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Failed to load history.");
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severityFilter, typeFilter]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

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
      <div className="space-y-6">
        <section className="surface-panel-strong rounded-[30px] p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                Audit Trail
              </div>
              <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                Scan history should read like evidence, not raw rows.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                This view is where reviewers, auditors, and internal teams evaluate what happened, when it happened, and what action followed.
              </p>
            </div>
            <button
              type="button"
              onClick={fetchScans}
              className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.06]"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh history
            </button>
          </div>
        </section>

        <section className="surface-panel rounded-[28px] px-5 py-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mr-1 flex items-center gap-1 text-xs font-medium text-slate-500">
              <Filter className="h-3 w-3" /> Severity
            </span>
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => handleSeverityFilter(s)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  severityFilter === s
                    ? "bg-gradient-to-r from-emerald-400 to-cyan-400 text-slate-950"
                    : "bg-white/[0.03] text-slate-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mr-1 text-xs font-medium text-slate-500">Type</span>
              {SCAN_TYPES.map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => handleTypeFilter(t)}
                  className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                    typeFilter === t
                      ? "bg-gradient-to-r from-emerald-400 to-cyan-400 text-slate-950"
                      : "bg-white/[0.03] text-slate-400 hover:text-white"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-slate-400">
              <Search className="h-3.5 w-3.5" />
              {total} records
            </div>
          </div>
        </section>

        {error && <div className="rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">{error}</div>}

        <div className="surface-panel overflow-hidden rounded-[28px]">
          {loading ? (
            <div className="p-10">
              <LoadingSpinner size="lg" text="Loading history" />
            </div>
          ) : scans.length === 0 ? (
            <div className="p-6">
              <EmptyState
                icon={<Clock />}
                title="No scans found"
                message="No scans match your current filters. Adjust the filters or run a new scan."
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/10 text-left text-xs text-slate-500">
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
                <tbody className="divide-y divide-white/10">
                  {scans.map((scan) => {
                    const risk = Math.round(scan.risk_score ?? 0);
                    return (
                      <tr key={scan.scan_id ?? scan.id} className="hover:bg-white/[0.03]">
                        <td className="px-5 py-3 whitespace-nowrap text-xs text-slate-400">
                          {formatDate(scan.created_at)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5 text-xs capitalize text-slate-300">
                            <ScanTypeIcon type={scan.scan_type} />
                            {scan.scan_type ?? "-"}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={scan.severity} />
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">
                              <div className={`h-full rounded-full ${riskBarColor(risk)}`} style={{ width: `${Math.min(risk, 100)}%` }} />
                            </div>
                            <span className="text-xs tabular-nums text-slate-400">{risk}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <ActionBadge action={scan.recommended_action} />
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-flex min-w-[1.75rem] items-center justify-center rounded-full bg-white/[0.05] px-2 py-1 text-xs font-medium tabular-nums text-slate-300">
                            {scan.total_entities ?? 0}
                          </span>
                        </td>
                        <td className="max-w-[160px] px-4 py-3 text-xs text-slate-400">
                          <span className="block truncate" title={scan.input_preview ?? ""}>
                            {(scan.input_preview ?? "").slice(0, 60) || "-"}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={() => setSelectedScan(scan)}
                            className="flex h-8 w-8 items-center justify-center rounded-xl text-slate-400 transition hover:bg-white/[0.05] hover:text-white"
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

        {!loading && scans.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 px-1">
            <p className="text-xs text-slate-500">
              Showing {start}-{end} of {total} scans
            </p>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="rounded-xl bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/[0.06] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              >
                Previous
              </button>
              <span className="text-xs text-slate-500">
                {page} / {totalPages}
              </span>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="rounded-xl bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/[0.06] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>

              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="rounded-xl border border-white/10 bg-white/[0.03] px-2 py-1.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none"
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

      {selectedScan && <ScanDetailModal scan={selectedScan} onClose={() => setSelectedScan(null)} />}
    </DashboardLayout>
  );
}
