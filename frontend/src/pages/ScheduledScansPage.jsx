import React, { useCallback, useEffect, useState } from "react";
import { Clock, Play, Plus, RefreshCw, Sparkles, Trash2, ToggleLeft, ToggleRight, X } from "lucide-react";
import { scheduledScanApi } from "../api/scheduled_scans";
import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import EmptyState from "../components/ui/EmptyState";

function formatDate(isoString) {
  if (!isoString) return "-";
  return new Date(isoString).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function CreateModal({ isOpen, onClose, onCreate, loading }) {
  const [name, setName] = useState("");
  const [scanType, setScanType] = useState("text");
  const [target, setTarget] = useState("");
  const [scheduleCron, setScheduleCron] = useState("0 9 * * *");

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    onCreate({ name, scan_type: scanType, target, schedule_cron: scheduleCron });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="surface-panel-strong relative w-full max-w-md rounded-[28px] p-6 shadow-2xl">
        <button
          type="button"
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-500 transition hover:text-white"
        >
          <X className="h-5 w-5" />
        </button>
        <h3 className="mb-4 text-lg font-semibold text-white">Create Scheduled Scan</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs text-slate-400">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full rounded-xl bg-white/[0.03] border border-white/10 px-4 py-2.5 text-sm text-white outline-none focus:border-cyan-500"
              placeholder="Daily API Key Check"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Scan Type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full rounded-xl bg-white/[0.03] border border-white/10 px-4 py-2.5 text-sm text-white outline-none focus:border-cyan-500"
            >
              <option value="text">Text</option>
              <option value="file">File</option>
              <option value="network">Network</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Target Content</label>
            <textarea
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
              rows={3}
              className="w-full rounded-xl bg-white/[0.03] border border-white/10 px-4 py-2.5 text-sm text-white outline-none focus:border-cyan-500"
              placeholder="Text or URL to scan"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Schedule (Cron)</label>
            <input
              type="text"
              value={scheduleCron}
              onChange={(e) => setScheduleCron(e.target.value)}
              required
              className="w-full rounded-xl bg-white/[0.03] border border-white/10 px-4 py-2.5 text-sm text-white outline-none focus:border-cyan-500 font-mono-ui"
              placeholder="0 9 * * *"
            />
            <p className="mt-1 text-[11px] text-slate-500">Example: 0 9 * * * (daily at 9 AM)</p>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="flex-1 rounded-xl border border-white/10 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 py-2.5 text-sm font-semibold text-slate-950 transition disabled:opacity-50"
            >
              {loading ? "Creating..." : "Create"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ScheduledScansPage() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [togglingIds, setTogglingIds] = useState(new Set());
  const [deletingIds, setDeletingIds] = useState(new Set());
  const [runningIds, setRunningIds] = useState(new Set());

  const fetchJobs = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await scheduledScanApi.listJobs();
      setJobs(res.data?.items || []);
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Failed to load scheduled scans.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  async function handleCreate(jobData) {
    setCreateLoading(true);
    setError("");
    try {
      await scheduledScanApi.createJob(jobData);
      setShowCreateModal(false);
      await fetchJobs();
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to create scheduled scan.");
    } finally {
      setCreateLoading(false);
    }
  }

  async function handleToggle(jobId) {
    setTogglingIds((prev) => new Set(prev).add(jobId));
    try {
      await scheduledScanApi.toggleJob(jobId);
      await fetchJobs();
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to toggle scheduled scan.");
    } finally {
      setTogglingIds((prev) => {
        const next = new Set(prev);
        next.delete(jobId);
        return next;
      });
    }
  }

  async function handleDelete(jobId) {
    if (!confirm("Are you sure you want to delete this scheduled scan?")) return;
    setDeletingIds((prev) => new Set(prev).add(jobId));
    try {
      await scheduledScanApi.deleteJob(jobId);
      await fetchJobs();
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to delete scheduled scan.");
    } finally {
      setDeletingIds((prev) => {
        const next = new Set(prev);
        next.delete(jobId);
        return next;
      });
    }
  }

  async function handleRunNow(jobId) {
    setRunningIds((prev) => new Set(prev).add(jobId));
    try {
      await scheduledScanApi.runNow(jobId);
      await fetchJobs();
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to run scheduled scan.");
    } finally {
      setRunningIds((prev) => {
        const next = new Set(prev);
        next.delete(jobId);
        return next;
      });
    }
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <section className="surface-panel-strong rounded-[30px] p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                Automation
              </div>
              <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                Scheduled scans run automatically, so you don't have to.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Set up recurring scans for daily checks, API monitoring, or periodic content review. Runs on your schedule with Celery.
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => setShowCreateModal(true)}
                className="inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px]"
              >
                <Plus className="h-4 w-4" />
                New scheduled scan
              </button>
              <button
                type="button"
                onClick={fetchJobs}
                className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.06]"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>
        </section>

        {error && <div className="rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">{error}</div>}

        {loading ? (
          <div className="surface-panel rounded-[28px] p-10">
            <LoadingSpinner size="lg" text="Loading scheduled scans" />
          </div>
        ) : jobs.length === 0 ? (
          <EmptyState
            icon={<Clock />}
            title="No scheduled scans"
            message="Create your first scheduled scan to automate recurring checks."
            actionLabel="Create scheduled scan"
            onAction={() => setShowCreateModal(true)}
          />
        ) : (
          <div className="surface-panel overflow-hidden rounded-[28px]">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/10 text-left text-xs text-slate-500">
                    <th className="px-5 py-3.5 font-medium">Name</th>
                    <th className="px-4 py-3.5 font-medium">Type</th>
                    <th className="px-4 py-3.5 font-medium">Schedule</th>
                    <th className="px-4 py-3.5 font-medium">Status</th>
                    <th className="px-4 py-3.5 font-medium">Last Run</th>
                    <th className="px-4 py-3.5 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {jobs.map((job) => (
                    <tr key={job.job_id} className="hover:bg-white/[0.03]">
                      <td className="px-5 py-3.5 font-medium text-white">{job.name}</td>
                      <td className="px-4 py-3.5 capitalize text-slate-300">{job.scan_type}</td>
                      <td className="px-4 py-3.5 font-mono-ui text-xs text-slate-400">{job.schedule_cron}</td>
                      <td className="px-4 py-3.5">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
                            job.is_active
                              ? "bg-emerald-900/30 text-emerald-300"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {job.is_active ? "Active" : "Paused"}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-slate-400">{formatDate(job.last_run_at)}</td>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            disabled={togglingIds.has(job.job_id)}
                            onClick={() => handleToggle(job.job_id)}
                            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/[0.05] hover:text-white disabled:opacity-50"
                            title={job.is_active ? "Pause" : "Activate"}
                          >
                            {job.is_active ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                          </button>
                          <button
                            type="button"
                            disabled={runningIds.has(job.job_id)}
                            onClick={() => handleRunNow(job.job_id)}
                            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/[0.05] hover:text-white disabled:opacity-50"
                            title="Run now"
                          >
                            <Play className="h-4 w-4" />
                          </button>
                          <button
                            type="button"
                            disabled={deletingIds.has(job.job_id)}
                            onClick={() => handleDelete(job.job_id)}
                            className="rounded-lg p-1.5 text-red-400 transition hover:bg-red-600/20 hover:text-red-300 disabled:opacity-50"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      <CreateModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onCreate={handleCreate}
        loading={createLoading}
      />
    </DashboardLayout>
  );
}
