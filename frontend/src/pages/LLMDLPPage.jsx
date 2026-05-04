import React, { useCallback, useEffect, useRef, useState } from "react";
import { Brain, ChevronDown, ChevronUp, Clock, Play, RefreshCw, Shield, Sparkles } from "lucide-react";
import { llmDlpApi } from "../api/llm_dlp";
import DashboardLayout from "../components/layout/DashboardLayout";
import EmptyState from "../components/ui/EmptyState";
import LoadingSpinner from "../components/ui/LoadingSpinner";

const STATUS_COLORS = {
  allowed: "text-emerald-300 bg-emerald-900/20 border-emerald-700/50",
  blocked: "text-red-300 bg-red-900/20 border-red-700/50",
  redacted: "text-amber-300 bg-amber-900/20 border-amber-700/50",
  violation: "text-red-300 bg-red-900/20 border-red-700/50",
};

function formatDate(isoString) {
  if (!isoString) return "-";
  return new Date(isoString).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function LLMDLPPage() {
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const promptRef = useRef(null);

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await llmDlpApi.getHistory(1, 20);
      setHistory(res.data?.items || []);
    } catch (e) {
      // silent
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const res = await llmDlpApi.getStats();
      setStats(res.data);
    } catch (e) {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchHistory();
    fetchStats();
  }, [fetchHistory, fetchStats]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!prompt.trim() || loading) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await llmDlpApi.chat(prompt.trim());
      setResult(res.data);
    } catch (err) {
      setResult({
        status: "error",
        reason: err?.response?.data?.detail || err?.message || "Request failed",
        pre_entities: [],
        post_entities: [],
        deactivated_keys: [],
      });
    } finally {
      setLoading(false);
      fetchHistory();
      fetchStats();
    }
  }

  function toggleExpand(id) {
    setExpandedId(expandedId === id ? null : id);
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <section className="surface-panel-strong rounded-[30px] p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                LLM DLP
              </div>
              <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                Scan before you send. Audit after you receive.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Every prompt is pre-scanned for secrets. The LLM only sees redacted text. Responses are post-scanned for leaked keys, which are auto-logged for deactivation.
              </p>
            </div>
            {stats && (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                {[
                  { label: "Total", value: stats.total_interactions ?? 0 },
                  { label: "Blocked", value: stats.blocked ?? 0, color: "text-red-300" },
                  { label: "Redacted", value: stats.redacted ?? 0, color: "text-amber-300" },
                  { label: "Leaked Keys", value: stats.leaked_keys_detected ?? 0, color: "text-red-400" },
                ].map((s) => (
                  <div key={s.label} className="surface-panel rounded-2xl px-4 py-3 text-center">
                    <p className={`text-xl font-bold tabular-nums ${s.color || "text-white"}`}>{s.value}</p>
                    <p className="mt-1 text-[11px] uppercase tracking-wider text-slate-500">{s.label}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Prompt Input */}
        <div className="surface-panel rounded-[28px] p-5">
          <div className="mb-3 flex items-center gap-2">
            <Brain className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white">Prompt</h2>
          </div>
          <form onSubmit={handleSubmit} className="space-y-3">
            <textarea
              ref={promptRef}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              rows={5}
              className="w-full rounded-xl bg-white/[0.03] border border-white/10 px-4 py-3 text-sm text-white outline-none focus:border-cyan-500 resize-none"
              placeholder="Type a prompt here... Secrets like API keys, passwords, SSNs will be detected and redacted before sending to the LLM."
              disabled={loading}
            />
            <div className="flex items-center justify-between">
              <p className="text-xs text-slate-500">
                {prompt.length} characters
              </p>
              <button
                type="submit"
                disabled={loading || !prompt.trim()}
                className="inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px] disabled:opacity-50 disabled:hover:translate-y-0"
              >
                {loading ? <LoadingSpinner size="sm" /> : <Play className="h-4 w-4" />}
                {loading ? "Processing..." : "Send via DLP Pipeline"}
              </button>
            </div>
          </form>
        </div>

        {/* Result */}
        {result && (
          <div className="surface-panel rounded-[28px] p-5 space-y-4">
            <div className="flex items-center gap-3">
              <span
                className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${
                  STATUS_COLORS[result.status] || "text-slate-300 bg-slate-800 border-slate-600"
                }`}
              >
                <Shield className="h-3.5 w-3.5" />
                {result.status?.toUpperCase()}
              </span>
              {result.interaction_id && (
                <span className="font-mono-ui text-[11px] text-slate-500">{result.interaction_id}</span>
              )}
            </div>

            {result.reason && (
              <div className="rounded-xl border border-red-700/50 bg-red-950/30 px-4 py-3 text-sm text-red-200">
                {result.reason}
              </div>
            )}

            {/* Pre-scan */}
            {result.pre_entities && result.pre_entities.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Pre-Scan Detected ({result.pre_entities.length} entities)
                </h3>
                <div className="flex flex-wrap gap-2">
                  {result.pre_entities.map((e, i) => (
                    <span
                      key={i}
                      className="rounded-lg border border-cyan-700/40 bg-cyan-900/20 px-2.5 py-1 text-xs text-cyan-300"
                    >
                      {e.entity_type}: {e.value?.slice(0, 20)}{e.value?.length > 20 ? "..." : ""}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Redacted prompt */}
            {result.redacted_prompt && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Redacted Prompt Sent to LLM
                </h3>
                <div className="rounded-xl bg-slate-950 border border-white/5 p-3 text-sm text-slate-300 whitespace-pre-wrap font-mono-ui">
                  {result.redacted_prompt}
                </div>
              </div>
            )}

            {/* LLM Response */}
            {result.llm_response && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  LLM Response
                </h3>
                <div className="rounded-xl bg-slate-950 border border-white/5 p-3 text-sm text-slate-300 whitespace-pre-wrap">
                  {result.llm_response}
                </div>
              </div>
            )}

            {/* Post-scan */}
            {result.post_entities && result.post_entities.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-red-400">
                  Post-Scan Leaks Detected ({result.post_entities.length} entities)
                </h3>
                <div className="flex flex-wrap gap-2">
                  {result.post_entities.map((e, i) => (
                    <span
                      key={i}
                      className="rounded-lg border border-red-700/40 bg-red-900/20 px-2.5 py-1 text-xs text-red-300"
                    >
                      {e.entity_type}: {e.value?.slice(0, 20)}{e.value?.length > 20 ? "..." : ""}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Deactivated keys */}
            {result.deactivated_keys && result.deactivated_keys.length > 0 && (
              <div className="rounded-xl border border-red-700/50 bg-red-950/20 p-4 space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-red-300">
                  Auto-Deactivated Keys ({result.deactivated_keys.length})
                </h3>
                <ul className="space-y-1 text-sm text-red-200">
                  {result.deactivated_keys.map((k, i) => (
                    <li key={i} className="font-mono-ui">
                      {k.type}: {k.value_preview} — {k.note}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* History */}
        <div className="surface-panel rounded-[28px] p-5">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-white">Recent Interactions</h2>
            </div>
            <button
              onClick={fetchHistory}
              className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/[0.05] hover:text-white"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>

          {historyLoading ? (
            <LoadingSpinner text="Loading history" />
          ) : history.length === 0 ? (
            <EmptyState
              icon={<Brain />}
              title="No interactions yet"
              message="Send your first prompt through the DLP pipeline."
            />
          ) : (
            <div className="space-y-2">
              {history.map((item) => (
                <div key={item.interaction_id} className="rounded-xl border border-white/5 bg-white/[0.02] overflow-hidden">
                  <button
                    onClick={() => toggleExpand(item.interaction_id)}
                    className="flex w-full items-center justify-between px-4 py-3 text-left transition hover:bg-white/[0.03]"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span
                        className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                          STATUS_COLORS[item.status] || "text-slate-300 bg-slate-800 border-slate-600"
                        }`}
                      >
                        {item.status}
                      </span>
                      <span className="truncate text-sm text-slate-300">{item.original_preview}</span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-xs text-slate-500">{formatDate(item.created_at)}</span>
                      {expandedId === item.interaction_id ? (
                        <ChevronUp className="h-4 w-4 text-slate-400" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-slate-400" />
                      )}
                    </div>
                  </button>
                  {expandedId === item.interaction_id && (
                    <div className="border-t border-white/5 px-4 py-3 text-xs text-slate-400 space-y-1">
                      <p><span className="text-slate-500">ID:</span> {item.interaction_id}</p>
                      <p><span className="text-slate-500">Provider:</span> {item.llm_provider} / {item.model_used}</p>
                      <p>
                        <span className="text-slate-500">Auto-deactivated:</span>{" "}
                        {item.auto_deactivated ? (
                          <span className="text-red-300">Yes</span>
                        ) : (
                          <span className="text-slate-400">No</span>
                        )}
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
