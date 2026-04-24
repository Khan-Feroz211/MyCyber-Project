import React, { useRef, useState } from "react";
import {
  AlertCircle,
  Calendar,
  CheckCircle,
  Globe,
  HardDrive,
  Loader2,
  Paperclip,
  Terminal,
  Type,
  Upload,
} from "lucide-react";
import { scanApi } from "../api/scans";
import { scheduledScanApi } from "../api/scheduledScans";
import DashboardLayout from "../components/layout/DashboardLayout";
import SeverityBadge from "../components/ui/SeverityBadge";
import ActionBadge from "../components/ui/ActionBadge";

/* ─── helpers ──────────────────────────────────────────────────────── */

const TEXT_CONTEXTS = ["general", "email", "code", "document", "network"];
const PROTOCOLS = ["HTTP", "HTTPS", "FTP", "SMTP", "DNS", "TCP", "UDP"];
const MAX_TEXT_LEN = 50_000;
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MB

function riskBarColor(score) {
  if (score > 70) return "bg-red-500";
  if (score > 40) return "bg-amber-500";
  return "bg-green-500";
}

function confidencePct(conf) {
  if (conf == null) return "—";
  const n = typeof conf === "number" ? conf : parseFloat(conf);
  if (isNaN(n)) return "—";
  return n <= 1 ? `${Math.round(n * 100)}%` : `${Math.round(n)}%`;
}

function toBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const b64 = reader.result.split(",")[1];
      resolve(b64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

/* ─── Tab button ───────────────────────────────────────────────────── */
function TabButton({ label, icon: Icon, active, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-2 rounded-full px-4 py-1.5 text-sm font-medium transition ${
        active
          ? "bg-cyber-600 text-white"
          : "text-gray-400 hover:text-white hover:bg-gray-800"
      }`}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </button>
  );
}

/* ─── Results panel ────────────────────────────────────────────────── */
function ResultsPanel({ result }) {
  if (!result) return null;

  const risk = Math.round(result.risk_score ?? 0);
  const entities = Array.isArray(result.entities) ? result.entities : [];
  const isSafe =
    (result.severity ?? "").toUpperCase() === "SAFE" ||
    result.total_entities === 0;

  const ENTITY_ROW_BG = {
    CRITICAL: "bg-red-950/30",
    HIGH: "bg-orange-950/30",
    MEDIUM: "bg-yellow-950/20",
    LOW: "bg-blue-950/20",
    SAFE: "bg-green-950/20",
  };

  return (
    <div className="mt-6 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      {/* Header row */}
      <div className="flex flex-wrap items-center gap-4 px-5 py-4 border-b border-gray-800">
        <SeverityBadge severity={result.severity} />
        <div className="flex items-baseline gap-1">
          <span className="text-3xl font-bold text-white tabular-nums">
            {risk}
          </span>
          <span className="text-sm text-gray-500">/100</span>
        </div>
        <ActionBadge action={result.recommended_action} />
        {result.scan_duration_ms != null && (
          <span className="text-xs text-gray-500">
            {result.scan_duration_ms} ms
          </span>
        )}
      </div>

      {/* Summary */}
      {result.summary && (
        <p className="px-5 py-3 text-sm text-gray-300 leading-relaxed border-b border-gray-800">
          {result.summary}
        </p>
      )}

      {/* Safe message */}
      {isSafe && (
        <div className="flex items-center gap-3 px-5 py-5 bg-green-950/20">
          <CheckCircle className="h-5 w-5 text-green-500 shrink-0" />
          <p className="text-sm font-medium text-green-400">
            No sensitive data detected
          </p>
        </div>
      )}

      {/* Entities table */}
      {!isSafe && entities.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-gray-500 border-b border-gray-800">
                <th className="px-5 py-3 font-medium">Entity Type</th>
                <th className="px-4 py-3 font-medium">Redacted Value</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
                <th className="px-4 py-3 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {entities.map((ent, idx) => {
                const sev = (ent.severity ?? "").toUpperCase();
                return (
                  <tr
                    key={idx}
                    className={`${ENTITY_ROW_BG[sev] ?? ""} transition`}
                  >
                    <td className="px-5 py-3 text-gray-300 uppercase tracking-wide font-mono text-xs">
                      {ent.entity_type ?? ent.type ?? "—"}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400 break-all max-w-[240px]">
                      {ent.redacted_value ?? ent.value ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs tabular-nums">
                      {confidencePct(ent.confidence)}
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={ent.severity} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ─── Main page ────────────────────────────────────────────────────── */
export default function ScanPage() {
  const [activeTab, setActiveTab] = useState("text");

  /* Text tab state */
  const [textInput, setTextInput] = useState("");
  const [textContext, setTextContext] = useState("general");

  /* File tab state */
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileError, setFileError] = useState("");
  const fileInputRef = useRef(null);
  const externalDriveInputRef = useRef(null);

  /* Network tab state */
  const [netPayload, setNetPayload] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [destination, setDestination] = useState("");
  const [protocol, setProtocol] = useState("HTTP");

  /* Scheduled scan state */
  const [schedName, setSchedName] = useState("");
  const [schedTarget, setSchedTarget] = useState("");
  const [schedType, setSchedType] = useState("text");
  const [schedCron, setSchedCron] = useState("0 9 * * *");
  const [schedJobs, setSchedJobs] = useState([]);
  const [schedLoading, setSchedLoading] = useState(false);
  const [schedMsg, setSchedMsg] = useState("");

  /* Shared state */
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");

  function resetResult() {
    setScanResult(null);
    setScanError("");
  }

  async function loadScheduledJobs() {
    try {
      const res = await scheduledScanApi.list();
      setSchedJobs(res.data.items || []);
    } catch {}
  }

  async function handleCreateScheduled(e) {
    e.preventDefault();
    setSchedLoading(true);
    setSchedMsg("");
    try {
      await scheduledScanApi.create({
        name: schedName,
        scan_type: schedType,
        target: schedTarget,
        schedule_cron: schedCron,
      });
      setSchedMsg("Scheduled scan created.");
      setSchedName("");
      setSchedTarget("");
      await loadScheduledJobs();
    } catch (err) {
      setSchedMsg(err?.response?.data?.detail || "Failed to create scheduled scan.");
    } finally {
      setSchedLoading(false);
    }
  }

  async function toggleJob(jobId) {
    try {
      await scheduledScanApi.toggle(jobId);
      await loadScheduledJobs();
    } catch {}
  }

  async function deleteJob(jobId) {
    try {
      await scheduledScanApi.delete(jobId);
      await loadScheduledJobs();
    } catch {}
  }

  async function runJobNow(jobId) {
    try {
      await scheduledScanApi.runNow(jobId);
      setSchedMsg("Scan executed.");
    } catch (err) {
      setSchedMsg(err?.response?.data?.detail || "Run failed.");
    }
  }

  /* ── Text scan ── */
  async function handleTextScan(e) {
    e.preventDefault();
    if (!textInput.trim()) return;
    resetResult();
    setLoading(true);
    try {
      const res = await scanApi.scanText(textInput, textContext);
      setScanResult(res.data);
    } catch (err) {
      setScanError(err?.response?.data?.detail || err?.message || "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  /* ── File scan ── */
  function handleFileSelect(file) {
    setFileError("");
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setFileError("File exceeds 10 MB limit.");
      return;
    }
    setSelectedFile(file);
    resetResult();
  }

  async function handleFileScan(e) {
    e.preventDefault();
    if (!selectedFile) return;
    resetResult();
    setLoading(true);
    try {
      const b64 = await toBase64(selectedFile);
      const res = await scanApi.scanFile(selectedFile.name, b64);
      setScanResult(res.data);
    } catch (err) {
      setScanError(err?.response?.data?.detail || err?.message || "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleExternalDriveScan(e) {
    e.preventDefault();
    await handleFileScan(e);
  }

  /* ── Network scan ── */
  async function handleNetworkScan(e) {
    e.preventDefault();
    if (!netPayload.trim()) return;
    resetResult();
    setLoading(true);
    try {
      const res = await scanApi.scanNetwork(netPayload, sourceIp, destination, protocol);
      setScanResult(res.data);
    } catch (err) {
      setScanError(err?.response?.data?.detail || err?.message || "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  /* ── Loading overlay ── */
  const LoadingOverlay = () => (
    <div className="flex flex-col items-center justify-center py-14 gap-4">
      <Loader2 className="h-10 w-10 animate-spin text-cyan-500" />
      <p className="text-sm text-gray-400 font-medium">Analyzing with AI…</p>
    </div>
  );

  return (
    <DashboardLayout>
      <div className="max-w-3xl mx-auto space-y-6">
        {/* ── Tabs ── */}
        <div className="flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-2xl p-1.5 w-fit">
          <TabButton
            label="Text"
            icon={Type}
            active={activeTab === "text"}
            onClick={() => { setActiveTab("text"); resetResult(); }}
          />
          <TabButton
            label="File"
            icon={Paperclip}
            active={activeTab === "file"}
            onClick={() => { setActiveTab("file"); resetResult(); }}
          />
          <TabButton
            label="Network"
            icon={Globe}
            active={activeTab === "network"}
            onClick={() => { setActiveTab("network"); resetResult(); }}
          />
          <TabButton
            label="External Drive"
            icon={HardDrive}
            active={activeTab === "external-drive"}
            onClick={() => { setActiveTab("external-drive"); resetResult(); }}
          />
          <TabButton
            label="Scheduled"
            icon={Calendar}
            active={activeTab === "scheduled"}
            onClick={() => { setActiveTab("scheduled"); resetResult(); loadScheduledJobs(); }}
          />
        </div>

        {/* ── Tab panels ── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          {/* TEXT TAB */}
          {activeTab === "text" && (
            <form onSubmit={handleTextScan} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">
                  Text to scan
                </label>
                <textarea
                  rows={10}
                  value={textInput}
                  onChange={(e) => setTextInput(e.target.value.slice(0, MAX_TEXT_LEN))}
                  placeholder="Paste text to scan for PII and sensitive data..."
                  className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-3 text-sm resize-y focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
                />
                <p className="mt-1 text-right text-xs text-gray-500 tabular-nums">
                  {textInput.length.toLocaleString()} / {MAX_TEXT_LEN.toLocaleString()}
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">
                  Context
                </label>
                <select
                  value={textContext}
                  onChange={(e) => setTextContext(e.target.value)}
                  className="rounded-lg bg-gray-800 border border-gray-700 text-gray-200 text-sm px-3 py-2 focus:outline-none focus:border-cyan-500 capitalize"
                >
                  {TEXT_CONTEXTS.map((ctx) => (
                    <option key={ctx} value={ctx} className="capitalize">
                      {ctx.charAt(0).toUpperCase() + ctx.slice(1)}
                    </option>
                  ))}
                </select>
              </div>

              <button
                type="submit"
                disabled={loading || !textInput.trim()}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 text-sm transition"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : null}
                {loading ? "Analyzing with AI…" : "Scan Text"}
              </button>
            </form>
          )}

          {/* FILE TAB */}
          {activeTab === "file" && (
            <form onSubmit={handleFileScan} className="space-y-4">
              {/* Drop zone */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => e.key === "Enter" && fileInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  handleFileSelect(e.dataTransfer.files[0] ?? null);
                }}
                className="flex flex-col items-center justify-center gap-3 border-2 border-dashed border-gray-700 hover:border-cyan-600 rounded-xl py-12 cursor-pointer transition"
              >
                <Upload className="h-10 w-10 text-gray-500" />
                {selectedFile ? (
                  <div className="text-center">
                    <p className="text-sm font-medium text-white">
                      {selectedFile.name}
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {(selectedFile.size / 1024).toFixed(1)} KB
                    </p>
                  </div>
                ) : (
                  <div className="text-center space-y-1">
                    <p className="text-sm text-gray-300 font-medium">
                      Drop file here or click to browse
                    </p>
                    <p className="text-xs text-gray-500">
                      Supported: .txt, .pdf, .docx, .csv, .json, .log, .xml
                    </p>
                    <p className="text-xs text-gray-600">Max 10 MB</p>
                  </div>
                )}
              </div>

              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                accept=".txt,.pdf,.docx,.csv,.json,.log,.xml,.eml"
                onChange={(e) => handleFileSelect(e.target.files[0] ?? null)}
              />

              {fileError && (
                <p className="text-xs text-red-400">{fileError}</p>
              )}

              <button
                type="submit"
                disabled={loading || !selectedFile}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 text-sm transition"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                {loading ? "Analyzing with AI…" : "Scan File"}
              </button>
            </form>
          )}

          {activeTab === "external-drive" && (
            <form onSubmit={handleExternalDriveScan} className="space-y-4">
              <div className="rounded-lg border border-cyan-900 bg-cyan-950/20 p-4 text-sm text-gray-300">
                Attach or mount the external drive on your device, then browse and select a file from that drive.
                This uses the live file-scan API. The browser cannot directly detect physical drive insertion.
              </div>

              <div
                role="button"
                tabIndex={0}
                onClick={() => externalDriveInputRef.current?.click()}
                onKeyDown={(e) => e.key === "Enter" && externalDriveInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  handleFileSelect(e.dataTransfer.files[0] ?? null);
                }}
                className="flex flex-col items-center justify-center gap-3 border-2 border-dashed border-cyan-800 hover:border-cyan-600 rounded-xl py-12 cursor-pointer transition"
              >
                <HardDrive className="h-10 w-10 text-cyan-500" />
                {selectedFile ? (
                  <div className="text-center">
                    <p className="text-sm font-medium text-white">
                      {selectedFile.name}
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {(selectedFile.size / 1024).toFixed(1)} KB
                    </p>
                  </div>
                ) : (
                  <div className="text-center space-y-1">
                    <p className="text-sm text-gray-300 font-medium">
                      Select a file from the attached drive
                    </p>
                    <p className="text-xs text-gray-500">
                      Browse to the mounted USB or external drive and choose a file to scan
                    </p>
                  </div>
                )}
              </div>

              <input
                ref={externalDriveInputRef}
                type="file"
                className="hidden"
                accept=".txt,.pdf,.docx,.csv,.json,.log,.xml,.eml"
                onChange={(e) => handleFileSelect(e.target.files[0] ?? null)}
              />

              {fileError && (
                <p className="text-xs text-red-400">{fileError}</p>
              )}

              <button
                type="submit"
                disabled={loading || !selectedFile}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 text-sm transition"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                {loading ? "Scanning drive file..." : "Scan External Drive File"}
              </button>
            </form>
          )}

          {/* NETWORK TAB */}
          {activeTab === "network" && (
            <form onSubmit={handleNetworkScan} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">
                  Network payload
                </label>
                <textarea
                  rows={8}
                  value={netPayload}
                  onChange={(e) => setNetPayload(e.target.value)}
                  placeholder="Paste network payload, HTTP request, or packet data..."
                  className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-3 text-sm font-mono resize-y focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">
                    Source IP{" "}
                    <span className="text-gray-600 font-normal">(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={sourceIp}
                    onChange={(e) => setSourceIp(e.target.value)}
                    placeholder="192.168.1.1"
                    className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 transition"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">
                    Destination{" "}
                    <span className="text-gray-600 font-normal">(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={destination}
                    onChange={(e) => setDestination(e.target.value)}
                    placeholder="example.com / 10.0.0.1"
                    className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 transition"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1">
                    Protocol
                  </label>
                  <select
                    value={protocol}
                    onChange={(e) => setProtocol(e.target.value)}
                    className="w-full rounded-lg bg-gray-800 border border-gray-700 text-gray-200 text-sm px-3 py-2 focus:outline-none focus:border-cyan-500"
                  >
                    {PROTOCOLS.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading || !netPayload.trim()}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 text-sm transition"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                {loading ? "Analyzing with AI…" : "Scan Network"}
              </button>
            </form>
          )}

          {/* SCHEDULED TAB */}
          {activeTab === "scheduled" && (
            <div className="space-y-6">
              <form onSubmit={handleCreateScheduled} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1.5">Job name</label>
                    <input
                      type="text"
                      value={schedName}
                      onChange={(e) => setSchedName(e.target.value)}
                      placeholder="Daily API key check"
                      required
                      className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 transition"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1.5">Scan type</label>
                    <select
                      value={schedType}
                      onChange={(e) => setSchedType(e.target.value)}
                      className="w-full rounded-lg bg-gray-800 border border-gray-700 text-gray-200 text-sm px-3 py-2 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="text">Text</option>
                      <option value="file">File</option>
                      <option value="network">Network</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1.5">Target / payload</label>
                  <textarea
                    rows={4}
                    value={schedTarget}
                    onChange={(e) => setSchedTarget(e.target.value)}
                    placeholder="Paste the recurring text or payload to scan..."
                    required
                    className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-3 text-sm resize-y focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1.5">Cron expression</label>
                  <input
                    type="text"
                    value={schedCron}
                    onChange={(e) => setSchedCron(e.target.value)}
                    placeholder="0 9 * * *"
                    required
                    className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500 transition"
                  />
                  <p className="mt-1 text-xs text-gray-500">Example: 0 9 * * * = every day at 9:00 AM UTC</p>
                </div>
                <button
                  type="submit"
                  disabled={schedLoading || !schedName.trim() || !schedTarget.trim()}
                  className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 text-sm transition"
                >
                  {schedLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  {schedLoading ? "Saving…" : "Create Scheduled Scan"}
                </button>
                {schedMsg && (
                  <p className={`text-sm ${schedMsg.includes("Failed") || schedMsg.includes("failed") || schedMsg.includes("Run failed") ? "text-red-400" : "text-green-400"}`}>
                    {schedMsg}
                  </p>
                )}
              </form>

              {schedJobs.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-white">Active jobs</h3>
                  <div className="space-y-2">
                    {schedJobs.map((job) => (
                      <div key={job.job_id} className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-950 px-4 py-3">
                        <div>
                          <p className="text-sm font-medium text-white">{job.name}</p>
                          <p className="text-xs text-gray-500">{job.scan_type} · {job.schedule_cron} · {job.is_active ? "Active" : "Paused"}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => runJobNow(job.job_id)}
                            className="rounded-md bg-cyan-900 px-2 py-1 text-xs font-medium text-cyan-300 hover:bg-cyan-800 transition"
                          >
                            Run now
                          </button>
                          <button
                            type="button"
                            onClick={() => toggleJob(job.job_id)}
                            className="rounded-md bg-gray-800 px-2 py-1 text-xs font-medium text-gray-300 hover:bg-gray-700 transition"
                          >
                            {job.is_active ? "Pause" : "Resume"}
                          </button>
                          <button
                            type="button"
                            onClick={() => deleteJob(job.job_id)}
                            className="rounded-md bg-red-900/40 px-2 py-1 text-xs font-medium text-red-300 hover:bg-red-900/60 transition"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Loading overlay ── */}
        {loading && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl">
            <LoadingOverlay />
          </div>
        )}

        {/* ── Scan error ── */}
        {!loading && scanError && (
          <div className="flex items-start gap-3 rounded-xl bg-red-950 border border-red-700 px-5 py-4">
            <AlertCircle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            <p className="text-sm text-red-300">{scanError}</p>
          </div>
        )}

        {/* ── Results ── */}
        {!loading && scanResult && <ResultsPanel result={scanResult} />}
      </div>
    </DashboardLayout>
  );
}
