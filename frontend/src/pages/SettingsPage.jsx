import React from "react";
import { useNavigate } from "react-router-dom";
import { Copy, CreditCard, Key, ShieldCheck } from "lucide-react";
import { authApi } from "../api/auth";
import { useAuth } from "../context/AuthContext";
import DashboardLayout from "../components/layout/DashboardLayout";

function PlanBadge({ plan }) {
  const label = (plan ?? "FREE").toUpperCase();
  const styles =
    label === "ENTERPRISE"
      ? "bg-purple-900 text-purple-300 border border-purple-700"
      : label === "PRO"
      ? "bg-cyber-900 text-cyan-300 border border-cyan-700"
      : "bg-gray-800 text-gray-300 border border-gray-600";
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase ${styles}`}>
      {label}
    </span>
  );
}

function usageColor(pct) {
  if (pct >= 80) return "bg-red-500";
  if (pct >= 50) return "bg-amber-500";
  return "bg-green-500";
}

export default function SettingsPage() {
  const { user, refreshUser } = useAuth();
  const navigate = useNavigate();
  const [usage, setUsage] = React.useState(null);
  const [mfaStatus, setMfaStatus] = React.useState({ enabled: false, rollout_mode: "off" });
  const [setupData, setSetupData] = React.useState(null);
  const [verifyCode, setVerifyCode] = React.useState("");
  const [disableCode, setDisableCode] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [message, setMessage] = React.useState("");

  const loadMfaStatus = React.useCallback(async () => {
    const res = await authApi.getMfaStatus();
    setMfaStatus(res.data);
  }, []);

  React.useEffect(() => {
    loadMfaStatus().catch((err) => {
      setError(err?.response?.data?.detail || "Failed to load MFA status.");
    });
  }, [loadMfaStatus]);

  React.useEffect(() => {
    authApi
      .meFull()
      .then((res) => {
        setUsage(res.data?.usage || null);
      })
      .catch(() => {});
  }, []);

  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage("Copied to clipboard.");
    } catch {
      setError("Clipboard copy failed.");
    }
  }

  async function handleStartMfaSetup() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const res = await authApi.beginMfaSetup();
      setSetupData(res.data);
      setMessage("Authenticator setup initialized. Add the account in your app, then verify.");
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to start MFA setup.");
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyMfa(e) {
    e.preventDefault();
    if (verifyCode.length !== 6) {
      setError("Enter a valid 6-digit authenticator code.");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await authApi.verifyMfa(verifyCode);
      await Promise.all([loadMfaStatus(), refreshUser()]);
      setSetupData(null);
      setVerifyCode("");
      setMessage("MFA enabled for this account.");
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to verify MFA code.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisableMfa(e) {
    e.preventDefault();
    if (disableCode.length !== 6) {
      setError("Enter a valid 6-digit authenticator code.");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await authApi.disableMfa(disableCode);
      await Promise.all([loadMfaStatus(), refreshUser()]);
      setDisableCode("");
      setSetupData(null);
      setMessage("MFA disabled for this account.");
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to disable MFA.");
    } finally {
      setBusy(false);
    }
  }

  const planLimit = usage?.scan_limit ?? 0;
  const scanCountMonth = usage?.scans_used ?? user?.scan_count_month ?? 0;
  const usagePct = planLimit > 0 ? Math.min(Math.round((scanCountMonth / planLimit) * 100), 100) : 0;
  const currentPlan = (usage?.plan ?? user?.plan ?? "free").toLowerCase();
  const rolloutMode = String(mfaStatus.rollout_mode || "off").toUpperCase();

  return (
    <DashboardLayout>
      <div className="max-w-3xl mx-auto space-y-8">
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-5">Profile</h2>
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="flex items-center justify-center h-14 w-14 rounded-full bg-cyber-700 text-white text-lg font-bold shrink-0 select-none">
              {(user?.email ?? "?")[0].toUpperCase()}
            </div>
            <div className="flex-1 min-w-0 space-y-1">
              <p className="text-white font-medium truncate">
                {user?.full_name ?? user?.email ?? "User"}
              </p>
              <p className="text-sm text-gray-400 truncate">{user?.email ?? "-"}</p>
              <PlanBadge plan={user?.plan} />
            </div>
            <button
              type="button"
              className="shrink-0 rounded-lg bg-cyber-600 hover:bg-cyber-700 text-white text-sm font-semibold px-4 py-2 transition"
            >
              Upgrade Plan
            </button>
          </div>
        </section>

        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-5">API Usage</h2>
          <div className="space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400">Scans this month</span>
              <span className="tabular-nums text-white font-medium">
                {scanCountMonth} / {planLimit}
              </span>
            </div>
            <div className="w-full h-2.5 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${usageColor(usagePct)}`}
                style={{ width: `${usagePct}%` }}
              />
            </div>
            <p className="text-xs text-gray-500">
              {usagePct}% of your{" "}
              <span className="font-medium text-gray-300 uppercase">{currentPlan}</span>{" "}
              plan limit used this month.
            </p>
          </div>
        </section>

        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-5">Security</h2>

          {error && (
            <div className="mb-4 rounded-md border border-red-800 bg-red-900/30 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          )}
          {message && (
            <div className="mb-4 rounded-md border border-emerald-800 bg-emerald-900/30 px-4 py-3 text-sm text-emerald-200">
              {message}
            </div>
          )}

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Key className="h-4 w-4 text-gray-400" />
                <div>
                  <p className="text-sm text-white font-medium">Password</p>
                  <p className="text-xs text-gray-500">Update your account password</p>
                </div>
              </div>
              <button
                type="button"
                className="rounded-lg border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white text-sm font-medium px-4 py-2 transition"
              >
                Change Password
              </button>
            </div>

            <div className="border-t border-gray-800 pt-4 flex items-center justify-between">
              <div>
                <p className="text-sm text-white font-medium">Active Sessions</p>
                <p className="text-xs text-gray-500">You have 1 active session</p>
              </div>
              <span className="text-xs text-green-400 font-medium">Current device</span>
            </div>

            <div className="border-t border-gray-800 pt-4 flex items-center justify-between">
              <div>
                <p className="text-sm text-white font-medium">JWT Token Expiry</p>
                <p className="text-xs text-gray-500">Tokens expire after 24 hours of inactivity</p>
              </div>
              <span className="text-xs text-gray-400">24h</span>
            </div>

            <div className="border-t border-gray-800 pt-4 space-y-4">
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-cyan-400" />
                    <p className="text-sm text-white font-medium">Multi-Factor Authentication (MFA)</p>
                  </div>
                  <p className="text-xs text-gray-500">
                    Authenticator-app based verification using the live backend MFA flow.
                  </p>
                  <p className="text-[11px] text-cyan-400">
                    Rollout: {rolloutMode} • Account status: {mfaStatus.enabled ? "ENABLED" : "DISABLED"}
                  </p>
                </div>
                <button
                  type="button"
                  disabled={busy}
                  onClick={mfaStatus.enabled ? undefined : handleStartMfaSetup}
                  className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                    mfaStatus.enabled
                      ? "bg-emerald-700/30 text-emerald-300 border border-emerald-700"
                      : "bg-cyber-600 hover:bg-cyber-700 text-white disabled:opacity-60"
                  }`}
                >
                  {mfaStatus.enabled ? "Enabled" : "Set up MFA"}
                </button>
              </div>

              {!mfaStatus.enabled && setupData && (
                <div className="rounded-lg border border-cyan-900 bg-cyan-950/20 p-4 space-y-4">
                  <div className="space-y-2">
                    <p className="text-sm font-medium text-white">Step 1: Add this account to your authenticator app</p>
                    <div className="rounded-lg bg-gray-950 border border-gray-800 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-xs text-gray-500">Secret</p>
                          <p className="font-mono text-xs text-gray-200 break-all">{setupData.secret}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText(setupData.secret)}
                          className="rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:text-white"
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                    <div className="rounded-lg bg-gray-950 border border-gray-800 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-xs text-gray-500">Provisioning URI</p>
                          <p className="font-mono text-xs text-gray-200 break-all">{setupData.provisioning_uri}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText(setupData.provisioning_uri)}
                          className="rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:text-white"
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <form onSubmit={handleVerifyMfa} className="space-y-3">
                    <p className="text-sm font-medium text-white">Step 2: Verify the current 6-digit code</p>
                    <div className="flex gap-3">
                      <input
                        type="text"
                        inputMode="numeric"
                        value={verifyCode}
                        onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                        placeholder="123456"
                        className="flex-1 rounded-lg bg-gray-800 border border-gray-700 text-white px-4 py-2.5 text-sm"
                      />
                      <button
                        type="submit"
                        disabled={busy}
                        className="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60"
                      >
                        Verify
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {mfaStatus.enabled && (
                <form onSubmit={handleDisableMfa} className="rounded-lg border border-amber-900 bg-amber-950/20 p-4 space-y-3">
                  <p className="text-sm font-medium text-white">Disable MFA</p>
                  <p className="text-xs text-gray-400">
                    Enter a current authenticator code to remove MFA from this account.
                  </p>
                  <div className="flex gap-3">
                    <input
                      type="text"
                      inputMode="numeric"
                      value={disableCode}
                      onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      placeholder="123456"
                      className="flex-1 rounded-lg bg-gray-800 border border-gray-700 text-white px-4 py-2.5 text-sm"
                    />
                    <button
                      type="submit"
                      disabled={busy}
                      className="rounded-lg bg-red-700 hover:bg-red-600 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60"
                    >
                      Disable
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </section>

        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-base font-semibold text-white">Plans &amp; Billing</h2>
            <PlanBadge plan={user?.plan} />
          </div>
          <p className="text-sm text-gray-400 mb-4">
            Manage your subscription, view usage, and upgrade your plan from the billing page.
          </p>
          <button
            type="button"
            onClick={() => navigate("/billing")}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-5 py-2.5 transition"
          >
            <CreditCard className="h-4 w-4" />
            Manage billing
          </button>
        </section>
      </div>
    </DashboardLayout>
  );
}
