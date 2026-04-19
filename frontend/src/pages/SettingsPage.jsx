import React from "react";
import { useNavigate } from "react-router-dom";
import { CreditCard, Key } from "lucide-react";
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
  const { user } = useAuth();
  const navigate = useNavigate();
  const [mfaPreferred, setMfaPreferred] = React.useState(
    () => localStorage.getItem("mycyber_mfa_preferred") === "true"
  );

  function handleMfaToggle(enabled) {
    setMfaPreferred(enabled);
    localStorage.setItem("mycyber_mfa_preferred", String(enabled));
  }

  const planLimit = user?.plan_limit ?? 50;
  const scanCountMonth = user?.scan_count_month ?? 0;
  const usagePct = Math.min(Math.round((scanCountMonth / planLimit) * 100), 100);
  const currentPlan = (user?.plan ?? "free").toLowerCase();

  return (
    <DashboardLayout>
      <div className="max-w-3xl mx-auto space-y-8">
        {/* ── Profile ── */}
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
              <p className="text-sm text-gray-400 truncate">{user?.email ?? "—"}</p>
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

        {/* ── API Usage ── */}
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

        {/* ── Security ── */}
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-5">Security</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Key className="h-4 w-4 text-gray-400" />
                <div>
                  <p className="text-sm text-white font-medium">Password</p>
                  <p className="text-xs text-gray-500">
                    Update your account password
                  </p>
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
                <p className="text-xs text-gray-500">
                  Tokens expire after 24 hours of inactivity
                </p>
              </div>
              <span className="text-xs text-gray-400">24h</span>
            </div>

            <div className="border-t border-gray-800 pt-4 flex items-start justify-between gap-4">
              <div>
                <p className="text-sm text-white font-medium">Multi-Factor Authentication (MFA)</p>
                <p className="text-xs text-gray-500">
                  Enable app-based 2FA preference now. Enforcement in login will be enabled in a future release.
                </p>
                <p className="mt-1 text-[11px] text-cyan-400">Status: MFA groundwork enabled (not enforced yet)</p>
              </div>
              <label className="relative inline-flex cursor-pointer items-center">
                <input
                  type="checkbox"
                  className="peer sr-only"
                  checked={mfaPreferred}
                  onChange={(e) => handleMfaToggle(e.target.checked)}
                />
                <div className="peer h-6 w-11 rounded-full bg-gray-700 after:absolute after:left-[2px] after:top-[2px] after:h-5 after:w-5 after:rounded-full after:bg-white after:transition-all after:content-[''] peer-checked:bg-cyber-600 peer-checked:after:translate-x-full" />
              </label>
            </div>
          </div>
        </section>

        {/* ── Plans ── */}
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-base font-semibold text-white">Plans &amp; Billing</h2>
            <PlanBadge plan={user?.plan} />
          </div>
          <p className="text-sm text-gray-400 mb-4">
            Manage your subscription, view usage, and upgrade your plan from the
            billing page.
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
