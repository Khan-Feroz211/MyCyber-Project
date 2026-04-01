import React from "react";
import { Key, Shield, Star, Zap } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import DashboardLayout from "../components/layout/DashboardLayout";

const PLANS = [
  {
    key: "free",
    label: "Free",
    icon: <Shield className="h-5 w-5" />,
    color: "border-gray-700",
    highlightColor: "border-cyber-500",
    price: "$0 / mo",
    features: ["50 scans / month", "Text scan only", "Basic PII detection", "Community support"],
  },
  {
    key: "pro",
    label: "Pro",
    icon: <Zap className="h-5 w-5" />,
    color: "border-gray-700",
    highlightColor: "border-cyber-500",
    price: "$29 / mo",
    features: [
      "2,000 scans / month",
      "Text, File & Network scans",
      "AI-powered analysis",
      "Priority support",
      "API access",
    ],
  },
  {
    key: "enterprise",
    label: "Enterprise",
    icon: <Star className="h-5 w-5" />,
    color: "border-gray-700",
    highlightColor: "border-purple-500",
    price: "Custom",
    features: [
      "Unlimited scans",
      "All scan types",
      "Custom AI models",
      "Dedicated support",
      "SSO / SAML",
      "Multi-tenant",
    ],
  },
];

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
          </div>
        </section>

        {/* ── Plans ── */}
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-5">Plans</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {PLANS.map((plan) => {
              const isCurrent = plan.key === currentPlan;
              return (
                <div
                  key={plan.key}
                  className={`rounded-xl border-2 p-5 flex flex-col gap-4 transition ${
                    isCurrent ? plan.highlightColor : plan.color
                  } bg-gray-800/50`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-white font-semibold">
                      <span className="text-cyan-400">{plan.icon}</span>
                      {plan.label}
                    </div>
                    {isCurrent && (
                      <span className="text-xs text-cyan-400 font-medium">Current</span>
                    )}
                  </div>
                  <p className="text-xl font-bold text-white tabular-nums">{plan.price}</p>
                  <ul className="space-y-1.5 flex-1">
                    {plan.features.map((feat) => (
                      <li key={feat} className="text-xs text-gray-400 flex items-center gap-1.5">
                        <span className="h-1 w-1 rounded-full bg-cyan-500 shrink-0" />
                        {feat}
                      </li>
                    ))}
                  </ul>
                  {!isCurrent && (
                    <button
                      type="button"
                      className="mt-auto w-full rounded-lg bg-cyber-600 hover:bg-cyber-700 text-white text-sm font-semibold py-2 transition"
                    >
                      Upgrade to {plan.label}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </DashboardLayout>
  );
}
