import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, CreditCard, X } from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import { billingApi } from "../api/billing";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtPKR(amount) {
  return new Intl.NumberFormat("en-PK").format(amount);
}

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

function daysUntil(iso) {
  if (!iso) return null;
  const diff = new Date(iso) - new Date();
  return Math.max(0, Math.ceil(diff / 86_400_000));
}

function barColor(pct) {
  if (pct >= 80) return "bg-red-500";
  if (pct >= 50) return "bg-amber-500";
  return "bg-green-500";
}

function planBadgeStyle(plan) {
  if (plan === "enterprise") return "bg-purple-900 text-purple-300 border border-purple-700";
  if (plan === "pro") return "bg-blue-900 text-blue-300 border border-blue-700";
  return "bg-gray-800 text-gray-300 border border-gray-600";
}

function eventBadgeStyle(eventType) {
  switch (eventType) {
    case "subscription_created":
    case "payment_succeeded":
      return "bg-green-900 text-green-300";
    case "payment_failed":
      return "bg-red-900 text-red-300";
    case "subscription_cancelled":
    case "scan_limit_reset":
      return "bg-gray-700 text-gray-300";
    case "plan_upgraded":
      return "bg-blue-900 text-blue-300";
    default:
      return "bg-gray-700 text-gray-300";
  }
}

function eventLabel(eventType) {
  return eventType
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// ---------------------------------------------------------------------------
// Upgrade confirmation modal
// ---------------------------------------------------------------------------

function UpgradeModal({ plan, billingCycle, onConfirm, onCancel, loading }) {
  if (!plan) return null;
  const basePrice = plan.price_pkr;
  const price = billingCycle === "semester" ? basePrice * 5 : basePrice;
  const cycleLabel = billingCycle === "semester" ? "semester (6 months)" : "month";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <button
          type="button"
          onClick={onCancel}
          className="absolute top-4 right-4 text-gray-500 hover:text-white transition"
        >
          <X className="h-5 w-5" />
        </button>
        <h3 className="text-white text-lg font-semibold mb-1">Confirm upgrade</h3>
        <p className="text-gray-400 text-sm mb-5">
          You are upgrading to the{" "}
          <span className="text-white font-medium">{plan.name}</span> plan.
        </p>
        <div className="bg-gray-800 rounded-xl p-4 mb-5 space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-gray-400">Plan</span>
            <span className="text-white font-medium">{plan.name}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-400">Billing cycle</span>
            <span className="text-white font-medium capitalize">{cycleLabel}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-400">Amount</span>
            <span className="text-white font-semibold">PKR {fmtPKR(price)}</span>
          </div>
        </div>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="flex-1 rounded-lg border border-gray-600 text-gray-300 hover:text-white hover:border-gray-500 text-sm font-medium py-2.5 transition disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={loading}
            className="flex-1 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold py-2.5 transition disabled:opacity-50"
          >
            {loading ? "Redirecting…" : "Proceed to payment"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cancel confirmation modal
// ---------------------------------------------------------------------------

function CancelModal({ onConfirm, onCancel, loading }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <button
          type="button"
          onClick={onCancel}
          className="absolute top-4 right-4 text-gray-500 hover:text-white transition"
        >
          <X className="h-5 w-5" />
        </button>
        <h3 className="text-white text-lg font-semibold mb-1">Cancel subscription?</h3>
        <p className="text-gray-400 text-sm mb-5">
          Your subscription will be cancelled. You will keep access to your current
          plan until the end of the billing period.
        </p>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="flex-1 rounded-lg border border-gray-600 text-gray-300 hover:text-white hover:border-gray-500 text-sm font-medium py-2.5 transition disabled:opacity-50"
          >
            Keep subscription
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={loading}
            className="flex-1 rounded-lg border border-red-600 text-red-400 hover:bg-red-600 hover:text-white text-sm font-semibold py-2.5 transition disabled:opacity-50"
          >
            {loading ? "Cancelling…" : "Yes, cancel"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TAB 1 — Plans
// ---------------------------------------------------------------------------

function PlansTab({ plans, subscription, onSwitchToUsage }) {
  const [billingCycle, setBillingCycle] = useState("monthly");
  const [upgradeTarget, setUpgradeTarget] = useState(null);
  const [upgradeLoading, setUpgradeLoading] = useState(false);
  const [error, setError] = useState(null);

  const currentPlan = subscription?.plan ?? "free";

  async function handleConfirmUpgrade() {
    if (!upgradeTarget) return;
    setUpgradeLoading(true);
    setError(null);
    try {
      const res = await billingApi.upgrade(upgradeTarget.plan_id, billingCycle);
      const checkoutUrl = res.data?.checkout_url;
      if (checkoutUrl) {
        window.location.href = checkoutUrl;
      } else {
        setError("No checkout URL returned. Please try again.");
        setUpgradeLoading(false);
      }
    } catch (err) {
      setError(err.response?.data?.detail ?? "Upgrade failed. Please try again.");
      setUpgradeLoading(false);
    }
  }

  return (
    <>
      {upgradeTarget && (
        <UpgradeModal
          plan={upgradeTarget}
          billingCycle={billingCycle}
          onConfirm={handleConfirmUpgrade}
          onCancel={() => setUpgradeTarget(null)}
          loading={upgradeLoading}
        />
      )}

      {/* Billing cycle toggle */}
      <div className="flex items-center gap-2 mb-6">
        <span className="text-sm text-gray-400">Billing cycle:</span>
        <div className="inline-flex rounded-lg border border-gray-700 overflow-hidden">
          <button
            type="button"
            onClick={() => setBillingCycle("monthly")}
            className={`px-4 py-1.5 text-sm font-medium transition ${
              billingCycle === "monthly"
                ? "bg-blue-600 text-white"
                : "text-gray-400 hover:text-white hover:bg-gray-800"
            }`}
          >
            Monthly
          </button>
          <button
            type="button"
            onClick={() => setBillingCycle("semester")}
            className={`px-4 py-1.5 text-sm font-medium transition ${
              billingCycle === "semester"
                ? "bg-blue-600 text-white"
                : "text-gray-400 hover:text-white hover:bg-gray-800"
            }`}
          >
            Semester (5 months, save 17%)
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-lg bg-red-900/40 border border-red-700 text-red-300 text-sm px-4 py-3">
          {error}
        </div>
      )}

      {/* Plan cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {plans.map((plan) => {
          const isCurrent = plan.plan_id === currentPlan;
          const isPro = plan.plan_id === "pro";
          const isEnterprise = plan.plan_id === "enterprise";
          const isFree = plan.plan_id === "free";
          const displayPrice =
            billingCycle === "semester" && plan.price_pkr > 0
              ? plan.price_pkr * 5
              : plan.price_pkr;

          const canUpgrade =
            !isCurrent &&
            !isFree &&
            (currentPlan === "free" ||
              (currentPlan === "pro" && isEnterprise));

          return (
            <div
              key={plan.plan_id}
              className={`relative bg-gray-900 border rounded-xl p-6 flex flex-col ${
                isCurrent
                  ? "border-blue-600"
                  : isPro
                  ? "border-blue-800"
                  : "border-gray-800"
              }`}
            >
              {/* Most popular badge */}
              {isPro && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                  <span className="bg-blue-900 text-blue-300 text-xs px-2 py-1 rounded-full font-medium">
                    Most popular
                  </span>
                </div>
              )}

              <div className="flex items-center justify-between mb-1">
                <h3 className="text-lg font-semibold text-white">{plan.name}</h3>
                {isCurrent && (
                  <span className="bg-blue-600 text-white text-xs px-3 py-1 rounded-full font-medium">
                    Current plan
                  </span>
                )}
              </div>

              {/* Price */}
              <div className="mb-5">
                {plan.price_pkr === 0 ? (
                  <span className="text-3xl font-bold text-white">Free</span>
                ) : isEnterprise ? (
                  <div>
                    <span className="text-3xl font-bold text-white">
                      PKR {fmtPKR(displayPrice)}
                    </span>
                    <span className="text-gray-400 text-sm ml-1">
                      /{billingCycle === "semester" ? "6 mo" : "mo"}
                    </span>
                  </div>
                ) : (
                  <div>
                    <span className="text-3xl font-bold text-white">
                      PKR {fmtPKR(displayPrice)}
                    </span>
                    <span className="text-gray-400 text-sm ml-1">
                      /{billingCycle === "semester" ? "6 mo" : "mo"}
                    </span>
                  </div>
                )}
              </div>

              {/* Features */}
              <ul className="space-y-2 flex-1 mb-6">
                {plan.features.map((feat) => (
                  <li key={feat} className="flex items-start gap-2">
                    <Check className="h-4 w-4 text-green-400 shrink-0 mt-0.5" />
                    <span className="text-sm text-gray-300">{feat}</span>
                  </li>
                ))}
              </ul>

              {/* CTA */}
              {isCurrent ? (
                <button
                  type="button"
                  disabled
                  className="w-full rounded-lg bg-gray-700 text-gray-400 text-sm font-semibold py-2.5 cursor-not-allowed"
                >
                  Current plan
                </button>
              ) : isEnterprise && !canUpgrade ? (
                <a
                  href="mailto:sales@mycyberdlp.com"
                  className="block w-full text-center rounded-lg border border-gray-600 text-gray-300 hover:text-white hover:border-gray-500 text-sm font-semibold py-2.5 transition"
                >
                  Contact sales
                </a>
              ) : isEnterprise ? (
                <button
                  type="button"
                  onClick={() => setUpgradeTarget(plan)}
                  className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold py-2.5 transition"
                >
                  Upgrade — PKR {fmtPKR(displayPrice)}/{billingCycle === "semester" ? "6 mo" : "mo"}
                </button>
              ) : canUpgrade ? (
                <button
                  type="button"
                  onClick={() => setUpgradeTarget(plan)}
                  className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold py-2.5 transition"
                >
                  Upgrade — PKR {fmtPKR(billingCycle === "semester" ? plan.price_pkr * 5 : plan.price_pkr)}/mo
                </button>
              ) : (
                <button
                  type="button"
                  disabled
                  className="w-full rounded-lg bg-gray-700 text-gray-400 text-sm font-semibold py-2.5 cursor-not-allowed"
                >
                  {isFree ? "Free" : "Unavailable"}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// TAB 2 — Usage
// ---------------------------------------------------------------------------

function UsageTab({ usage, onSwitchToPlans }) {
  if (!usage) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-gray-400 text-sm">
        Loading usage data…
      </div>
    );
  }

  const pct = Math.min(usage.percent_used ?? 0, 100);
  const days = daysUntil(usage.resets_at);
  const planLabel = (usage.plan ?? "free").toUpperCase();

  return (
    <div className="space-y-4">
      {/* Main usage card */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-white font-semibold">Scan quota</h3>
          <span
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase ${planBadgeStyle(
              usage.plan
            )}`}
          >
            {planLabel}
          </span>
        </div>

        {/* Progress bar */}
        <div>
          <div className="flex items-center justify-between text-sm mb-1.5">
            <span className="text-gray-400">
              {fmtPKR(usage.scans_used)} / {fmtPKR(usage.scan_limit)} scans used
            </span>
            <span className="text-gray-400 tabular-nums">{pct}%</span>
          </div>
          <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${barColor(pct)}`}
              style={{ width: `${pct}%` }}
            />
          </div>
          {days !== null && (
            <p className="text-xs text-gray-500 mt-1.5">
              Resets in{" "}
              <span className="text-gray-300 font-medium">{days} day{days !== 1 ? "s" : ""}</span>
            </p>
          )}
        </div>
      </div>

      {/* 2x2 stat grid */}
      <div className="grid grid-cols-2 gap-4">
        {[
          { label: "Scans used", value: fmtPKR(usage.scans_used) },
          { label: "Scans remaining", value: fmtPKR(usage.scans_remaining) },
          { label: "Plan limit", value: fmtPKR(usage.scan_limit) },
          { label: "% used", value: `${pct}%` },
        ].map(({ label, value }) => (
          <div
            key={label}
            className="bg-gray-900 border border-gray-800 rounded-xl p-4"
          >
            <p className="text-xs text-gray-500 mb-1">{label}</p>
            <p className="text-2xl font-bold text-white tabular-nums">{value}</p>
          </div>
        ))}
      </div>

      {/* Features included */}
      {usage.plan_config?.features?.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-white font-semibold mb-3">Features included</h3>
          <ul className="space-y-2">
            {usage.plan_config.features.map((feat) => (
              <li key={feat} className="flex items-center gap-2">
                <Check className="h-4 w-4 text-green-400 shrink-0" />
                <span className="text-sm text-gray-300">{feat}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Upgrade CTA for free plan */}
      {usage.plan === "free" && (
        <div className="bg-blue-900/30 border border-blue-800 rounded-xl p-5 text-center space-y-3">
          <p className="text-white font-semibold">Upgrade to Pro for 100x more scans</p>
          <p className="text-sm text-blue-300">
            Get 10,000 scans/month, network scanning, real-time alerts, and API access.
          </p>
          <button
            type="button"
            onClick={onSwitchToPlans}
            className="rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-6 py-2.5 transition"
          >
            View plans
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// TAB 3 — History
// ---------------------------------------------------------------------------

function HistoryTab({ history, subscription, onCancelSuccess }) {
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);
  const [cancelError, setCancelError] = useState(null);
  const [cancelMessage, setCancelMessage] = useState(null);

  const canCancel =
    subscription?.status === "active" && subscription?.plan !== "free";

  async function handleConfirmCancel() {
    setCancelLoading(true);
    setCancelError(null);
    try {
      const res = await billingApi.cancel();
      setCancelMessage(res.data?.message ?? "Subscription cancelled.");
      setShowCancelModal(false);
      if (onCancelSuccess) onCancelSuccess();
    } catch (err) {
      setCancelError(err.response?.data?.detail ?? "Cancellation failed. Please try again.");
    } finally {
      setCancelLoading(false);
    }
  }

  return (
    <>
      {showCancelModal && (
        <CancelModal
          onConfirm={handleConfirmCancel}
          onCancel={() => setShowCancelModal(false)}
          loading={cancelLoading}
        />
      )}

      {cancelMessage && (
        <div className="mb-4 rounded-lg bg-green-900/40 border border-green-700 text-green-300 text-sm px-4 py-3">
          {cancelMessage}
        </div>
      )}
      {cancelError && (
        <div className="mb-4 rounded-lg bg-red-900/40 border border-red-700 text-red-300 text-sm px-4 py-3">
          {cancelError}
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        {history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500">
            <CreditCard className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">No billing history yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                    Date
                  </th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                    Event
                  </th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                    Plan
                  </th>
                  <th className="text-right px-5 py-3.5 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                    Amount
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {history.map((evt) => (
                  <tr key={evt.event_id} className="hover:bg-gray-800/40 transition">
                    <td className="px-5 py-3.5 text-gray-400 tabular-nums whitespace-nowrap">
                      {fmtDate(evt.created_at)}
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${eventBadgeStyle(
                          evt.event_type
                        )}`}
                      >
                        {eventLabel(evt.event_type)}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-gray-300 capitalize">
                      {evt.plan ?? "—"}
                    </td>
                    <td className="px-5 py-3.5 text-right tabular-nums text-gray-300">
                      {evt.amount_pkr > 0 ? `PKR ${fmtPKR(evt.amount_pkr)}` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {canCancel && (
        <div className="mt-6 flex justify-end">
          <button
            type="button"
            onClick={() => setShowCancelModal(true)}
            className="rounded-lg border border-red-700 text-red-400 hover:bg-red-600 hover:text-white hover:border-red-600 text-sm font-medium px-5 py-2.5 transition"
          >
            Cancel subscription
          </button>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Main BillingPage
// ---------------------------------------------------------------------------

const TABS = ["Plans", "Usage", "History"];

export default function BillingPage() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("Plans");

  const [plans, setPlans] = useState([]);
  const [usage, setUsage] = useState(null);
  const [subscription, setSubscription] = useState(null);
  const [history, setHistory] = useState([]);
  const [loadingPlans, setLoadingPlans] = useState(true);
  const [loadingUsage, setLoadingUsage] = useState(true);
  const [loadingHistory, setLoadingHistory] = useState(true);

  const fetchAll = useCallback(() => {
    setLoadingPlans(true);
    billingApi
      .getPlans()
      .then((res) => setPlans(res.data ?? []))
      .catch(() => {})
      .finally(() => setLoadingPlans(false));

    setLoadingUsage(true);
    Promise.all([billingApi.getUsage(), billingApi.getSubscription()])
      .then(([usageRes, subRes]) => {
        setUsage(usageRes.data ?? null);
        setSubscription(subRes.data ?? null);
      })
      .catch(() => {})
      .finally(() => setLoadingUsage(false));

    setLoadingHistory(true);
    billingApi
      .getHistory()
      .then((res) => setHistory(res.data ?? []))
      .catch(() => {})
      .finally(() => setLoadingHistory(false));
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const isLoading =
    (activeTab === "Plans" && loadingPlans) ||
    (activeTab === "Usage" && loadingUsage) ||
    (activeTab === "History" && loadingHistory);

  return (
    <DashboardLayout>
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <CreditCard className="h-6 w-6 text-blue-400 shrink-0" />
          <h1 className="text-xl font-bold text-white">Billing &amp; Plans</h1>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 border-b border-gray-800">
          {TABS.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2.5 text-sm font-medium transition border-b-2 -mb-px ${
                activeTab === tab
                  ? "text-white border-blue-500"
                  : "text-gray-400 border-transparent hover:text-white hover:border-gray-600"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-gray-500 text-sm">
            Loading…
          </div>
        ) : (
          <>
            {activeTab === "Plans" && (
              <PlansTab
                plans={plans}
                subscription={subscription}
                onSwitchToUsage={() => setActiveTab("Usage")}
              />
            )}
            {activeTab === "Usage" && (
              <UsageTab
                usage={usage}
                onSwitchToPlans={() => setActiveTab("Plans")}
              />
            )}
            {activeTab === "History" && (
              <HistoryTab
                history={history}
                subscription={subscription}
                onCancelSuccess={fetchAll}
              />
            )}
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
