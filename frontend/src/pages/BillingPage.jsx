import React, { useCallback, useEffect, useState } from "react";
import { Check, CreditCard, RefreshCw, ShieldCheck, Sparkles, X } from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import { billingApi } from "../api/billing";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import EmptyState from "../components/ui/EmptyState";

function fmtPKR(amount) {
  return new Intl.NumberFormat("en-PK").format(amount);
}

function fmtDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

function daysUntil(iso) {
  if (!iso) return null;
  const diff = new Date(iso) - new Date();
  return Math.max(0, Math.ceil(diff / 86400000));
}

function barColor(pct) {
  if (pct >= 80) return "bg-red-500";
  if (pct >= 50) return "bg-amber-500";
  return "bg-emerald-400";
}

function planBadgeStyle(plan) {
  if (plan === "enterprise") return "bg-purple-900/50 text-purple-200 border border-purple-700";
  if (plan === "pro") return "bg-cyan-900/50 text-cyan-200 border border-cyan-700";
  return "bg-slate-800 text-slate-200 border border-slate-700";
}

function eventBadgeStyle(eventType) {
  switch (eventType) {
    case "subscription_created":
    case "payment_succeeded":
      return "bg-emerald-900/50 text-emerald-200";
    case "payment_failed":
      return "bg-red-900/50 text-red-200";
    case "subscription_cancelled":
    case "scan_limit_reset":
      return "bg-slate-800 text-slate-200";
    case "plan_upgraded":
      return "bg-cyan-900/50 text-cyan-200";
    default:
      return "bg-slate-800 text-slate-200";
  }
}

function eventLabel(eventType) {
  return String(eventType || "")
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function ModalFrame({ title, children, onCancel }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="surface-panel-strong relative w-full max-w-md rounded-[28px] p-6 shadow-2xl">
        <button
          type="button"
          onClick={onCancel}
          className="absolute right-4 top-4 text-slate-500 transition hover:text-white"
        >
          <X className="h-5 w-5" />
        </button>
        <h3 className="mb-1 text-lg font-semibold text-white">{title}</h3>
        {children}
      </div>
    </div>
  );
}

function UpgradeModal({ plan, billingCycle, onConfirm, onCancel, loading }) {
  if (!plan) return null;
  const basePrice = plan.price_pkr;
  const price = billingCycle === "semester" ? basePrice * 5 : basePrice;
  const cycleLabel = billingCycle === "semester" ? "semester (6 months)" : "month";

  return (
    <ModalFrame title="Confirm upgrade" onCancel={onCancel}>
      <p className="mb-5 text-sm text-slate-400">
        You are upgrading to the <span className="font-medium text-white">{plan.name}</span> plan.
      </p>
      <div className="surface-panel mb-5 rounded-2xl p-4 space-y-2">
        <div className="flex justify-between text-sm">
          <span className="text-slate-400">Plan</span>
          <span className="font-medium text-white">{plan.name}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-slate-400">Billing cycle</span>
          <span className="font-medium capitalize text-white">{cycleLabel}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-slate-400">Amount</span>
          <span className="font-semibold text-white">PKR {fmtPKR(price)}</span>
        </div>
      </div>
      <div className="flex gap-3">
        <button
          type="button"
          onClick={onCancel}
          disabled={loading}
          className="flex-1 rounded-xl border border-white/10 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          disabled={loading}
          className="flex-1 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 py-2.5 text-sm font-semibold text-slate-950 transition disabled:opacity-50"
        >
          {loading ? "Redirecting..." : "Proceed to payment"}
        </button>
      </div>
    </ModalFrame>
  );
}

function CancelModal({ onConfirm, onCancel, loading }) {
  return (
    <ModalFrame title="Cancel subscription?" onCancel={onCancel}>
      <p className="mb-5 text-sm text-slate-400">
        Your subscription will be cancelled. Access remains available until the current billing period ends.
      </p>
      <div className="flex gap-3">
        <button
          type="button"
          onClick={onCancel}
          disabled={loading}
          className="flex-1 rounded-xl border border-white/10 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-white/[0.05] disabled:opacity-50"
        >
          Keep subscription
        </button>
        <button
          type="button"
          onClick={onConfirm}
          disabled={loading}
          className="flex-1 rounded-xl border border-red-700 py-2.5 text-sm font-semibold text-red-300 transition hover:bg-red-600 hover:text-white disabled:opacity-50"
        >
          {loading ? "Cancelling..." : "Yes, cancel"}
        </button>
      </div>
    </ModalFrame>
  );
}

function PlansTab({ plans, subscription }) {
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

      <div className="mb-6 flex items-center gap-2">
        <span className="text-sm text-slate-400">Billing cycle:</span>
        <div className="surface-panel inline-flex overflow-hidden rounded-xl">
          <button
            type="button"
            onClick={() => setBillingCycle("monthly")}
            className={`px-4 py-2 text-sm font-medium transition ${
              billingCycle === "monthly" ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            Monthly
          </button>
          <button
            type="button"
            onClick={() => setBillingCycle("semester")}
            className={`px-4 py-2 text-sm font-medium transition ${
              billingCycle === "semester" ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            Semester
          </button>
        </div>
        <span className="font-mono-ui text-[11px] uppercase tracking-[0.18em] text-cyan-300/70">
          Save 17% on 6 months
        </span>
      </div>

      {error && <div className="mb-4 rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">{error}</div>}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {plans.map((plan) => {
          const isCurrent = plan.plan_id === currentPlan;
          const isEnterprise = plan.plan_id === "enterprise";
          const isFree = plan.plan_id === "free";
          const displayPrice = billingCycle === "semester" && plan.price_pkr > 0 ? plan.price_pkr * 5 : plan.price_pkr;
          const canUpgrade = !isCurrent && !isFree && (currentPlan === "free" || (currentPlan === "pro" && isEnterprise));

          return (
            <div
              key={plan.plan_id}
              className={`relative rounded-[28px] p-6 ${isCurrent ? "surface-panel-strong border-cyan-300/30" : "surface-panel"} hover-lift flex flex-col`}
            >
              {plan.plan_id === "pro" && (
                <div className="absolute -top-3 left-6">
                  <span className="rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400 px-3 py-1 text-xs font-semibold text-slate-950">
                    Most popular
                  </span>
                </div>
              )}

              <div className="mb-1 flex items-center justify-between gap-3">
                <h3 className="text-lg font-semibold text-white">{plan.name}</h3>
                {isCurrent && (
                  <span className="rounded-full border border-cyan-500/30 bg-cyan-500/15 px-3 py-1 text-xs font-medium text-cyan-200">
                    Current
                  </span>
                )}
              </div>

              <div className="mb-5">
                {plan.price_pkr === 0 ? (
                  <span className="text-3xl font-bold text-white">Free</span>
                ) : (
                  <div>
                    <span className="text-3xl font-bold text-white">PKR {fmtPKR(displayPrice)}</span>
                    <span className="ml-1 text-sm text-slate-400">/{billingCycle === "semester" ? "6 mo" : "mo"}</span>
                  </div>
                )}
              </div>

              <ul className="mb-6 flex-1 space-y-2">
                {plan.features.map((feat) => (
                  <li key={feat} className="flex items-start gap-2">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                    <span className="text-sm text-slate-300">{feat}</span>
                  </li>
                ))}
              </ul>

              {isCurrent ? (
                <button type="button" disabled className="w-full cursor-not-allowed rounded-xl bg-slate-800 py-2.5 text-sm font-semibold text-slate-500">
                  Current plan
                </button>
              ) : isEnterprise && !canUpgrade ? (
                <a
                  href="mailto:sales@mycyberdlp.com"
                  className="block w-full rounded-xl border border-white/10 py-2.5 text-center text-sm font-semibold text-slate-200 transition hover:bg-white/[0.05]"
                >
                  Contact sales
                </a>
              ) : canUpgrade ? (
                <button
                  type="button"
                  onClick={() => setUpgradeTarget(plan)}
                  className="w-full rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 py-2.5 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px]"
                >
                  Upgrade for PKR {fmtPKR(displayPrice)}
                </button>
              ) : (
                <button type="button" disabled className="w-full cursor-not-allowed rounded-xl bg-slate-800 py-2.5 text-sm font-semibold text-slate-500">
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

function UsageTab({ usage }) {
  if (!usage) {
    return (
      <div className="surface-panel rounded-[28px] p-6">
        <LoadingSpinner text="Loading usage" />
      </div>
    );
  }

  const pct = Math.min(usage.percent_used ?? 0, 100);
  const days = daysUntil(usage.resets_at);
  const planLabel = (usage.plan ?? "free").toUpperCase();

  return (
    <div className="space-y-4">
      <div className="surface-panel-strong rounded-[28px] p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Usage</p>
            <h3 className="mt-1 font-semibold text-white">Scan quota</h3>
          </div>
          <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase ${planBadgeStyle(usage.plan)}`}>
            {planLabel}
          </span>
        </div>

        <div>
          <div className="mb-1.5 flex items-center justify-between text-sm">
            <span className="text-slate-400">
              {fmtPKR(usage.scans_used)} / {fmtPKR(usage.scan_limit)} scans used
            </span>
            <span className="tabular-nums text-slate-300">{pct}%</span>
          </div>
          <div className="h-3 w-full overflow-hidden rounded-full bg-slate-800">
            <div className={`h-full rounded-full transition-all ${barColor(pct)}`} style={{ width: `${pct}%` }} />
          </div>
          {days !== null && (
            <p className="mt-1.5 text-xs text-slate-500">
              Resets in <span className="font-medium text-slate-300">{days} day{days !== 1 ? "s" : ""}</span>
            </p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {[
          { label: "Scans used", value: fmtPKR(usage.scans_used) },
          { label: "Scans remaining", value: fmtPKR(usage.scans_remaining) },
          { label: "Plan limit", value: fmtPKR(usage.scan_limit) },
          { label: "% used", value: `${pct}%` },
        ].map(({ label, value }) => (
          <div key={label} className="surface-panel rounded-2xl p-4">
            <p className="mb-1 text-xs text-slate-500">{label}</p>
            <p className="text-2xl font-bold text-white tabular-nums">{value}</p>
          </div>
        ))}
      </div>

      {usage.plan_config?.features?.length > 0 && (
        <div className="surface-panel rounded-[28px] p-6">
          <h3 className="mb-3 font-semibold text-white">Features included</h3>
          <ul className="space-y-2">
            {usage.plan_config.features.map((feat) => (
              <li key={feat} className="flex items-center gap-2">
                <Check className="h-4 w-4 shrink-0 text-emerald-300" />
                <span className="text-sm text-slate-300">{feat}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function HistoryTab({ history, subscription, onCancelSuccess }) {
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);
  const [cancelError, setCancelError] = useState(null);
  const [cancelMessage, setCancelMessage] = useState(null);

  const canCancel = subscription?.status === "active" && subscription?.plan !== "free";

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
      {showCancelModal && <CancelModal onConfirm={handleConfirmCancel} onCancel={() => setShowCancelModal(false)} loading={cancelLoading} />}
      {cancelMessage && <div className="mb-4 rounded-2xl border border-emerald-700 bg-emerald-950/30 px-4 py-3 text-sm text-emerald-200">{cancelMessage}</div>}
      {cancelError && <div className="mb-4 rounded-2xl border border-red-700 bg-red-950/30 px-4 py-3 text-sm text-red-200">{cancelError}</div>}

      <div className="surface-panel overflow-hidden rounded-[28px]">
        {history.length === 0 ? (
          <div className="p-6">
            <EmptyState icon={<CreditCard />} title="No billing history yet" message="Payments, upgrades, and subscription events will appear here." />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="px-5 py-3.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Date</th>
                  <th className="px-5 py-3.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Event</th>
                  <th className="px-5 py-3.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Plan</th>
                  <th className="px-5 py-3.5 text-right text-xs font-semibold uppercase tracking-wide text-slate-500">Amount</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {history.map((evt) => (
                  <tr key={evt.event_id} className="hover:bg-white/[0.03]">
                    <td className="px-5 py-3.5 whitespace-nowrap text-slate-400 tabular-nums">{fmtDate(evt.created_at)}</td>
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${eventBadgeStyle(evt.event_type)}`}>
                        {eventLabel(evt.event_type)}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 capitalize text-slate-300">{evt.plan ?? "-"}</td>
                    <td className="px-5 py-3.5 text-right text-slate-300 tabular-nums">
                      {evt.amount_pkr > 0 ? `PKR ${fmtPKR(evt.amount_pkr)}` : "-"}
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
            className="rounded-xl border border-red-700 px-5 py-2.5 text-sm font-medium text-red-300 transition hover:bg-red-600 hover:text-white"
          >
            Cancel subscription
          </button>
        </div>
      )}
    </>
  );
}

const TABS = ["Plans", "Usage", "History"];

export default function BillingPage() {
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
      <div className="mx-auto max-w-5xl space-y-6">
        <section className="surface-panel-strong rounded-[30px] p-6 sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                Commercial Controls
              </div>
              <h1 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">
                Billing that feels operationally clean, not bolted on.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Plans, consumption, and subscription history need to look trustworthy because finance and procurement teams judge product maturity here.
              </p>
            </div>
            <button
              type="button"
              onClick={fetchAll}
              className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.06]"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh billing
            </button>
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-3">
            <div className="surface-panel rounded-2xl px-4 py-4">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Current plan</p>
              <p className="mt-2 text-xl font-semibold uppercase text-white">{subscription?.plan ?? usage?.plan ?? "free"}</p>
            </div>
            <div className="surface-panel rounded-2xl px-4 py-4">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Subscription status</p>
              <p className="mt-2 text-xl font-semibold text-white">{subscription?.status ?? "active"}</p>
            </div>
            <div className="surface-panel rounded-2xl px-4 py-4">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.24em] text-slate-500">Included features</p>
              <p className="mt-2 text-xl font-semibold text-white tabular-nums">{usage?.plan_config?.features?.length ?? 0}</p>
            </div>
          </div>
        </section>

        <div className="flex gap-2 overflow-x-auto pb-1">
          {TABS.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                activeTab === tab
                  ? "bg-gradient-to-r from-emerald-400 to-cyan-400 text-slate-950"
                  : "surface-panel text-slate-300 hover:text-white"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {isLoading ? (
          <div className="surface-panel rounded-[28px] p-10">
            <LoadingSpinner size="lg" text="Loading billing" />
          </div>
        ) : (
          <>
            {activeTab === "Plans" && <PlansTab plans={plans} subscription={subscription} />}
            {activeTab === "Usage" && <UsageTab usage={usage} />}
            {activeTab === "History" && (
              <HistoryTab history={history} subscription={subscription} onCancelSuccess={fetchAll} />
            )}
          </>
        )}

        <section className="surface-panel rounded-[28px] p-5">
          <div className="flex items-start gap-3">
            <ShieldCheck className="mt-0.5 h-5 w-5 text-cyan-300" />
            <div>
              <h2 className="text-sm font-semibold text-white">Launch readiness note</h2>
              <p className="mt-1 text-sm leading-7 text-slate-400">
                For production launch, replace any temporary support addresses and make sure invoice, tax, and payment copy matches your actual commercial operations.
              </p>
            </div>
          </div>
        </section>
      </div>
    </DashboardLayout>
  );
}
