import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, CheckCircle2, LockKeyhole, Radar, Shield, Sparkles } from "lucide-react";
import Footer from "../components/layout/Footer";

const trustBadges = [
  "Private-by-default scanning",
  "Built for Pakistan and global teams",
  "Enterprise-ready security posture",
  "Fast trial-to-demo experience",
];

const problems = [
  {
    stat: "PKR 2.3M average breach impact",
    description:
      "Operational loss is only part of the cost. Trust decay, churn, and delayed deals usually hit harder.",
  },
  {
    stat: "83% of leaks start internally",
    description:
      "The dangerous path is usually ordinary: exports, emails, attachments, logs, and copied secrets.",
  },
  {
    stat: "Compliance reviews block revenue",
    description:
      "Buyers increasingly expect concrete controls, fast evidence, and software that looks operationally mature.",
  },
];

const steps = [
  "Paste text, upload a file, or inspect traffic",
  "Classify risk instantly across sensitive entities",
  "Trigger action, review history, and audit outcomes",
];

const entities = [
  "CNIC",
  "Email",
  "API Keys",
  "Credit Cards",
  "Passwords",
  "Phone Numbers",
  "IBANs",
  "IP Addresses",
  "Secret Tokens",
  "Internal IDs",
];

const plans = [
  {
    name: "Free",
    price: "PKR 0",
    scans: "100 scans/month",
    note: "For first validation and internal testing",
    highlighted: false,
  },
  {
    name: "Pro",
    price: "PKR 4,500/month",
    scans: "10,000 scans",
    note: "For active teams that need visibility and buyer confidence",
    highlighted: true,
  },
  {
    name: "Enterprise",
    price: "PKR 15,000/month",
    scans: "Unlimited",
    note: "For controlled rollouts, multiple stakeholders, and strict requirements",
    highlighted: false,
  },
];

const faqs = [
  {
    q: "Is my data stored after scanning?",
    a: "Not by default. The product is designed around in-memory processing unless scan history is explicitly enabled.",
  },
  {
    q: "Which local formats do you detect?",
    a: "Pakistani CNIC, IBAN, and local phone patterns are first-class targets alongside common global identifiers.",
  },
  {
    q: "Can this be embedded into another app?",
    a: "Yes. The product direction supports API-led integration for workflows, portals, and internal security tooling.",
  },
  {
    q: "Why invest in UI polish for a security product?",
    a: "Because enterprise software is judged before it is tested. Trust, clarity, and operational discipline need to be visible immediately.",
  },
];

function ShieldLogo() {
  return (
    <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-300/20 bg-gradient-to-br from-emerald-400/25 via-cyan-400/15 to-sky-400/25 shadow-[0_12px_30px_rgba(45,212,191,0.18)]">
      <Shield className="h-5 w-5 text-cyan-100" />
    </div>
  );
}

function SignalPill({ icon: Icon, children }) {
  return (
    <span className="surface-panel inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm text-slate-200">
      <Icon className="h-4 w-4 text-cyan-300" />
      {children}
    </span>
  );
}

export default function LandingPage() {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="product-shell min-h-screen text-gray-100">
      <header className="sticky top-0 z-40 border-b border-white/10 bg-[#07111a]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
          <Link to="/" className="flex items-center gap-3">
            <ShieldLogo />
            <div>
              <span className="font-mono-ui text-[11px] uppercase tracking-[0.28em] text-cyan-300/70">MyCyber</span>
              <div className="text-base font-semibold tracking-tight text-white sm:text-lg">DLP Platform</div>
            </div>
          </Link>

          <nav className="hidden items-center gap-3 md:flex">
            <a href="#pricing" className="text-sm text-slate-300 transition hover:text-white">Pricing</a>
            <a href="#faq" className="text-sm text-slate-300 transition hover:text-white">FAQ</a>
            <Link
              to="/login"
              className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-200 transition hover:border-white/20 hover:bg-white/[0.06]"
            >
              Sign in
            </Link>
            <Link
              to="/register"
              className="rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:scale-[1.02]"
            >
              Start free
            </Link>
          </nav>

          <button
            type="button"
            className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.03] text-xl md:hidden"
            onClick={() => setMenuOpen((value) => !value)}
            aria-label="Toggle menu"
          >
            ☰
          </button>
        </div>

        {menuOpen && (
          <div className="border-t border-white/10 bg-[#07111a]/95 px-4 py-4 sm:px-6 md:hidden">
            <div className="flex flex-col gap-3">
              <a href="#pricing" className="text-sm text-slate-300" onClick={() => setMenuOpen(false)}>Pricing</a>
              <a href="#faq" className="text-sm text-slate-300" onClick={() => setMenuOpen(false)}>FAQ</a>
              <Link
                to="/login"
                className="w-full rounded-xl border border-white/10 px-4 py-2 text-center text-sm font-medium text-gray-200"
                onClick={() => setMenuOpen(false)}
              >
                Sign in
              </Link>
              <Link
                to="/register"
                className="w-full rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-4 py-2 text-center text-sm font-semibold text-slate-950"
                onClick={() => setMenuOpen(false)}
              >
                Start free
              </Link>
            </div>
          </div>
        )}
      </header>

      <main>
        <section className="relative overflow-hidden px-4 pb-16 pt-14 sm:px-6 sm:pb-24 sm:pt-20 lg:px-8">
          <div className="mx-auto grid max-w-7xl gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
            <div className="float-in">
              <div className="eyebrow">
                <Sparkles className="h-3.5 w-3.5" />
                Launch-ready security SaaS
              </div>
              <h1 className="headline-balance mt-6 max-w-4xl text-4xl font-bold tracking-tight text-white sm:text-6xl">
                Security software that <span className="brand-gradient">looks credible</span> before the first enterprise demo.
              </h1>
              <p className="mt-6 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
                MyCyber helps teams detect sensitive-data exposure across text, files, and traffic with a product experience that feels operational, trustworthy, and commercially ready.
              </p>
              <div className="mt-8 flex flex-col items-start gap-3 sm:flex-row sm:items-center">
                <Link
                  to="/register"
                  className="inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-7 py-3 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px]"
                >
                  Launch your workspace
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <a
                  href="#demo"
                  className="rounded-2xl border border-white/10 bg-white/[0.03] px-7 py-3 text-sm font-semibold text-gray-100 transition hover:border-white/20 hover:bg-white/[0.05]"
                >
                  Explore the product
                </a>
              </div>
              <div className="mt-8 flex flex-wrap gap-3">
                <SignalPill icon={LockKeyhole}>Private by design</SignalPill>
                <SignalPill icon={Radar}>Fast risk visibility</SignalPill>
                <SignalPill icon={Shield}>Product-grade trust</SignalPill>
              </div>
            </div>

            <div className="float-in lg:pl-8">
              <div className="surface-panel-strong relative overflow-hidden rounded-[28px] p-5">
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/50 to-transparent" />
                <div className="mb-5 flex items-center justify-between">
                  <div>
                    <p className="font-mono-ui text-[11px] uppercase tracking-[0.28em] text-cyan-300/70">Live Risk Console</p>
                    <p className="mt-1 text-sm text-slate-400">How the product should feel in front of buyers</p>
                  </div>
                  <span className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-200">
                    Ready
                  </span>
                </div>

                <div className="grid gap-4">
                  <div className="hover-lift rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-semibold text-white">Data Exposure Risk</p>
                      <span className="font-mono-ui text-xs text-cyan-300">CRITICAL</span>
                    </div>
                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-800">
                      <div className="h-full w-[82%] rounded-full bg-gradient-to-r from-amber-400 via-orange-500 to-red-500" />
                    </div>
                    <p className="mt-3 text-sm text-slate-400">82 / 100 risk score driven by credentials, CNIC, and network-export patterns.</p>
                  </div>

                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="hover-lift rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Incidents</p>
                      <p className="mt-2 text-3xl font-bold text-white">24</p>
                      <p className="mt-1 text-sm text-slate-400">Live audit events ready for response actions.</p>
                    </div>
                    <div className="hover-lift rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-xs uppercase tracking-[0.24em] text-slate-500">MFA Rollout</p>
                      <p className="mt-2 text-3xl font-bold text-white">Opt-in</p>
                      <p className="mt-1 text-sm text-slate-400">Real account security controls with product-grade onboarding.</p>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-cyan-400/15 bg-gradient-to-r from-cyan-400/10 to-emerald-400/10 p-4">
                    <p className="text-sm font-semibold text-white">Why this matters</p>
                    <p className="mt-2 text-sm leading-7 text-slate-300">
                      Security buyers infer reliability from interface discipline. Smooth motion, strong typography, and clean hierarchy are part of the trust model.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mx-auto mt-10 flex max-w-7xl flex-wrap gap-3">
            {trustBadges.map((badge) => (
              <span key={badge} className="surface-panel rounded-full px-4 py-2 text-sm text-slate-200">
                {badge}
              </span>
            ))}
          </div>
        </section>

        <section className="px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <div className="mb-10 max-w-2xl">
              <p className="eyebrow">Commercial Reality</p>
              <h2 className="headline-balance mt-5 text-3xl font-bold tracking-tight text-white sm:text-4xl">
                The product has to solve risk and signal maturity at the same time.
              </h2>
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {problems.map((item, index) => (
                <article
                  key={item.stat}
                  className="surface-panel hover-lift rounded-[24px] p-6"
                  style={{ animationDelay: `${index * 90}ms` }}
                >
                  <div className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-red-500/14 text-red-300">
                    <Shield className="h-5 w-5" />
                  </div>
                  <h3 className="text-lg font-semibold text-white">{item.stat}</h3>
                  <p className="mt-2 text-sm leading-7 text-slate-400">{item.description}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="demo" className="px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <div className="mb-10 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
              <div className="max-w-2xl">
                <p className="eyebrow">Workflow</p>
                <h2 className="headline-balance mt-5 text-3xl font-bold text-white sm:text-4xl">A simple product story beats feature overload.</h2>
              </div>
              <p className="max-w-xl text-sm leading-7 text-slate-400">
                Buyers should understand the loop immediately: inspect, classify, respond, and prove outcomes.
              </p>
            </div>
            <div className="grid gap-4 md:grid-cols-3">
              {steps.map((step, index) => (
                <div key={step} className="surface-panel hover-lift rounded-[24px] p-6">
                  <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-400 to-cyan-400 text-base font-bold text-slate-950">
                    {index + 1}
                  </div>
                  <p className="text-sm font-medium leading-7 text-slate-100">{step}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <div className="mb-10 max-w-2xl">
              <p className="eyebrow">Coverage</p>
              <h2 className="mt-5 text-3xl font-bold text-white sm:text-4xl">What the platform can recognize.</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {entities.map((entity) => (
                <div
                  key={entity}
                  className="surface-panel hover-lift rounded-2xl px-4 py-3 text-center text-sm font-medium text-cyan-100"
                >
                  {entity}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="pricing" className="px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <div className="text-center">
              <p className="eyebrow">Pricing</p>
              <h2 className="mt-5 text-3xl font-bold text-white sm:text-4xl">Designed for adoption first, expansion second.</h2>
              <p className="mt-4 text-sm text-cyan-200/80">Start lean, then move into operational deployment.</p>
            </div>
            <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-3">
              {plans.map((plan) => (
                <article
                  key={plan.name}
                  className={`relative rounded-[28px] p-6 ${
                    plan.highlighted ? "surface-panel-strong border-cyan-300/30" : "surface-panel"
                  } hover-lift`}
                >
                  {plan.highlighted && (
                    <span className="absolute -top-3 left-6 rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400 px-3 py-1 text-xs font-semibold text-slate-950">
                      Best starting point
                    </span>
                  )}
                  <h3 className="text-xl font-semibold text-white">{plan.name}</h3>
                  <p className="mt-4 text-3xl font-bold text-white">{plan.price}</p>
                  <p className="mt-2 text-sm text-cyan-200">{plan.scans}</p>
                  <p className="mt-4 text-sm leading-7 text-slate-400">{plan.note}</p>
                  <Link
                    to="/register"
                    className={`mt-6 inline-flex w-full items-center justify-center rounded-xl px-4 py-2.5 text-sm font-semibold transition ${
                      plan.highlighted
                        ? "bg-gradient-to-r from-emerald-400 to-cyan-400 text-slate-950"
                        : "border border-white/10 bg-white/[0.03] text-white hover:bg-white/[0.06]"
                    }`}
                  >
                    Get started
                  </Link>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="faq" className="px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <div className="mx-auto max-w-4xl">
            <div className="text-center">
              <p className="eyebrow">FAQ</p>
              <h2 className="mt-5 text-3xl font-bold text-white sm:text-4xl">Questions a serious buyer will ask.</h2>
            </div>
            <div className="mt-10 space-y-4">
              {faqs.map((item) => (
                <article key={item.q} className="surface-panel hover-lift rounded-[24px] p-5">
                  <h3 className="text-base font-semibold text-white">{item.q}</h3>
                  <p className="mt-2 text-sm leading-7 text-slate-400">{item.a}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="px-4 pb-16 sm:px-6 sm:pb-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <div className="surface-panel-strong overflow-hidden rounded-[32px] p-8 text-center sm:p-12">
              <p className="font-mono-ui text-[11px] uppercase tracking-[0.28em] text-cyan-300/70">Next Move</p>
              <h2 className="headline-balance mt-4 text-3xl font-bold text-white sm:text-4xl">
                Launch with a product that feels stable, not improvised.
              </h2>
              <p className="mx-auto mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                The UI is part of the pitch. Clean hierarchy, controlled motion, and strong surfaces make the product easier to trust in trials, demos, and first customer conversations.
              </p>
              <Link
                to="/register"
                className="mt-8 inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-7 py-3 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px]"
              >
                Create free account
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
