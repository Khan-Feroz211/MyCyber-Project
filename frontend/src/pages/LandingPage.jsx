import React, { useState } from "react";
import { Link } from "react-router-dom";
import Footer from "../components/layout/Footer";

const trustBadges = [
  "🔒 GDPR compliant",
  "🇵🇰 Built for Pakistan",
  "⚡ Results in <1 second",
  "🛡️ SOC2 ready",
];

const problems = [
  {
    stat: "PKR 2.3M average breach impact",
    description:
      "Data breaches drain cash, trust, and customer loyalty before teams can react.",
  },
  {
    stat: "83% of leaks start internally",
    description:
      "Sensitive data often escapes through ordinary documents, chats, and exports.",
  },
  {
    stat: "Compliance fines can stop operations",
    description:
      "Regulators and enterprise buyers now demand proactive controls, not promises.",
  },
];

const steps = [
  "Upload or paste your content",
  "AI scans for 9 types of sensitive data",
  "Get instant BLOCK/WARN/ALLOW decision",
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
];

const plans = [
  {
    name: "Free",
    price: "PKR 0",
    scans: "100 scans/month",
    note: "Perfect to start and validate workflows",
    highlighted: false,
  },
  {
    name: "Pro",
    price: "PKR 4,500/month",
    scans: "10,000 scans",
    note: "For growing teams with active compliance needs",
    highlighted: true,
  },
  {
    name: "Enterprise",
    price: "PKR 15,000/month",
    scans: "Unlimited",
    note: "For large organizations with strict controls",
    highlighted: false,
  },
];

const faqs = [
  {
    q: "Is my data stored after scanning?",
    a: "No. Scans are processed in memory and not stored unless you enable scan history.",
  },
  {
    q: "Which Pakistani ID formats do you detect?",
    a: "CNIC (13-digit), IBAN (PK format), and all Pakistani phone formats (+92, 0300...).",
  },
  {
    q: "Can I use the API in my own app?",
    a: "Yes - Pro and Enterprise plans include full REST API access with documentation.",
  },
  {
    q: "How is billing handled in Pakistan?",
    a: "We use Safepay - Pakistan's leading payment gateway. Pay with JazzCash, Easypaisa, or bank transfer.",
  },
];

function ShieldLogo() {
  return (
    <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-green-400/50 bg-green-500/10 text-lg">
      🛡️
    </div>
  );
}

export default function LandingPage() {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="sticky top-0 z-40 border-b border-gray-800/80 bg-gray-950/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link to="/" className="flex items-center gap-3">
            <ShieldLogo />
            <span className="text-lg font-semibold tracking-tight">MyCyber DLP</span>
          </Link>

          <nav className="hidden items-center gap-3 md:flex">
            <Link
              to="/login"
              className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-200 transition hover:border-gray-500"
            >
              Sign in
            </Link>
            <Link
              to="/register"
              className="rounded-lg bg-green-500 px-4 py-2 text-sm font-semibold text-gray-950 transition hover:bg-green-400"
            >
              Start free
            </Link>
          </nav>

          <button
            type="button"
            className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-gray-700 text-xl md:hidden"
            onClick={() => setMenuOpen((value) => !value)}
            aria-label="Toggle menu"
          >
            ☰
          </button>
        </div>

        {menuOpen && (
          <div className="border-t border-gray-800 bg-gray-950 px-6 py-4 md:hidden">
            <div className="flex flex-col gap-3">
              <Link
                to="/login"
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-200"
                onClick={() => setMenuOpen(false)}
              >
                Sign in
              </Link>
              <Link
                to="/register"
                className="rounded-lg bg-green-500 px-4 py-2 text-sm font-semibold text-gray-950"
                onClick={() => setMenuOpen(false)}
              >
                Start free
              </Link>
            </div>
          </div>
        )}
      </header>

      <main>
        <section className="relative overflow-hidden px-6 pb-20 pt-20 lg:px-8">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(34,197,94,0.2),_transparent_45%)]" />
          <div className="relative mx-auto max-w-6xl text-center">
            <h1 className="mx-auto max-w-3xl text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
              Stop Data Leaks Before They Cost You
            </h1>
            <p className="mx-auto mt-6 max-w-3xl text-base leading-7 text-gray-400 sm:text-lg">
              AI-powered PII detection for Pakistani businesses. Scan text, files,
              and network traffic in seconds. CNIC, email, API keys, credit cards -
              we catch what your team misses.
            </p>
            <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Link
                to="/register"
                className="rounded-lg bg-green-500 px-7 py-3 text-sm font-semibold text-gray-950 transition hover:bg-green-400"
              >
                Start free - no card needed
              </Link>
              <a
                href="#demo"
                className="rounded-lg border border-gray-600 px-7 py-3 text-sm font-semibold text-gray-100 transition hover:border-gray-400"
              >
                See a demo
              </a>
            </div>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3 text-sm text-gray-300">
              {trustBadges.map((badge) => (
                <span key={badge} className="rounded-full border border-gray-700 bg-gray-900 px-4 py-2">
                  {badge}
                </span>
              ))}
            </div>
          </div>
        </section>

        <section className="border-y border-gray-900 bg-gray-950 px-6 py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <h2 className="text-center text-3xl font-bold tracking-tight text-white sm:text-4xl">
              One leaked CNIC can cost you everything
            </h2>
            <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-3">
              {problems.map((item) => (
                <article key={item.stat} className="rounded-2xl border border-gray-800 bg-gray-900 p-6">
                  <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-full bg-red-500/20 text-red-300">
                    ⚠
                  </div>
                  <h3 className="text-lg font-semibold text-white">{item.stat}</h3>
                  <p className="mt-2 text-sm leading-6 text-gray-400">{item.description}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="demo" className="px-6 py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <h2 className="text-center text-3xl font-bold text-white sm:text-4xl">How It Works</h2>
            <div className="mx-auto mt-12 max-w-5xl">
              <div className="relative grid grid-cols-1 gap-8 md:grid-cols-3">
                <div className="absolute left-0 right-0 top-6 hidden h-px bg-gray-700 md:block" />
                {steps.map((step, index) => (
                  <div key={step} className="relative rounded-xl border border-gray-800 bg-gray-900/60 p-6 text-center">
                    <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-500 text-lg font-bold text-gray-950">
                      {index + 1}
                    </div>
                    <p className="text-sm font-medium text-gray-100">{step}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="border-y border-gray-900 bg-gray-950 px-6 py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <h2 className="text-center text-3xl font-bold text-white sm:text-4xl">What We Detect</h2>
            <div className="mt-10 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {entities.map((entity) => (
                <div
                  key={entity}
                  className="rounded-full border border-green-500/40 bg-green-500/10 px-4 py-2 text-center text-sm font-medium text-green-200"
                >
                  {entity}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="pricing" className="px-6 py-20 lg:px-8">
          <div className="mx-auto max-w-6xl">
            <h2 className="text-center text-3xl font-bold text-white sm:text-4xl">Pricing</h2>
            <p className="mt-4 text-center text-sm text-green-300">Pay annually, save 2 months</p>
            <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-3">
              {plans.map((plan) => (
                <article
                  key={plan.name}
                  className={`relative rounded-2xl border p-6 ${
                    plan.highlighted
                      ? "border-green-400 bg-gray-900 shadow-[0_0_0_1px_rgba(74,222,128,0.3)]"
                      : "border-gray-800 bg-gray-900"
                  }`}
                >
                  {plan.highlighted && (
                    <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-green-500 px-3 py-1 text-xs font-semibold text-gray-950">
                      Most popular
                    </span>
                  )}
                  <h3 className="text-xl font-semibold text-white">{plan.name}</h3>
                  <p className="mt-4 text-3xl font-bold text-white">{plan.price}</p>
                  <p className="mt-2 text-sm text-green-300">{plan.scans}</p>
                  <p className="mt-4 text-sm text-gray-400">{plan.note}</p>
                  <Link
                    to="/register"
                    className="mt-6 inline-flex w-full items-center justify-center rounded-lg bg-green-500 px-4 py-2 text-sm font-semibold text-gray-950 transition hover:bg-green-400"
                  >
                    Get started
                  </Link>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="border-y border-gray-900 bg-gray-950 px-6 py-20 lg:px-8">
          <div className="mx-auto max-w-6xl text-center">
            <h2 className="text-2xl font-bold text-white">Used by security teams at:</h2>
            <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
              {["Client 1", "Client 2", "Client 3", "Client 4"].map((name) => (
                <div
                  key={name}
                  className="flex h-20 items-center justify-center rounded-xl border border-gray-800 bg-gray-900 text-sm text-gray-500"
                >
                  {name} logo
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs text-gray-500">Add real logos after first clients</p>
          </div>
        </section>

        <section className="px-6 py-20 lg:px-8">
          <div className="mx-auto max-w-4xl">
            <h2 className="text-center text-3xl font-bold text-white sm:text-4xl">FAQ</h2>
            <div className="mt-10 space-y-4">
              {faqs.map((item) => (
                <article key={item.q} className="rounded-xl border border-gray-800 bg-gray-900 p-5">
                  <h3 className="text-base font-semibold text-white">{item.q}</h3>
                  <p className="mt-2 text-sm leading-6 text-gray-400">{item.a}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="px-6 pb-20 lg:px-8">
          <div className="mx-auto max-w-6xl rounded-3xl bg-gradient-to-r from-green-900 via-green-800 to-emerald-700 p-10 text-center shadow-2xl">
            <h2 className="text-3xl font-bold text-white">Start detecting leaks in 60 seconds</h2>
            <p className="mt-3 text-sm text-green-100">Free plan - no credit card required</p>
            <Link
              to="/register"
              className="mt-6 inline-flex rounded-lg bg-white px-7 py-3 text-sm font-semibold text-green-900 transition hover:bg-green-50"
            >
              Create free account
            </Link>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
