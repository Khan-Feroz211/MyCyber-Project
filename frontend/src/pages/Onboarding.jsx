import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { scanApi } from "../api/scans";
import { useAuth } from "../context/AuthContext";
import { useOnboarding } from "../context/OnboardingContext";

const EXAMPLE_TEXT = `Example: My CNIC is 42101-1234567-1
and my email is admin@company.com.
API key: sk-proj-abc123def456`;

function ProgressDots({ step }) {
  return (
    <div className="mb-8 flex items-center justify-center gap-3">
      {[1, 2, 3].map((dot) => (
        <div
          key={dot}
          className={`h-3 w-3 rounded-full transition ${
            dot <= step ? "bg-green-500" : "bg-gray-700"
          }`}
          aria-label={`Step ${dot}`}
        />
      ))}
    </div>
  );
}

function StepCard({ children }) {
  return (
    <section className="rounded-2xl border border-gray-800 bg-gray-900/80 p-6 shadow-xl sm:p-8">
      {children}
    </section>
  );
}

export default function Onboarding() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const {
    currentStep,
    setCurrentStep,
    completeOnboarding,
    skipOnboarding,
  } = useOnboarding();

  const [input, setInput] = useState(EXAMPLE_TEXT);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState(null);

  const progress = useMemo(() => {
    if (currentStep === 1) return 33;
    if (currentStep === 2) return 66;
    return 100;
  }, [currentStep]);

  const scansRemaining = Math.max(0, 100 - ((user?.scan_count_month ?? 0) + 1));

  async function runScan() {
    if (!input.trim()) {
      setScanError("Please add text before running scan.");
      return;
    }

    setScanError("");
    setScanLoading(true);

    try {
      const response = await scanApi.scanText(input);
      setScanResult(response.data);
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        err?.response?.data?.detail ||
        "Scan failed. Please try again.";
      setScanError(message);
    } finally {
      setScanLoading(false);
    }
  }

  function nextStep() {
    setCurrentStep((prev) => Math.min(3, prev + 1));
  }

  function handleSkip() {
    skipOnboarding();
    navigate("/dashboard", { replace: true });
  }

  function finishToDashboard() {
    completeOnboarding();
    navigate("/dashboard", { replace: true });
  }

  function finishToBilling() {
    completeOnboarding();
    navigate("/billing", { replace: true });
  }

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key !== "Enter" || event.shiftKey) return;

      const targetTag = event.target?.tagName?.toLowerCase();
      const isTextarea = targetTag === "textarea";

      if (currentStep === 1) {
        event.preventDefault();
        nextStep();
      } else if (currentStep === 2 && scanResult && !isTextarea) {
        event.preventDefault();
        nextStep();
      } else if (currentStep === 3) {
        event.preventDefault();
        finishToDashboard();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [currentStep, scanResult]);

  return (
    <div className="min-h-screen bg-gray-950 px-4 py-8 text-gray-100 sm:px-6 lg:px-8">
      <main className="mx-auto w-full max-w-2xl">
        <div className="mb-4 overflow-hidden rounded-full bg-gray-800">
          <div
            className="h-2 rounded-full bg-green-500 transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
        <ProgressDots step={currentStep} />

        {currentStep === 1 && (
          <StepCard>
            <div className="mb-6 flex justify-center">
              <div className="flex h-20 w-20 animate-pulse items-center justify-center rounded-full border border-green-400/40 bg-green-500/10 text-4xl">
                🛡️
              </div>
            </div>
            <h1 className="text-center text-3xl font-bold text-white">Welcome to MyCyber</h1>
            <p className="mt-3 text-center text-gray-300">Welcome, {user?.email || "there"}!</p>
            <p className="mt-2 text-center text-sm text-gray-400">
              You are on the Free plan - 100 scans/month
            </p>
            <p className="mt-2 text-center text-sm text-gray-400">
              Let&apos;s run your first scan in 60 seconds
            </p>

            <button
              type="button"
              onClick={nextStep}
              className="mt-8 w-full rounded-lg bg-green-500 px-5 py-3 text-sm font-semibold text-gray-950 transition hover:bg-green-400"
            >
              Get started
            </button>

            <button
              type="button"
              onClick={handleSkip}
              className="mt-4 block w-full text-center text-sm text-gray-400 transition hover:text-gray-200"
            >
              Skip tour
            </button>
          </StepCard>
        )}

        {currentStep === 2 && (
          <StepCard>
            <h2 className="text-2xl font-bold text-white">Scan something now</h2>
            <p className="mt-2 text-sm text-gray-400">Paste any text to scan</p>

            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={7}
              className="mt-5 w-full rounded-xl border border-gray-700 bg-gray-950 p-4 text-sm text-gray-100 outline-none transition focus:border-green-500 focus:ring-1 focus:ring-green-500"
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  if (!scanLoading) runScan();
                }
              }}
            />

            {scanError && (
              <div className="mt-4 rounded-lg border border-red-700 bg-red-950/70 px-4 py-3 text-sm text-red-300">
                {scanError}
              </div>
            )}

            {scanResult && (
              <div className="mt-4 rounded-lg border border-green-700/60 bg-green-900/20 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm text-gray-300">Severity</span>
                  <span className="rounded-full bg-red-500 px-3 py-1 text-xs font-semibold text-white">
                    {scanResult.severity || "CRITICAL"}
                  </span>
                </div>
                <p className="mt-3 text-sm text-gray-300">
                  MyCyber found {scanResult.total_entities ?? 0} sensitive items ✓
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(scanResult.entities || []).map((entity, idx) => (
                    <span
                      key={`${entity.entity_type}-${idx}`}
                      className="rounded-full border border-gray-600 bg-gray-800 px-3 py-1 text-xs text-gray-200"
                    >
                      {entity.entity_type}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <button
              type="button"
              onClick={runScan}
              disabled={scanLoading}
              className="mt-6 w-full rounded-lg bg-green-500 px-5 py-3 text-sm font-semibold text-gray-950 transition hover:bg-green-400 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {scanLoading ? "Running scan..." : "Run scan"}
            </button>

            {scanResult && (
              <button
                type="button"
                onClick={nextStep}
                className="mt-3 w-full rounded-lg border border-gray-600 px-5 py-3 text-sm font-semibold text-gray-100 transition hover:border-gray-400"
              >
                Next
              </button>
            )}
          </StepCard>
        )}

        {currentStep === 3 && (
          <StepCard>
            <div className="mb-5 flex justify-center">
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-green-500/20 text-5xl text-green-400 animate-pulse">
                ✓
              </div>
            </div>
            <h2 className="text-center text-3xl font-bold text-white">You&apos;re protected</h2>
            <p className="mt-3 text-center text-gray-300">Your first scan is complete</p>
            <p className="mt-2 text-center text-sm text-gray-400">
              MyCyber detected: CNIC, EMAIL, API_KEY
            </p>
            <p className="mt-2 text-center text-sm text-gray-400">
              On the Free plan you have {scansRemaining} scans remaining
            </p>

            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              <button
                type="button"
                onClick={finishToDashboard}
                className="w-full rounded-lg bg-green-500 px-5 py-3 text-sm font-semibold text-gray-950 transition hover:bg-green-400"
              >
                Go to dashboard
              </button>
              <button
                type="button"
                onClick={finishToBilling}
                className="w-full rounded-lg border border-gray-600 px-5 py-3 text-sm font-semibold text-gray-100 transition hover:border-gray-400"
              >
                Upgrade to Pro
              </button>
            </div>

            <p className="mt-4 text-center text-xs text-gray-500">
              Upgrade for 10,000 scans/month + Telegram alerts + API access
            </p>
          </StepCard>
        )}
      </main>
    </div>
  );
}
