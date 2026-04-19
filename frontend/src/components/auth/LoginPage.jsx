import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Shield, CheckCircle } from "lucide-react";
import { useAuth } from "../../context/AuthContext";

const FEATURES = [
  "Real-time PII Detection",
  "AI-Powered Threat Analysis",
  "Multi-tenant Security Platform",
];

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await login(email, password);
      navigate("/dashboard");
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        err?.response?.data?.detail ||
        err?.message ||
        "Invalid email or password.";
      setError(typeof message === "string" ? message : "Invalid email or password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen w-full bg-gray-950">
      {/* ── Left panel (hidden on mobile) ── */}
      <div className="hidden md:flex md:w-1/2 flex-col justify-center items-center bg-gray-900 px-12 py-16">
        {/* Brand */}
        <div className="flex items-center gap-3 mb-6">
          <Shield className="h-14 w-14 text-cyan-400" strokeWidth={1.5} />
          <div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">
              MyCyber DLP
            </h1>
            <p className="text-sm text-gray-400 mt-0.5">
              Enterprise Data Leakage Prevention
            </p>
          </div>
        </div>

        {/* Divider */}
        <div className="w-full max-w-xs border-t border-gray-700 my-8" />

        {/* Feature bullets */}
        <ul className="w-full max-w-xs space-y-5">
          {FEATURES.map((feat) => (
            <li key={feat} className="flex items-center gap-3">
              <CheckCircle
                className="h-5 w-5 shrink-0 text-cyan-500"
                strokeWidth={2}
              />
              <span className="text-gray-200 text-sm font-medium">{feat}</span>
            </li>
          ))}
        </ul>

        {/* Decorative bottom gradient */}
        <div className="mt-auto w-full max-w-xs h-1 rounded-full bg-gradient-to-r from-cyan-600 via-cyber-500 to-transparent opacity-50" />
      </div>

      {/* ── Right panel ── */}
      <div className="flex flex-1 items-center justify-center bg-gray-950 px-6 py-12">
        <div className="w-full max-w-md">
          {/* Mobile brand mark */}
          <div className="flex md:hidden items-center justify-center gap-2 mb-8">
            <Shield className="h-8 w-8 text-cyan-400" strokeWidth={1.5} />
            <span className="text-xl font-bold text-white">MyCyber DLP</span>
          </div>

          {/* Heading */}
          <h2 className="text-2xl font-bold text-white mb-1">Welcome back</h2>
          <p className="text-sm text-gray-400 mb-8">
            Sign in to your security dashboard
          </p>

          {/* Error banner */}
          {error && (
            <div className="mb-5 rounded-lg bg-red-950 border border-red-700 px-4 py-3">
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate className="space-y-5">
            {/* Email */}
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-300 mb-1.5"
              >
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
              />
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-300 mb-1.5"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-2.5 pr-11 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-400 hover:text-gray-200 transition"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="mt-2 w-full flex items-center justify-center gap-2 rounded-lg bg-cyber-600 hover:bg-cyber-700 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold py-2.5 text-sm transition"
            >
              {loading && (
                <svg
                  className="h-4 w-4 animate-spin"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v8H4z"
                  />
                </svg>
              )}
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>

          {/* Register link */}
          <p className="mt-6 text-center text-sm text-gray-500">
            Don&apos;t have an account?{" "}
            <Link
              to="/register"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition"
            >
              Register
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
