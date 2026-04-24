import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Shield, ArrowLeft, Mail, CheckCircle } from "lucide-react";
import { authApi } from "../../api/auth";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [resetToken, setResetToken] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await authApi.requestPasswordReset(email);
      setSubmitted(true);
      // In development, the reset token is returned
      if (res.data.reset_token) {
        setResetToken(res.data.reset_token);
      }
    } catch (err) {
      const message =
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to process request. Please try again.";
      setError(typeof message === "string" ? message : "Failed to process request.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen w-full bg-gray-950">
      {/* Left panel (hidden on mobile) */}
      <div className="hidden md:flex md:w-1/2 flex-col justify-center items-center bg-gray-900 px-12 py-16">
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

        <div className="w-full max-w-xs border-t border-gray-700 my-8" />

        <ul className="w-full max-w-xs space-y-5">
          <li className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 shrink-0 text-cyan-500" strokeWidth={2} />
            <span className="text-gray-200 text-sm font-medium">
              Secure password reset
            </span>
          </li>
          <li className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 shrink-0 text-cyan-500" strokeWidth={2} />
            <span className="text-gray-200 text-sm font-medium">
              Token-based authentication
            </span>
          </li>
          <li className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 shrink-0 text-cyan-500" strokeWidth={2} />
            <span className="text-gray-200 text-sm font-medium">
              Encrypted reset links
            </span>
          </li>
        </ul>
      </div>

      {/* Right panel */}
      <div className="flex flex-1 items-center justify-center bg-gray-950 px-6 py-12">
        <div className="w-full max-w-md">
          {/* Mobile brand mark */}
          <div className="flex md:hidden items-center justify-center gap-2 mb-8">
            <Shield className="h-8 w-8 text-cyan-400" strokeWidth={1.5} />
            <span className="text-xl font-bold text-white">MyCyber DLP</span>
          </div>

          {/* Back link */}
          <Link
            to="/login"
            className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition mb-6"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to login
          </Link>

          {!submitted ? (
            <>
              <h2 className="text-2xl font-bold text-white mb-1">
                Forgot your password?
              </h2>
              <p className="text-sm text-gray-400 mb-8">
                No worries — enter your email and we'll send you a reset link.
              </p>

              {error && (
                <div className="mb-5 rounded-lg bg-red-950 border border-red-700 px-4 py-3">
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              <form onSubmit={handleSubmit} noValidate className="space-y-5">
                <div>
                  <label
                    htmlFor="email"
                    className="block text-sm font-medium text-gray-300 mb-1.5"
                  >
                    Email address
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-500" />
                    <input
                      id="email"
                      type="email"
                      autoComplete="email"
                      placeholder="you@company.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-2.5 pl-11 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
                    />
                  </div>
                </div>

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
                  {loading ? "Sending..." : "Send Reset Link"}
                </button>
              </form>
            </>
          ) : (
            <div className="text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-900/30 border border-green-700">
                <CheckCircle className="h-6 w-6 text-green-500" />
              </div>

              <h2 className="text-xl font-bold text-white mb-2">
                Check your email
              </h2>
              <p className="text-sm text-gray-400 mb-6">
                We've sent a password reset link to{" "}
                <span className="text-gray-200 font-medium">{email}</span>
              </p>

              {resetToken && (
                <div className="mb-6 rounded-lg bg-gray-800 border border-gray-700 p-4 text-left">
                  <p className="text-xs text-gray-400 mb-2">
                    Development mode — reset token:
                  </p>
                  <code className="block break-all text-xs font-mono text-cyan-400 bg-gray-900 rounded p-2">
                    {resetToken}
                  </code>
                  <Link
                    to={`/reset-password?token=${resetToken}`}
                    className="inline-block mt-3 text-xs text-cyan-400 hover:text-cyan-300 underline"
                  >
                    Click here to reset your password
                  </Link>
                </div>
              )}

              <p className="text-xs text-gray-500">
                Didn't receive the email? Check your spam folder or{" "}
                <button
                  onClick={() => setSubmitted(false)}
                  className="text-cyan-400 hover:text-cyan-300 font-medium transition"
                >
                  try another email
                </button>
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
