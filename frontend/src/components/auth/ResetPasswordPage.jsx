import React, { useState, useEffect } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Shield, ArrowLeft, Eye, EyeOff, CheckCircle } from "lucide-react";
import { authApi } from "../../api/auth";

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [token, setToken] = useState("");

  useEffect(() => {
    const tokenFromUrl = searchParams.get("token");
    if (tokenFromUrl) {
      setToken(tokenFromUrl);
    } else {
      setError("Missing reset token. Please request a new password reset link.");
    }
  }, [searchParams]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (!token) {
      setError("Missing reset token. Please request a new password reset link.");
      return;
    }

    setLoading(true);

    try {
      await authApi.confirmPasswordReset(token, newPassword);
      setSuccess(true);
      setTimeout(() => {
        navigate("/login");
      }, 2000);
    } catch (err) {
      const message =
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to reset password. Please try again.";
      setError(typeof message === "string" ? message : "Failed to reset password.");
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
              Secure encrypted reset
            </span>
          </li>
          <li className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 shrink-0 text-cyan-500" strokeWidth={2} />
            <span className="text-gray-200 text-sm font-medium">
              Token expires in 1 hour
            </span>
          </li>
          <li className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 shrink-0 text-cyan-500" strokeWidth={2} />
            <span className="text-gray-200 text-sm font-medium">
              Bcrypt password hashing
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

          {!success ? (
            <>
              <h2 className="text-2xl font-bold text-white mb-1">
                Reset your password
              </h2>
              <p className="text-sm text-gray-400 mb-8">
                Enter your new password below.
              </p>

              {error && (
                <div className="mb-5 rounded-lg bg-red-950 border border-red-700 px-4 py-3">
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              <form onSubmit={handleSubmit} noValidate className="space-y-5">
                <div>
                  <label
                    htmlFor="newPassword"
                    className="block text-sm font-medium text-gray-300 mb-1.5"
                  >
                    New password
                  </label>
                  <div className="relative">
                    <input
                      id="newPassword"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                      minLength={8}
                      className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
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
                  <p className="mt-1.5 text-xs text-gray-500">
                    Must be at least 8 characters
                  </p>
                </div>

                <div>
                  <label
                    htmlFor="confirmPassword"
                    className="block text-sm font-medium text-gray-300 mb-1.5"
                  >
                    Confirm password
                  </label>
                  <div className="relative">
                    <input
                      id="confirmPassword"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                      minLength={8}
                      className="w-full rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading || !token}
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
                  {loading ? "Resetting..." : "Reset Password"}
                </button>
              </form>
            </>
          ) : (
            <div className="text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-900/30 border border-green-700">
                <CheckCircle className="h-6 w-6 text-green-500" />
              </div>

              <h2 className="text-xl font-bold text-white mb-2">
                Password reset successful!
              </h2>
              <p className="text-sm text-gray-400">
                Redirecting to login...
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
