import React from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoadingSpinner from "./components/ui/LoadingSpinner";

/* ─── Lazy imports (pages) ─────────────────────────────────────────── */
// Eager imports keep the initial bundle small while still being
// immediately available — swap to React.lazy if code-splitting is desired.
import LoginPage from "./components/auth/LoginPage";
import RegisterPage from "./components/auth/RegisterPage";
import DashboardPage from "./pages/DashboardPage";
import ScanPage from "./pages/ScanPage";
import HistoryPage from "./pages/HistoryPage";
import AlertsPage from "./pages/AlertsPage";
import SettingsPage from "./pages/SettingsPage";
import BillingPage from "./pages/BillingPage";
import AdminIncidentsPage from "./pages/AdminIncidentsPage";
import LandingPage from "./pages/LandingPage";
import PrivacyPolicy from "./pages/legal/PrivacyPolicy";
import TermsOfService from "./pages/legal/TermsOfService";
import Footer from "./components/layout/Footer";
import Onboarding from "./pages/Onboarding";
import {
  OnboardingProvider,
  useOnboarding,
} from "./context/OnboardingContext";

/* ─── Private route guard ──────────────────────────────────────────── */
/**
 * Wraps a page that requires the user to be authenticated.
 * Shows a full-screen spinner while the auth state is restoring
 * from localStorage (initial page load), then either renders
 * the page or redirects to /login.
 */
function PrivateRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <LoadingSpinner size="lg" text="Loading…" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

function OnboardingRoute() {
  const { isAuthenticated, loading } = useAuth();
  const { shouldShowOnboarding, isComplete } = useOnboarding();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <LoadingSpinner size="lg" text="Loading..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!shouldShowOnboarding || isComplete) {
    return <Navigate to="/dashboard" replace />;
  }

  return <Onboarding />;
}

function ProtectedAppRoute({ children }) {
  const { shouldShowOnboarding, isComplete } = useOnboarding();

  if (shouldShowOnboarding && !isComplete) {
    return <Navigate to="/onboarding" replace />;
  }

  return <PrivateRoute>{children}</PrivateRoute>;
}

function AdminRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <LoadingSpinner size="lg" text="Loading..." />
      </div>
    );
  }

  if (!user?.is_admin) {
    return <Navigate to="/dashboard" replace />;
  }

  return <ProtectedAppRoute>{children}</ProtectedAppRoute>;
}

function HomeRoute() {
  const { isAuthenticated, loading } = useAuth();
  const { shouldShowOnboarding, isComplete } = useOnboarding();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <LoadingSpinner size="lg" text="Loading..." />
      </div>
    );
  }

  if (isAuthenticated) {
    if (shouldShowOnboarding && !isComplete) {
      return <Navigate to="/onboarding" replace />;
    }
    return <Navigate to="/dashboard" replace />;
  }

  return <LandingPage />;
}

function SecurityPage() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <main className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
        <h1 className="text-3xl font-bold text-white">Security</h1>
        <p className="mt-4 text-gray-400">
          Security overview page is being finalized. Contact support for security
          questionnaires and architecture notes.
        </p>
      </main>
      <Footer />
    </div>
  );
}

function ContactPage() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <main className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
        <h1 className="text-3xl font-bold text-white">Contact</h1>
        <p className="mt-4 text-gray-400">
          Reach us at support@mycyber.pk for customer support and sales@mycyber.pk
          for enterprise onboarding.
        </p>
      </main>
      <Footer />
    </div>
  );
}

/* ─── Router ────────────────────────────────────────────────────────── */
function AppRoutes() {
  return (
    <Routes>
      {/* ── Public routes ── */}
      <Route path="/" element={<HomeRoute />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/privacy" element={<PrivacyPolicy />} />
      <Route path="/terms" element={<TermsOfService />} />
      <Route path="/security" element={<SecurityPage />} />
      <Route path="/contact" element={<ContactPage />} />
      <Route path="/onboarding" element={<OnboardingRoute />} />

      {/* ── Protected routes ── */}
      <Route
        path="/dashboard"
        element={
          <ProtectedAppRoute>
            <DashboardPage />
          </ProtectedAppRoute>
        }
      />
      <Route
        path="/scan"
        element={
          <ProtectedAppRoute>
            <ScanPage />
          </ProtectedAppRoute>
        }
      />
      <Route
        path="/history"
        element={
          <ProtectedAppRoute>
            <HistoryPage />
          </ProtectedAppRoute>
        }
      />
      <Route
        path="/alerts"
        element={
          <ProtectedAppRoute>
            <AlertsPage />
          </ProtectedAppRoute>
        }
      />
      <Route
        path="/billing"
        element={
          <ProtectedAppRoute>
            <BillingPage />
          </ProtectedAppRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedAppRoute>
            <SettingsPage />
          </ProtectedAppRoute>
        }
      />
      <Route
        path="/admin/incidents"
        element={
          <AdminRoute>
            <AdminIncidentsPage />
          </AdminRoute>
        }
      />

      {/* ── Catch-all redirects ── */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

/* ─── Root app ──────────────────────────────────────────────────────── */
export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <OnboardingProvider>
          <AppRoutes />
        </OnboardingProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
