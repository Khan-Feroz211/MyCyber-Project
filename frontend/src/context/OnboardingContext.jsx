import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useAuth } from "./AuthContext";

const ONBOARDED_KEY = "mycyber_onboarded";

const OnboardingContext = createContext(null);

export function OnboardingProvider({ children }) {
  const { user, loading: authLoading } = useAuth();
  const [shouldShowOnboarding, setShouldShowOnboarding] = useState(false);
  const [currentStep, setCurrentStep] = useState(1);
  const [isComplete, setIsComplete] = useState(false);

  useEffect(() => {
    if (authLoading) return;

    const marker = localStorage.getItem(ONBOARDED_KEY);

    if (!user) {
      setShouldShowOnboarding(false);
      setIsComplete(false);
      setCurrentStep(1);
      return;
    }

    if (marker === "true" || marker === "skip") {
      setShouldShowOnboarding(false);
      setIsComplete(true);
      return;
    }

    const scansUsed = Number(user.scan_count_month ?? 0);
    const firstTimeUser = scansUsed === 0;

    setShouldShowOnboarding(firstTimeUser);
    setIsComplete(!firstTimeUser);
    setCurrentStep(1);
  }, [user, authLoading]);

  function completeOnboarding() {
    localStorage.setItem(ONBOARDED_KEY, "true");
    setIsComplete(true);
    setShouldShowOnboarding(false);
  }

  function skipOnboarding() {
    localStorage.setItem(ONBOARDED_KEY, "skip");
    setIsComplete(true);
    setShouldShowOnboarding(false);
  }

  const value = useMemo(
    () => ({
      shouldShowOnboarding,
      currentStep,
      setCurrentStep,
      isComplete,
      completeOnboarding,
      skipOnboarding,
    }),
    [shouldShowOnboarding, currentStep, isComplete]
  );

  return (
    <OnboardingContext.Provider value={value}>
      {children}
    </OnboardingContext.Provider>
  );
}

export function useOnboarding() {
  const ctx = useContext(OnboardingContext);
  if (!ctx) {
    throw new Error("useOnboarding must be used within an OnboardingProvider");
  }
  return ctx;
}
