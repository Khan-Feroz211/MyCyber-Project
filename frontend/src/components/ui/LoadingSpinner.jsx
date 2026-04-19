import React from "react";

const SIZE_MAP = {
  sm: "h-4 w-4 border-2",
  md: "h-8 w-8 border-2",
  lg: "h-12 w-12 border-4",
};

/**
 * Centered loading spinner.
 *
 * @param {"sm"|"md"|"lg"} [size="md"]
 * @param {string} [text] - Optional label rendered below the spinner.
 */
export default function LoadingSpinner({ size = "md", text }) {
  const ringClass = SIZE_MAP[size] ?? SIZE_MAP.md;

  return (
    <div className="flex flex-col items-center justify-center gap-3">
      <div className="relative">
        <div className={`absolute inset-0 rounded-full bg-cyan-400/10 blur-md ${ringClass}`} aria-hidden="true" />
        <div
          className={`${ringClass} relative animate-spin rounded-full border border-white/10 border-t-cyan-400 border-r-emerald-300`}
          role="status"
          aria-label="Loading"
        />
      </div>
      {text && (
        <span className="font-mono-ui text-xs uppercase tracking-[0.22em] text-slate-400 select-none">{text}</span>
      )}
    </div>
  );
}
