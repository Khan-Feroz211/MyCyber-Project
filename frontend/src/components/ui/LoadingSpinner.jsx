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
      <div
        className={`${ringClass} animate-spin rounded-full border-gray-700 border-t-cyan-500`}
        role="status"
        aria-label="Loading"
      />
      {text && (
        <span className="text-sm text-gray-400 select-none">{text}</span>
      )}
    </div>
  );
}
