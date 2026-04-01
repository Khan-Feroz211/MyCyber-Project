import React from "react";

const SEVERITY_STYLES = {
  CRITICAL:
    "bg-red-900 text-red-300 border border-red-700",
  HIGH: "bg-orange-900 text-orange-300 border border-orange-700",
  MEDIUM: "bg-yellow-900 text-yellow-300 border border-yellow-700",
  LOW: "bg-blue-900 text-blue-300 border border-blue-700",
  SAFE: "bg-green-900 text-green-300 border border-green-700",
};

/**
 * Colored pill badge for scan / alert severity levels.
 *
 * @param {"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"SAFE"} severity
 */
export default function SeverityBadge({ severity }) {
  const key = (severity ?? "").toUpperCase();
  const styles =
    SEVERITY_STYLES[key] ??
    "bg-gray-800 text-gray-400 border border-gray-600";

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 font-mono text-xs font-medium uppercase tracking-wide ${styles}`}
    >
      {key || severity}
    </span>
  );
}
