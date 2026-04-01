import React from "react";

const ACTION_STYLES = {
  BLOCK: "bg-red-600 text-white",
  WARN: "bg-yellow-600 text-white",
  ALLOW: "bg-green-600 text-white",
};

/**
 * Colored pill badge for DLP action decisions.
 *
 * @param {"BLOCK"|"WARN"|"ALLOW"} action
 */
export default function ActionBadge({ action }) {
  const key = (action ?? "").toUpperCase();
  const styles = ACTION_STYLES[key] ?? "bg-gray-700 text-gray-200";

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${styles}`}
    >
      {key || action}
    </span>
  );
}
