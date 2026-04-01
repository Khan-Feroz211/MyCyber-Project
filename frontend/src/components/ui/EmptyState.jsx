import React from "react";

/**
 * Generic empty-state placeholder.
 *
 * @param {React.ReactNode} [icon]       - Large icon rendered above the title
 * @param {string}          title        - Primary heading
 * @param {string}          [message]    - Secondary description text
 * @param {string}          [actionLabel] - CTA button label
 * @param {() => void}      [onAction]   - CTA click handler
 */
export default function EmptyState({
  icon,
  title,
  message,
  actionLabel,
  onAction,
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      {icon && (
        <div className="flex items-center justify-center h-16 w-16 rounded-full bg-gray-800 text-gray-500 mb-5 [&>svg]:h-8 [&>svg]:w-8">
          {icon}
        </div>
      )}
      <h3 className="text-base font-semibold text-white mb-2">{title}</h3>
      {message && (
        <p className="text-sm text-gray-400 max-w-xs leading-relaxed">
          {message}
        </p>
      )}
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-6 rounded-lg bg-cyber-600 hover:bg-cyber-700 text-white text-sm font-semibold px-5 py-2 transition"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
