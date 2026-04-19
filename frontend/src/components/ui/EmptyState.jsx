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
    <div className="surface-panel flex flex-col items-center justify-center rounded-[28px] px-6 py-16 text-center">
      {icon && (
        <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/15 bg-cyan-400/10 text-cyan-200 [&>svg]:h-8 [&>svg]:w-8">
          {icon}
        </div>
      )}
      <h3 className="mb-2 text-base font-semibold text-white">{title}</h3>
      {message && (
        <p className="max-w-xs text-sm leading-relaxed text-slate-400">
          {message}
        </p>
      )}
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-6 rounded-xl bg-gradient-to-r from-emerald-400 to-cyan-400 px-5 py-2 text-sm font-semibold text-slate-950 transition hover:translate-y-[-2px]"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
