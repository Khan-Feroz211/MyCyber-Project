import React from "react";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

/**
 * Summary statistic card used on the dashboard overview page.
 *
 * @param {string}  title    - Metric label
 * @param {string|number} value - Main numeric / text value
 * @param {string}  [subtitle] - Small secondary line below the title
 * @param {React.ReactNode} [icon] - Icon rendered in the colored circle
 * @param {string}  [color]  - Tailwind color class for the icon ring (e.g. "bg-cyber-700")
 * @param {{ direction: "up"|"down"|"neutral", label: string }} [trend]
 */
export default function StatCard({
  title,
  value,
  subtitle,
  icon,
  color = "bg-gray-800",
  trend,
}) {
  function TrendIcon() {
    if (!trend) return null;
    const dir = trend.direction;

    if (dir === "up")
      return <TrendingUp className="h-3.5 w-3.5 text-safe-500" />;
    if (dir === "down")
      return <TrendingDown className="h-3.5 w-3.5 text-danger-500" />;
    return <Minus className="h-3.5 w-3.5 text-gray-500" />;
  }

  const trendColor =
    trend?.direction === "up"
      ? "text-safe-500"
      : trend?.direction === "down"
      ? "text-danger-500"
      : "text-gray-500";

  return (
    <div className="surface-panel hover-lift relative flex flex-col justify-between overflow-hidden rounded-2xl p-6">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/40 to-transparent" />
      {/* Icon circle — top right */}
      {icon && (
        <div
          className={`absolute right-4 top-4 flex h-11 w-11 items-center justify-center rounded-2xl shadow-lg ${color}`}
        >
          <span className="text-white [&>svg]:h-5 [&>svg]:w-5">{icon}</span>
        </div>
      )}

      {/* Value */}
      <p className="mt-1 pr-12 text-3xl font-bold leading-none text-white tabular-nums">
        {value ?? "-"}
      </p>

      {/* Title */}
      <p className="mt-2 text-sm text-slate-400">{title}</p>

      {/* Trend + subtitle */}
      <div className="mt-3 flex items-center gap-1.5">
        <TrendIcon />
        {trend && (
          <span className={`text-xs font-medium ${trendColor}`}>
            {trend.label}
          </span>
        )}
        {subtitle && !trend && (
          <span className="text-xs text-gray-500">{subtitle}</span>
        )}
      </div>

      {/* Subtle bottom-left accent bar */}
      <div className={`absolute bottom-0 left-0 h-[3px] w-1/3 rounded-r-full opacity-75 ${color}`} />
    </div>
  );
}
