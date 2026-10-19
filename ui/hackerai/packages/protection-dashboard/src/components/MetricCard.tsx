import type { ReactNode } from "react";

export function MetricCard({
  label,
  value,
  detail,
  icon,
  tone = "blue",
}: {
  label: string;
  value: number | string;
  detail: string;
  icon: ReactNode;
  tone?: "blue" | "green" | "amber";
}) {
  return (
    <article aria-label={`${label}: ${value}. ${detail}`} className={`metric-card metric-${tone}`}>
      <div className="metric-topline">
        <span className="metric-label">{label}</span>
        <span className="metric-icon" aria-hidden="true">
          {icon}
        </span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  );
}
