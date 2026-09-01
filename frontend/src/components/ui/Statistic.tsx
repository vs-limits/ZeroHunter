/**
 * KPI 风格小卡片：大数字 + 灰底 label，可选 trend / suffix。
 */
import React from "react";

interface Props {
  label: React.ReactNode;
  value: React.ReactNode;
  hint?: React.ReactNode;
  accent?: "primary" | "success" | "warning" | "danger" | "muted";
}

export function Statistic({ label, value, hint, accent }: Props) {
  return (
    <div className={`dm-stat ${accent ? `dm-stat-${accent}` : ""}`}>
      <div className="dm-stat-num">{value}</div>
      <div className="dm-stat-cap">{label}</div>
      {hint && <div className="dm-stat-hint">{hint}</div>}
    </div>
  );
}
