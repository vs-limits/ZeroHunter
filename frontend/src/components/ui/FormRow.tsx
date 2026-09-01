/**
 * 固定左标签 + 右控件的表单行。`description` 显示在标签下方作为辅说明。
 */
import React from "react";

interface Props {
  label?: React.ReactNode;
  description?: React.ReactNode;
  required?: boolean;
  align?: "center" | "top";
  children: React.ReactNode;
}

export function FormRow({
  label,
  description,
  required,
  align = "center",
  children,
}: Props) {
  return (
    <div className={`dm-srow dm-srow-${align}`}>
      <div className="dm-srow-label">
        {label && (
          <label>
            {label}
            {required && <span className="dm-required">*</span>}
          </label>
        )}
        {description && <div className="dm-srow-desc">{description}</div>}
      </div>
      <div className="dm-srow-control">{children}</div>
    </div>
  );
}
