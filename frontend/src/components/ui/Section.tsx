/**
 * 通用版块容器：标题 + 可选副标题 + 右侧操作 + 主体 + footer。
 * 参考 Ant Design Pro 的 Card 结构。
 */
import React from "react";
import "../../styles/section.css";

interface Props {
  title: React.ReactNode;
  /** 英文 / 路径等小字辅注（标题右侧一行） */
  hint?: React.ReactNode;
  description?: React.ReactNode;
  extra?: React.ReactNode;
  footer?: React.ReactNode;
  variant?: "default" | "danger";
  bordered?: boolean;
  children?: React.ReactNode;
}

export function Section({
  title,
  hint,
  description,
  extra,
  footer,
  variant = "default",
  bordered = true,
  children,
}: Props) {
  return (
    <section
      className={`dm-section dm-section-${variant} ${
        bordered ? "" : "dm-section-borderless"
      }`}
    >
      <header className="dm-section-head">
        <div className="dm-section-titles">
          <h3 className="dm-section-title">
            {title}
            {hint && <span className="dm-section-hint">{hint}</span>}
          </h3>
          {description && (
            <div className="dm-section-desc">{description}</div>
          )}
        </div>
        {extra && <div className="dm-section-extra">{extra}</div>}
      </header>
      <div className="dm-section-body">{children}</div>
      {footer && <footer className="dm-section-footer">{footer}</footer>}
    </section>
  );
}
