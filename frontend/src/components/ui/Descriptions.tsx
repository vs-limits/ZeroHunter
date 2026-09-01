/**
 * Ant Design Descriptions 风的只读键值列表。竖向多列响应式。
 */
import React from "react";

interface Item {
  key?: string;
  label: React.ReactNode;
  value: React.ReactNode;
  span?: 1 | 2 | "full";
}

interface Props {
  items: Item[];
  columns?: 1 | 2 | 3;
}

export function Descriptions({ items, columns = 2 }: Props) {
  return (
    <dl
      className="dm-descrip-grid"
      style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
    >
      {items.map((it, i) => (
        <div
          key={it.key ?? i}
          className={`dm-descrip-item ${it.span === "full" ? "full" : ""}`}
          style={
            it.span && it.span !== "full"
              ? { gridColumn: `span ${it.span}` }
              : undefined
          }
        >
          <dt>{it.label}</dt>
          <dd>{it.value ?? <span className="dm-descrip-empty">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}
