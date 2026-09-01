import { useEffect, useMemo, useState } from "react";
import {
  CollapseBlock,
  StatusLine,
  formatConsoleLine,
  isLegacyConsoleNoise,
  normalizeConsoleLines,
  parseCollapseLine,
  parseStatusLine,
} from "../lib/consoleFormat";

interface Props {
  lines: string[];
  emptyText?: string;
}

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export function ScanConsole({ lines, emptyText }: Props) {
  const blocks = useMemo(
    () => buildBlocks(normalizeConsoleLines(lines)),
    [lines]
  );

  if (lines.length === 0) {
    return <span className="dm-console-empty">{emptyText}</span>;
  }

  return (
    <div className="dm-console-lines">
      {blocks.map((block, index) => {
        if (block.kind === "collapse") {
          return <CollapseSection key={`c-${index}`} block={block.data} />;
        }
        if (block.kind === "status") {
          return (
            <StatusLineSection key={`s-${block.data.id}`} data={block.data} />
          );
        }
        return (
          <div key={`l-${index}`} className="dm-console-line">
            {formatConsoleLine(block.line, `l-${index}`)}
          </div>
        );
      })}
    </div>
  );
}

function StatusLineSection({ data }: { data: StatusLine }) {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(
      () => setFrame((prev) => (prev + 1) % SPINNER_FRAMES.length),
      90
    );
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="dm-console-status" aria-live="polite" aria-busy="true">
      <span className="dm-console-status-spinner">{SPINNER_FRAMES[frame]}</span>
      <span className="dm-console-status-label">{data.label}</span>
      {data.detail ? (
        <span className="dm-console-status-detail"> · {data.detail}</span>
      ) : null}
    </div>
  );
}

function CollapseSection({ block }: { block: CollapseBlock }) {
  const [open, setOpen] = useState(false);

  return (
    <details
      className="dm-console-collapse"
      open={open}
      onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}
    >
      <summary className="dm-console-collapse-summary">
        <span className="dm-console-collapse-icon">{open ? "▾" : "▸"}</span>
        <span className="dm-console-collapse-label">
          {block.label}
          <span className="dm-console-collapse-hint">（点击展开）</span>
        </span>
        <span className="dm-console-collapse-count">{block.count} 行</span>
      </summary>
      <div className="dm-console-collapse-body">
        {block.lines.map((line, index) => (
          <div key={index} className="dm-console-line">
            {formatConsoleLine(line, `x-${index}`)}
          </div>
        ))}
      </div>
    </details>
  );
}

type LineBlock =
  | { kind: "line"; line: string }
  | { kind: "collapse"; data: CollapseBlock }
  | { kind: "status"; data: StatusLine };

function buildBlocks(lines: string[]): LineBlock[] {
  const out: LineBlock[] = [];
  const statusIndex = new Map<string, number>();

  for (const line of lines) {
    const status = parseStatusLine(line);
    if (status) {
      if (!status.active) {
        const idx = statusIndex.get(status.id);
        if (idx !== undefined) {
          out[idx] = { kind: "line", line: "" };
          statusIndex.delete(status.id);
        }
        continue;
      }
      const existing = statusIndex.get(status.id);
      if (existing !== undefined) {
        out[existing] = { kind: "status", data: status };
      } else {
        statusIndex.set(status.id, out.length);
        out.push({ kind: "status", data: status });
      }
      continue;
    }

    if (isLegacyConsoleNoise(line)) continue;

    const collapsed = parseCollapseLine(line);
    if (collapsed) {
      out.push({ kind: "collapse", data: collapsed });
    } else {
      out.push({ kind: "line", line });
    }
  }

  return out.filter(
    (block) => !(block.kind === "line" && block.line === "")
  );
}
