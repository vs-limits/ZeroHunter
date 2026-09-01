import { CSSProperties, Fragment, ReactNode } from "react";

export const COLLAPSE_PREFIX = "@@DM_COLLAPSE@@";
export const STATUS_PREFIX = "@@DM_STATUS@@";

export type CollapseBlock = {
  count: number;
  label: string;
  lines: string[];
};

export type StatusLine = {
  id: string;
  active: boolean;
  label: string;
  detail?: string;
};

export function stripAnsi(text: string): string {
  return text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "");
}

function machinePrefixIndex(line: string, prefix: string): number {
  return stripAnsi(line).indexOf(prefix);
}

/** Merge Rich-wrapped @@DM_*@@ JSON fragments into single logical lines. */
export function normalizeConsoleLines(lines: string[]): string[] {
  const out: string[] = [];
  let pending: string | null = null;

  const flushPending = () => {
    if (pending !== null) {
      out.push(pending);
      pending = null;
    }
  };

  for (const raw of lines) {
    const plain = stripAnsi(raw).trimEnd();
    if (!plain) continue;

    if (pending !== null) {
      pending += plain.trimStart();
      if (parseStatusLine(pending) || parseCollapseLine(pending)) {
        flushPending();
      }
      continue;
    }

    const statusIdx = machinePrefixIndex(plain, STATUS_PREFIX);
    const collapseIdx = machinePrefixIndex(plain, COLLAPSE_PREFIX);
    if (statusIdx >= 0 || collapseIdx >= 0) {
      const start = statusIdx >= 0 ? statusIdx : collapseIdx;
      const normalized = plain.slice(start);
      if (parseStatusLine(normalized) || parseCollapseLine(normalized)) {
        out.push(normalized);
      } else {
        pending = normalized;
      }
      continue;
    }

    out.push(raw);
  }

  flushPending();
  return out;
}

const ANSI_RE = /\x1b\[([0-9;]*)m/g;
const RICH_TAG_RE = /(\[[^\]]+\])/g;

const ANSI_COLORS: Record<number, string> = {
  30: "#8c8c8c",
  31: "#ff7875",
  32: "#73d13d",
  33: "#ffc53d",
  34: "#69b1ff",
  35: "#d3adf7",
  36: "#5cdbd3",
  37: "#f0f0f0",
  90: "#595959",
  91: "#ff4d4f",
  92: "#52c41a",
  93: "#faad14",
  94: "#1677ff",
  95: "#9254de",
  96: "#13c2c2",
  97: "#ffffff",
};

const RICH_STYLE: Record<string, CSSProperties> = {
  bold: { fontWeight: 600 },
  dim: { opacity: 0.62 },
  red: { color: "#ff7875" },
  green: { color: "#73d13d" },
  yellow: { color: "#ffc53d" },
  cyan: { color: "#5cdbd3" },
  magenta: { color: "#d3adf7" },
  blue: { color: "#69b1ff" },
};

function mergeStyle(base: CSSProperties, extra: CSSProperties): CSSProperties {
  return { ...base, ...extra };
}

function parseAnsiCodes(codes: string, state: StyleState): StyleState {
  const next = { ...state, style: { ...state.style } };
  if (!codes) {
    return { style: {}, stack: [] };
  }
  const parts = codes.split(";").filter(Boolean);
  let i = 0;
  while (i < parts.length) {
    const code = Number(parts[i]);
    if (code === 0) {
      next.style = {};
    } else if (code === 1) {
      next.style = mergeStyle(next.style, { fontWeight: 600 });
    } else if (code === 2 || code === 22) {
      next.style =
        code === 2
          ? mergeStyle(next.style, { opacity: 0.62 })
          : { ...next.style, opacity: undefined };
    } else if (ANSI_COLORS[code]) {
      next.style = mergeStyle(next.style, { color: ANSI_COLORS[code] });
    } else if (code === 38 && parts[i + 1] === "2") {
      const r = Number(parts[i + 2]);
      const g = Number(parts[i + 3]);
      const b = Number(parts[i + 4]);
      next.style = mergeStyle(next.style, { color: `rgb(${r}, ${g}, ${b})` });
      i += 4;
    }
    i += 1;
  }
  return next;
}

type StyleState = { style: CSSProperties; stack: CSSProperties[] };

function richTagToStyle(tag: string): CSSProperties | null {
  if (tag.startsWith("/")) return null;
  const tokens = tag.trim().split(/\s+/);
  let style: CSSProperties = {};
  for (const token of tokens) {
    const mapped = RICH_STYLE[token];
    if (mapped) style = mergeStyle(style, mapped);
  }
  return Object.keys(style).length ? style : null;
}

function renderRichMarkup(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const stack: CSSProperties[] = [];
  let style: CSSProperties = {};
  let key = 0;

  const pushText = (chunk: string) => {
    if (!chunk) return;
    nodes.push(
      <span key={`${keyPrefix}-${key++}`} style={style}>
        {chunk}
      </span>
    );
  };

  const parts = text.split(RICH_TAG_RE);
  for (const part of parts) {
    if (!part) continue;
    if (part.startsWith("[") && part.endsWith("]")) {
      const tag = part.slice(1, -1);
      if (tag.startsWith("/")) {
        const name = tag.slice(1).trim();
        if (!name) {
          stack.length = 0;
          style = {};
        } else {
          while (stack.length) {
            const top = stack.pop()!;
            style = top;
            if (name === "bold" && !Object.prototype.hasOwnProperty.call(top, "fontWeight")) break;
          }
        }
      } else {
        stack.push(style);
        const extra = richTagToStyle(tag);
        style = extra ? mergeStyle(style, extra) : style;
      }
      continue;
    }
    pushText(part);
  }
  return nodes;
}

function renderAnsi(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let state: StyleState = { style: {}, stack: [] };
  let key = 0;
  let match: RegExpExecArray | null;

  ANSI_RE.lastIndex = 0;
  while ((match = ANSI_RE.exec(text)) !== null) {
    if (match.index > last) {
      nodes.push(
        <span key={`${keyPrefix}-${key++}`} style={state.style}>
          {text.slice(last, match.index)}
        </span>
      );
    }
    state = parseAnsiCodes(match[1], state);
    last = match.index + match[0].length;
  }
  if (last < text.length) {
    nodes.push(
      <span key={`${keyPrefix}-${key++}`} style={state.style}>
        {text.slice(last)}
      </span>
    );
  }
  return nodes.length ? nodes : [text];
}

export function parseCollapseLine(line: string): CollapseBlock | null {
  const plain = stripAnsi(line).trim();
  const idx = plain.indexOf(COLLAPSE_PREFIX);
  if (idx < 0) return null;
  try {
    const data = JSON.parse(plain.slice(idx + COLLAPSE_PREFIX.length)) as CollapseBlock;
    if (!Array.isArray(data.lines)) return null;
    return {
      count: data.count ?? data.lines.length,
      label: data.label ?? `${data.lines.length} 条已折叠输出`,
      lines: data.lines,
    };
  } catch {
    return null;
  }
}

export function parseStatusLine(line: string): StatusLine | null {
  const plain = stripAnsi(line).trim();
  const idx = plain.indexOf(STATUS_PREFIX);
  if (idx < 0) return null;
  try {
    const data = JSON.parse(plain.slice(idx + STATUS_PREFIX.length)) as Partial<StatusLine>;
    if (!data.id || typeof data.active !== "boolean") return null;
    return {
      id: String(data.id),
      active: data.active,
      label: String(data.label ?? ""),
      detail: data.detail ? String(data.detail) : undefined,
    };
  } catch {
    return null;
  }
}

/** Strip Rich redraw / legacy heartbeat noise from persisted console logs. */
export function isLegacyConsoleNoise(line: string): boolean {
  const plain = line
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")
    .replace(/\[\?25l|\[2K/g, "")
    .trim();
  if (!plain) return true;
  if (/^调用 TreeScan Agent/.test(plain)) return true;
  if (/^❤\s*callscan\s*进度/.test(plain)) return true;
  if (/^->\s*❤\s*callscan\s*进度/.test(plain)) return true;
  if (/^->\s*callscan 进度 \d+\/\d+/.test(plain)) return true;
  return false;
}

export function formatConsoleLine(line: string, keyPrefix: string): ReactNode {
  if (line.includes("\x1b[")) {
    return <Fragment>{renderAnsi(line, keyPrefix)}</Fragment>;
  }
  if (/\[[a-z/]/.test(line)) {
    return <Fragment>{renderRichMarkup(line, keyPrefix)}</Fragment>;
  }
  return line;
}
