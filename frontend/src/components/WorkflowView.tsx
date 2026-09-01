import { useEffect, useMemo, useRef, useState } from "react";
import {
  EventsChunk,
  ProjectItem,
  RunEvent,
  WorkflowGraph,
  WorkflowNode,
  getEvents,
  getWorkflow,
} from "../api";
import { AGENT_LABELS, RUN_STATUS_LABELS } from "../i18n";
import { cacheKey, fetchCached, invalidateCache } from "../lib/requestCache";
import "../styles/workflow.css";

interface Props {
  project: ProjectItem;
  runId: string | null;
  scanStatus?: string;
}

const REFRESH_MS = 4000;

export function WorkflowView({ project, runId, scanStatus }: Props) {
  const [graph, setGraph] = useState<WorkflowGraph | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  const cacheTtl = scanStatus === "running" ? 3_000 : 60_000;

  async function load(force = false) {
    try {
      const wfKey = cacheKey(["workflow", project.project_path, runId]);
      const evKey = cacheKey(["events", project.project_path, runId, 0, 1000]);
      const [g, e] = await Promise.all([
        fetchCached(wfKey, () => getWorkflow(project.project_path, runId), {
          force,
          ttlMs: cacheTtl,
        }),
        fetchCached(
          evKey,
          () => getEvents(project.project_path, runId, 0, 1000),
          { force, ttlMs: cacheTtl }
        ),
      ]);
      setGraph(g);
      setEvents(e.events);
    } catch (err) {
      setError(String(err));
    }
  }

  useEffect(() => {
    setGraph(null);
    setEvents([]);
    setError(null);
    invalidateCache(cacheKey(["workflow", project.project_path, runId]));
    invalidateCache(cacheKey(["events", project.project_path, runId]));
    load(true);
  }, [project.project_path, runId]);

  useEffect(() => {
    if (timerRef.current) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (!autoRefresh) return;
    timerRef.current = window.setInterval(() => {
      load(scanStatus === "running");
    }, REFRESH_MS);
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh, project.project_path, runId]);

  const activeNodeData = useMemo(
    () => (graph ? graph.nodes.find((n) => n.id === activeNode) ?? null : null),
    [graph, activeNode]
  );

  return (
    <>
      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">工作流</h3>
          <div className="dm-spacer" />
          <label className="dm-switch">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span>自动刷新 ({REFRESH_MS / 1000}s)</span>
          </label>
          <button className="dm-btn dm-btn-sm" onClick={() => void load()}>
            ↻ 立即刷新
          </button>
        </div>
        {error && (
          <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
            {error}
          </div>
        )}

        {graph && (
          <FlowCanvas
            graph={graph}
            activeNode={activeNode}
            onNodeClick={setActiveNode}
          />
        )}
      </div>

      <div className="dm-grid-2">
        <div className="dm-card">
          <h3 className="dm-card-title">节点详情</h3>
          {activeNodeData ? (
            <NodeDetail node={activeNodeData} />
          ) : (
            <div className="dm-empty-tip">选择节点</div>
          )}
        </div>

        <div className="dm-card">
          <h3 className="dm-card-title">事件流</h3>
          <div className="dm-card-sub">{events.length} 条</div>
          <div className="dm-eventlog">
            {events.length === 0 && <div className="dm-empty-tip">暂无事件</div>}
            {events
              .slice()
              .reverse()
              .map((e, i) => (
                <EventItem key={`${e.ts}-${i}`} ev={e} />
              ))}
          </div>
        </div>
      </div>
    </>
  );
}

// ---------------- 画布 ----------------

interface CanvasLayout {
  width: number;
  height: number;
  positions: Record<string, { x: number; y: number; w: number; h: number }>;
}

function buildLayout(graph: WorkflowGraph): CanvasLayout {
  // 横向流水线：repo -> treescan -> callscan -> dataflowscan -> auditor -> findings
  // 节点宽 220 高 110，水平间距 80。
  const order = ["repo", "treescan", "callscan", "dataflowscan", "auditor", "findings"];
  const W = 220;
  const H = 110;
  const GAP_X = 80;
  const PAD = 32;
  const Y = PAD + H / 2;

  const positions: CanvasLayout["positions"] = {};
  order.forEach((id, idx) => {
    positions[id] = {
      x: PAD + idx * (W + GAP_X),
      y: PAD,
      w: W,
      h: H,
    };
  });

  // pipeline 总体作为顶部条带，不绘制为节点
  const last = order[order.length - 1];
  const lastPos = positions[last];
  const width = lastPos.x + W + PAD;
  const height = PAD + H + PAD;

  return { width, height, positions };
}

function FlowCanvas({
  graph,
  activeNode,
  onNodeClick,
}: {
  graph: WorkflowGraph;
  activeNode: string | null;
  onNodeClick: (id: string) => void;
}) {
  const layout = useMemo(() => buildLayout(graph), [graph]);

  return (
    <div className="dm-flow-wrap">
      <svg
        className="dm-flow-svg"
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <marker
            id="arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-text-tertiary)" />
          </marker>
          <marker
            id="arrow-active"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-primary)" />
          </marker>
        </defs>

        {/* 边 */}
        {graph.edges.map((e, i) => {
          const a = layout.positions[e.from];
          const b = layout.positions[e.to];
          if (!a || !b) return null;
          const x1 = a.x + a.w;
          const y1 = a.y + a.h / 2;
          const x2 = b.x;
          const y2 = b.y + b.h / 2;
          const cx = (x1 + x2) / 2;
          const path = `M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}`;
          // 状态判定：上游 done 或 running 才点亮
          const fromNode = graph.nodes.find((n) => n.id === e.from);
          const toNode = graph.nodes.find((n) => n.id === e.to);
          const lit =
            fromNode?.status === "done" &&
            (toNode?.status === "done" ||
              toNode?.status === "running" ||
              toNode?.status === "ready");
          const animated = toNode?.status === "running";
          return (
            <g key={i}>
              <path
                d={path}
                className={`dm-flow-edge ${lit ? "lit" : ""} ${animated ? "animated" : ""}`}
                markerEnd={`url(#${lit ? "arrow-active" : "arrow"})`}
                fill="none"
              />
              {e.label && (
                <text
                  x={cx}
                  y={(y1 + y2) / 2 - 6}
                  textAnchor="middle"
                  className="dm-flow-edge-label"
                >
                  {e.label}
                </text>
              )}
            </g>
          );
        })}

        {/* 节点 */}
        {graph.nodes.map((n) => {
          const pos = layout.positions[n.id];
          if (!pos) return null;
          const isActive = activeNode === n.id;
          return (
            <NodeBlock
              key={n.id}
              node={n}
              x={pos.x}
              y={pos.y}
              w={pos.w}
              h={pos.h}
              active={isActive}
              onClick={() => onNodeClick(n.id)}
            />
          );
        })}
      </svg>
    </div>
  );
}

function NodeBlock({
  node,
  x,
  y,
  w,
  h,
  active,
  onClick,
}: {
  node: WorkflowNode;
  x: number;
  y: number;
  w: number;
  h: number;
  active: boolean;
  onClick: () => void;
}) {
  const cls = [
    "dm-flow-node",
    `kind-${node.kind}`,
    `status-${node.status}`,
    active ? "active" : "",
  ]
    .filter(Boolean)
    .join(" ");

  const turnsLine =
    node.kind === "agent"
      ? `${node.turns ?? 0} 轮 · 输入 ${formatToken(
          node.tokens?.prompt
        )} · 输出 ${formatToken(node.tokens?.completion)}`
      : node.kind === "output"
        ? node.summary
          ? `存在漏洞 ${(node.summary as any).vulnerable ?? 0} · 安全 ${(node.summary as any).safe ?? 0}`
          : "尚未生成"
        : node.kind === "input"
          ? node.path ?? ""
          : "";

  return (
    <g className={cls} transform={`translate(${x}, ${y})`} onClick={onClick}>
      <rect
        x={0}
        y={0}
        width={w}
        height={h}
        rx={10}
        ry={10}
        className="dm-flow-node-body"
      />
      <rect
        x={0}
        y={0}
        width={w}
        height={4}
        rx={10}
        ry={10}
        className="dm-flow-node-bar"
      />
      <text x={14} y={28} className="dm-flow-node-title">
        {node.label}
      </text>
      {node.en && (
        <text x={14} y={44} className="dm-flow-node-en">
          {node.en}
        </text>
      )}
      <foreignObject x={14} y={50} width={w - 28} height={h - 60}>
        <div className="dm-flow-node-meta">
          <div className={`dm-flow-status status-${node.status}`}>
            <span className="dot" />
            {RUN_STATUS_LABELS[node.status] ?? node.status}
          </div>
          <div className="dm-flow-node-line">{turnsLine}</div>
        </div>
      </foreignObject>
    </g>
  );
}

function formatToken(n?: number): string {
  if (n === undefined || n === null || isNaN(n)) return "0";
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

// ---------------- 节点详情 ----------------

function NodeDetail({ node }: { node: WorkflowNode }) {
  return (
    <>
      <div className="dm-card-head" style={{ marginBottom: 8 }}>
        <span className={`dm-tag status-tag status-${node.status}`}>
          {RUN_STATUS_LABELS[node.status] ?? node.status}
        </span>
        <strong>{node.label}</strong>
      </div>

      <dl className="dm-descrip">
        <dt>类型</dt>
        <dd>{node.kind}</dd>
        {node.kind === "agent" && (
          <>
            <dt>对话轮次</dt>
            <dd>{node.turns ?? 0}</dd>
            <dt>Token</dt>
            <dd>
              输入 {(node.tokens?.prompt ?? 0).toLocaleString()} · 输出{" "}
              {(node.tokens?.completion ?? 0).toLocaleString()}
            </dd>
            {node.elapsed != null && (
              <>
                <dt>耗时</dt>
                <dd>{node.elapsed.toFixed(2)} s</dd>
              </>
            )}
            {node.started_at && (
              <>
                <dt>开始时间</dt>
                <dd>{node.started_at}</dd>
              </>
            )}
            {node.ended_at && (
              <>
                <dt>结束时间</dt>
                <dd>{node.ended_at}</dd>
              </>
            )}
            {node.error && (
              <>
                <dt>异常</dt>
                <dd style={{ color: "var(--color-error)" }}>{node.error}</dd>
              </>
            )}
          </>
        )}
        {node.kind === "input" && node.path && (
          <>
            <dt>路径</dt>
            <dd style={{ fontFamily: "var(--mono)" }}>{node.path}</dd>
          </>
        )}
        {node.kind === "output" && node.summary && (
          <>
            <dt>已审计</dt>
            <dd>{(node.summary as any).total_audited ?? 0}</dd>
            <dt>存在漏洞</dt>
            <dd style={{ color: "var(--color-error)" }}>
              {(node.summary as any).vulnerable ?? 0}
            </dd>
            <dt>不确定</dt>
            <dd>{(node.summary as any).uncertain ?? 0}</dd>
            <dt>安全</dt>
            <dd>{(node.summary as any).safe ?? 0}</dd>
          </>
        )}
      </dl>

      {node.outputs && node.outputs.length > 0 && (
        <>
          <div className="dm-pf-label" style={{ marginTop: 12, marginBottom: 6 }}>
            产物文件
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {node.outputs.map((o) => {
              const present = node.outputs_present?.includes(o);
              return (
                <span
                  key={o}
                  className={`dm-tag ${present ? "verdict-safe" : "sev-low"}`}
                  title={present ? "已生成" : "未生成"}
                >
                  {o}
                </span>
              );
            })}
          </div>
        </>
      )}
    </>
  );
}

// ---------------- 事件项 ----------------

function EventItem({ ev }: { ev: RunEvent }) {
  const t = ev.type;
  const icon = eventIcon(t);
  return (
    <div className={`dm-event dm-event-${t}`}>
      <span className="dm-event-time">{ev.ts?.split("T")[1] ?? ev.ts}</span>
      <span className="dm-event-icon">{icon}</span>
      <span className="dm-event-type">{t}</span>
      {ev.agent && (
        <span className="dm-tag" style={{ height: 18, fontSize: 11 }}>
          {AGENT_LABELS[ev.agent as string] ?? ev.agent}
        </span>
      )}
      <span className="dm-event-payload">{summarizeEvent(ev)}</span>
    </div>
  );
}

function eventIcon(type: string): string {
  switch (type) {
    case "pipeline_start":
    case "pipeline_end":
      return "◆";
    case "agent_start":
    case "step_start":
      return "▶";
    case "agent_end":
    case "step_end":
      return "■";
    case "agent_error":
    case "llm_error":
      return "✕";
    case "llm_request":
      return "↑";
    case "llm_response":
      return "↓";
    default:
      return "·";
  }
}

function summarizeEvent(ev: RunEvent): string {
  switch (ev.type) {
    case "agent_start":
    case "step_start":
      return `开始`;
    case "agent_end":
    case "step_end":
      return `耗时 ${(ev as any).elapsed?.toFixed?.(2) ?? "?"} s`;
    case "agent_error":
    case "llm_error":
      return `${(ev as any).error_type ?? ""}：${(ev as any).error ?? ""}`;
    case "llm_request":
      return `第 ${(ev as any).turn} 轮 · ${(ev as any).model} · ${(ev as any).messages_count ?? 0} 条消息`;
    case "llm_response":
      return `第 ${(ev as any).turn} 轮 · ${(ev as any).finish_reason ?? ""} · in ${
        (ev as any).usage?.prompt_tokens ?? "?"
      } / out ${(ev as any).usage?.completion_tokens ?? "?"}`;
    case "pipeline_start":
      return `step=${(ev as any).step ?? "all"}`;
    case "pipeline_end":
      return `总耗时 ${(ev as any).elapsed?.toFixed?.(2) ?? "?"} s`;
    default:
      return "";
  }
}
