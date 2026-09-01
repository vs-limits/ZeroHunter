import { useEffect, useMemo, useRef, useState } from "react";
import {
  ScanItem,
  ScanStatus,
  listQueue,
  scheduleScan,
  startScan,
  stopScan,
} from "../api";
import { AGENT_LABELS, RUN_STATUS_LABELS } from "../i18n";
import "../styles/queue.css";

const POLL_MS = 5000;

type Filter = ScanStatus | "all";

export function QueueView({
  onSelectScan,
}: {
  onSelectScan?: (item: ScanItem) => void;
}) {
  const [items, setItems] = useState<ScanItem[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  async function load() {
    try {
      const r = await listQueue();
      setItems(r.items);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }

  useEffect(() => {
    load();
    pollRef.current = window.setInterval(load, POLL_MS);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  const counts = useMemo(() => {
    const c: Record<ScanStatus, number> = {
      pending: 0,
      running: 0,
      done: 0,
      error: 0,
      stopped: 0,
    };
    items.forEach((it) => {
      c[it.status] = (c[it.status] ?? 0) + 1;
    });
    return c;
  }, [items]);

  const filtered = useMemo(() => {
    if (filter === "all") return items;
    return items.filter((it) => it.status === filter);
  }, [items, filter]);

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">任务队列</h2>
          <div className="dm-pageheader-extra">
            <button className="dm-btn dm-btn-ghost" onClick={load}>
              ↻ 刷新
            </button>
          </div>
        </div>
      </div>

      <div className="dm-tab-content">
        {/* 状态过滤 */}
        <div className="dm-card">
          <div className="dm-queue-filters">
            <FilterChip
              active={filter === "all"}
              onClick={() => setFilter("all")}
              label="全部"
              count={items.length}
            />
            <FilterChip
              active={filter === "running"}
              onClick={() => setFilter("running")}
              label="正在扫描"
              count={counts.running}
              status="running"
            />
            <FilterChip
              active={filter === "pending"}
              onClick={() => setFilter("pending")}
              label="待扫描"
              count={counts.pending}
              status="pending"
            />
            <FilterChip
              active={filter === "stopped"}
              onClick={() => setFilter("stopped")}
              label="已停止"
              count={counts.stopped}
              status="stopped"
            />
            <FilterChip
              active={filter === "done"}
              onClick={() => setFilter("done")}
              label="扫描完成"
              count={counts.done}
              status="done"
            />
            <FilterChip
              active={filter === "error"}
              onClick={() => setFilter("error")}
              label="出错"
              count={counts.error}
              status="error"
            />
          </div>
        </div>

        {error && (
          <div className="dm-card">
            <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
              {error}
            </div>
          </div>
        )}

        {filtered.length === 0 ? (
          <div className="dm-empty">
            <div className="dm-empty-title">没有匹配的任务</div>
          </div>
        ) : (
          <div className="dm-card">
            <table className="dm-table dm-queue-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>项目</th>
                  <th>状态</th>
                  <th>当前 Agent</th>
                  <th>已完成 / 计划</th>
                  <th>计划时间</th>
                  <th>创建时间</th>
                  <th>耗时</th>
                  <th style={{ width: 280 }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((it) => (
                  <QueueRow
                    key={`${it.project_path}::${it.scan_id}`}
                    item={it}
                    onSelectScan={onSelectScan}
                    onChanged={load}
                    onError={(msg) => setError(msg)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function FilterChip({
  active,
  onClick,
  label,
  count,
  status,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
  status?: ScanStatus;
}) {
  return (
    <button
      className={`dm-queue-chip ${active ? "active" : ""}`}
      onClick={onClick}
    >
      {status && <span className={`dm-scan-dot dm-scan-dot-${status}`} />}
      {label}
      <span className="dm-queue-chip-count">{count}</span>
    </button>
  );
}

function QueueRow({
  item,
  onSelectScan,
  onChanged,
  onError,
}: {
  item: ScanItem;
  onSelectScan?: (item: ScanItem) => void;
  onChanged: () => void | Promise<void>;
  onError: (msg: string) => void;
}) {
  const [busy, setBusy] = useState(false);

  async function call(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      await onChanged();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const completed = item.completed_agents ?? [];
  const status = item.status;

  return (
    <tr>
      <td>
        <button
          className="dm-queue-name-btn"
          onClick={() => onSelectScan?.(item)}
          title="跳到该扫描"
        >
          {item.name}
          {item.target.mode === "directory" && (
            <span className="dm-queue-target">{item.target.rel_dir}</span>
          )}
        </button>
        <div className="dm-queue-id">{item.scan_id}</div>
      </td>
      <td>
        <code className="dm-code-inline">{item.project_path}</code>
      </td>
      <td>
        <span className={`dm-run-status ${status}`}>
          {RUN_STATUS_LABELS[status] ?? status}
        </span>
      </td>
      <td>
        {item.current_agent ? (
          <span className="dm-tag">{AGENT_LABELS[item.current_agent] ?? item.current_agent}</span>
        ) : (
          <span className="dm-meta-line">—</span>
        )}
      </td>
      <td>
        <div className="dm-queue-progress">
          {item.agents.map((a) => (
            <span
              key={a}
              className={`dm-queue-step ${
                completed.includes(a) ? "done" : item.current_agent === a ? "running" : ""
              }`}
              title={completed.includes(a) ? "已完成" : item.current_agent === a ? "进行中" : "待执行"}
            >
              {AGENT_LABELS[a] ?? a}
            </span>
          ))}
        </div>
      </td>
      <td>
        {item.scheduled_at ? (
          <span className="dm-meta-line">{formatTs(item.scheduled_at)}</span>
        ) : (
          <span className="dm-meta-line">—</span>
        )}
      </td>
      <td>
        <span className="dm-meta-line">{formatTs(item.created_at)}</span>
      </td>
      <td>
        <span className="dm-meta-line">
          {item.duration_seconds != null
            ? `${item.duration_seconds.toFixed(1)} s`
            : "—"}
        </span>
      </td>
      <td>
        <div className="dm-queue-actions">
          {status === "pending" && !item.scheduled_at && (
            <button
              className="dm-btn dm-btn-sm dm-btn-primary"
              disabled={busy || item.legacy}
              onClick={() =>
                call(() =>
                  startScan({
                    project_path: item.project_path,
                    scan_id: item.scan_id,
                    agents: item.agents,
                    resume: false,
                  })
                )
              }
            >
              开始扫描
            </button>
          )}
          {status === "pending" && item.scheduled_at && (
            <button
              className="dm-btn dm-btn-sm"
              disabled={busy || item.legacy}
              onClick={() =>
                call(() =>
                  scheduleScan({
                    project_path: item.project_path,
                    scan_id: item.scan_id,
                    scheduled_at: null,
                  })
                )
              }
            >
              取消定时
            </button>
          )}
          {(status === "stopped" || status === "error") && completed.length > 0 && (
            <button
              className="dm-btn dm-btn-sm dm-btn-primary"
              disabled={busy || item.legacy}
              onClick={() =>
                call(() =>
                  startScan({
                    project_path: item.project_path,
                    scan_id: item.scan_id,
                    agents: item.agents,
                    resume: true,
                  })
                )
              }
            >
              继续扫描
            </button>
          )}
          {(status === "done" || status === "error" || status === "stopped") && (
            <button
              className="dm-btn dm-btn-sm"
              disabled={busy || item.legacy}
              onClick={() =>
                call(() =>
                  startScan({
                    project_path: item.project_path,
                    scan_id: item.scan_id,
                    agents: item.agents,
                    resume: false,
                  })
                )
              }
            >
              重新扫描
            </button>
          )}
          {status === "running" && (
            <button
              className="dm-btn dm-btn-sm dm-btn-danger"
              disabled={busy}
              onClick={() => call(() => stopScan(item.project_path, item.scan_id))}
            >
              停止扫描
            </button>
          )}
          <button
            className="dm-btn dm-btn-sm dm-btn-ghost"
            onClick={() => onSelectScan?.(item)}
          >
            打开
          </button>
        </div>
      </td>
    </tr>
  );
}

function formatTs(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "");
}
