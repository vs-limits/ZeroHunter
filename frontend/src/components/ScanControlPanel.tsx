import { useEffect, useRef, useState } from "react";
import {
  ConsoleLog,
  ProjectItem,
  ScanChangeOptions,
  ScanItem,
  deleteScan,
  getScan,
  readScanConsole,
  retryAuditFailures,
  scheduleScan,
  startScan,
  stopScan,
  streamUrl,
  updateScan,
} from "../api";
import { AGENT_LABELS, RUN_STATUS_LABELS } from "../i18n";
import { ScanConsole } from "./ScanConsole";
import "../styles/control.css";

interface Props {
  project: ProjectItem;
  scan: ScanItem;
  onScanChanged: (next?: ScanItem, opts?: ScanChangeOptions) => void | Promise<void>;
  onScanDeleted: () => void | Promise<void>;
}

const ALL_AGENTS: { key: string; label: string }[] = [
  { key: "treescan", label: "目录画像" },
  { key: "callscan", label: "调用扫描" },
  { key: "dataflowscan", label: "数据流恢复" },
  { key: "auditor", label: "漏洞审计" },
];

const POLL_MS = 3000;
const CONSOLE_TAIL = 4000;

export function ScanControlPanel({
  project,
  scan,
  onScanChanged,
  onScanDeleted,
}: Props) {
  const isLegacy = !!scan.legacy;

  // 元信息表单
  const [name, setName] = useState(scan.name);
  const [targetMode, setTargetMode] = useState<"all" | "directory">(scan.target.mode);
  const [targetRelDir, setTargetRelDir] = useState(scan.target.rel_dir ?? "");
  const [agents, setAgents] = useState<string[]>(scan.agents);
  const [callscanUseLlm, setCallscanUseLlm] = useState(
    scan.options?.callscan_use_llm !== false
  );
  const recommendedConcurrency = recommendCallscanConcurrency();
  const recommendedAuditorConcurrency = recommendAuditorConcurrency();
  const [callscanConcurrency, setCallscanConcurrency] = useState(
    scan.options?.callscan_concurrency ?? recommendedConcurrency
  );
  const [auditorConcurrency, setAuditorConcurrency] = useState(
    scan.options?.auditor_concurrency ?? recommendedAuditorConcurrency
  );
  const [gt, setGt] = useState({
    expected_total: scan.ground_truth?.expected_total ?? "",
    missed: scan.ground_truth?.missed ?? "",
    notes: scan.ground_truth?.notes ?? "",
  });
  const [savingMeta, setSavingMeta] = useState(false);
  const [savingGt, setSavingGt] = useState(false);

  // 定时
  const [scheduleAt, setScheduleAt] = useState<string>(
    toLocalDatetimeInput(scan.scheduled_at)
  );
  useEffect(() => {
    setScheduleAt(toLocalDatetimeInput(scan.scheduled_at));
  }, [scan.scheduled_at]);

  // 控制台
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [consoleSize, setConsoleSize] = useState<number>(0);
  const consoleRef = useRef<HTMLDivElement | null>(null);

  // SSE 实时终端（子进程 stdout）
  const sseRef = useRef<EventSource | null>(null);
  const sseLiveRef = useRef(false);
  const attachedRunRef = useRef<string | null>(null);
  const onScanChangedRef = useRef(onScanChanged);
  onScanChangedRef.current = onScanChanged;
  const [activeRun, setActiveRun] = useState<string | null>(scan.last_run_id);
  /** 点击启动后强制轮询，直到 scan.status 变为非 running */
  const [pollUntilSettled, setPollUntilSettled] = useState(false);

  // 轮询：仅刷 scan 元信息（终端走 SSE）
  const pollRef = useRef<number | null>(null);
  useEffect(() => {
    setActiveRun(scan.last_run_id);
  }, [scan.scan_id, scan.last_run_id]);

  // 切换扫描时重置表单
  useEffect(() => {
    setName(scan.name);
    setTargetMode(scan.target.mode);
    setTargetRelDir(scan.target.rel_dir ?? "");
    setAgents(scan.agents);
    setCallscanUseLlm(scan.options?.callscan_use_llm !== false);
    setCallscanConcurrency(
      scan.options?.callscan_concurrency ?? recommendCallscanConcurrency()
    );
    setAuditorConcurrency(
      scan.options?.auditor_concurrency ?? recommendAuditorConcurrency()
    );
    setGt({
      expected_total: scan.ground_truth?.expected_total ?? "",
      missed: scan.ground_truth?.missed ?? "",
      notes: scan.ground_truth?.notes ?? "",
    });
  }, [scan.scan_id]);

  // 切换扫描 / 非运行态：从磁盘加载历史 console（运行中由 SSE 实时追加）
  useEffect(() => {
    let cancelled = false;
    if (isLegacy) return;
    if (scan.status === "running") return;
    void loadConsoleFromDisk();
    return () => {
      cancelled = true;
    };
  }, [project.project_path, scan.scan_id, scan.status, isLegacy]);

  useEffect(() => {
    attachedRunRef.current = null;
    sseRef.current?.close();
    sseLiveRef.current = false;
  }, [scan.scan_id]);

  // 已在运行的扫描：进入页面时接上 SSE（服务端会先回放已缓冲行，再推实时）
  useEffect(() => {
    if (isLegacy) return;
    if (scan.status !== "running" || !scan.last_run_id) return;
    if (attachedRunRef.current === scan.last_run_id) return;
    setPollUntilSettled(true);
    attachStream(scan.last_run_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan.scan_id, scan.last_run_id, scan.status, isLegacy]);

  // 运行中：仅轮询 scan.json 状态（不读 console、不刷新全项目列表）
  useEffect(() => {
    const shouldPoll = scan.status === "running" || pollUntilSettled;
    if (!shouldPoll) {
      if (pollRef.current) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }
    const tick = async () => {
      try {
        const fresh = await getScan(project.project_path, scan.scan_id);
        const settled = fresh.status !== "running";
        await onScanChangedRef.current(fresh, { syncLists: settled });
        if (settled) {
          setPollUntilSettled(false);
          setActiveRun(null);
          sseRef.current?.close();
          sseLiveRef.current = false;
          attachedRunRef.current = null;
          await loadConsoleFromDisk();
        } else if (!sseLiveRef.current) {
          // SSE 未连上时的兜底（如 run 已结束但 status 仍为 running）
          await loadConsoleFromDisk();
        }
      } catch {
        /* ignore */
      }
    };
    void tick();
    pollRef.current = window.setInterval(tick, POLL_MS);
    return () => {
      if (pollRef.current) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [scan.status, scan.scan_id, pollUntilSettled, project.project_path]);

  useEffect(
    () => () => {
      sseRef.current?.close();
      sseLiveRef.current = false;
    },
    []
  );

  async function loadConsoleFromDisk() {
    if (isLegacy) return;
    try {
      const c: ConsoleLog = await readScanConsole(
        project.project_path,
        scan.scan_id,
        CONSOLE_TAIL
      );
      setConsoleLines(c.lines);
      setConsoleSize(c.size);
      scrollConsoleToBottom();
    } catch {
      /* ignore */
    }
  }

  function scrollConsoleToBottom() {
    requestAnimationFrame(() => {
      const el = consoleRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  function attachStream(rid: string) {
    if (attachedRunRef.current === rid && sseLiveRef.current) return;
    attachedRunRef.current = rid;
    sseRef.current?.close();
    sseLiveRef.current = true;
    const es = new EventSource(streamUrl(rid));
    sseRef.current = es;
    es.onerror = () => {
      sseLiveRef.current = false;
      void loadConsoleFromDisk();
    };
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "stdout") {
          setConsoleLines((prev) => [...prev, msg.line]);
          scrollConsoleToBottom();
        } else if (msg.type === "status") {
          if (msg.status !== "running" && msg.status !== "pending") {
            void (async () => {
              try {
                const fresh = await getScan(project.project_path, scan.scan_id);
                await onScanChangedRef.current(fresh, { syncLists: true });
                await loadConsoleFromDisk();
              } catch {
                /* ignore */
              }
              setPollUntilSettled(false);
              setActiveRun(null);
              sseLiveRef.current = false;
            })();
          }
        } else if (msg.type === "end") {
          es.close();
          sseLiveRef.current = false;
          attachedRunRef.current = null;
          void (async () => {
            try {
              const fresh = await getScan(project.project_path, scan.scan_id);
              await onScanChangedRef.current(fresh, { syncLists: true });
              await loadConsoleFromDisk();
            } catch {
              /* ignore */
            }
            setPollUntilSettled(false);
            setActiveRun(null);
          })();
        } else if (msg.type === "error") {
          setConsoleLines((prev) => [...prev, `[error] ${msg.message}`]);
        }
      } catch {
        /* ignore */
      }
    };
  }

  function scanOptionsPatch() {
    return {
      options: {
        callscan_use_llm: callscanUseLlm,
        callscan_concurrency: callscanConcurrency,
        auditor_concurrency: auditorConcurrency,
      },
    };
  }

  async function saveMeta() {
    if (isLegacy) return;
    setSavingMeta(true);
    try {
      const next = await updateScan(project.project_path, scan.scan_id, {
        name: name.trim() || scan.name,
        agents,
        target: {
          mode: targetMode,
          rel_dir: targetMode === "directory" ? targetRelDir.trim() || null : null,
        },
        ...scanOptionsPatch(),
      });
      await onScanChanged(next);
    } catch (e) {
      setConsoleLines((p) => [...p, `[error] 保存失败：${String(e)}`]);
    } finally {
      setSavingMeta(false);
    }
  }

  async function saveGt() {
    if (isLegacy) return;
    setSavingGt(true);
    try {
      const next = await updateScan(project.project_path, scan.scan_id, {
        ground_truth: {
          expected_total:
            gt.expected_total === "" ? null : Number(gt.expected_total),
          missed: gt.missed === "" ? null : Number(gt.missed),
          notes: gt.notes,
        },
      });
      await onScanChanged(next);
    } catch (e) {
      setConsoleLines((p) => [...p, `[error] 保存失败：${String(e)}`]);
    } finally {
      setSavingGt(false);
    }
  }

  async function beginRun(
    launch: () => Promise<{ run_id: string }>,
    optimistic?: Partial<ScanItem>
  ) {
    setPollUntilSettled(true);
    if (optimistic) {
      await onScanChanged({ ...scan, ...optimistic });
    }
    const r = await launch();
    setActiveRun(r.run_id);
    attachStream(r.run_id);
    const fresh = await getScan(project.project_path, scan.scan_id);
    await onScanChanged(fresh);
  }

  async function startNow(resume: boolean) {
    if (isLegacy) return;
    if (agents.length === 0) {
      setConsoleLines((p) => [...p, `[error] 至少选择一个 Agent`]);
      return;
    }
    try {
      const saved = await updateScan(project.project_path, scan.scan_id, {
        name: name.trim() || scan.name,
        agents,
        target: {
          mode: targetMode,
          rel_dir: targetMode === "directory" ? targetRelDir.trim() || null : null,
        },
        ...scanOptionsPatch(),
      });
      await onScanChanged(saved);
      await beginRun(
        () =>
          startScan({
            project_path: project.project_path,
            scan_id: scan.scan_id,
            agents,
            resume,
          }),
        {
          status: "running",
          current_agent: null,
          finished_at: null,
          last_error: null,
        }
      );
    } catch (e) {
      setPollUntilSettled(false);
      setConsoleLines((p) => [...p, `[error] ${String(e)}`]);
    }
  }

  async function retryFailedAudits() {
    if (isLegacy) return;
    const n =
      scan.audit_failure_count ??
      scan.audit_summary?.llm_failed ??
      0;
    if (n <= 0) {
      setConsoleLines((p) => [...p, `[error] 没有可重试的审计异常项`]);
      return;
    }
    if (
      !confirm(
        `将仅重跑 Auditor 中 ${n} 条失败链（保留已成功审计的断点）。是否继续？`
      )
    ) {
      return;
    }
    try {
      await beginRun(
        () =>
          retryAuditFailures({
            project_path: project.project_path,
            scan_id: scan.scan_id,
          }),
        {
          status: "running",
          current_agent: "auditor",
          finished_at: null,
          last_error: null,
          completed_agents: (scan.completed_agents ?? []).filter(
            (a) => a !== "auditor"
          ),
        }
      );
    } catch (e) {
      setPollUntilSettled(false);
      setConsoleLines((p) => [...p, `[error] ${String(e)}`]);
    }
  }

  async function stop() {
    try {
      await stopScan(project.project_path, scan.scan_id);
      const fresh = await getScan(project.project_path, scan.scan_id);
      await onScanChanged(fresh, { syncLists: true });
      await loadConsoleFromDisk();
    } catch (e) {
      setConsoleLines((p) => [...p, `[error] ${String(e)}`]);
    }
  }

  async function applySchedule(value: string) {
    if (isLegacy) return;
    try {
      // 先保存最新 agents
      await updateScan(project.project_path, scan.scan_id, {
        agents,
        target: {
          mode: targetMode,
          rel_dir: targetMode === "directory" ? targetRelDir.trim() || null : null,
        },
        ...scanOptionsPatch(),
      });
      const sched = value ? new Date(value).toISOString() : null;
      const next = await scheduleScan({
        project_path: project.project_path,
        scan_id: scan.scan_id,
        scheduled_at: sched,
        agents,
      });
      await onScanChanged(next);
    } catch (e) {
      setConsoleLines((p) => [...p, `[error] 设置定时失败：${String(e)}`]);
    }
  }

  async function cancelSchedule() {
    setScheduleAt("");
    await applySchedule("");
  }

  async function remove() {
    if (isLegacy) return;
    if (!confirm(`确定删除扫描「${scan.name}」？此操作会清除所有产物文件。`)) return;
    try {
      await deleteScan(project.project_path, scan.scan_id);
      await onScanDeleted();
    } catch (e) {
      setConsoleLines((p) => [...p, `[error] 删除失败：${String(e)}`]);
    }
  }

  // —— 状态 → 可见动作集 ——
  const status = scan.status;
  const completed = scan.completed_agents ?? [];
  const hasCompleted = completed.length > 0;
  const showStart = !isLegacy && status === "pending" && !scan.scheduled_at;
  const showResume =
    !isLegacy &&
    (status === "stopped" || status === "error") &&
    hasCompleted;
  const showRetry =
    !isLegacy &&
    (status === "done" || status === "error" || status === "stopped") &&
    !showResume;
  const showStop = !isLegacy && status === "running";
  const auditFailureCount =
    scan.audit_failure_count ?? scan.audit_summary?.llm_failed ?? 0;
  const showRetryFailures =
    !isLegacy &&
    !showStop &&
    auditFailureCount > 0 &&
    (status === "done" || status === "error" || status === "stopped");

  return (
    <>
      {isLegacy && (
        <div className="dm-card">
          <div className="dm-tag">历史扫描</div>
          <span style={{ marginLeft: 12, color: "var(--color-text-tertiary)" }}>
            只读
          </span>
        </div>
      )}

      {/* —— 扫描信息 + 配置 —— */}
      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">扫描信息</h3>
          <ScanStatusBadge scan={scan} />
        </div>

        {scan.scheduled_at && (
          <div className="dm-meta-line" style={{ marginBottom: 8 }}>
            ⏱ 已设置定时 · {formatTs(scan.scheduled_at)}
          </div>
        )}
        {auditFailureCount > 0 && status !== "running" && (
          <div className="dm-scan-error-banner dm-scan-warn-banner">
            <div className="dm-scan-error-title">
              审计异常 {auditFailureCount} 条
            </div>
            <div className="dm-scan-error-body">
              LLM 调用失败 {auditFailureCount} 条
            </div>
          </div>
        )}
        {scan.completed_agents && scan.completed_agents.length > 0 && (
          <div className="dm-meta-line" style={{ marginBottom: 8 }}>
            ✓ 已完成 Agent：{scan.completed_agents.map((a) => AGENT_LABELS[a] ?? a).join(" · ")}
          </div>
        )}
        {status === "error" && scan.last_error && (
          <div className="dm-scan-error-banner">
            <div className="dm-scan-error-title">上次运行失败</div>
            <div className="dm-scan-error-body">{scan.last_error}</div>
            {hasCompleted && (
              <div className="dm-scan-error-hint">可使用「继续扫描」。</div>
            )}
          </div>
        )}

        <div className="dm-form-row">
          <label>名称</label>
          <input
            type="text"
            value={name}
            disabled={isLegacy}
            onChange={(e) => setName(e.target.value)}
            placeholder="给本次扫描起个名字"
            style={{ flex: 1 }}
          />
        </div>
        <div className="dm-form-row">
          <label>扫描目标</label>
          <div className="dm-segctrl">
            <button
              className={`dm-segctrl-item ${targetMode === "all" ? "active" : ""}`}
              onClick={() => !isLegacy && setTargetMode("all")}
              disabled={isLegacy}
            >
              全仓库
            </button>
            <button
              className={`dm-segctrl-item ${
                targetMode === "directory" ? "active" : ""
              }`}
              onClick={() => !isLegacy && setTargetMode("directory")}
              disabled={isLegacy}
            >
              指定目录
            </button>
          </div>
          {targetMode === "directory" && (
            <input
              type="text"
              value={targetRelDir}
              disabled={isLegacy}
              onChange={(e) => setTargetRelDir(e.target.value)}
              placeholder="例如：handlers"
              style={{ flex: 1, fontFamily: "var(--mono)" }}
            />
          )}
        </div>
        <div className="dm-form-row dm-form-agents">
          <label>启用 Agent</label>
          <div className="dm-agent-grid">
            {ALL_AGENTS.map((a) => {
              const on = agents.includes(a.key);
              const done = completed.includes(a.key);
              return (
                <label
                  key={a.key}
                  className={`dm-agent-card ${on ? "on" : ""} ${
                    isLegacy ? "disabled" : ""
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={on}
                    disabled={isLegacy}
                    onChange={(e) => {
                      const next = new Set(agents);
                      if (e.target.checked) next.add(a.key);
                      else next.delete(a.key);
                      setAgents(
                        ALL_AGENTS.map((x) => x.key).filter((k) => next.has(k))
                      );
                    }}
                  />
                  <div>
                    <div className="dm-agent-card-title">
                      {a.label}
                      {done && (
                        <span className="dm-tag verdict-safe" style={{ marginLeft: 6 }}>
                          已完成
                        </span>
                      )}
                    </div>
                  </div>
                </label>
              );
            })}
          </div>
        </div>
        {agents.includes("callscan") && (
          <>
            <div className="dm-form-row dm-callscan-llm-row">
              <label>CallScan</label>
              <label className="dm-inline-check">
                <input
                  type="checkbox"
                  checked={callscanUseLlm}
                  disabled={isLegacy || scan.status === "running"}
                  onChange={(e) => setCallscanUseLlm(e.target.checked)}
                />
                <span>启用 LLM 推理</span>
              </label>
            </div>
            <div className="dm-form-row dm-callscan-concurrency-row">
              <label>并发数</label>
              <input
                type="number"
                min={1}
                max={16}
                value={callscanConcurrency}
                disabled={isLegacy || scan.status === "running"}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (!Number.isFinite(n)) return;
                  setCallscanConcurrency(Math.max(1, Math.min(16, Math.round(n))));
                }}
                style={{ width: 72 }}
              />
              <span className="dm-meta-line">
                推荐 {recommendedConcurrency}（本机{" "}
                {typeof navigator !== "undefined"
                  ? navigator.hardwareConcurrency || "?"
                  : "?"}{" "}
                核 · 每路独立 MCP 进程，调用图在 MCP 内缓存 30 分钟）
              </span>
              <button
                type="button"
                className="dm-btn dm-btn-ghost dm-btn-sm"
                disabled={isLegacy || scan.status === "running"}
                onClick={() => setCallscanConcurrency(recommendedConcurrency)}
              >
                使用推荐值
              </button>
            </div>
          </>
        )}
        {agents.includes("auditor") && (
          <div className="dm-form-row dm-auditor-concurrency-row">
            <label>Auditor 并发</label>
            <input
              type="number"
              min={1}
              max={2500}
              value={auditorConcurrency}
              disabled={isLegacy || scan.status === "running"}
              onChange={(e) => {
                const n = Number(e.target.value);
                if (!Number.isFinite(n)) return;
                setAuditorConcurrency(Math.max(1, Math.min(2500, Math.round(n))));
              }}
              style={{ width: 88 }}
            />
            <span className="dm-meta-line">
              推荐 {recommendedAuditorConcurrency}（DeepSeek 官方支持高并发 · MCP
              进程池最多 32 路）
            </span>
            <button
              type="button"
              className="dm-btn dm-btn-ghost dm-btn-sm"
              disabled={isLegacy || scan.status === "running"}
              onClick={() => setAuditorConcurrency(recommendedAuditorConcurrency)}
            >
              使用推荐值
            </button>
          </div>
        )}
        <div className="dm-form-row">
          <label />
          <button
            className="dm-btn"
            onClick={saveMeta}
            disabled={isLegacy || savingMeta}
          >
            {savingMeta ? "保存中…" : "保存配置"}
          </button>

          {showStart && (
            <button
              className="dm-btn dm-btn-primary"
              onClick={() => startNow(false)}
              disabled={agents.length === 0}
            >
              开始扫描
            </button>
          )}
          {showResume && (
            <button
              className="dm-btn dm-btn-primary"
              onClick={() => startNow(true)}
              disabled={agents.length === 0}
              title={`从 ${completed.join(", ")} 之后继续`}
            >
              继续扫描
            </button>
          )}
          {showRetry && (
            <button
              className="dm-btn"
              onClick={() => startNow(false)}
              disabled={agents.length === 0}
            >
              重新扫描
            </button>
          )}
          {showRetryFailures && (
            <button
              className="dm-btn dm-btn-primary"
              onClick={retryFailedAudits}
              title={`仅重跑 ${auditFailureCount} 条 Auditor 失败链`}
            >
              重试异常项 ({auditFailureCount})
            </button>
          )}
          {showStop && (
            <button className="dm-btn dm-btn-danger" onClick={stop}>
              停止扫描
            </button>
          )}
          <div className="dm-spacer" />
          {!isLegacy && (
            <button className="dm-btn dm-btn-ghost" onClick={remove}>
              删除扫描
            </button>
          )}
        </div>
      </div>

      {/* —— 定时执行 —— */}
      <div className="dm-card">
        <h3 className="dm-card-title">定时执行</h3>
        <div className="dm-form-row">
          <label>执行时间</label>
          <input
            type="datetime-local"
            value={scheduleAt}
            disabled={isLegacy}
            onChange={(e) => setScheduleAt(e.target.value)}
            step={60}
            style={{ minWidth: 220 }}
          />
          <button
            className="dm-btn dm-btn-primary"
            onClick={() => applySchedule(scheduleAt)}
            disabled={isLegacy || !scheduleAt}
          >
            {scan.scheduled_at ? "更新定时" : "设置定时"}
          </button>
          {scan.scheduled_at && (
            <button className="dm-btn" onClick={cancelSchedule} disabled={isLegacy}>
              取消定时
            </button>
          )}
          <div className="dm-spacer" />
          {scan.scheduled_at && (
            <span className="dm-meta-line">
              下一次：{formatTs(scan.scheduled_at)}
            </span>
          )}
        </div>
      </div>

      {/* —— Ground truth —— */}
      <div className="dm-card">
        <h3 className="dm-card-title">质量标注</h3>
        <div className="dm-form-row">
          <label>预期漏洞总数</label>
          <input
            type="number"
            min={0}
            value={gt.expected_total}
            disabled={isLegacy}
            onChange={(e) => setGt({ ...gt, expected_total: e.target.value })}
            placeholder=""
            style={{ flex: 1 }}
          />
        </div>
        <div className="dm-form-row">
          <label>漏报数量</label>
          <input
            type="number"
            min={0}
            value={gt.missed}
            disabled={isLegacy}
            onChange={(e) => setGt({ ...gt, missed: e.target.value })}
            placeholder=""
            style={{ flex: 1 }}
          />
        </div>
        <div className="dm-form-row">
          <label>备注</label>
          <textarea
            rows={2}
            value={gt.notes}
            disabled={isLegacy}
            onChange={(e) => setGt({ ...gt, notes: e.target.value })}
            placeholder=""
            style={{ flex: 1, height: "auto", padding: "6px 9px" }}
          />
        </div>
        <div className="dm-form-row">
          <label />
          <button className="dm-btn" onClick={saveGt} disabled={isLegacy || savingGt}>
            {savingGt ? "保存中…" : "保存标注"}
          </button>
          <span className="dm-meta-line" style={{ marginLeft: 12 }}>
            {scan.audit_summary ? (
              <>
                模型给出 <strong>{scan.audit_summary.vulnerable ?? 0}</strong> 个 vulnerable
              </>
            ) : (
              <>该扫描尚无审计结果</>
            )}
          </span>
        </div>
      </div>

      {/* —— 控制台输出 —— */}
      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">控制台输出</h3>
          <span className="dm-meta-line">
            {(consoleSize / 1024).toFixed(1)} KB
          </span>
          {scan.current_agent && status === "running" && (
            <span className="dm-meta-line">
              当前 · {AGENT_LABELS[scan.current_agent] ?? scan.current_agent}
            </span>
          )}
          <div className="dm-spacer" />
          <button
            className="dm-btn dm-btn-ghost dm-btn-sm"
            onClick={async () => {
              const c = await readScanConsole(
                project.project_path,
                scan.scan_id,
                CONSOLE_TAIL
              );
              setConsoleLines(c.lines);
              setConsoleSize(c.size);
              scrollConsoleToBottom();
            }}
          >
            ↻ 重新读取
          </button>
        </div>

        <div ref={consoleRef} className="dm-console">
          <ScanConsole
            lines={consoleLines}
            emptyText="尚无输出。开始扫描后所有 stdout/stderr 会持久化到 console.log，切换页面后回来仍能继续看到完整记录。"
          />
        </div>
      </div>
    </>
  );
}

// =============================================================
// helpers
// =============================================================

function ScanStatusBadge({ scan }: { scan: ScanItem }) {
  if (scan.legacy) return <span className="dm-tag">历史</span>;
  const cls = `dm-run-status ${scan.status}`;
  return (
    <span className={cls}>{RUN_STATUS_LABELS[scan.status] ?? scan.status}</span>
  );
}

function toLocalDatetimeInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}`;
}

function formatTs(iso: string): string {
  if (!iso) return "";
  return iso.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "");
}

function recommendCallscanConcurrency(): number {
  if (typeof navigator === "undefined") return 4;
  const cores = navigator.hardwareConcurrency || 4;
  return Math.max(1, Math.min(8, cores));
}

function recommendAuditorConcurrency(): number {
  if (typeof navigator === "undefined") return 8;
  const cores = navigator.hardwareConcurrency || 4;
  return Math.max(4, Math.min(16, cores * 2));
}
