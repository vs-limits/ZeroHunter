import { useCallback, useEffect, useRef, useState } from "react";
import { LogIndexItem, LogRound, listLogs, readLogRounds } from "../api";
import { AGENT_LABELS } from "../i18n";
import "../styles/list.css";
import "../styles/logs.css";

const PAGE_SIZE = 20;

export function LogsView() {
  const [files, setFiles] = useState<LogIndexItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [agent, setAgent] = useState<string>("");

  useEffect(() => {
    listLogs()
      .then((r) => {
        setFiles(r.items);
        if (r.items.length > 0 && !selected) setSelected(r.items[0].name);
      })
      .catch(() => {});
  }, []);

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">对话日志</h2>
          <div className="dm-pageheader-extra">
            <span className="dm-meta-line">
              共 {files.length} 个日志文件
            </span>
          </div>
        </div>
      </div>

      <div className="dm-tab-content">
        <div className="dm-card">
          <div className="dm-toolbar">
            <select
              value={selected ?? ""}
              onChange={(e) => setSelected(e.target.value || null)}
              style={{ minWidth: 220 }}
            >
              {files.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.name} · {Math.round(f.size / 1024 / 1024)} MB
                </option>
              ))}
              {files.length === 0 && <option value="">（无日志）</option>}
            </select>
            <select value={agent} onChange={(e) => setAgent(e.target.value)}>
              <option value="">全部 Agent</option>
              <option value="treescan">目录画像</option>
              <option value="callscan">调用扫描</option>
              <option value="dataflowscan">数据流恢复</option>
              <option value="auditor">漏洞审计</option>
            </select>
          </div>
        </div>

        {selected && (
          <RoundsList
            key={`${selected}|${agent}`}
            name={selected}
            agent={agent || undefined}
          />
        )}
      </div>
    </>
  );
}

function RoundsList({ name, agent }: { name: string; agent?: string }) {
  const [rounds, setRounds] = useState<LogRound[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  const loadNext = useCallback(async () => {
    if (loading || done) return;
    setLoading(true);
    try {
      const r = await readLogRounds(name, rounds.length, PAGE_SIZE, agent);
      setTotal(r.total);
      setRounds((prev) => {
        const next = [...prev, ...r.rounds];
        if (next.length >= r.total) setDone(true);
        return next;
      });
      if (r.rounds.length === 0) setDone(true);
    } catch (e) {
      setError(String(e));
      setDone(true);
    } finally {
      setLoading(false);
    }
  }, [loading, done, rounds.length, name, agent]);

  useEffect(() => {
    if (rounds.length === 0 && !loading && !done) loadNext();
  }, [rounds.length, loading, done, loadNext]);

  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) loadNext();
        }
      },
      { rootMargin: "300px 0px" }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [loadNext]);

  return (
    <div className="dm-card">
      <div className="dm-card-sub">
        {name} · 已加载 {rounds.length} / {total}
      </div>
      {error && (
        <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
          {error}
        </div>
      )}
      <div className="dm-list">
        {rounds.map((r, i) => (
          <RoundCard key={`${r.ts}-${i}`} round={r} index={i + 1} />
        ))}
      </div>
      <div ref={sentinelRef} className="dm-loadmore-bar">
        {loading ? "加载中…" : done ? "已加载完成" : "向下滚动加载更多"}
      </div>
    </div>
  );
}

function RoundCard({ round, index }: { round: LogRound; index: number }) {
  const [openMessages, setOpenMessages] = useState(false);
  const [openResponse, setOpenResponse] = useState(false);

  const messages = (round.request?.messages as Array<{ role: string; content: string }>) || [];
  const tools = round.request?.tools as { count?: number; names?: string[] } | undefined;
  const choices = (round.response?.response as any)?.choices ?? [];
  const usage = (round.response?.response as any)?.usage as
    | { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number }
    | undefined;
  const respContent: string =
    choices?.[0]?.message?.content ?? (round.error ? `[error] ${round.error.error}` : "");
  const toolCalls = choices?.[0]?.message?.tool_calls;

  return (
    <div className="dm-row dm-log-round">
      <div className="dm-row-head">
        <span className="dm-row-id">#{index}</span>
        <span className="dm-tag" title={round.agent ?? ""}>
          {round.agent ? AGENT_LABELS[round.agent] ?? round.agent : "?"}
        </span>
        <span className="dm-tag">{round.model ?? "?"}</span>
        <span className="dm-row-meta">{round.ts}</span>
        <div className="dm-spacer" />
        {usage && (
          <span className="dm-meta-line">
            输入 {usage.prompt_tokens ?? "?"} Token · 输出 {usage.completion_tokens ?? "?"} Token
          </span>
        )}
        {round.error && <span className="dm-tag verdict-vulnerable">异常</span>}
      </div>

      <div className="dm-log-section">
        <button
          className="dm-btn dm-btn-ghost dm-btn-sm"
          onClick={() => setOpenMessages((o) => !o)}
        >
          {openMessages ? "▼" : "▶"} 请求消息（{messages.length}）
          {tools?.count ? ` · 工具 ${tools.count}` : ""}
        </button>
        {openMessages && (
          <div className="dm-log-messages">
            {messages.map((m, idx) => (
              <div key={idx} className={`dm-log-msg dm-role-${m.role}`}>
                <div className="dm-log-msg-role">{translateRole(m.role)}</div>
                <pre className="dm-log-msg-content">
                  {typeof m.content === "string"
                    ? m.content
                    : JSON.stringify(m.content, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="dm-log-section">
        <button
          className="dm-btn dm-btn-ghost dm-btn-sm"
          onClick={() => setOpenResponse((o) => !o)}
        >
          {openResponse ? "▼" : "▶"} 响应
          {toolCalls && Array.isArray(toolCalls) && toolCalls.length > 0
            ? ` · 工具调用 ${toolCalls.length}`
            : ""}
        </button>
        {openResponse && (
          <div className="dm-log-messages">
            {respContent && (
              <div className="dm-log-msg dm-role-assistant">
                <div className="dm-log-msg-role">assistant 助手</div>
                <pre className="dm-log-msg-content">{respContent}</pre>
              </div>
            )}
            {Array.isArray(toolCalls) &&
              toolCalls.map((tc: any, i: number) => (
                <div key={i} className="dm-log-msg dm-role-tool">
                  <div className="dm-log-msg-role">工具调用 · {tc?.function?.name}</div>
                  <pre className="dm-log-msg-content">
                    {tc?.function?.arguments ?? JSON.stringify(tc, null, 2)}
                  </pre>
                </div>
              ))}
            {round.error && (
              <div className="dm-log-msg dm-role-error">
                <div className="dm-log-msg-role">异常</div>
                <pre className="dm-log-msg-content">
                  {String(round.error.error_type)} : {String(round.error.error)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

const ROLE_LABELS: Record<string, string> = {
  system: "system 系统",
  user: "user 用户",
  assistant: "assistant 助手",
  tool: "tool 工具",
};

function translateRole(role: string): string {
  return ROLE_LABELS[role] ?? role;
}
