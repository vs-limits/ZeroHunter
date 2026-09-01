import { useEffect, useState } from "react";
import {
  ConversationAgentBucket,
  ConversationTurnDetail,
  ConversationTurnIndex,
  ProjectItem,
  listConversations,
  readConversationTurn,
} from "../api";
import { AGENT_LABELS } from "../i18n";
import { cacheKey, fetchCached, invalidateCache } from "../lib/requestCache";
import "../styles/conversations.css";

interface Props {
  project: ProjectItem;
  runId: string | null;
  scanStatus?: string;
}

export function ConversationsView({ project, runId, scanStatus }: Props) {
  const [agents, setAgents] = useState<ConversationAgentBucket[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeAgent, setActiveAgent] = useState<string | null>(null);
  const [activeTurn, setActiveTurn] = useState<number | null>(null);
  const [detail, setDetail] = useState<ConversationTurnDetail | null>(null);
  const [detailErr, setDetailErr] = useState<string | null>(null);

  useEffect(() => {
    setAgents([]);
    setActiveAgent(null);
    setActiveTurn(null);
    setDetail(null);
    setError(null);
    const ttl = scanStatus === "running" ? 3_000 : 60_000;
    const key = cacheKey(["conversations", project.project_path, runId]);
    invalidateCache(key);
    fetchCached(key, () => listConversations(project.project_path, runId), {
      force: true,
      ttlMs: ttl,
    })
      .then((r) => {
        setAgents(r.agents);
        if (r.agents.length > 0) {
          const first = r.agents[0];
          setActiveAgent(first.agent);
          if (first.turns.length > 0) setActiveTurn(first.turns[0].turn);
        }
      })
      .catch((e) => setError(String(e)));
  }, [project.project_path, runId, scanStatus]);

  useEffect(() => {
    if (!activeAgent || activeTurn == null) return;
    setDetail(null);
    setDetailErr(null);
    readConversationTurn(project.project_path, runId, activeAgent, activeTurn)
      .then((r) => setDetail(r))
      .catch((e) => setDetailErr(String(e)));
  }, [project.project_path, runId, activeAgent, activeTurn]);

  const currentBucket = agents.find((a) => a.agent === activeAgent);

  if (error) {
    return (
      <div className="dm-empty">
        <div className="dm-empty-title">无法读取对话日志</div>
        <div className="dm-empty-tip">{error}</div>
      </div>
    );
  }

  if (agents.length === 0) {
    return (
      <div className="dm-empty">
        <div className="dm-empty-title">该 run 还没有对话日志</div>
      </div>
    );
  }

  return (
    <div className="dm-conv-layout">
      {/* 左侧：agent → turn 列表 */}
      <aside className="dm-conv-aside">
        {agents.map((a) => (
          <div key={a.agent} className="dm-conv-agent-block">
            <button
              className={`dm-conv-agent-head ${activeAgent === a.agent ? "active" : ""}`}
              onClick={() => {
                setActiveAgent(a.agent);
                if (a.turns.length > 0) setActiveTurn(a.turns[0].turn);
              }}
            >
              <span className="dm-conv-agent-zh">
                {AGENT_LABELS[a.agent] ?? a.agent}
              </span>
              <span className="dm-conv-agent-count">{a.turns_count}</span>
            </button>
            {activeAgent === a.agent && (
              <ul className="dm-conv-turns">
                {a.turns.map((t) => (
                  <li key={t.turn}>
                    <button
                      className={`dm-conv-turn ${
                        activeTurn === t.turn ? "active" : ""
                      } status-${t.status}`}
                      onClick={() => setActiveTurn(t.turn)}
                    >
                      <span className="dm-conv-turn-no">#{t.turn}</span>
                      <span className="dm-conv-turn-info">
                        <span className="dm-conv-turn-status">
                          <TurnStatusBadge t={t} />
                        </span>
                        <span className="dm-conv-turn-meta">
                          in {t.usage?.prompt_tokens ?? "?"} / out{" "}
                          {t.usage?.completion_tokens ?? "?"}
                        </span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </aside>

      {/* 右侧：turn 详情 */}
      <section className="dm-conv-detail">
        {detailErr && (
          <div className="dm-card">
            <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
              {detailErr}
            </div>
          </div>
        )}
        {detail ? (
          <TurnDetailView detail={detail} bucket={currentBucket ?? null} />
        ) : (
          <div className="dm-card">
            <div className="dm-empty-tip">读取中…</div>
          </div>
        )}
      </section>
    </div>
  );
}

function TurnStatusBadge({ t }: { t: ConversationTurnIndex }) {
  if (t.status === "ok")
    return (
      <span className="dm-tag verdict-safe" style={{ height: 18 }}>
        完成
      </span>
    );
  if (t.status === "error")
    return (
      <span className="dm-tag verdict-vulnerable" style={{ height: 18 }}>
        异常
      </span>
    );
  return (
    <span className="dm-tag" style={{ height: 18 }}>
      进行中
    </span>
  );
}

function TurnDetailView({
  detail,
  bucket,
}: {
  detail: ConversationTurnDetail;
  bucket: ConversationAgentBucket | null;
}) {
  const req = detail.request;
  const respMessage = (detail.response?.raw as any)?.choices?.[0]?.message;
  const respContent: string = respMessage?.content ?? "";
  const reasoning: string = respMessage?.reasoning_content ?? "";
  const toolCalls = respMessage?.tool_calls ?? [];
  const usage = (detail.response?.raw as any)?.usage;
  const finish = (detail.response?.raw as any)?.choices?.[0]?.finish_reason;

  return (
    <>
      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">
            第 {detail.turn} 轮 · {AGENT_LABELS[detail.agent] ?? detail.agent}
          </h3>
          {finish && <span className="dm-tag">{finish}</span>}
          {detail.error && <span className="dm-tag verdict-vulnerable">异常</span>}
          <div className="dm-spacer" />
          {usage && (
            <span className="dm-meta-line">
              输入 {usage.prompt_tokens ?? "?"} · 输出 {usage.completion_tokens ?? "?"} ·
              合计 {usage.total_tokens ?? "?"} Token
            </span>
          )}
        </div>
        {req && (
          <dl className="dm-descrip" style={{ marginTop: 8 }}>
            <dt>模型</dt>
            <dd style={{ fontFamily: "var(--mono)" }}>{req.model}</dd>
            <dt>温度</dt>
            <dd>{req.temperature}</dd>
            <dt>max_tokens</dt>
            <dd>{req.max_tokens}</dd>
            <dt>tool_choice</dt>
            <dd style={{ fontFamily: "var(--mono)" }}>
              {typeof req.tool_choice === "string"
                ? req.tool_choice
                : JSON.stringify(req.tool_choice ?? "—")}
            </dd>
            <dt>工具数量</dt>
            <dd>{req.tools?.length ?? 0}</dd>
          </dl>
        )}
      </div>

      {/* 请求消息 */}
      {req?.messages && req.messages.length > 0 && (
        <div className="dm-card">
          <h3 className="dm-card-title">请求消息 ({req.messages.length})</h3>
          <div className="dm-msg-list">
            {req.messages.map((m, idx) => (
              <Message key={idx} role={m.role} content={m.content} extras={m as any} />
            ))}
          </div>
        </div>
      )}

      {/* 响应 */}
      <div className="dm-card">
        <h3 className="dm-card-title">响应</h3>
        {detail.error ? (
          <div className="dm-msg dm-role-error">
            <div className="dm-msg-head">
              <span className="dm-msg-role">异常</span>
              <span className="dm-msg-meta">{detail.error.error_type}</span>
            </div>
            <pre className="dm-msg-content">{detail.error.error}</pre>
          </div>
        ) : (
          <div className="dm-msg-list">
            {reasoning && (
              <Message role="reasoning" content={reasoning} label="思考过程" />
            )}
            {respContent && (
              <Message role="assistant" content={respContent} />
            )}
            {Array.isArray(toolCalls) &&
              toolCalls.map((tc: any, i: number) => (
                <Message
                  key={i}
                  role="tool"
                  label={`工具调用 · ${tc?.function?.name ?? "?"}`}
                  content={
                    typeof tc?.function?.arguments === "string"
                      ? tc.function.arguments
                      : JSON.stringify(tc, null, 2)
                  }
                />
              ))}
            {!respContent && !reasoning && (!toolCalls || toolCalls.length === 0) && (
              <div className="dm-empty-tip">空响应</div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

function Message({
  role,
  content,
  label,
  extras,
}: {
  role: string;
  content: string;
  label?: string;
  extras?: { tool_calls?: unknown[] };
}) {
  return (
    <div className={`dm-msg dm-role-${role}`}>
      <div className="dm-msg-head">
        <span className="dm-msg-role">{label ?? roleLabel(role)}</span>
        {extras?.tool_calls && (extras.tool_calls as any).length > 0 && (
          <span className="dm-tag" style={{ height: 18 }}>
            {(extras.tool_calls as any).length} tool_calls
          </span>
        )}
        <span className="dm-msg-meta">
          {typeof content === "string" ? `${content.length} chars` : ""}
        </span>
      </div>
      <pre className="dm-msg-content">
        {typeof content === "string" ? content : JSON.stringify(content, null, 2)}
      </pre>
    </div>
  );
}

function roleLabel(role: string): string {
  switch (role) {
    case "system":
      return "系统";
    case "user":
      return "用户";
    case "assistant":
      return "助手";
    case "tool":
      return "工具";
    case "reasoning":
      return "思考";
    default:
      return role;
  }
}
