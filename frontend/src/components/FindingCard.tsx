import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { ChevronDown, ChevronRight, Star, X as IconX } from "lucide-react";
import {
  AuditFinding,
  ConversationByChainResponse,
  ConversationTurnDetail,
  ProjectContainer,
  ReviewTrack,
  ReviewVerdict,
  ScanMark,
  VulnerabilityDetail,
  convertFindingToVulnerability,
  readConversationByChain,
  upsertMark,
} from "../api";
import {
  SEVERITY_LABELS,
  VERDICT_LABELS,
  bilingualVuln,
} from "../i18n";
import { useExpandMode } from "../lib/preferences";
import "../styles/conversations.css";
import "../styles/finding.css";

const TRACKS: { key: ReviewTrack; label: string; en: string }[] = [
  { key: "codex", label: "Codex 核验", en: "codex" },
  { key: "manual", label: "人工核验", en: "manual" },
  { key: "cc", label: "CC 核验", en: "cc" },
];

const VERDICT_FIELDS: Record<ReviewTrack, { v: keyof ScanMark; r: keyof ScanMark; t: keyof ScanMark }> = {
  codex: { v: "Codex核验", r: "Codex-Review", t: "Codex核验时间" },
  manual: { v: "人工核验", r: "人工-Review", t: "人工核验时间" },
  cc: { v: "CC核验", r: "CC-Review", t: "CC核验时间" },
};

const VERDICT_BUTTON: { key: ReviewVerdict; label: string; cls: string }[] = [
  { key: "true_positive", label: "真阳 TP", cls: "tp" },
  { key: "false_positive", label: "误报 FP", cls: "fp" },
  { key: "uncertain", label: "存疑", cls: "uc" },
];

export function getTrackVerdict(mark: ScanMark | undefined, track: ReviewTrack): ReviewVerdict | "" {
  if (!mark) return "";
  const v = mark[VERDICT_FIELDS[track].v];
  return (v as ReviewVerdict | "") || "";
}

export function getTrackReview(mark: ScanMark | undefined, track: ReviewTrack): string {
  if (!mark) return "";
  return String(mark[VERDICT_FIELDS[track].r] ?? "");
}

export function getTrackTimestamp(mark: ScanMark | undefined, track: ReviewTrack): string {
  if (!mark) return "";
  return String(mark[VERDICT_FIELDS[track].t] ?? "");
}

type DetailTab = "vuln" | "request" | "response";

const TAB_DEFS: { key: DetailTab; label: string }[] = [
  { key: "vuln", label: "漏洞详情" },
  { key: "request", label: "请求上下文" },
  { key: "response", label: "模型响应" },
];

interface Props {
  f: AuditFinding;
  mark?: ScanMark;
  /** 没传 scanId 时只读不写 */
  scanId?: string;
  projectContainer: ProjectContainer;
  projectPath: string;
  /** 用来定位对话流的 run / scan id */
  runId: string | null;
  onMarksChanged: (marks: Record<string, ScanMark>) => void;
  onVulnerabilityCreated?: (vulnerability: VulnerabilityDetail) => void | Promise<void>;
}

export function FindingCard({
  f,
  mark,
  scanId,
  projectContainer,
  projectPath,
  runId,
  onMarksChanged,
  onVulnerabilityCreated,
}: Props) {
  const [expanded, setExpanded] = useState(false);
  const [tab, setTab] = useState<DetailTab>("vuln");
  const [converting, setConverting] = useState(false);
  const [mode] = useExpandMode();

  const sev = (f.severity || "").toLowerCase();
  const vd = (f.verdict || "").toLowerCase();
  const vulnBi = f.vulnerability_type ? bilingualVuln(f.vulnerability_type) : null;

  const canMark = !!scanId;
  const canConvert = !!scanId && !!onVulnerabilityCreated;
  const favorite = !!mark?.favorite;

  function toggleExpand() {
    setExpanded((e) => !e);
  }

  function close() {
    setExpanded(false);
  }

  const applyMark = useCallback(
    async (
      track: ReviewTrack,
      update: { verdict?: ReviewVerdict | "clear"; review?: string | null }
    ) => {
      if (!scanId) return;
      try {
        const r = await upsertMark({
          project_path: projectPath,
          scan_id: scanId,
          chain_id: f.chain_id,
          reviewer: track,
          verdict: update.verdict,
          review: update.review,
        });
        onMarksChanged(r.items || {});
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(err);
      }
    },
    [scanId, projectPath, f.chain_id, onMarksChanged]
  );

  async function toggleFavorite(e: MouseEvent<HTMLButtonElement>) {
    e.stopPropagation();
    if (!scanId) return;
    try {
      const r = await upsertMark({
        project_path: projectPath,
        scan_id: scanId,
        chain_id: f.chain_id,
        favorite: !favorite,
      });
      onMarksChanged(r.items || {});
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
    }
  }

  async function convertToVulnerability(e: MouseEvent) {
    e.stopPropagation();
    if (!scanId || !onVulnerabilityCreated || converting) return;
    setConverting(true);
    try {
      const first = await convertFindingToVulnerability(projectContainer, {
        project_path: projectPath,
        scan_id: scanId,
        chain_id: f.chain_id,
      });
      if (first.duplicate) {
        const openExisting = window.confirm(
          "这条扫描发现已经转为正式漏洞。点击“确定”打开已有漏洞，点击“取消”复制生成新漏洞。"
        );
        if (openExisting) {
          await onVulnerabilityCreated(first.item);
          return;
        }
        const copied = await convertFindingToVulnerability(projectContainer, {
          project_path: projectPath,
          scan_id: scanId,
          chain_id: f.chain_id,
          duplicate: true,
        });
        await onVulnerabilityCreated(copied.item);
        return;
      }
      await onVulnerabilityCreated(first.item);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      window.alert(`转为漏洞失败：${String(err)}`);
    } finally {
      setConverting(false);
    }
  }

  const trackBadges = useMemo(() => {
    return TRACKS.map((t) => ({
      ...t,
      verdict: getTrackVerdict(mark, t.key),
      review: getTrackReview(mark, t.key),
    })).filter((it) => it.verdict || it.review);
  }, [mark]);

  // 抽屉模式：Esc 关闭
  useEffect(() => {
    if (!expanded || mode !== "drawer") return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [expanded, mode]);

  const detailBody = (
    <DetailBody
      tab={tab}
      setTab={setTab}
      f={f}
      mark={mark}
      runId={runId}
      projectPath={projectPath}
      canMark={canMark}
      applyMark={applyMark}
    />
  );

  return (
    <>
      <div
        className={`dm-row dm-row-sev-${sev} dm-finding-row ${expanded ? "expanded" : ""}`}
      >
        <div
          className="dm-row-head dm-finding-head"
          onClick={toggleExpand}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              toggleExpand();
            }
          }}
        >
          {canMark && (
            <button
              type="button"
              className={`dm-finding-star ${favorite ? "on" : ""}`}
              onClick={toggleFavorite}
              title={favorite ? "取消关注" : "关注漏洞审计项"}
              aria-label={favorite ? "取消关注漏洞审计项" : "关注漏洞审计项"}
            >
              <Star size={15} fill={favorite ? "currentColor" : "none"} aria-hidden />
            </button>
          )}
          <span className="dm-finding-caret" aria-hidden>
            {expanded && mode === "inline" ? (
              <ChevronDown size={14} />
            ) : (
              <ChevronRight size={14} />
            )}
          </span>
          <span className="dm-row-id">{f.chain_id}</span>
          <span className={`dm-tag verdict-${vd}`}>{VERDICT_LABELS[vd] ?? f.verdict}</span>

          {trackBadges.map((tb) => (
            <TrackBadge
              key={tb.key}
              track={tb.key}
              label={tb.label}
              verdict={tb.verdict}
              review={tb.review}
            />
          ))}

          <span className={`dm-tag sev-${sev}`}>{SEVERITY_LABELS[sev] ?? f.severity}</span>
          {vulnBi && (
            <span className="dm-tag" title={vulnBi.en}>
              {vulnBi.zh}
            </span>
          )}
          {f.cwe_guess && <span className="dm-tag">{f.cwe_guess}</span>}
          <span className="dm-row-meta">
            {f.sink?.file}:{f.sink?.line} · {f.sink?.expr}
          </span>
          <div className="dm-spacer" />
          {canConvert && (
            <button
              className="dm-btn dm-btn-sm dm-btn-primary"
              onClick={convertToVulnerability}
              disabled={converting}
            >
              {converting ? "转换中..." : "转为漏洞"}
            </button>
          )}
          <span className="dm-meta-line">置信度 {(Number(f.confidence) * 100 || 0).toFixed(0)}%</span>
          <span className="dm-finding-hint">
            {expanded ? "收起" : mode === "drawer" ? "查看详情" : "展开"}
          </span>
        </div>

        {f.title && f.title !== "unit-test" && (
          <div style={{ marginTop: 6, fontSize: 13, color: "var(--color-text)" }}>{f.title}</div>
        )}
        {f.principle && (
          <div style={{ marginTop: 4, fontSize: 12, color: "var(--color-text-secondary)" }}>
            <strong>原理：</strong>
            {f.principle}
          </div>
        )}
        {f.refuted_by && (
          <div style={{ marginTop: 4, fontSize: 12, color: "var(--color-text-secondary)" }}>
            <strong>已拦截：</strong>
            {f.refuted_by}
          </div>
        )}

        {expanded && mode === "inline" && (
          <div className="dm-finding-detail dm-finding-detail-inline" onClick={(e) => e.stopPropagation()}>
            {detailBody}
          </div>
        )}
      </div>

      {expanded && mode === "drawer" && (
        <FindingDrawer
          chainId={f.chain_id}
          title={f.title && f.title !== "unit-test" ? f.title : `${vulnBi?.zh ?? f.vulnerability_type}`}
          severity={sev}
          onClose={close}
        >
          {detailBody}
        </FindingDrawer>
      )}
    </>
  );
}

function DetailBody({
  tab,
  setTab,
  f,
  mark,
  runId,
  projectPath,
  canMark,
  applyMark,
}: {
  tab: DetailTab;
  setTab: (t: DetailTab) => void;
  f: AuditFinding;
  mark?: ScanMark;
  runId: string | null;
  projectPath: string;
  canMark: boolean;
  applyMark: (
    track: ReviewTrack,
    update: { verdict?: ReviewVerdict | "clear"; review?: string | null }
  ) => Promise<void>;
}) {
  return (
    <>
      <div className="dm-finding-tabs">
        {TAB_DEFS.map((d) => (
          <button
            key={d.key}
            className={`dm-finding-tab ${tab === d.key ? "active" : ""}`}
            onClick={() => setTab(d.key)}
          >
            {d.label}
          </button>
        ))}
      </div>

      {tab === "vuln" && (
        <VulnTab f={f} mark={mark} canMark={canMark} applyMark={applyMark} />
      )}
      {(tab === "request" || tab === "response") && (
        <ConversationTab
          tab={tab}
          projectPath={projectPath}
          runId={runId}
          chainId={f.chain_id}
        />
      )}
    </>
  );
}

function VulnTab({
  f,
  mark,
  canMark,
  applyMark,
}: {
  f: AuditFinding;
  mark?: ScanMark;
  canMark: boolean;
  applyMark: (
    track: ReviewTrack,
    update: { verdict?: ReviewVerdict | "clear"; review?: string | null }
  ) => Promise<void>;
}) {
  return (
    <>
      {canMark && (
        <div className="dm-track-stack">
          {TRACKS.map((t) => (
            <TrackEditor
              key={t.key}
              track={t.key}
              label={t.label}
              verdict={getTrackVerdict(mark, t.key)}
              review={getTrackReview(mark, t.key)}
              timestamp={getTrackTimestamp(mark, t.key)}
              onChange={(update) => applyMark(t.key, update)}
            />
          ))}
        </div>
      )}

      {f.exploit_poc && (
        <Section label="利用示例">
          <pre className="dm-row-body">{f.exploit_poc}</pre>
        </Section>
      )}
      {f.fix_suggestion && (
        <Section label="修复建议">
          <pre className="dm-row-body">{f.fix_suggestion}</pre>
        </Section>
      )}
      {Array.isArray(f.data_flow) && f.data_flow.length > 0 && (
        <Section label="数据流">
          <pre className="dm-row-body">{JSON.stringify(f.data_flow, null, 2)}</pre>
        </Section>
      )}
      {Array.isArray(f.evidence) && f.evidence.length > 0 && (
        <Section label="证据">
          <pre className="dm-row-body">{JSON.stringify(f.evidence, null, 2)}</pre>
        </Section>
      )}
    </>
  );
}

function ConversationTab({
  tab,
  projectPath,
  runId,
  chainId,
}: {
  tab: "request" | "response";
  projectPath: string;
  runId: string | null;
  chainId: string;
}) {
  const [data, setData] = useState<ConversationByChainResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const requestedRef = useRef<string | null>(null);

  useEffect(() => {
    const key = `${projectPath}::${runId ?? ""}::${chainId}`;
    if (requestedRef.current === key) return;
    requestedRef.current = key;
    setData(null);
    setError(null);
    setLoading(true);
    readConversationByChain(projectPath, runId, chainId)
      .then((r) => setData(r))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [projectPath, runId, chainId]);

  if (loading) {
    return <div className="dm-meta-line" style={{ padding: "8px 2px" }}>加载对话流…</div>;
  }
  if (error) {
    return (
      <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
        读取失败：{error}
      </div>
    );
  }
  if (!data || data.turns.length === 0) {
    return (
      <div className="dm-meta-line">未在 auditor 对话流中找到 chain_id={chainId} 的轮次。</div>
    );
  }

  if (tab === "request") return <RequestPane turns={data.turns} />;
  return <ResponsePane turns={data.turns} />;
}

// =================== 请求上下文 ===================

interface ParsedSystem {
  base: string;
  skillHeader?: { language: string; vulnerability: string };
  skill?: string;
}

const SKILL_MARKER = /\n\n<!-- SKILL: ([^\s/]+)\s*\/\s*([^\s>]+) -->\n/;

function parseSystemMessage(content: string): ParsedSystem {
  if (typeof content !== "string") return { base: String(content ?? "") };
  const match = content.match(SKILL_MARKER);
  if (!match || match.index === undefined) return { base: content };
  const base = content.slice(0, match.index).trimEnd();
  const after = content.slice(match.index + match[0].length).trimStart();
  return {
    base,
    skillHeader: { language: match[1], vulnerability: match[2] },
    skill: after,
  };
}

interface ParsedUser {
  chain_id?: string;
  language?: string;
  vulnerability_type?: string;
  severity?: string;
  sink?: string;
  pack: string;
}

function parseInitialUserMessage(content: string): ParsedUser {
  const out: ParsedUser = { pack: content };
  if (typeof content !== "string") return out;
  const lines = content.split("\n");
  // 找到第一个空行作为头部结束
  let headerEnd = -1;
  for (let i = 0; i < Math.min(lines.length, 12); i++) {
    if (lines[i].trim() === "") {
      headerEnd = i;
      break;
    }
  }
  if (headerEnd === -1) return out;
  const header = lines.slice(0, headerEnd);
  out.pack = lines.slice(headerEnd + 1).join("\n");
  for (const ln of header) {
    if (ln.startsWith("chain_id:")) out.chain_id = ln.slice("chain_id:".length).trim();
    else if (ln.startsWith("language:")) {
      const m = ln.match(/language:\s*(\S+)\s*\/\s*vulnerability_type:\s*(\S+)/);
      if (m) {
        out.language = m[1];
        out.vulnerability_type = m[2];
      }
    } else if (ln.startsWith("severity:")) out.severity = ln.slice("severity:".length).trim();
    else if (ln.startsWith("sink location:"))
      out.sink = ln.slice("sink location:".length).trim();
  }
  return out;
}

function RequestPane({ turns }: { turns: ConversationTurnDetail[] }) {
  // 取最后一个 turn 的 messages 作为完整历史（包含 system / 初始 user / 中间 tool 等）
  const lastTurn = turns[turns.length - 1];
  const messages = lastTurn?.request?.messages ?? [];

  const systemMessage =
    messages.find((m) => m.role === "system")?.content ?? "";
  const initialUser = messages.find((m) => m.role === "user");
  const initialUserContent = initialUser?.content ?? "";

  const parsedSystem = useMemo(() => parseSystemMessage(systemMessage), [systemMessage]);
  const parsedUser = useMemo(() => parseInitialUserMessage(initialUserContent), [initialUserContent]);

  // 中间的 tool / assistant 历史（出现在多轮工具调用时）
  const followUp = messages.filter(
    (m, idx) => idx > 1 // 跳过 system + 初始 user
  );

  return (
    <div className="dm-finding-conv">
      <PromptBlock title="系统提示词（基础）" lang="text" body={parsedSystem.base} />
      {parsedSystem.skill && (
        <PromptBlock
          title={`技能块 · ${parsedSystem.skillHeader?.language ?? ""} / ${parsedSystem.skillHeader?.vulnerability ?? ""}`}
          lang="markdown"
          body={parsedSystem.skill}
        />
      )}
      <div className="dm-prompt-grid">
        {parsedUser.chain_id && (
          <KV label="chain_id" value={parsedUser.chain_id} mono />
        )}
        {parsedUser.language && parsedUser.vulnerability_type && (
          <KV
            label="language / vuln"
            value={`${parsedUser.language} / ${parsedUser.vulnerability_type}`}
            mono
          />
        )}
        {parsedUser.severity && <KV label="severity" value={parsedUser.severity} mono />}
        {parsedUser.sink && <KV label="sink" value={parsedUser.sink} mono />}
      </div>
      <PromptBlock
        title="用户提示词（audit_pack）"
        lang="text"
        body={parsedUser.pack || initialUserContent}
      />

      {followUp.length > 0 && (
        <details className="dm-finding-followup">
          <summary>多轮工具调用记录（{followUp.length}）</summary>
          <div className="dm-msg-list" style={{ marginTop: 8 }}>
            {followUp.map((m, idx) => (
              <MessageCard
                key={idx}
                role={m.role}
                content={typeof m.content === "string" ? m.content : JSON.stringify(m.content, null, 2)}
                toolCalls={(m as any).tool_calls}
              />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

// =================== 响应 ===================

function ResponsePane({ turns }: { turns: ConversationTurnDetail[] }) {
  if (turns.length === 0) {
    return <div className="dm-meta-line">没有可显示的响应。</div>;
  }
  return (
    <div className="dm-finding-conv">
      {turns.map((t, idx) => {
        const respMessage = (t.response?.raw as any)?.choices?.[0]?.message;
        const content: string = respMessage?.content ?? "";
        const reasoning: string = respMessage?.reasoning_content ?? "";
        const toolCalls = respMessage?.tool_calls ?? [];
        const usage = (t.response?.raw as any)?.usage;
        const finish = (t.response?.raw as any)?.choices?.[0]?.finish_reason;

        const isFinal = idx === turns.length - 1 && !toolCalls?.length;

        return (
          <div key={`${t.turn}-${idx}`} className="dm-finding-resp-turn">
            <div className="dm-finding-resp-head">
              <span className="dm-finding-resp-label">
                第 {t.turn} 轮{isFinal ? " · 最终结论" : toolCalls?.length ? " · 工具调用" : ""}
              </span>
              {finish && <span className="dm-tag" style={{ height: 18 }}>{finish}</span>}
              {t.error && <span className="dm-tag verdict-vulnerable" style={{ height: 18 }}>异常</span>}
              <div className="dm-spacer" />
              {usage && (
                <span className="dm-meta-line">
                  in {usage.prompt_tokens ?? "?"} · out {usage.completion_tokens ?? "?"}
                </span>
              )}
            </div>

            {t.error ? (
              <pre className="dm-row-body">
                [{t.error.error_type}] {t.error.error}
              </pre>
            ) : (
              <>
                {reasoning && (
                  <MessageCard role="reasoning" content={reasoning} label="思考过程" />
                )}
                {content && (
                  <MessageCard
                    role={isFinal ? "assistant-final" : "assistant"}
                    content={content}
                    label={isFinal ? "最终响应" : "助手"}
                  />
                )}
                {Array.isArray(toolCalls) && toolCalls.length > 0 && (
                  <div className="dm-msg-list">
                    {toolCalls.map((tc: any, i: number) => (
                      <MessageCard
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
                  </div>
                )}
                {!content && !reasoning && (!toolCalls || toolCalls.length === 0) && (
                  <div className="dm-empty-tip">空响应</div>
                )}
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}

// =================== 公共组件 ===================

function PromptBlock({
  title,
  body,
  lang,
}: {
  title: string;
  body: string;
  lang?: string;
}) {
  return (
    <div className={`dm-msg dm-role-${lang === "markdown" ? "user" : "system"}`}>
      <div className="dm-msg-head">
        <span className="dm-msg-role">{title}</span>
        <span className="dm-msg-meta">{body.length} chars</span>
      </div>
      <pre className="dm-msg-content">{body}</pre>
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="dm-finding-kv">
      <span className="dm-finding-kv-label">{label}</span>
      <span
        className="dm-finding-kv-value"
        style={mono ? { fontFamily: "var(--mono)" } : undefined}
      >
        {value}
      </span>
    </div>
  );
}

function MessageCard({
  role,
  content,
  label,
  toolCalls,
}: {
  role: string;
  content: string;
  label?: string;
  toolCalls?: unknown[];
}) {
  return (
    <div className={`dm-msg dm-role-${role}`}>
      <div className="dm-msg-head">
        <span className="dm-msg-role">{label ?? roleLabel(role)}</span>
        {toolCalls && toolCalls.length > 0 && (
          <span className="dm-tag" style={{ height: 18 }}>
            {toolCalls.length} tool_calls
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
    case "assistant-final":
      return "助手";
    case "tool":
      return "工具";
    case "reasoning":
      return "思考";
    default:
      return role;
  }
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 10 }}>
      <div className="dm-pf-label" style={{ marginBottom: 4 }}>
        {label}
      </div>
      {children}
    </div>
  );
}

function TrackBadge({
  track,
  label,
  verdict,
  review,
}: {
  track: ReviewTrack;
  label: string;
  verdict: ReviewVerdict | "";
  review: string;
}) {
  const verdictMeta = verdictBadge(verdict);
  return (
    <span
      className={`dm-track-badge dm-track-${track} ${verdictMeta?.cls ?? ""}`}
      title={review || `${label} 已标注`}
    >
      <span className="dm-track-badge-label">{shortTrack(track)}</span>
      {verdictMeta && <span className="dm-track-badge-icon">{verdictMeta.icon}</span>}
      {!verdict && review && <span className="dm-track-badge-icon">📝</span>}
    </span>
  );
}

function shortTrack(t: ReviewTrack): string {
  return t === "codex" ? "Codex" : t === "manual" ? "人工" : "CC";
}

function verdictBadge(v: ReviewVerdict | ""): { icon: string; cls: string } | null {
  if (v === "true_positive") return { icon: "✓", cls: "tp" };
  if (v === "false_positive") return { icon: "✗", cls: "fp" };
  if (v === "uncertain") return { icon: "?", cls: "uc" };
  return null;
}

function TrackEditor({
  track,
  label,
  verdict,
  review,
  timestamp,
  onChange,
}: {
  track: ReviewTrack;
  label: string;
  verdict: ReviewVerdict | "";
  review: string;
  timestamp: string;
  onChange: (update: { verdict?: ReviewVerdict | "clear"; review?: string | null }) => void;
}) {
  const [draftReview, setDraftReview] = useState(review);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraftReview(review);
  }, [review, timestamp]);

  const dirty = draftReview !== review;

  async function pickVerdict(v: ReviewVerdict | "clear") {
    onChange({ verdict: v });
  }
  async function saveReview() {
    if (!dirty || saving) return;
    setSaving(true);
    try {
      await onChange({ review: draftReview });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className={`dm-track-card dm-track-${track}`}>
      <div className="dm-track-head">
        <span className="dm-track-title">{label}</span>
        {timestamp && (
          <span className="dm-meta-line">
            更新 {timestamp.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "")}
          </span>
        )}
        <div className="dm-spacer" />
        {VERDICT_BUTTON.map((b) => (
          <button
            key={b.key}
            className={`dm-mark-btn ${verdict === b.key ? `active ${b.cls}` : ""}`}
            onClick={() => pickVerdict(b.key)}
          >
            {b.label}
          </button>
        ))}
        {verdict && (
          <button
            className="dm-mark-btn"
            onClick={() => pickVerdict("clear")}
            title="清除核验，不动备注"
          >
            清除
          </button>
        )}
      </div>

      <div className="dm-track-review">
        <textarea
          className="dm-review-note"
          rows={2}
          value={draftReview}
          onChange={(e) => setDraftReview(e.target.value)}
          placeholder={`${label} 的备注：例如上下文已 escape；追溯到 commit ...；漏报原因`}
        />
        <div className="dm-review-actions">
          <span className="dm-meta-line">
            {draftReview.length} 字符
            {dirty && " · 未保存"}
          </span>
          <div className="dm-spacer" />
          {dirty && (
            <button
              className="dm-btn dm-btn-sm"
              onClick={() => setDraftReview(review)}
              disabled={saving}
            >
              撤销
            </button>
          )}
          <button
            className="dm-btn dm-btn-sm dm-btn-primary"
            onClick={saveReview}
            disabled={!dirty || saving}
          >
            {saving ? "保存中…" : "保存备注"}
          </button>
        </div>
      </div>
    </div>
  );
}

// =================== 抽屉 ===================

function FindingDrawer({
  chainId,
  title,
  severity,
  onClose,
  children,
}: {
  chainId: string;
  title: string;
  severity: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const node = (
    <div className="dm-finding-drawer-root" role="dialog" aria-modal="true">
      <div className="dm-finding-drawer-mask" onClick={onClose} />
      <aside className={`dm-finding-drawer dm-row-sev-${severity}`}>
        <header className="dm-finding-drawer-head">
          <div className="dm-finding-drawer-title">
            <span className="dm-row-id">{chainId}</span>
            <span className="dm-finding-drawer-name">{title}</span>
          </div>
          <button
            className="dm-finding-drawer-close"
            onClick={onClose}
            title="关闭（Esc）"
            aria-label="关闭"
          >
            <IconX size={16} />
          </button>
        </header>
        <div className="dm-finding-drawer-body">{children}</div>
      </aside>
    </div>
  );
  return createPortal(node, document.body);
}
