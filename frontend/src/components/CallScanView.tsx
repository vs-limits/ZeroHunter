import { useCallback, useEffect, useRef, useState } from "react";
import { ProjectItem, readArtifactJson, readJsonl } from "../api";
import { SEVERITY_LABELS, VULN_LABELS, bilingualLang, bilingualVuln } from "../i18n";
import "../styles/list.css";
import "../styles/callscan.css";

interface Props {
  project: ProjectItem;
  runId: string | null;
}

interface CallScanAgent {
  status?: string;
  languages?: string[];
  summary?: {
    sink_hits?: number;
    candidate_chains?: number;
    with_call_chain?: number;
    no_call_chain?: number;
    skipped_rules?: number;
    by_severity?: Record<string, number>;
    by_vulnerability?: Record<string, number>;
    by_function?: Record<string, number>;
    filter_stats?: Record<string, number>;
    top_candidates?: unknown[];
  };
}

interface ChainItem {
  type?: string;
  index?: number;
  chain_id?: string;
  severity?: string;
  vulnerability_type?: string;
  language?: string;
  sink_file?: string;
  sink_line?: number;
  sink_function?: string;
  has_call_chain?: boolean;
  call_chain_count?: number;
  call_chains?: unknown[];
  summary?: string;
  audit_pack?: string;
}

const PAGE_SIZE = 80;

export function CallScanView({ project, runId }: Props) {
  const [agent, setAgent] = useState<CallScanAgent | null>(null);
  const [agentErr, setAgentErr] = useState<string | null>(null);

  const [filename, setFilename] = useState<"callscan_chains.priority.jsonl" | "callscan_chains.jsonl">(
    "callscan_chains.jsonl"
  );

  const [items, setItems] = useState<ChainItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [chainErr, setChainErr] = useState<string | null>(null);

  const sentinelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setItems([]);
    setTotal(0);
    setDone(false);
    setChainErr(null);
    setAgent(null);
    setAgentErr(null);
    readArtifactJson<CallScanAgent>(project.project_path, "callscan_agent.json", runId)
      .then((r) => setAgent(r.data))
      .catch((e) => setAgentErr(String(e)));
  }, [project.project_path, runId, filename]);

  const loadNext = useCallback(async () => {
    if (loading || done) return;
    setLoading(true);
    try {
      const offset = items.length;
      const r = await readJsonl(project.project_path, filename, runId, offset, PAGE_SIZE);
      setTotal(r.total);
      const chains = r.items.filter((it: any) => it.type === "chain") as ChainItem[];
      setItems((prev) => {
        const next = [...prev, ...chains];
        if (next.length >= r.total) setDone(true);
        return next;
      });
      if (chains.length === 0) setDone(true);
    } catch (e) {
      setChainErr(String(e));
      setDone(true);
    } finally {
      setLoading(false);
    }
  }, [loading, done, items.length, project.project_path, filename, runId]);

  useEffect(() => {
    if (items.length === 0 && !loading && !done) {
      loadNext();
    }
  }, [items.length, loading, done, loadNext]);

  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            loadNext();
          }
        }
      },
      { rootMargin: "300px 0px" }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [loadNext]);

  const summary = agent?.summary;

  return (
    <>
      <div className="dm-card dm-card-callscan">
        <h3 className="dm-card-title">调用扫描 总览</h3>

        {agentErr && <div className="dm-meta-line">未找到 callscan_agent.json：{agentErr}</div>}
        {agent && summary && (
          <>
            <div className="dm-stats-grid">
              <Stat label="命中点" value={summary.sink_hits ?? 0} accent="callscan" />
              <Stat label="候选链" value={summary.candidate_chains ?? 0} accent="callscan" />
              <Stat label="含调用链" value={summary.with_call_chain ?? 0} accent="callscan" />
              <Stat label="跳过规则" value={summary.skipped_rules ?? 0} accent="muted" />
            </div>

            {summary.by_severity && Object.keys(summary.by_severity).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按严重度</div>
                <BadgeMap map={summary.by_severity} kind="severity" />
              </div>
            )}
            {summary.by_vulnerability && Object.keys(summary.by_vulnerability).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按漏洞类型</div>
                <BadgeMap map={summary.by_vulnerability} kind="vuln" />
              </div>
            )}
          </>
        )}
      </div>

      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">候选调用链</h3>
          <span className="dm-meta-line">
            已加载 <strong style={{ color: "var(--text)" }}>{items.length}</strong> / {total || "?"}
          </span>
          <div className="dm-spacer" />
          <select
            className="dm-btn"
            value={filename}
            onChange={(e) => setFilename(e.target.value as any)}
          >
            <option value="callscan_chains.jsonl">全部候选链 (full)</option>
            <option value="callscan_chains.priority.jsonl">兼容文件 (priority alias)</option>
          </select>
        </div>
        <div className="dm-meta-line">
          {filename} · 滚动到底部自动加载，每批 {PAGE_SIZE} 条。
        </div>

        {chainErr && (
          <div className="dm-meta-line" style={{ marginTop: 8, color: "var(--danger)" }}>
            {chainErr}
          </div>
        )}

        <div className="dm-list" style={{ marginTop: 14 }}>
          {items.map((c) => (
            <ChainCard key={c.chain_id ?? `${c.index}`} c={c} />
          ))}
        </div>

        <div ref={sentinelRef} className="dm-loadmore-bar">
          {loading
            ? "加载中…"
            : done
              ? items.length === 0
                ? "（空）"
                : "已加载完成"
              : "向下滚动加载更多"}
        </div>
      </div>
    </>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number | string;
  accent?: "callscan" | "audit" | "muted";
}) {
  return (
    <div className={`dm-stat-cell stat-${accent ?? ""}`}>
      <div className="dm-stat-label">{label}</div>
      <div className="dm-stat-value">{value}</div>
    </div>
  );
}

function BadgeMap({ map, kind }: { map: Record<string, number>; kind?: "severity" | "vuln" }) {
  const entries = Object.entries(map).sort((a, b) => b[1] - a[1]);
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {entries.map(([k, v]) => {
        const zh =
          kind === "severity"
            ? SEVERITY_LABELS[k] ?? k
            : kind === "vuln"
              ? VULN_LABELS[k] ?? k
              : k;
        return (
          <span
            key={k}
            className={`dm-tag ${kind === "severity" ? `sev-${k}` : ""}`}
            title={`${k}: ${v}`}
          >
            {zh} <strong style={{ marginLeft: 4 }}>{v}</strong>
          </span>
        );
      })}
    </div>
  );
}

function ChainCard({ c }: { c: ChainItem }) {
  const sev = (c.severity || "").toLowerCase();
  const vulnBi = c.vulnerability_type ? bilingualVuln(c.vulnerability_type) : null;
  const langBi = c.language ? bilingualLang(c.language) : null;
  return (
    <div className={`dm-row dm-row-sev-${sev}`}>
      <div className="dm-row-head">
        <span className="dm-row-id">{c.chain_id}</span>
        <span className={`dm-tag sev-${sev}`}>
          {SEVERITY_LABELS[sev] ?? sev ?? "?"}
        </span>
        {vulnBi && <span className="dm-tag" title={vulnBi.en}>{vulnBi.zh}</span>}
        {langBi && <span className="dm-tag" title={langBi.en}>{langBi.zh}</span>}
        <span className="dm-row-meta">
          {c.sink_file}:{c.sink_line} · {c.sink_function}
        </span>
        {c.has_call_chain ? (
          <span className="dm-tag">链路 {c.call_chain_count ?? 0}</span>
        ) : (
          <span className="dm-tag">无调用链</span>
        )}
      </div>
      {c.audit_pack && <pre className="dm-row-body">{c.audit_pack}</pre>}
    </div>
  );
}
