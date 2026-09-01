import { useCallback, useEffect, useRef, useState } from "react";
import { ProjectItem, readArtifactJson, readJsonl } from "../api";
import { SEVERITY_LABELS, VULN_LABELS, bilingualLang, bilingualVuln } from "../i18n";
import "../styles/list.css";
import "../styles/dataflowscan.css";

interface Props {
  project: ProjectItem;
  runId: string | null;
}

interface DataFlowGraph {
  status?: string;
  summary?: {
    nodes?: number;
    edges?: number;
    source_nodes?: number;
    storage_nodes?: number;
    sink_nodes?: number;
    write_edges?: number;
    read_edges?: number;
    total_chains?: number;
    cross_request_chains?: number;
    recovered_partial?: number;
    confirmed_chains?: number;
    probable_chains?: number;
    weak_chains?: number;
    suppressed_chains?: number;
    deduplicated_chains?: number;
    by_vulnerability?: Record<string, number>;
    by_chain_kind?: Record<string, number>;
    by_evidence_quality?: Record<string, number>;
    by_storage_kind?: Record<string, number>;
    by_noise_tag?: Record<string, number>;
    by_breakpoint?: Record<string, number>;
    breakpoints?: number;
  };
  breakpoints?: unknown[];
}

interface DataFlowChain {
  type?: string;
  index?: number;
  chain_id?: string;
  chain_kind?: string;
  severity?: string;
  vulnerability_type?: string;
  language?: string;
  sink_file?: string;
  sink_line?: number;
  sink_function?: string;
  summary?: string;
  storage?: { label?: string; key?: string; field?: string; kind?: string };
  storage_identity?: Record<string, unknown> | null;
  storage_edges?: Array<{ kind?: string; file?: string; line?: number; storage_key?: string }>;
  binding_edges?: Array<{ kind?: string; file?: string; line?: number; source_symbol?: string; target_symbol?: string }>;
  sanitizer_trace?: Array<{ kind?: string; strength?: string; file?: string; line?: number; evidence?: string }>;
  positive_evidence?: Array<Record<string, unknown>>;
  refuting_evidence?: Array<Record<string, unknown>>;
  weak_sanitizer?: Array<Record<string, unknown>>;
  evidence_quality?: "confirmed" | "probable" | "weak" | string;
  evidence_score?: number;
  suppressed?: boolean;
  noise_tags?: string[];
  breakpoints?: string[];
  recovery_trace?: unknown[];
  audit_pack?: string;
}

const PAGE_SIZE = 80;

export function DataFlowScanView({ project, runId }: Props) {
  const [graph, setGraph] = useState<DataFlowGraph | null>(null);
  const [graphErr, setGraphErr] = useState<string | null>(null);
  const [items, setItems] = useState<DataFlowChain[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [chainErr, setChainErr] = useState<string | null>(null);
  const [showWeak, setShowWeak] = useState(false);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setGraph(null);
    setGraphErr(null);
    setItems([]);
    setTotal(0);
    setDone(false);
    setChainErr(null);
    readArtifactJson<DataFlowGraph>(project.project_path, "dataflow_graph.json", runId)
      .then((r) => setGraph(r.data))
      .catch((e) => setGraphErr(String(e)));
  }, [project.project_path, runId]);

  const loadNext = useCallback(async () => {
    if (loading || done) return;
    setLoading(true);
    try {
      const offset = items.length;
      const r = await readJsonl(
        project.project_path,
        "cross_request_chains.jsonl",
        runId,
        offset,
        PAGE_SIZE
      );
      setTotal(r.total);
      const chains = r.items.filter((it: any) => it.type === "chain") as DataFlowChain[];
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
  }, [loading, done, items.length, project.project_path, runId]);

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
          if (e.isIntersecting) loadNext();
        }
      },
      { rootMargin: "300px 0px" }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [loadNext]);

  const summary = graph?.summary;
  const visibleItems = showWeak
    ? items
    : items.filter((c) => c.evidence_quality !== "weak" && !c.suppressed);
  const hiddenItems = items.length - visibleItems.length;

  return (
    <>
      <div className="dm-card dm-card-dataflow">
        <h3 className="dm-card-title">数据流恢复 总览</h3>

        {graphErr && <div className="dm-meta-line">未找到 dataflow_graph.json：{graphErr}</div>}
        {graph && summary && (
          <>
            <div className="dm-stats-grid">
              <Stat label="跨请求链" value={summary.cross_request_chains ?? 0} accent="dataflow" />
              <Stat label="恢复链" value={summary.recovered_partial ?? 0} accent="dataflow" />
              <Stat label="总候选" value={summary.total_chains ?? 0} accent="muted" />
              <Stat label="存储节点" value={summary.storage_nodes ?? 0} accent="dataflow" />
              <Stat label="Source" value={summary.source_nodes ?? 0} accent="dataflow" />
              <Stat label="Sink" value={summary.sink_nodes ?? 0} accent="dataflow" />
              <Stat label="Confirmed" value={summary.confirmed_chains ?? 0} accent="dataflow" />
              <Stat label="Probable" value={summary.probable_chains ?? 0} accent="dataflow" />
              <Stat label="Weak" value={summary.weak_chains ?? 0} accent="muted" />
              <Stat label="Suppressed" value={summary.suppressed_chains ?? 0} accent="muted" />
              <Stat label="Deduped" value={summary.deduplicated_chains ?? 0} accent="muted" />
              <Stat label="读边" value={summary.read_edges ?? 0} accent="muted" />
              <Stat label="断点" value={summary.breakpoints ?? 0} accent="muted" />
            </div>

            {summary.by_vulnerability && Object.keys(summary.by_vulnerability).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按漏洞类型</div>
                <BadgeMap map={summary.by_vulnerability} kind="vuln" />
              </div>
            )}
            {summary.by_chain_kind && Object.keys(summary.by_chain_kind).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按链类型</div>
                <BadgeMap map={summary.by_chain_kind} kind="chain" />
              </div>
            )}
            {summary.by_evidence_quality && Object.keys(summary.by_evidence_quality).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按证据质量</div>
                <BadgeMap map={summary.by_evidence_quality} kind="quality" />
              </div>
            )}
            {summary.by_storage_kind && Object.keys(summary.by_storage_kind).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按持久化介质</div>
                <BadgeMap map={summary.by_storage_kind} />
              </div>
            )}
            {summary.by_noise_tag && Object.keys(summary.by_noise_tag).length > 0 && (
              <div className="dm-section-block">
                <div className="dm-pf-label">按降噪标签</div>
                <BadgeMap map={summary.by_noise_tag} />
              </div>
            )}
          </>
        )}
      </div>

      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">跨请求候选链</h3>
          <span className="dm-meta-line">
            已加载 <strong style={{ color: "var(--text)" }}>{items.length}</strong> / {total || "?"}
          </span>
        </div>
        <div className="dm-meta-line">
          cross_request_chains.jsonl · 滚动到底部自动加载，每批 {PAGE_SIZE} 条。
        </div>
        <div className="dm-dataflow-mini" style={{ marginTop: 10 }}>
          <button
            type="button"
            className={`dm-tag ${showWeak ? "sev-low" : ""}`}
            onClick={() => setShowWeak((v) => !v)}
          >
            {showWeak ? "隐藏 weak/suppressed" : "显示 weak/suppressed"}
          </button>
          {!showWeak && hiddenItems > 0 && (
            <span className="dm-tag sev-low">已隐藏 {hiddenItems} 条弱证据/抑制链</span>
          )}
        </div>

        {chainErr && (
          <div className="dm-meta-line" style={{ marginTop: 8, color: "var(--danger)" }}>
            {chainErr}
          </div>
        )}

        <div className="dm-list" style={{ marginTop: 14 }}>
          {visibleItems.map((c) => (
            <DataFlowChainCard key={c.chain_id ?? `${c.index}`} c={c} />
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
  accent?: "dataflow" | "muted";
}) {
  return (
    <div className={`dm-stat-cell stat-${accent ?? ""}`}>
      <div className="dm-stat-label">{label}</div>
      <div className="dm-stat-value">{value}</div>
    </div>
  );
}

function BadgeMap({
  map,
  kind,
}: {
  map: Record<string, number>;
  kind?: "severity" | "vuln" | "chain" | "quality";
}) {
  const entries = Object.entries(map).sort((a, b) => b[1] - a[1]);
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {entries.map(([k, v]) => {
        const zh =
          kind === "severity"
            ? SEVERITY_LABELS[k] ?? k
            : kind === "vuln"
              ? VULN_LABELS[k] ?? k
              : kind === "chain"
                ? CHAIN_KIND_LABELS[k] ?? k
              : kind === "quality"
                ? QUALITY_LABELS[k] ?? k
              : STORAGE_LABELS[k] ?? k;
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

function formatStorageIdentity(identity: Record<string, unknown> | null | undefined): string {
  if (!identity) return "";
  const direct = identity.identity;
  if (typeof direct === "string" && direct.trim()) return direct;
  const kind = String(identity.kind ?? "").trim();
  if (kind === "sql_column") {
    return [identity.table ?? "*", identity.column ?? "*"].map(String).join(".");
  }
  if (kind === "file_path") {
    return String(identity.path ?? identity.field ?? "");
  }
  return [kind, identity.key ?? identity.name ?? identity.symbol ?? identity.field]
    .filter((v) => v !== undefined && v !== null && String(v).trim())
    .map(String)
    .join(":");
}

function DataFlowChainCard({ c }: { c: DataFlowChain }) {
  const sev = (c.severity || "").toLowerCase();
  const vulnBi = c.vulnerability_type ? bilingualVuln(c.vulnerability_type) : null;
  const langBi = c.language ? bilingualLang(c.language) : null;
  const chainKind = c.chain_kind ?? "cross_request";
  const storageIdentity = formatStorageIdentity(c.storage_identity);
  return (
    <div className={`dm-row dm-row-sev-${sev}`}>
      <div className="dm-row-head">
        <span className="dm-row-id">{c.chain_id}</span>
        <span className={`dm-tag sev-${sev}`}>
          {SEVERITY_LABELS[sev] ?? sev ?? "?"}
        </span>
        {c.evidence_quality && (
          <span className={`dm-tag ${QUALITY_TAG_CLASS[c.evidence_quality] ?? ""}`}>
            {QUALITY_LABELS[c.evidence_quality] ?? c.evidence_quality}
            {typeof c.evidence_score === "number" ? ` · ${c.evidence_score}` : ""}
          </span>
        )}
        {c.suppressed && <span className="dm-tag sev-low">suppressed</span>}
        <span className="dm-tag">{CHAIN_KIND_LABELS[chainKind] ?? chainKind}</span>
        {vulnBi && <span className="dm-tag" title={vulnBi.en}>{vulnBi.zh}</span>}
        {langBi && <span className="dm-tag" title={langBi.en}>{langBi.zh}</span>}
        <span className="dm-row-meta">
          {c.sink_file}:{c.sink_line} · {c.sink_function}
        </span>
      </div>
      {c.summary && <div className="dm-meta-line" style={{ marginTop: 6 }}>{c.summary}</div>}
      <div className="dm-dataflow-mini">
        {c.storage && (
          <span className="dm-tag" title={c.storage.key ?? ""}>
            存储 · {c.storage.label ?? c.storage.field ?? c.storage.kind ?? "unknown"}
          </span>
        )}
        {storageIdentity && (
          <span className="dm-tag" title={storageIdentity}>
            identity · {storageIdentity}
          </span>
        )}
        {c.storage_edges?.slice(0, 3).map((edge, idx) => (
          <span key={`${edge.kind}-${idx}`} className="dm-tag">
            {edge.kind} · {edge.file}:{edge.line}
          </span>
        ))}
        {c.binding_edges?.slice(0, 3).map((edge, idx) => (
          <span key={`binding-${edge.kind}-${idx}`} className="dm-tag">
            {edge.kind} · {edge.source_symbol || "?"} → {edge.target_symbol || "?"}
          </span>
        ))}
        {c.sanitizer_trace?.slice(0, 3).map((item, idx) => (
          <span
            key={`sanitizer-${item.kind}-${idx}`}
            className={`dm-tag ${item.strength === "strong" ? "sev-low" : ""}`}
            title={item.evidence ?? ""}
          >
            filter · {item.kind}:{item.strength}
          </span>
        ))}
        {c.refuting_evidence?.slice(0, 3).map((item, idx) => (
          <span key={`refute-${idx}`} className="dm-tag sev-low" title={String(item.evidence ?? "")}>
            refute · {String(item.kind ?? "evidence")}
          </span>
        ))}
        {c.noise_tags?.map((tag) => (
          <span key={tag} className="dm-tag sev-low">
            noise · {tag}
          </span>
        ))}
        {c.breakpoints?.map((bp) => (
          <span key={bp} className="dm-tag sev-low">
            断点 · {bp}
          </span>
        ))}
      </div>
      {c.audit_pack && <pre className="dm-row-body">{c.audit_pack}</pre>}
    </div>
  );
}

const CHAIN_KIND_LABELS: Record<string, string> = {
  cross_request: "跨请求",
  recovered_partial: "恢复中",
  direct_call: "直接调用",
};

const STORAGE_LABELS: Record<string, string> = {
  orm_field: "ORM 字段",
  sql_field: "SQL 字段",
  template_field: "模板变量",
  file_slot: "文件槽",
  request_var: "请求变量",
  session_key: "Session 键",
  cache_key: "缓存键",
  config_key: "配置键",
};

const QUALITY_LABELS: Record<string, string> = {
  confirmed: "Confirmed",
  probable: "Probable",
  weak: "Weak",
  legacy: "Legacy",
};

const QUALITY_TAG_CLASS: Record<string, string> = {
  confirmed: "sev-high",
  probable: "sev-medium",
  weak: "sev-low",
};
