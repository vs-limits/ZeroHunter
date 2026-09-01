import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AuditFinding,
  ProjectContainer,
  ProjectItem,
  ReviewTrack,
  ReviewVerdict,
  ScanMark,
  VulnerabilityDetail,
  listMarks,
  readAuditAgent,
  readMarkdown,
} from "../api";
import {
  SEVERITY_LABELS,
  VERDICT_LABELS,
  VULN_LABELS,
  bilingualVuln,
} from "../i18n";
import { Markdown } from "./Markdown";
import { FindingCard, getTrackVerdict } from "./FindingCard";
import { cacheKey, fetchCached } from "../lib/requestCache";
import "../styles/list.css";

interface Props {
  project: ProjectItem;
  projectContainer: ProjectContainer;
  runId: string | null;
  scanId?: string;
  onVulnerabilityCreated?: (vulnerability: VulnerabilityDetail) => void | Promise<void>;
}

const PAGE_SIZE = 40;
type View = "json" | "markdown";

const AUDIT_VIEW_KEYS = new Set<View>(["json", "markdown"]);

function isAuditView(value: string | null): value is View {
  return !!value && AUDIT_VIEW_KEYS.has(value as View);
}

function readAuditViewFromLocation(): View {
  const params = new URLSearchParams(window.location.search);
  const view = params.get("audit_view");
  return isAuditView(view) ? view : "json";
}

function writeAuditViewToLocation(view: View, replace = false) {
  const params = new URLSearchParams(window.location.search);
  params.set("tab", "audit");
  params.set("audit_view", view);
  const next = `${window.location.pathname}?${params.toString()}${window.location.hash}`;
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (next === current) return;
  if (replace) window.history.replaceState(null, "", next);
  else window.history.pushState(null, "", next);
}

export function AuditView({
  project,
  projectContainer,
  runId,
  scanId,
  onVulnerabilityCreated,
}: Props) {
  const [view, setView] = useState<View>(() => readAuditViewFromLocation());

  useEffect(() => {
    const next = readAuditViewFromLocation();
    setView(next);
    const params = new URLSearchParams(window.location.search);
    if (params.get("tab") === "audit" && !isAuditView(params.get("audit_view"))) {
      writeAuditViewToLocation(next, true);
    }
  }, [project.project_path, runId, scanId]);

  useEffect(() => {
    function onPopState() {
      setView(readAuditViewFromLocation());
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  function selectView(next: View) {
    setView(next);
    writeAuditViewToLocation(next);
  }

  return (
    <>
      <div className="dm-card dm-card-audit">
        <div className="dm-card-head">
          <h3 className="dm-card-title">漏洞审计结果</h3>
          <div className="dm-spacer" />
          <div className="dm-segctrl">
            <button
              className={`dm-segctrl-item ${view === "json" ? "active" : ""}`}
              onClick={() => selectView("json")}
            >
              结构化视图
            </button>
            <button
              className={`dm-segctrl-item ${view === "markdown" ? "active" : ""}`}
              onClick={() => selectView("markdown")}
            >
              报告视图
            </button>
          </div>
        </div>
      </div>

      {view === "json" && (
        <AuditJson
          project={project}
          projectContainer={projectContainer}
          runId={runId}
          scanId={scanId}
          onVulnerabilityCreated={onVulnerabilityCreated}
        />
      )}
      {view === "markdown" && <AuditMarkdown project={project} runId={runId} />}
    </>
  );
}

// ============================================================
// 结构化视图
// ============================================================

const TRACK_OPTIONS: { key: ReviewTrack; label: string; en: string }[] = [
  { key: "codex", label: "Codex 核验", en: "codex" },
  { key: "manual", label: "人工核验", en: "manual" },
  { key: "cc", label: "CC 核验", en: "cc" },
];

const REVIEW_VERDICT_FILTER: { key: ReviewVerdict | "none"; label: string; cls: string }[] = [
  { key: "true_positive", label: "真阳", cls: "tp" },
  { key: "false_positive", label: "误报", cls: "fp" },
  { key: "uncertain", label: "存疑", cls: "uc" },
  { key: "none", label: "未标注", cls: "none" },
];

function AuditJson({
  project,
  projectContainer,
  runId,
  scanId,
  onVulnerabilityCreated,
}: {
  project: ProjectItem;
  projectContainer: ProjectContainer;
  runId: string | null;
  scanId?: string;
  onVulnerabilityCreated?: (vulnerability: VulnerabilityDetail) => void | Promise<void>;
}) {
  const [head, setHead] = useState<Record<string, unknown> | null>(null);
  const [items, setItems] = useState<AuditFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [marks, setMarks] = useState<Record<string, ScanMark>>({});
  const [error, setError] = useState<string | null>(null);

  // 服务端筛选：severity / verdict / keyword
  const [severity, setSeverity] = useState("");
  const [verdict, setVerdict] = useState("");
  const [keyword, setKeyword] = useState("");
  const [committedKeyword, setCommittedKeyword] = useState("");

  // 客户端筛选：漏洞类型多选 + 三家 reviewer × {tp/fp/uc/none}
  const [vulnSel, setVulnSel] = useState<Set<string>>(new Set());
  const [reviewSel, setReviewSel] = useState<
    Record<ReviewTrack, Set<ReviewVerdict | "none">>
  >({
    codex: new Set(),
    manual: new Set(),
    cc: new Set(),
  });
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [favoritesOnly, setFavoritesOnly] = useState(false);

  const sentinelRef = useRef<HTMLDivElement | null>(null);
  const loadingRef = useRef(false);
  const filterKey = `${severity}|${verdict}|${committedKeyword}`;

  // 服务端筛选切换 / 项目切换时重置
  useEffect(() => {
    setItems([]);
    setTotal(0);
    setDone(false);
    setError(null);
  }, [project.project_path, runId, filterKey]);

  // 加载标注
  useEffect(() => {
    if (!scanId) {
      setMarks({});
      return;
    }
    listMarks(project.project_path, scanId)
      .then((r) => setMarks(r.items || {}))
      .catch(() => setMarks({}));
  }, [project.project_path, scanId]);

  const loadNext = useCallback(async () => {
    if (loadingRef.current || done) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const offset = items.length;
      const r = await fetchCached(
        cacheKey([
          "audit",
          project.project_path,
          runId,
          offset,
          PAGE_SIZE,
          severity,
          verdict,
          committedKeyword,
        ]),
        () =>
          readAuditAgent(project.project_path, runId, {
            offset,
            limit: PAGE_SIZE,
            severity: severity || undefined,
            verdict: verdict || undefined,
            keyword: committedKeyword || undefined,
          }),
        { ttlMs: 120_000 }
      );
      setHead(r.head);
      setTotal(r.total);
      setItems((prev) => {
        const next = [...prev, ...r.findings];
        if (next.length >= r.total) setDone(true);
        return next;
      });
      if (r.findings.length === 0) setDone(true);
    } catch (e) {
      setError(String(e));
      setDone(true);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, [
    done,
    items.length,
    project.project_path,
    runId,
    severity,
    verdict,
    committedKeyword,
  ]);

  useEffect(() => {
    if (items.length === 0 && !loading && !done) loadNext();
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

  // 头部里把 by_vulnerability 转成下拉选项
  const vulnOptions: [string, number][] = useMemo(() => {
    const summary = (head?.summary as any) || {};
    const map = (summary.by_vulnerability || {}) as Record<string, number>;
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [head]);

  // 客户端二次筛选
  const filteredItems = useMemo(() => {
    return items.filter((f) => {
      if (vulnSel.size > 0 && !vulnSel.has(f.vulnerability_type)) return false;
      const m = marks[f.chain_id];
      if (favoritesOnly && !m?.favorite) return false;
      for (const t of TRACK_OPTIONS) {
        const sel = reviewSel[t.key];
        if (sel.size === 0) continue;
        const v = getTrackVerdict(m, t.key);
        const key = (v || "none") as ReviewVerdict | "none";
        if (!sel.has(key)) return false;
      }
      return true;
    });
  }, [items, marks, vulnSel, reviewSel, favoritesOnly]);

  function toggleVuln(v: string) {
    setVulnSel((prev) => {
      const next = new Set(prev);
      if (next.has(v)) next.delete(v);
      else next.add(v);
      return next;
    });
  }
  function toggleReview(track: ReviewTrack, v: ReviewVerdict | "none") {
    setReviewSel((prev) => {
      const cur = new Set(prev[track]);
      if (cur.has(v)) cur.delete(v);
      else cur.add(v);
      return { ...prev, [track]: cur };
    });
  }
  function clearAllFilters() {
    setSeverity("");
    setVerdict("");
    setKeyword("");
    setCommittedKeyword("");
    setVulnSel(new Set());
    setReviewSel({ codex: new Set(), manual: new Set(), cc: new Set() });
    setFavoritesOnly(false);
  }
  const activeFilterCount =
    (severity ? 1 : 0) +
    (verdict ? 1 : 0) +
    (committedKeyword ? 1 : 0) +
    (favoritesOnly ? 1 : 0) +
    vulnSel.size +
    Object.values(reviewSel).reduce((s, set) => s + set.size, 0);

  return (
    <>
      {head && (
        <div className="dm-card">
          <h3 className="dm-card-title">审计概要</h3>
          <SummaryStrip head={head} />
        </div>
      )}

      <div className="dm-card">
        <div className="dm-toolbar">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">全部严重度</option>
            <option value="critical">严重 critical</option>
            <option value="high">高危 high</option>
            <option value="medium">中危 medium</option>
            <option value="low">低危 low</option>
          </select>
          <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="">全部模型判定</option>
            <option value="vulnerable">存在漏洞 vulnerable</option>
            <option value="uncertain">不确定 uncertain</option>
            <option value="safe">安全 safe</option>
          </select>
          <input
            type="text"
            placeholder="搜索关键字（链 ID / 文件 / 漏洞类型）"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") setCommittedKeyword(keyword.trim());
            }}
            style={{ flex: 1, minWidth: 220 }}
          />
          <button
            className="dm-btn dm-btn-sm"
            onClick={() => setCommittedKeyword(keyword.trim())}
          >
            搜索
          </button>
          <button
            className={`dm-btn dm-btn-sm ${filtersOpen ? "dm-btn-primary" : ""}`}
            onClick={() => setFiltersOpen((v) => !v)}
            title="按核验状态 / 漏洞类型筛选"
          >
            高级筛选
            {activeFilterCount > 0 && (
              <span className="dm-tag-mini" style={{ marginLeft: 6 }}>
                {activeFilterCount}
              </span>
            )}
          </button>
          <button
            className={`dm-btn dm-btn-sm ${favoritesOnly ? "dm-btn-primary" : ""}`}
            onClick={() => setFavoritesOnly((v) => !v)}
            title="只看已关注的漏洞审计项"
          >
            只看关注
          </button>
          {activeFilterCount > 0 && (
            <button className="dm-btn dm-btn-ghost dm-btn-sm" onClick={clearAllFilters}>
              清空筛选
            </button>
          )}
          <div className="dm-spacer" />
          <span className="dm-meta-line">
            显示 {filteredItems.length} / {items.length} · 已加载 {items.length} / {total}
          </span>
        </div>

        {filtersOpen && (
          <div className="dm-filter-panel">
            <FilterRow label="漏洞类型">
              {vulnOptions.length === 0 && (
                <span className="dm-empty-tip">无数据</span>
              )}
              {vulnOptions.map(([k, n]) => (
                <FilterChip
                  key={k}
                  active={vulnSel.has(k)}
                  onClick={() => toggleVuln(k)}
                >
                  {VULN_LABELS[k] ?? k}
                  <span className="dm-filter-count">{n}</span>
                </FilterChip>
              ))}
            </FilterRow>

            {TRACK_OPTIONS.map((t) => (
              <FilterRow key={t.key} label={t.label}>
                {REVIEW_VERDICT_FILTER.map((opt) => {
                  const active = reviewSel[t.key].has(opt.key);
                  return (
                    <FilterChip
                      key={opt.key}
                      active={active}
                      tone={opt.cls}
                      onClick={() => toggleReview(t.key, opt.key)}
                    >
                      {opt.label}
                    </FilterChip>
                  );
                })}
              </FilterRow>
            ))}

          </div>
        )}

        {error && (
          <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
            {error}
          </div>
        )}

        <div className="dm-list">
          {filteredItems.map((f, idx) => (
            <FindingCard
              key={`${f.chain_id}:${f.index ?? idx}`}
              f={f}
              mark={marks[f.chain_id]}
              scanId={scanId}
              projectContainer={projectContainer}
              projectPath={project.project_path}
              runId={runId}
              onMarksChanged={setMarks}
              onVulnerabilityCreated={onVulnerabilityCreated}
            />
          ))}
        </div>

        <div ref={sentinelRef} className="dm-loadmore-bar">
          {loading
            ? "加载中…"
            : done
              ? items.length === 0
                ? "（空）"
                : filteredItems.length === 0
                  ? "（筛选结果为空）"
                  : "已加载完成"
              : "向下滚动加载更多"}
        </div>
      </div>
    </>
  );
}

// ============================================================
// 概要 / Markdown / 工具组件
// ============================================================

function SummaryStrip({ head }: { head: Record<string, unknown> }) {
  const summary = head.summary as
    | {
        total_audited?: number;
        vulnerable?: number;
        uncertain?: number;
        safe?: number;
        by_severity?: Record<string, number>;
        by_vulnerability?: Record<string, number>;
      }
    | undefined;
  if (!summary) return null;
  return (
    <>
      <div className="dm-stats-grid">
        <Stat label="已审计" value={summary.total_audited ?? 0} accent="audit" />
        <Stat label="存在漏洞" value={summary.vulnerable ?? 0} accent="danger" />
        <Stat label="不确定" value={summary.uncertain ?? 0} accent="warn" />
        <Stat label="安全" value={summary.safe ?? 0} accent="ok" />
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
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <div className={`dm-stat-cell ${accent ? `stat-${accent}` : ""}`}>
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
            title={k}
          >
            {zh} <strong style={{ marginLeft: 4 }}>{v}</strong>
          </span>
        );
      })}
    </div>
  );
}

function FilterRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="dm-filter-row">
      <div className="dm-filter-row-label">
        <span>{label}</span>
      </div>
      <div className="dm-filter-row-chips">{children}</div>
    </div>
  );
}

function FilterChip({
  active,
  tone,
  onClick,
  children,
}: {
  active: boolean;
  tone?: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      className={`dm-filter-chip ${active ? "active" : ""} ${tone ? `tone-${tone}` : ""}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

// ============================================================
// Markdown 视图（保持原样）
// ============================================================

function AuditMarkdown({ project, runId }: { project: ProjectItem; runId: string | null }) {
  const [head, setHead] = useState("");
  const [sections, setSections] = useState<string[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyword, setKeyword] = useState("");
  const [committed, setCommitted] = useState("");

  const sentinelRef = useRef<HTMLDivElement | null>(null);
  const loadingRef = useRef(false);

  useEffect(() => {
    setSections([]);
    setHead("");
    setTotal(0);
    setDone(false);
    setError(null);
  }, [project.project_path, runId, committed]);

  const loadNext = useCallback(async () => {
    if (loadingRef.current || done) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const r = await readMarkdown(
        project.project_path,
        "audit_findings.md",
        runId,
        sections.length,
        20,
        committed || undefined
      );
      setHead(r.head);
      setTotal(r.total);
      setSections((prev) => {
        const next = [...prev, ...r.sections];
        if (next.length >= r.total) setDone(true);
        return next;
      });
      if (r.sections.length === 0) setDone(true);
    } catch (e) {
      setError(String(e));
      setDone(true);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, [done, sections.length, project.project_path, runId, committed]);

  useEffect(() => {
    if (sections.length === 0 && !loading && !done) loadNext();
  }, [sections.length, loading, done, loadNext]);

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
      <div className="dm-toolbar">
        <input
          type="text"
          placeholder="搜索章节关键字（链 ID / 文件名 / 漏洞类型）"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") setCommitted(keyword.trim());
          }}
          style={{ flex: 1, minWidth: 240 }}
        />
        <button className="dm-btn" onClick={() => setCommitted(keyword.trim())}>
          搜索
        </button>
        {committed && (
          <button
            className="dm-btn dm-btn-ghost"
            onClick={() => {
              setKeyword("");
              setCommitted("");
            }}
          >
            清除
          </button>
        )}
        <div className="dm-spacer" />
        <span className="dm-meta-line">{sections.length} / {total} 节</span>
      </div>

      {head && (
        <div className="dm-md">
          <Markdown source={head} />
        </div>
      )}

      {error && <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>{error}</div>}

      <div className="dm-list">
        {sections.map((s, i) => (
          <div key={i} className="dm-row">
            <div className="dm-md">
              <Markdown source={s} />
            </div>
          </div>
        ))}
      </div>

      <div ref={sentinelRef} className="dm-loadmore-bar">
        {loading ? "加载中…" : done ? (sections.length === 0 ? "（空）" : "已加载完成") : "向下滚动加载更多"}
      </div>
    </div>
  );
}
