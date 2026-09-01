import { useEffect, useState } from "react";
import {
  DashboardOverview,
  DashboardSeriesPoint,
  getDashboard,
} from "../api";
import {
  AGENT_LABELS,
  SEVERITY_LABELS,
  VULN_LABELS,
  bilingualLang,
} from "../i18n";
import "../styles/dashboard.css";

export function DashboardView() {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [error, setError] = useState<string | null>(null);

  function load(refresh = false) {
    setError(null);
    getDashboard({ refresh })
      .then((r) => setData(r))
      .catch((e) => setError(String(e)));
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">仪表盘</h2>
          <div className="dm-pageheader-extra">
            <button className="dm-btn dm-btn-ghost" onClick={() => load(true)}>
              ↻ 刷新
            </button>
          </div>
        </div>
      </div>

      <div className="dm-tab-content">
        {error && (
          <div className="dm-card">
            <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
              {error}
            </div>
          </div>
        )}

        {data && (
          <>
            <KpiSection data={data} />

            <div className="dm-grid-2">
              <QualitySection data={data} />
              <SeriesSection series={data.series ?? []} />
            </div>

            <div className="dm-grid-2">
              <div className="dm-card">
                <h3 className="dm-card-title">按严重度</h3>
                <DistributionList
                  map={data.by_severity}
                  total={Object.values(data.by_severity).reduce((a, b) => a + b, 0)}
                  zh={SEVERITY_LABELS}
                  variant="severity"
                />
              </div>

              <div className="dm-card">
                <h3 className="dm-card-title">按漏洞类型</h3>
                <DistributionList
                  map={data.by_vulnerability}
                  total={Object.values(data.by_vulnerability).reduce((a, b) => a + b, 0)}
                  zh={VULN_LABELS}
                  topN={12}
                />
              </div>

              <div className="dm-card">
                <h3 className="dm-card-title">按语言（候选链来源）</h3>
                <DistributionList
                  map={data.by_language}
                  total={Object.values(data.by_language).reduce((a, b) => a + b, 0)}
                  zh={Object.fromEntries(
                    Object.keys(data.by_language).map((k) => [k, bilingualLang(k).zh])
                  )}
                />
              </div>

              <div className="dm-card">
                <h3 className="dm-card-title">Agent Token 用量</h3>
                <table className="dm-table">
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>轮次</th>
                      <th>输入 Token</th>
                      <th>输出 Token</th>
                      <th>平均耗时 / s</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(data.agent_tokens).map(([k, v]) => {
                      const avg = data.agent_avg_elapsed?.[k];
                      return (
                        <tr key={k}>
                          <td>{AGENT_LABELS[k] ?? k}</td>
                          <td>{v.turns}</td>
                          <td>{v.prompt.toLocaleString()}</td>
                          <td>{v.completion.toLocaleString()}</td>
                          <td>{avg != null ? avg.toFixed(2) : "-"}</td>
                        </tr>
                      );
                    })}
                    {Object.keys(data.agent_tokens).length === 0 && (
                      <tr>
                        <td colSpan={5} className="dm-table-empty">
                          暂无对话日志
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="dm-card">
              <h3 className="dm-card-title">项目清单</h3>
              <table className="dm-table">
                <thead>
                  <tr>
                    <th>项目</th>
                    <th>扫描数</th>
                    <th>候选链</th>
                    <th>已审计</th>
                    <th>存在漏洞</th>
                    <th>不确定</th>
                    <th>安全</th>
                  </tr>
                </thead>
                <tbody>
                  {data.projects.map((p) => (
                    <tr key={p.project_path}>
                      <td>
                        <code className="dm-code-inline">{p.project_path}</code>
                      </td>
                      <td>{p.scan_count ?? 0}</td>
                      <td>{p.candidate_chains ?? "-"}</td>
                      <td>{p.total_audited ?? "-"}</td>
                      <td className={(p.vulnerable ?? 0) > 0 ? "danger" : ""}>
                        {p.vulnerable ?? "-"}
                      </td>
                      <td>{p.uncertain ?? "-"}</td>
                      <td>{p.safe ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </>
  );
}

// =============== KPI ===============

function KpiSection({ data }: { data: DashboardOverview }) {
  const totals = data.totals;
  return (
    <div className="dm-stats-grid dm-dashboard-kpi">
      <Kpi label="项目" value={totals.projects} accent="control" />
      <Kpi
        label="扫描总数"
        value={totals.scans ?? totals.runs ?? 0}
        accent="control"
      />
      <Kpi label="候选链" value={totals.candidate_chains} accent="callscan" />
      <Kpi label="已审计" value={totals.audited} accent="audit" />
      <Kpi label="存在漏洞" value={totals.vulnerable} accent="danger" />
      <Kpi label="安全" value={totals.safe} accent="ok" />
      <Kpi
        label="Token 输入"
        value={totals.tokens.prompt}
        accent="muted"
      />
      <Kpi
        label="Token 输出"
        value={totals.tokens.completion}
        accent="muted"
      />
    </div>
  );
}

// =============== 质量 ===============

function QualitySection({ data }: { data: DashboardOverview }) {
  const q = data.quality;
  if (!q) return null;
  return (
    <div className="dm-card">
      <h3 className="dm-card-title">质量指标</h3>
      <div className="dm-quality-grid">
        <QualityRing label="精度" value={q.precision} />
        <QualityRing label="召回率" value={q.recall} />
        <QualityRing label="F1" value={q.f1} />
      </div>
      <div className="dm-quality-meta">
        <MetaRow label="模型给出 vulnerable" value={q.total_vulnerable_findings} />
        <MetaRow label="已标注" value={q.total_marked_findings ?? 0} />
        <MetaRow label="标注 真阳 (TP)" value={q.true_positives} accent="danger" />
        <MetaRow label="标注 误报 (FP)" value={q.false_positives} accent="ok" />
        <MetaRow label="标注 存疑" value={q.uncertain} accent="warn" />
        <MetaRow label="自定义 漏报 (FN)" value={q.missed} accent="warn" />
        <MetaRow label="预期漏洞总数" value={q.expected_total} />
      </div>
    </div>
  );
}

function QualityRing({
  label,
  value,
}: {
  label: string;
  value: number | null;
}) {
  const pct = value == null ? null : Math.max(0, Math.min(1, value));
  const display = pct == null ? "—" : `${(pct * 100).toFixed(1)}%`;
  const dash = 2 * Math.PI * 30; // r=30
  const offset = pct == null ? dash : dash * (1 - pct);
  const colorClass =
    pct == null
      ? "muted"
      : pct >= 0.8
        ? "ok"
        : pct >= 0.5
          ? "warn"
          : "danger";
  return (
    <div className={`dm-ring dm-ring-${colorClass}`}>
      <svg viewBox="0 0 80 80" width={88} height={88}>
        <circle cx={40} cy={40} r={30} className="dm-ring-track" />
        <circle
          cx={40}
          cy={40}
          r={30}
          className="dm-ring-progress"
          style={{ strokeDasharray: dash, strokeDashoffset: offset }}
        />
      </svg>
      <div className="dm-ring-text">
        <div className="dm-ring-value">{display}</div>
        <div className="dm-ring-label">{label}</div>
      </div>
    </div>
  );
}

function MetaRow({
  label,
  value,
  accent,
}: {
  label: string;
  value: number | null | undefined;
  accent?: "danger" | "ok" | "warn";
}) {
  return (
    <div className="dm-quality-meta-row">
      <span className="dm-quality-meta-label">{label}</span>
      <span className={`dm-quality-meta-value ${accent ? `accent-${accent}` : ""}`}>
        {value ?? 0}
      </span>
    </div>
  );
}

// =============== 趋势 ===============

function SeriesSection({ series }: { series: DashboardSeriesPoint[] }) {
  const [metric, setMetric] = useState<
    "scans" | "audited" | "vulnerable" | "tokens"
  >("scans");
  return (
    <div className="dm-card">
      <div className="dm-card-head">
        <h3 className="dm-card-title">趋势</h3>
        <div className="dm-spacer" />
        <div className="dm-segctrl">
          {(
            [
              { key: "scans", label: "扫描数" },
              { key: "audited", label: "审计数" },
              { key: "vulnerable", label: "漏洞数" },
              { key: "tokens", label: "Token" },
            ] as const
          ).map((opt) => (
            <button
              key={opt.key}
              className={`dm-segctrl-item ${metric === opt.key ? "active" : ""}`}
              onClick={() => setMetric(opt.key)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>
      <SparkLineChart series={series} metric={metric} />
    </div>
  );
}

function SparkLineChart({
  series,
  metric,
}: {
  series: DashboardSeriesPoint[];
  metric: "scans" | "audited" | "vulnerable" | "tokens";
}) {
  if (series.length === 0) {
    return <div className="dm-empty-tip">无数据</div>;
  }
  const W = 720;
  const H = 200;
  const PAD_L = 40;
  const PAD_R = 16;
  const PAD_T = 12;
  const PAD_B = 28;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  const values = series.map((p) =>
    metric === "tokens" ? p.tokens_in + p.tokens_out : (p as any)[metric]
  );
  const max = Math.max(1, ...values);
  const stepX = series.length > 1 ? innerW / (series.length - 1) : innerW;

  const xy = (i: number, v: number) => ({
    x: PAD_L + i * stepX,
    y: PAD_T + innerH - (v / max) * innerH,
  });

  const linePath = values
    .map((v, i) => {
      const { x, y } = xy(i, v);
      return `${i === 0 ? "M" : "L"}${x},${y}`;
    })
    .join(" ");

  const areaPath =
    `M${PAD_L},${PAD_T + innerH} ` +
    values
      .map((v, i) => {
        const { x, y } = xy(i, v);
        return `L${x},${y}`;
      })
      .join(" ") +
    ` L${PAD_L + (series.length - 1) * stepX},${PAD_T + innerH} Z`;

  // Y 轴刻度
  const ticks = 4;
  const yTicks: { v: number; y: number }[] = [];
  for (let i = 0; i <= ticks; i++) {
    const v = (max / ticks) * i;
    yTicks.push({ v, y: PAD_T + innerH - (v / max) * innerH });
  }

  // X 轴日期：稀疏标注
  const xLabelEvery = Math.max(1, Math.ceil(series.length / 8));

  // tokens 模式还要叠加 in/out 双线
  const tokenInPath =
    metric === "tokens"
      ? series
          .map((p, i) => {
            const { x, y } = xy(i, p.tokens_in);
            return `${i === 0 ? "M" : "L"}${x},${y}`;
          })
          .join(" ")
      : "";
  const tokenOutPath =
    metric === "tokens"
      ? series
          .map((p, i) => {
            const { x, y } = xy(i, p.tokens_out);
            return `${i === 0 ? "M" : "L"}${x},${y}`;
          })
          .join(" ")
      : "";

  return (
    <div className="dm-spark">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H}>
        {yTicks.map((t, i) => (
          <g key={i}>
            <line
              x1={PAD_L}
              x2={W - PAD_R}
              y1={t.y}
              y2={t.y}
              className="dm-spark-grid"
            />
            <text x={PAD_L - 6} y={t.y + 3} className="dm-spark-axis" textAnchor="end">
              {Math.round(t.v).toLocaleString()}
            </text>
          </g>
        ))}

        <path d={areaPath} className="dm-spark-area" />
        <path d={linePath} className="dm-spark-line" />

        {metric === "tokens" && (
          <>
            <path d={tokenInPath} className="dm-spark-line dm-spark-line-in" />
            <path d={tokenOutPath} className="dm-spark-line dm-spark-line-out" />
          </>
        )}

        {values.map((v, i) => {
          const { x, y } = xy(i, v);
          return (
            <g key={i}>
              <circle cx={x} cy={y} r={3} className="dm-spark-dot" />
              <title>{`${series[i].date}: ${v.toLocaleString()}`}</title>
            </g>
          );
        })}

        {series.map((p, i) =>
          i % xLabelEvery === 0 || i === series.length - 1 ? (
            <text
              key={i}
              x={PAD_L + i * stepX}
              y={H - 8}
              className="dm-spark-axis"
              textAnchor="middle"
            >
              {p.date.slice(5)}
            </text>
          ) : null
        )}
      </svg>
      {metric === "tokens" && (
        <div className="dm-spark-legend">
          <span><i className="dot" /> 合计</span>
          <span><i className="dot in" /> 输入</span>
          <span><i className="dot out" /> 输出</span>
        </div>
      )}
    </div>
  );
}

// =============== 通用 ===============

function Kpi({
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
      <div className="dm-stat-value">{(value ?? 0).toLocaleString()}</div>
    </div>
  );
}

function DistributionList({
  map,
  total,
  zh,
  variant,
  topN,
}: {
  map: Record<string, number>;
  total: number;
  zh?: Record<string, string>;
  variant?: "severity";
  topN?: number;
}) {
  let entries = Object.entries(map).sort((a, b) => b[1] - a[1]);
  if (topN && entries.length > topN) entries = entries.slice(0, topN);
  if (entries.length === 0) {
    return <div className="dm-empty-tip">无数据</div>;
  }
  return (
    <div className="dm-bars">
      {entries.map(([k, v]) => {
        const pct = total > 0 ? (v / total) * 100 : 0;
        const display = (zh && zh[k]) || k;
        const cls =
          variant === "severity" && k in { critical: 1, high: 1, medium: 1, low: 1 }
            ? `dm-bar dm-bar-sev-${k}`
            : "dm-bar";
        return (
          <div key={k} className={cls}>
            <div className="dm-bar-row">
              <span className="dm-bar-label">{display}</span>
              <span className="dm-bar-value">{v.toLocaleString()}</span>
            </div>
            <div className="dm-bar-track">
              <div className="dm-bar-fill" style={{ width: `${pct}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
