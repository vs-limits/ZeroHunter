import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  FolderGit2,
  ListTree,
  Play,
  Plus,
  RefreshCw,
  ShieldAlert,
  Square,
  Trash2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  api,
  type ArtifactJsonResponse,
  type AuditBatch,
  type AuditResponse,
  type AuditSummary,
  type CandidateChain,
  type CandidateResponse,
  type DashboardResponse,
  type ProjectSummary,
  type RunInfo,
  type ScanRecord,
} from "./api";

type MainView = "dashboard" | "project" | "scan";
type ScanTab = "control" | "treescan" | "callscan" | "audit";

const EMPTY_AUDIT: AuditSummary = {
  total_chains: 0,
  total_audited: 0,
  vulnerable: 0,
  uncertain: 0,
  safe: 0,
  errors: 0,
  by_vulnerability: {},
  by_severity: {},
};

export function App() {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [dashboard, setDashboard] = useState<DashboardResponse | null>(null);
  const [activeProject, setActiveProject] = useState<ProjectSummary | null>(null);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);
  const [view, setView] = useState<MainView>("dashboard");
  const [tab, setTab] = useState<ScanTab>("control");
  const [scansByProject, setScansByProject] = useState<Record<string, ScanRecord[]>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshProjects = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [projectRes, dashboardRes] = await Promise.all([api.projects(), api.dashboard()]);
      setProjects(projectRes.items);
      setDashboard(dashboardRes);
      setActiveProject((current) => {
        if (!current) return projectRes.items[0] ?? null;
        return projectRes.items.find((item) => item.project_path === current.project_path) ?? projectRes.items[0] ?? null;
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshScans = useCallback(async (projectPath: string) => {
    const res = await api.scans(projectPath);
    setScansByProject((prev) => ({ ...prev, [projectPath]: res.items }));
    setActiveScan((current) => {
      if (!current || current.project_path !== projectPath) return current;
      return res.items.find((item) => item.scan_id === current.scan_id) ?? current;
    });
    return res.items;
  }, []);

  useEffect(() => {
    void refreshProjects();
  }, [refreshProjects]);

  useEffect(() => {
    if (!activeProject) return;
    if (scansByProject[activeProject.project_path]) return;
    void refreshScans(activeProject.project_path).catch((e) => setError(String(e)));
  }, [activeProject, refreshScans, scansByProject]);

  function selectProject(project: ProjectSummary) {
    setActiveProject(project);
    setActiveScan(null);
    setView("project");
  }

  function selectScan(project: ProjectSummary, scan: ScanRecord) {
    setActiveProject(project);
    setActiveScan(scan);
    setTab("control");
    setView("scan");
  }

  async function handleScanChanged(scan?: ScanRecord | null) {
    if (!activeProject) return;
    artifactCache.clear();
    const scans = await refreshScans(activeProject.project_path);
    if (scan === null) {
      setActiveScan(scans[0] ?? null);
      setView(scans[0] ? "scan" : "project");
      return;
    }
    if (scan) setActiveScan(scan);
    await refreshProjects();
  }

  async function handleProjectImported(project: ProjectSummary) {
    artifactCache.clear();
    setProjects((prev) => {
      const next = prev.filter((item) => item.project_path !== project.project_path);
      return [...next, project].sort((a, b) => a.project_path.localeCompare(b.project_path));
    });
    setActiveProject(project);
    setActiveScan(null);
    setView("project");
    await refreshScans(project.project_path).catch(() => undefined);
    await refreshProjects();
  }

  return (
    <div className="dm-shell">
      <aside className="dm-sidebar">
        <div className="dm-brand">
          <div className="dm-brand-mark">DM</div>
          <div>
            <div className="dm-brand-title">DEFECTMINE</div>
            <div className="dm-brand-sub">安全与漏洞管理工作台</div>
          </div>
        </div>

        <button className={`dm-nav ${view === "dashboard" ? "active" : ""}`} onClick={() => setView("dashboard")}>
          <BarChart3 size={16} /> 仪表盘
        </button>

        <SidebarProjectImport onImported={(project) => void handleProjectImported(project)} />

        <div className="dm-side-section">
          <div className="dm-side-title">待扫描项目</div>
          {projects.map((project) => {
            const scans = scansByProject[project.project_path] ?? [];
            const selected = activeProject?.project_path === project.project_path;
            return (
              <div key={project.project_path} className="dm-project-node">
                <button className={`dm-project-row ${selected && view !== "dashboard" ? "active" : ""}`} onClick={() => selectProject(project)}>
                  <FolderGit2 size={15} />
                  <span>{project.name || project.project_path}</span>
                  <small>{project.scan_count}</small>
                </button>
                {selected && (
                  <div className="dm-scan-list">
                    {scans.map((scan) => (
                      <button
                        key={scan.scan_id}
                        className={`dm-scan-row ${activeScan?.scan_id === scan.scan_id ? "active" : ""}`}
                        onClick={() => selectScan(project, scan)}
                      >
                        <StatusDot status={scan.status} />
                        <span>{scan.name || scan.scan_id}</span>
                      </button>
                    ))}
                    {scans.length === 0 && <div className="dm-empty-small">暂无扫描记录</div>}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </aside>

      <main className="dm-main">
        <header className="dm-topbar">
          <div>
            <div className="dm-kicker">Local Workbench</div>
            <h1>{view === "dashboard" ? "安全运营概览" : activeProject?.name || "项目详情"}</h1>
          </div>
          <div className="dm-top-actions">
            {loading && <span className="dm-muted">加载中</span>}
            <button className="dm-btn" onClick={() => void refreshProjects()}>
              <RefreshCw size={15} /> 刷新
            </button>
          </div>
        </header>

        {error && <div className="dm-banner-error">{error}</div>}

        {view === "dashboard" && (
          <DashboardView
            dashboard={dashboard}
            projects={projects}
            onSelectProject={selectProject}
            onProjectImported={(project) => void handleProjectImported(project)}
          />
        )}
        {view === "project" && activeProject && (
          <ProjectView
            project={activeProject}
            scans={scansByProject[activeProject.project_path] ?? []}
            onCreated={(scan) => {
              setActiveScan(scan);
              setView("scan");
              void handleScanChanged(scan);
            }}
            onSelectScan={(scan) => selectScan(activeProject, scan)}
          />
        )}
        {view === "scan" && activeProject && activeScan && (
          <ScanView project={activeProject} scan={activeScan} tab={tab} setTab={setTab} onScanChanged={handleScanChanged} />
        )}
      </main>
    </div>
  );
}

function DashboardView({
  dashboard,
  projects,
  onSelectProject,
  onProjectImported,
}: {
  dashboard: DashboardResponse | null;
  projects: ProjectSummary[];
  onSelectProject: (project: ProjectSummary) => void;
  onProjectImported: (project: ProjectSummary) => void;
}) {
  const audit = dashboard?.audit_summary ?? EMPTY_AUDIT;
  const projectCount = typeof dashboard?.projects === "number" ? dashboard.projects : projects.length;
  return (
    <section className="dm-stack">
      <div className="dm-grid dm-grid-4">
        <Metric title="项目数" value={projectCount} icon={<FolderGit2 size={18} />} />
        <Metric title="扫描记录" value={dashboard?.scans ?? 0} icon={<Activity size={18} />} />
        <Metric title="存在漏洞" value={audit.vulnerable} tone="danger" icon={<ShieldAlert size={18} />} />
        <Metric title="不确定" value={audit.uncertain} tone="warn" icon={<AlertTriangle size={18} />} />
      </div>
      <ProjectImportCard onImported={onProjectImported} />
      <Card title="项目资产" hint="projects">
        <div className="dm-table">
          <div className="dm-tr dm-th">
            <span>项目</span>
            <span>扫描</span>
            <span>漏洞</span>
            <span>不确定</span>
            <span>安全</span>
          </div>
          {projects.map((project) => (
            <button className="dm-tr dm-row-button" key={project.project_path} onClick={() => onSelectProject(project)}>
              <span>
                <strong>{project.name}</strong>
                <code>{project.project_path}</code>
              </span>
              <span>{project.scan_count}</span>
              <span className="dm-danger">{project.audit_summary?.vulnerable ?? 0}</span>
              <span className="dm-warn">{project.audit_summary?.uncertain ?? 0}</span>
              <span className="dm-ok">{project.audit_summary?.safe ?? 0}</span>
            </button>
          ))}
          {projects.length === 0 && <div className="dm-empty">还没有项目，可以先从左侧加入 repo_code 下的项目。</div>}
        </div>
      </Card>
    </section>
  );
}

function ProjectImportCard({ onImported }: { onImported: (project: ProjectSummary) => void }) {
  return (
    <Card title="加入项目" hint="repo_code">
      <ProjectImportForm onImported={onImported} />
      <p className="dm-muted">项目目录必须位于当前工作区的 repo_code 目录下；加入后即可新建扫描记录。</p>
    </Card>
  );
}

function SidebarProjectImport({ onImported }: { onImported: (project: ProjectSummary) => void }) {
  return (
    <div className="dm-sidebar-import">
      <div className="dm-side-title">加入项目</div>
      <ProjectImportForm compact onImported={onImported} />
    </div>
  );
}

function ProjectImportForm({ onImported, compact = false }: { onImported: (project: ProjectSummary) => void; compact?: boolean }) {
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function importProject() {
    const value = path.trim();
    if (!value) return;
    setBusy(true);
    setError("");
    try {
      const project = await api.importProject(value);
      setPath("");
      onImported(project);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className={compact ? "dm-compact-form" : "dm-inline-form"}>
        <input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder={compact ? "repo_code 相对路径" : "输入 repo_code 下的相对路径，例如 yeswiki/yeswiki-4.6.3"}
          onKeyDown={(e) => e.key === "Enter" && void importProject()}
        />
        <button className="dm-btn dm-btn-primary" onClick={() => void importProject()} disabled={busy || !path.trim()}>
          <Plus size={15} /> 加入
        </button>
      </div>
      {error && <div className="dm-banner-error">{error}</div>}
      {compact && <p className="dm-muted">例如：yeswiki/yeswiki-4.6.3</p>}
    </>
  );
}

function ProjectView({
  project,
  scans,
  onCreated,
  onSelectScan,
}: {
  project: ProjectSummary;
  scans: ScanRecord[];
  onCreated: (scan: ScanRecord) => void;
  onSelectScan: (scan: ScanRecord) => void;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    try {
      const scan = await api.createScan({
        project_path: project.project_path,
        name: name.trim() || `扫描 ${new Date().toLocaleString()}`,
        step: "manual",
      });
      setName("");
      onCreated(scan);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="dm-stack">
      <Card title="新建扫描" hint="scan space">
        <div className="dm-inline-form">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="扫描名称，例如 baseline round 1" />
          <button className="dm-btn dm-btn-primary" onClick={() => void create()} disabled={busy}>
            <Plus size={15} /> 新建
          </button>
        </div>
        <p className="dm-muted">新建扫描只创建一个扫描空间。后续流程为：候选链发现、手动选择候选链创建批次、启动批次审计。</p>
      </Card>
      <Card title="扫描记录" hint="history">
        <div className="dm-table dm-table-scans">
          <div className="dm-tr dm-th">
            <span>名称</span>
            <span>状态</span>
            <span>候选链</span>
            <span>漏洞</span>
            <span>创建时间</span>
          </div>
          {scans.map((scan) => (
            <button className="dm-tr dm-row-button" key={scan.scan_id} onClick={() => onSelectScan(scan)}>
              <span>
                <strong>{scan.name}</strong>
                <code>{scan.scan_id}</code>
              </span>
              <span><StatusBadge status={scan.status} /></span>
              <span>{scan.callscan_summary?.candidate_chains ?? 0}</span>
              <span className="dm-danger">{scan.audit_summary?.vulnerable ?? 0}</span>
              <span>{formatDate(scan.created_at)}</span>
            </button>
          ))}
          {scans.length === 0 && <div className="dm-empty">还没有扫描记录，可以从上方新建一条。</div>}
        </div>
      </Card>
    </section>
  );
}

function ScanView({
  project,
  scan,
  tab,
  setTab,
  onScanChanged,
}: {
  project: ProjectSummary;
  scan: ScanRecord;
  tab: ScanTab;
  setTab: (tab: ScanTab) => void;
  onScanChanged: (scan?: ScanRecord | null) => void | Promise<void>;
}) {
  const [selectedCandidateIds, setSelectedCandidateIds] = useState<Set<string>>(new Set());
  const audit = scan.audit_summary ?? EMPTY_AUDIT;

  useEffect(() => {
    setSelectedCandidateIds(new Set());
  }, [scan.scan_id]);

  const selectedIds = useMemo(() => Array.from(selectedCandidateIds), [selectedCandidateIds]);

  function toggleCandidate(chainId: string, checked: boolean) {
    setSelectedCandidateIds((current) => {
      const next = new Set(current);
      if (checked) next.add(chainId);
      else next.delete(chainId);
      return next;
    });
  }

  return (
    <section className="dm-stack">
      <div className="dm-scan-head">
        <div>
          <div className="dm-kicker">{scan.scan_id}</div>
          <h2>{scan.name}</h2>
          <div className="dm-muted">{project.project_path}</div>
        </div>
        <StatusBadge status={scan.status} />
      </div>
      <div className="dm-grid dm-grid-4">
        <Metric title="候选调用链" value={audit.total_chains || scan.callscan_summary?.candidate_chains || 0} icon={<ListTree size={18} />} />
        <Metric title="存在漏洞" value={audit.vulnerable} tone="danger" icon={<ShieldAlert size={18} />} />
        <Metric title="不确定" value={audit.uncertain} tone="warn" icon={<AlertTriangle size={18} />} />
        <Metric title="安全" value={audit.safe} tone="ok" icon={<CheckCircle2 size={18} />} />
      </div>
      <div className="dm-tabs">
        <TabButton active={tab === "control"} onClick={() => setTab("control")}>扫描控制</TabButton>
        <TabButton active={tab === "treescan"} onClick={() => setTab("treescan")}>TreeScan</TabButton>
        <TabButton active={tab === "callscan"} onClick={() => setTab("callscan")}>CallScan</TabButton>
        <TabButton active={tab === "audit"} onClick={() => setTab("audit")}>漏洞审计</TabButton>
      </div>
      {tab === "control" && (
        <ControlPanel
          project={project}
          scan={scan}
          selectedChainIds={selectedIds}
          onClearSelectedChains={() => setSelectedCandidateIds(new Set())}
          onScanChanged={onScanChanged}
        />
      )}
      {tab === "treescan" && <TreeScanPanel project={project} scan={scan} />}
      {tab === "callscan" && (
        <CallScanPanel
          project={project}
          scan={scan}
          selectedIds={selectedCandidateIds}
          onToggleCandidate={toggleCandidate}
          onClearSelected={() => setSelectedCandidateIds(new Set())}
        />
      )}
      {tab === "audit" && <AuditPanel project={project} scan={scan} />}
    </section>
  );
}

function ControlPanel({
  project,
  scan,
  selectedChainIds,
  onClearSelectedChains,
  onScanChanged,
}: {
  project: ProjectSummary;
  scan: ScanRecord;
  selectedChainIds: string[];
  onClearSelectedChains: () => void;
  onScanChanged: (scan?: ScanRecord | null) => void | Promise<void>;
}) {
  const [name, setName] = useState(scan.name);
  const [batchName, setBatchName] = useState("");
  const [batches, setBatches] = useState<AuditBatch[]>([]);
  const [auditDryRun, setAuditDryRun] = useState(Boolean(scan.audit_dry_run));
  const [busy, setBusy] = useState(false);
  const [runInfo, setRunInfo] = useState<RunInfo | null>(null);
  const [localError, setLocalError] = useState("");
  const streamRef = useRef<EventSource | null>(null);

  useEffect(() => {
    setName(scan.name);
    setAuditDryRun(Boolean(scan.audit_dry_run));
    setRunInfo(null);
    setLocalError("");
    void refreshBatches();
    return () => streamRef.current?.close();
  }, [scan.scan_id, scan.name, scan.audit_dry_run]);

  async function saveSettings() {
    setBusy(true);
    setLocalError("");
    try {
      const next = await persistSettings();
      await onScanChanged(next);
    } catch (e) {
      setLocalError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function persistSettings() {
    return api.updateScan(scan.scan_id, project.project_path, {
      name,
      audit_dry_run: auditDryRun,
    });
  }

  async function refreshBatches() {
    try {
      const result = await api.batches(scan.scan_id, project.project_path);
      setBatches(result.items ?? []);
    } catch {
      setBatches([]);
    }
  }

  async function discover(force = false) {
    setBusy(true);
    setLocalError("");
    try {
      await persistSettings();
      const run = await api.discoverScan(scan.scan_id, {
        project_path: project.project_path,
        force_discover: force,
      });
      setRunInfo({ ...run, project_path: project.project_path, last_message: "候选链发现已启动" });
      attachStream(run.run_id);
      await onScanChanged();
    } catch (e) {
      setLocalError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function createBatch() {
    if (selectedChainIds.length === 0) {
      setLocalError("请先在 CallScan 页面勾选候选链，再创建审计批次。");
      return;
    }
    setBusy(true);
    setLocalError("");
    try {
      await persistSettings();
      const batch = await api.createBatch(scan.scan_id, {
        project_path: project.project_path,
        name: batchName.trim() || undefined,
        audit_limit: selectedChainIds.length,
        audit_per_type: 0,
        selected_chain_ids: selectedChainIds,
        exclude_completed: false,
      });
      setBatchName("");
      onClearSelectedChains();
      setBatches((items) => [batch, ...items.filter((item) => item.batch_id !== batch.batch_id)]);
      await onScanChanged();
    } catch (e) {
      setLocalError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function startBatch(batchId: string) {
    setBusy(true);
    setLocalError("");
    try {
      const run = await api.startBatch(scan.scan_id, batchId, {
        project_path: project.project_path,
        audit_dry_run: auditDryRun,
      });
      setRunInfo({ ...run, project_path: project.project_path, last_message: `批次 ${batchId} 审计已启动` });
      attachStream(run.run_id);
      await onScanChanged();
    } catch (e) {
      setLocalError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    setLocalError("");
    try {
      const result = await api.stopScan(scan.scan_id, project.project_path);
      if (result.ok) await onScanChanged();
    } catch (e) {
      setLocalError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!confirm(`删除扫描记录「${scan.name}」？`)) return;
    await api.deleteScan(scan.scan_id, project.project_path);
    await onScanChanged(null);
  }

  function attachStream(runId: string) {
    streamRef.current?.close();
    const es = new EventSource(`/api/runs/${encodeURIComponent(runId)}/stream`);
    streamRef.current = es;
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "status") setRunInfo(msg as RunInfo);
        if (msg.type === "end") {
          es.close();
          void refreshBatches();
          void onScanChanged();
        }
      } catch {
        setLocalError("运行状态解析失败，请查看后端 console.log。");
      }
    };
    es.onerror = () => setRunInfo((current) => current ? { ...current, last_message: "状态流中断，请稍后刷新查看结果。" } : current);
  }

  return (
    <>
      <Card title="扫描控制" hint="manual workflow">
        <div className="dm-control-grid">
          <label>
            <span>扫描名称</span>
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="dm-checkbox">
            <input type="checkbox" checked={auditDryRun} onChange={(e) => setAuditDryRun(e.target.checked)} />
            <span>仅生成审计任务，不调用 LLM</span>
          </label>
        </div>
        <div className="dm-inline-form">
          <button className="dm-btn" onClick={() => void saveSettings()} disabled={busy}>保存名称</button>
          <button className="dm-btn" onClick={() => void discover(false)} disabled={busy || scan.status === "running"}>
            <RefreshCw size={14} /> 候选链发现
          </button>
          <button className="dm-btn" onClick={() => void discover(true)} disabled={busy || scan.status === "running"}>重新发现</button>
          {scan.status === "running" && (
            <button className="dm-btn dm-btn-danger" onClick={() => void stop()} disabled={busy}>
              <Square size={14} /> 停止
            </button>
          )}
          <button className="dm-btn dm-btn-ghost danger-text" onClick={() => void remove()}>
            <Trash2 size={14} /> 删除
          </button>
        </div>
        <div className="dm-run-summary">
          <Info label="当前状态" value={statusLabel(scan.status)} />
          <Info label="候选来源" value={candidateSourceLabel(scan.callscan_summary?.candidate_source)} />
          <Info label="候选链" value={String(scan.callscan_summary?.candidate_chains ?? 0)} />
          <Info label="最后运行" value={scan.last_run_id || "尚未运行"} />
        </div>
        <RunStatusPanel runInfo={runInfo} scan={scan} />
        {localError && <div className="dm-banner-error">{localError}</div>}
        <p className="dm-muted">工作台流程固定为：新建扫描、候选链发现、在 CallScan 中勾选候选链、创建审计批次、启动批次审计。</p>
      </Card>

      <Card title="审计批次" hint="selected chains">
        <div className="dm-inline-form">
          <input value={batchName} onChange={(e) => setBatchName(e.target.value)} placeholder="批次名称，例如 XSS coverage round 1" />
          <button className="dm-btn dm-btn-primary" onClick={() => void createBatch()} disabled={busy || selectedChainIds.length === 0}>
            <Plus size={14} /> 创建批次
          </button>
        </div>
        <p className="dm-muted">当前已选择 {selectedChainIds.length} 条候选链。手动选择允许重复审计已完成的调用链。</p>
        <div className="dm-list">
          {batches.map((batch) => (
            <div className="dm-chain-row" key={batch.batch_id}>
              <span className="dm-index">{batch.queue_count ?? 0}</span>
              <div>
                <strong>{batch.name || batch.batch_id}</strong>
                <code>{batch.batch_id}</code>
              </div>
              <span className="dm-pill">{statusLabel(batch.status)}</span>
              <button className="dm-btn dm-btn-small" onClick={() => void startBatch(batch.batch_id)} disabled={busy || scan.status === "running"}>
                <Play size={13} /> 审计
              </button>
            </div>
          ))}
          {batches.length === 0 && <div className="dm-empty">还没有审计批次。先完成候选链发现，并在 CallScan 页面勾选候选链。</div>}
        </div>
      </Card>
    </>
  );
}

function RunStatusPanel({ runInfo, scan }: { runInfo: RunInfo | null; scan: ScanRecord }) {
  const status = runInfo?.status ?? scan.status;
  const message = runInfo?.error_message || runInfo?.last_message || (status === "running" ? "任务运行中" : "等待启动");
  const cmd = runInfo?.cmd?.join(" ");
  return (
    <div className={`dm-run-panel ${status}`}>
      <div>
        <strong>{statusLabel(status)}</strong>
        <span>{message}</span>
      </div>
      <div className="dm-run-panel-meta">
        {runInfo?.elapsed_seconds != null && <span>耗时：{runInfo.elapsed_seconds}s</span>}
        {runInfo?.run_id && <span>运行：{runInfo.run_id}</span>}
      </div>
      {cmd && <code>{cmd}</code>}
      {runInfo?.error_message && runInfo.log_path && <small>日志文件：{runInfo.log_path}</small>}
    </div>
  );
}

function TreeScanPanel({ project, scan }: { project: ProjectSummary; scan: ScanRecord }) {
  const key = `${project.project_path}:${scan.scan_id}:treescan`;
  const { data, error, loading } = useArtifactCache<ArtifactJsonResponse<Record<string, unknown>>>(key, () =>
    api.artifactJson<Record<string, unknown>>(project.project_path, "treescan_agent.json", scan.scan_id)
  );
  const profile: Record<string, unknown> | undefined = data?.data;
  const stack = (profile?.technology_stack as Record<string, unknown>) ?? {};
  return (
    <Card title="项目理解" hint="treescan_agent.json">
      {loading && <div className="dm-muted">加载 TreeScan 项目画像中...</div>}
      {error && <div className="dm-banner-error">{error}</div>}
      {profile && (
        <div className="dm-profile-grid">
          <Info label="项目名称" value={text(profile.project_name)} />
          <Info label="项目类型" value={text(profile.project_type)} />
          <Info label="功能摘要" value={text(profile.project_function || profile.project_summary || profile.summary)} wide />
          <Info label="后端" value={listText(stack.backend)} />
          <Info label="前端" value={listText(stack.frontend)} />
          <Info label="数据库" value={listText(stack.database || stack.data)} />
          <Info label="工程背景" value={listText(profile.engineering_context)} wide />
        </div>
      )}
    </Card>
  );
}

function CallScanPanel({
  project,
  scan,
  selectedIds,
  onToggleCandidate,
  onClearSelected,
}: {
  project: ProjectSummary;
  scan: ScanRecord;
  selectedIds: Set<string>;
  onToggleCandidate: (chainId: string, checked: boolean) => void;
  onClearSelected: () => void;
}) {
  const pageSize = 50;
  const [offset, setOffset] = useState(0);
  const [vulnerabilityType, setVulnerabilityType] = useState("");
  const [severity, setSeverity] = useState("");
  const [data, setData] = useState<CandidateResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    api.candidates(scan.scan_id, project.project_path, {
      offset,
      limit: pageSize,
      vulnerability_type: vulnerabilityType || undefined,
      severity: severity || undefined,
    })
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [project.project_path, scan.scan_id, offset, vulnerabilityType, severity]);

  function clearFilters() {
    setVulnerabilityType("");
    setSeverity("");
    setOffset(0);
  }

  const total = data?.total ?? 0;
  const source = data?.source ?? scan.callscan_summary?.candidate_source ?? "none";
  const selectedCount = selectedIds.size;
  const vulnerabilityOptions = useMemo(
    () => sortedFacetEntries(data?.facets?.vulnerability_types ?? {}),
    [data?.facets?.vulnerability_types]
  );
  const severityOptions = useMemo(
    () => sortedRiskEntries(data?.facets?.risk_levels ?? {}),
    [data?.facets?.risk_levels]
  );

  return (
    <section className="dm-stack">
      <Card title="候选调用链" hint={source === "all" ? "callscan_chains.all.jsonl" : source === "priority" ? "callscan_chains.priority.jsonl" : "candidate pool"}>
        <div className="dm-run-summary">
          <Info label="候选来源" value={candidateSourceLabel(source)} />
          <Info label="候选链总数" value={String(scan.callscan_summary?.candidate_chains ?? total)} />
          <Info label="已审计记录" value={String(scan.callscan_summary?.completed ?? 0)} />
          <Info label="已选择" value={String(selectedCount)} />
        </div>
        <div className="dm-inline-form">
          <select value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}>
            <option value="">全部风险</option>
            {severityOptions.map(([name, count]) => (
              <option key={name} value={name}>{severityLabel(name)}（{count}）</option>
            ))}
          </select>
          <select value={vulnerabilityType} onChange={(e) => { setVulnerabilityType(e.target.value); setOffset(0); }}>
            <option value="">全部漏洞类型</option>
            {vulnerabilityOptions.map(([name, count]) => (
              <option key={name} value={name}>{vulnerabilityLabel(name)}（{count}）</option>
            ))}
          </select>
          {(vulnerabilityType || severity) && <button className="dm-btn dm-btn-ghost" onClick={clearFilters}>清空筛选</button>}
          {selectedCount > 0 && <button className="dm-btn dm-btn-ghost" onClick={onClearSelected}>清除选择</button>}
        </div>
        <p className="dm-muted">勾选候选链后，到“扫描控制”页创建审计批次。手动选择不会因为完成池记录而被跳过。</p>

        {loading && <div className="dm-muted">加载候选链中...</div>}
        {error && <div className="dm-banner-error">{error}</div>}
        {!loading && !error && source === "none" && (
          <div className="dm-empty">尚未执行候选链发现。请先在“扫描控制”页点击“候选链发现”。</div>
        )}
        {data && source !== "none" && (
          <>
            <div className="dm-muted">当前显示 {data.items.length} / {data.total} 条候选链。</div>
            <div className="dm-list">
              {data.items.map((item, index) => (
                <CandidateRow
                  key={item.chain_id || item.path_id || index}
                  item={item}
                  index={data.offset + index + 1}
                  selected={selectedIds.has(item.chain_id)}
                  onToggle={(checked) => onToggleCandidate(item.chain_id, checked)}
                />
              ))}
              {data.items.length === 0 && <div className="dm-empty">没有匹配的候选链。</div>}
            </div>
            <div className="dm-inline-form">
              <button className="dm-btn" disabled={offset <= 0} onClick={() => setOffset(Math.max(offset - pageSize, 0))}>上一页</button>
              <span className="dm-muted">{offset + 1} - {Math.min(offset + pageSize, total)} / {total}</span>
              <button className="dm-btn" disabled={offset + pageSize >= total} onClick={() => setOffset(offset + pageSize)}>下一页</button>
            </div>
          </>
        )}
      </Card>
    </section>
  );
}

function CandidateRow({
  item,
  index,
  selected,
  onToggle,
}: {
  item: CandidateChain;
  index: number;
  selected: boolean;
  onToggle: (checked: boolean) => void;
}) {
  const location = [item.file, item.line ? `:${item.line}` : ""].filter(Boolean).join("");
  return (
    <div className="dm-chain-row">
      <label className="dm-index" title="选择候选链">
        <input type="checkbox" checked={selected} onChange={(e) => onToggle(e.target.checked)} />
      </label>
      <div>
        <strong>{vulnerabilityLabel(item.vulnerability_type || "unknown")}</strong>
        <code>{location || item.chain_id || item.path_id || "-"}</code>
        <span className="dm-muted">
          {item.language || "unknown"} · {item.function || "sink"} · 风险分 {item.risk_score ?? 0} · #{index}
        </span>
      </div>
      <span className="dm-pill">{severityLabel(item.severity)} · {item.completed ? "已审计" : "未审计"}</span>
      {(item.batches?.length ?? 0) > 0 && <span className="dm-pill">批次 {item.batches?.length}</span>}
    </div>
  );
}

function AuditPanel({ project, scan }: { project: ProjectSummary; scan: ScanRecord }) {
  const [keyword, setKeyword] = useState("");
  const [committed, setCommitted] = useState("");
  const [severity, setSeverity] = useState("");
  const [vulnerability, setVulnerability] = useState("");
  const cacheKey = `${project.project_path}:${scan.scan_id}:audit:${severity}:${vulnerability}:${committed}`;
  const { data, error, loading } = useArtifactCache<AuditResponse<Record<string, unknown>>>(cacheKey, () =>
    api.audit<Record<string, unknown>>(
      project.project_path,
      scan.scan_id,
      0,
      80,
      severity || undefined,
      undefined,
      committed || undefined,
      vulnerability || undefined
    )
  );
  const summary = ((data?.head?.summary as AuditSummary | undefined) ?? scan.audit_summary ?? EMPTY_AUDIT);
  const cost = ((data?.head?.summary as any)?.cost ?? {}) as Record<string, unknown>;
  const vulnEntries = Object.entries(summary.by_vulnerability ?? {}).sort((a, b) => b[1] - a[1]);
  const vulnOptions = useMemo(() => {
    const fromScan = Object.keys(scan.audit_summary?.by_vulnerability ?? {});
    const fromCurrent = Object.keys(summary.by_vulnerability ?? {});
    const fromRows = (data?.findings ?? []).map((item) => displayVulnerabilityType(item)).filter((item) => item !== "unknown");
    return Array.from(new Set([...fromScan, ...fromCurrent, ...fromRows].filter(Boolean))).sort();
  }, [data?.findings, scan.audit_summary, summary.by_vulnerability]);

  return (
    <section className="dm-stack">
      <Card title="审计概要" hint="audit_agent.json">
        <div className="dm-grid dm-grid-4">
          <Metric title="调用链条数" value={summary.total_chains} icon={<ListTree size={18} />} />
          <Metric title="存在漏洞" value={summary.vulnerable} tone="danger" icon={<ShieldAlert size={18} />} />
          <Metric title="不确定" value={summary.uncertain} tone="warn" icon={<AlertTriangle size={18} />} />
          <Metric title="安全" value={summary.safe} tone="ok" icon={<CheckCircle2 size={18} />} />
        </div>
        <div className="dm-section-title">漏洞类型分布</div>
        <div className="dm-badges">
          {vulnEntries.length ? vulnEntries.map(([name, count]) => (
            <span className="dm-tag" key={name}>
              {vulnerabilityLabel(name)}
              <small>{name}</small>
              <strong>{count}</strong>
            </span>
          )) : <span className="dm-muted">暂无漏洞类型统计</span>}
        </div>
        {Object.keys(cost).length > 0 && (
          <>
            <div className="dm-section-title">调用成本估算</div>
            <div className="dm-badges">
              <span className="dm-tag">API 调用 <strong>{text(cost.estimated_api_calls)}</strong></span>
              <span className="dm-tag">工具轮次 <strong>{text(cost.tool_rounds)}</strong></span>
              <span className="dm-tag">单链最多调用 <strong>{text(cost.max_api_calls_per_chain)}</strong></span>
              <span className="dm-tag">工具轮次上限 <strong>{text(cost.tool_round_limit)}</strong></span>
            </div>
          </>
        )}
      </Card>
      <Card title="审计结果" hint="paged">
        <div className="dm-inline-form">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">全部严重度</option>
            <option value="critical">严重</option>
            <option value="high">高</option>
            <option value="medium">中</option>
            <option value="low">低</option>
            <option value="info">信息</option>
            <option value="unknown">风险未知</option>
          </select>
          <select value={vulnerability} onChange={(e) => setVulnerability(e.target.value)}>
            <option value="">全部漏洞类型</option>
            {vulnOptions.map((name) => (
              <option key={name} value={name}>{vulnerabilityLabel(name)}</option>
            ))}
          </select>
          <input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索 chain id / 文件 / 漏洞类型 / 证据"
            onKeyDown={(e) => e.key === "Enter" && setCommitted(keyword.trim())}
          />
          <button className="dm-btn" onClick={() => setCommitted(keyword.trim())}>搜索</button>
          {(severity || vulnerability || committed) && (
            <button
              className="dm-btn dm-btn-ghost"
              onClick={() => {
                setSeverity("");
                setVulnerability("");
                setKeyword("");
                setCommitted("");
              }}
            >
              清空
            </button>
          )}
        </div>
        <div className="dm-muted">审计结论表示可利用性判断，潜在风险来自 CallScan 候选链排序；“严重 + 不确定”表示高风险候选但证据不足。</div>
        {loading && <div className="dm-muted">加载审计结果中...</div>}
        {error && <div className="dm-banner-error">{error}</div>}
        {data && (
          <div className="dm-list">
            {data.findings.map((item, index) => (
              <div className="dm-audit-row" key={text(item.chain_id || index)}>
                <div className="dm-audit-main">
                  <strong>{text(item.title) !== "-" ? text(item.title) : vulnerabilityLabel(displayVulnerabilityType(item))}</strong>
                  <span>{text(item.principle || item.fix_suggestion || item.missing_info || "无摘要")}</span>
                  <code>{text(item.chain_id || item.analysis_id)}</code>
                </div>
                <span className={`dm-verdict ${verdictClass(item.verdict)}`}>审计结论：{verdictLabel(item.verdict)}</span>
                <span className="dm-pill">潜在风险：{severityLabel(item.severity)}</span>
              </div>
            ))}
            {data.findings.length === 0 && <div className="dm-empty">没有匹配的审计结果。</div>}
          </div>
        )}
      </Card>
    </section>
  );
}

const artifactCache = new Map<string, unknown>();

function useArtifactCache<T>(key: string, loader: () => Promise<T>) {
  const [data, setData] = useState<T | null>(() => (artifactCache.get(key) as T | undefined) ?? null);
  const [loading, setLoading] = useState(!artifactCache.has(key));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (artifactCache.has(key)) {
      setData(artifactCache.get(key) as T);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    loader()
      .then((result) => {
        if (cancelled) return;
        artifactCache.set(key, result);
        setData(result);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [key]);

  return { data, loading, error };
}

function Card({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <section className="dm-card">
      <div className="dm-card-head">
        <h3>{title}</h3>
        {hint && <span>{hint}</span>}
      </div>
      {children}
    </section>
  );
}

function Metric({ title, value, tone, icon }: { title: string; value: number | string; tone?: string; icon?: ReactNode }) {
  return (
    <div className={`dm-metric ${tone ? `tone-${tone}` : ""}`}>
      <div className="dm-metric-icon">{icon}</div>
      <div>
        <div className="dm-metric-title">{title}</div>
        <div className="dm-metric-value">{value}</div>
      </div>
    </div>
  );
}

function Info({ label, value, wide }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={`dm-info ${wide ? "wide" : ""}`}>
      <span>{label}</span>
      <strong>{value || "-"}</strong>
    </div>
  );
}

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return <button className={`dm-tab ${active ? "active" : ""}`} onClick={onClick}>{children}</button>;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`dm-status ${status}`}>{statusLabel(status)}</span>;
}

function StatusDot({ status }: { status: string }) {
  return <span className={`dm-dot ${status}`} title={status} />;
}

function statusLabel(status: string) {
  return ({ pending: "待运行", running: "运行中", done: "完成", error: "失败", killed: "已停止" } as Record<string, string>)[status] ?? status;
}

function formatDate(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function text(value: unknown): string {
  if (value == null || value === "") return "-";
  if (Array.isArray(value)) return value.map(text).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function listText(value: unknown) {
  const result = text(value);
  return result === "[]" ? "-" : result;
}

function displayVulnerabilityType(item: Record<string, unknown>): string {
  const callscanChain = item.callscan_chain as Record<string, unknown> | undefined;
  const sink = (item.sink || callscanChain?.sink) as Record<string, unknown> | undefined;
  return text(item.vulnerability_type || item.vuln_type || item.type || sink?.vulnerability_type || sink?.vulnerability || item.cwe_guess);
}

function sortedFacetEntries(values: Record<string, number>): [string, number][] {
  return Object.entries(values)
    .filter(([name]) => Boolean(name) && name !== "unknown")
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function sortedRiskEntries(values: Record<string, number>): [string, number][] {
  const order = new Map(["critical", "high", "medium", "low", "info", "unknown"].map((name, index) => [name, index]));
  return Object.entries(values)
    .filter(([name]) => Boolean(name))
    .sort((a, b) => (order.get(a[0]) ?? 99) - (order.get(b[0]) ?? 99) || b[1] - a[1]);
}

function vulnerabilityLabel(value: string): string {
  const key = String(value || "unknown").toLowerCase().replace(/[\s-]+/g, "_");
  return ({
    sql_injection: "SQL 注入",
    sql: "SQL 注入",
    sqli: "SQL 注入",
    command_execution: "命令执行",
    command_injection: "命令注入",
    os_command_injection: "系统命令注入",
    shell_injection: "Shell 注入",
    code_execution: "代码执行",
    remote_code_execution: "远程代码执行",
    rce: "远程代码执行",
    eval_injection: "Eval 注入",
    xss: "跨站脚本",
    reflected_xss: "反射型 XSS",
    stored_xss: "存储型 XSS",
    dom_xss: "DOM 型 XSS",
    dom_sink: "DOM 风险点",
    ssrf: "服务端请求伪造",
    xxe: "XML 外部实体",
    path_traversal: "路径穿越",
    directory_traversal: "目录穿越",
    file_inclusion: "文件包含",
    local_file_inclusion: "本地文件包含",
    remote_file_inclusion: "远程文件包含",
    lfi: "本地文件包含",
    rfi: "远程文件包含",
    file_upload: "文件上传",
    file_read_write: "文件读写",
    arbitrary_file_read: "任意文件读取",
    arbitrary_file_write: "任意文件写入",
    deserialization: "反序列化",
    unsafe_deserialization: "不安全反序列化",
    csrf_risk: "CSRF 风险",
    csrf: "跨站请求伪造",
    auth_bypass: "认证绕过",
    authorization_bypass: "授权绕过",
    unauthorized_access: "未授权访问",
    access_control: "访问控制",
    idor: "越权访问",
    weak_credential: "弱凭据",
    info_disclosure: "信息泄露",
    information_disclosure: "信息泄露",
    sensitive_data_exposure: "敏感信息泄露",
    crlf_injection: "CRLF 注入",
    ssti: "模板注入",
    template_injection: "模板注入",
    nosql_injection: "NoSQL 注入",
    ldap_injection: "LDAP 注入",
    graphql_injection: "GraphQL 注入",
    xpath_injection: "XPath 注入",
    buffer_overflow: "缓冲区溢出",
    memory_corruption: "内存破坏",
    integer_overflow: "整数溢出",
    open_redirect: "开放重定向",
    insecure_redirect: "不安全重定向",
    crypto_weakness: "密码学弱点",
    weak_crypto: "弱密码学",
    hardcoded_secret: "硬编码密钥",
    insecure_randomness: "不安全随机数",
    log_injection: "日志注入",
    header_injection: "Header 注入",
    request_forgery: "请求伪造",
    injection: "注入类风险",
    sink_hit: "危险函数命中",
    sink: "危险函数命中",
    unknown: "未知类型",
  } as Record<string, string>)[key] ?? value.replace(/_/g, " ");
}

function verdictLabel(value: unknown): string {
  const verdict = String(value ?? "").toLowerCase();
  if (verdict.includes("vulnerable") && !verdict.includes("not")) return "存在漏洞";
  if (verdict.includes("safe") || verdict.includes("not_vulnerable")) return "安全";
  if (verdict.includes("error")) return "审计失败";
  if (verdict.includes("uncertain") || verdict.includes("needs_review") || verdict.includes("inconclusive")) return "不确定";
  return "未知结论";
}

function severityLabel(value: unknown): string {
  const severity = String(value ?? "").toLowerCase();
  return ({
    critical: "严重",
    high: "高",
    medium: "中",
    low: "低",
    info: "信息",
    unknown: "风险未标注",
  } as Record<string, string>)[severity] ?? "风险未标注";
}

function verdictClass(value: unknown) {
  const verdict = String(value ?? "").toLowerCase();
  if (verdict.includes("error")) return "danger";
  if (verdict.includes("vulnerable") && !verdict.includes("not")) return "danger";
  if (verdict.includes("safe") || verdict.includes("not_vulnerable")) return "ok";
  return "warn";
}

function candidateSourceLabel(value: unknown): string {
  const source = String(value ?? "none");
  if (source === "all") return "全量候选池";
  if (source === "priority") return "旧优先队列";
  return "尚未生成";
}
