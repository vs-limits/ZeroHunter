import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Bug, PanelLeft, PanelLeftClose } from "lucide-react";
import {
  ProjectContainer,
  ScanItem,
  VulnerabilityItem,
  VersionItem,
  createScan,
  createVulnerability,
  deleteScan,
  deleteVulnerability,
  listProjects,
  listScans,
  listVulnerabilities,
  updateVulnerability,
} from "./api";
import { Sidebar } from "./components/Sidebar";
import { ScanView, isScanTab } from "./components/ScanView";
import { LogsView } from "./components/LogsView";
import { PromptView } from "./components/PromptView";
import { SkillsView } from "./components/SkillsView";
import { SinksView } from "./components/SinksView";
import { DashboardView } from "./components/DashboardView";
import { QueueView } from "./components/QueueView";
import { ProjectListView } from "./components/ProjectListView";
import { ProjectPanel } from "./components/ProjectPanel";
import { VersionPanel } from "./components/VersionPanel";
import { VulnerabilityView } from "./components/VulnerabilityView";
import { NewProjectPanel } from "./components/NewProjectPanel";
import { LlmSettingsView } from "./components/LlmSettingsView";
import { SettingsView } from "./components/SettingsView";
import { bilingualLang } from "./i18n";
import "./styles/layout.css";

export type Selection =
  | { kind: "dashboard" }
  | { kind: "queue" }
  | { kind: "projects" }
  | { kind: "project-new" }
  | { kind: "project"; project: ProjectContainer }
  | { kind: "version"; project: ProjectContainer; version: VersionItem }
  | {
      kind: "vulnerability";
      project: ProjectContainer;
      vulnerability: VulnerabilityItem;
    }
  | {
      kind: "scan";
      project: ProjectContainer;
      version: VersionItem;
      scan: ScanItem;
    }
  | { kind: "logs" }
  | { kind: "llm-settings" }
  | { kind: "settings" }
  | { kind: "prompt"; name: string }
  | { kind: "skill"; language: string; languageLabel: string }
  | { kind: "sink"; language: string; languageLabel: string };

interface Crumb {
  label: string;
  active?: boolean;
}

const ROUTE_KEYS = [
  "page",
  "project_path",
  "scan_id",
  "vulnerability_id",
  "name",
  "language",
  "tab",
  "audit_view",
];

function findProjectByPath(
  projects: ProjectContainer[],
  projectPath: string | null
): ProjectContainer | null {
  if (!projectPath) return null;
  return projects.find((project) => project.project_path === projectPath) ?? null;
}

function findVersionByPath(
  projects: ProjectContainer[],
  projectPath: string | null
): { project: ProjectContainer; version: VersionItem } | null {
  if (!projectPath) return null;
  for (const project of projects) {
    const version = project.versions.find((v) => v.project_path === projectPath);
    if (version) return { project, version };
  }
  return null;
}

function initialSelectionFromSearch(): Selection {
  const params = new URLSearchParams(window.location.search);
  const page = params.get("page") || "dashboard";
  if (page === "queue") return { kind: "queue" };
  if (page === "projects") return { kind: "projects" };
  if (page === "project-new") return { kind: "project-new" };
  if (page === "logs") return { kind: "logs" };
  if (page === "llm-settings") return { kind: "llm-settings" };
  if (page === "settings") return { kind: "settings" };
  if (page === "prompt") {
    const name = params.get("name");
    if (name) return { kind: "prompt", name };
  }
  if (page === "skill" || page === "sink") {
    const language = params.get("language");
    if (language) {
      const languageLabel = bilingualLang(language).zh;
      return page === "skill"
        ? { kind: "skill", language, languageLabel }
        : { kind: "sink", language, languageLabel };
    }
  }
  return { kind: "dashboard" };
}

function searchForSelection(selection: Selection, currentSearch: string): string {
  const params = new URLSearchParams(currentSearch);
  const currentTab = params.get("tab");
  const scanTab = isScanTab(currentTab) ? currentTab : "control";

  for (const key of ROUTE_KEYS) params.delete(key);
  params.set("page", selection.kind);

  switch (selection.kind) {
    case "project":
      params.set("project_path", selection.project.project_path);
      break;
    case "version":
      params.set("project_path", selection.version.project_path);
      break;
    case "scan":
      params.set("project_path", selection.version.project_path);
      params.set("scan_id", selection.scan.scan_id);
      params.set("tab", scanTab);
      if (scanTab === "audit") {
        const auditView = new URLSearchParams(currentSearch).get("audit_view");
        if (auditView === "json" || auditView === "markdown") {
          params.set("audit_view", auditView);
        }
      }
      break;
    case "vulnerability":
      params.set("project_path", selection.project.project_path);
      params.set("vulnerability_id", selection.vulnerability.vulnerability_id);
      break;
    case "prompt":
      params.set("name", selection.name);
      break;
    case "skill":
    case "sink":
      params.set("language", selection.language);
      break;
  }

  const query = params.toString();
  return query ? `?${query}` : "";
}

export default function App() {
  const [projects, setProjects] = useState<ProjectContainer[]>([]);
  const [scansByVersion, setScansByVersion] = useState<Record<string, ScanItem[]>>({});
  const [vulnerabilitiesByProject, setVulnerabilitiesByProject] = useState<
    Record<string, VulnerabilityItem[]>
  >({});
  const [loadingPath, setLoadingPath] = useState<string | null>(null);
  const [loadingVulnerabilityPath, setLoadingVulnerabilityPath] = useState<string | null>(null);
  const [selection, setSelection] = useState<Selection>(initialSelectionFromSearch);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [projectsLoaded, setProjectsLoaded] = useState(false);
  const [routeHydrated, setRouteHydrated] = useState(false);
  const applyingRouteRef = useRef(false);

  const refreshProjects = useCallback(async (opts?: { full?: boolean }) => {
    const r = await listProjects({ summary: !opts?.full });
    setProjects(r.items);
    return r.items;
  }, []);

  useEffect(() => {
    let cancelled = false;
    setProjectsLoaded(false);
    refreshProjects()
      .catch((e) => setError(String(e)))
      .finally(() => {
        if (!cancelled) setProjectsLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey, refreshProjects]);

  const refreshScans = useCallback(async (projectPath: string) => {
    try {
      const r = await listScans(projectPath);
      setScansByVersion((prev) => ({ ...prev, [projectPath]: r.items }));
      return r.items;
    } catch (e) {
      setError(String(e));
      return [];
    }
  }, []);

  const refreshVulnerabilities = useCallback(async (project: ProjectContainer) => {
    try {
      const r = await listVulnerabilities(project);
      setVulnerabilitiesByProject((prev) => ({
        ...prev,
        [project.project_path]: r.items,
      }));
      return r.items;
    } catch (e) {
      setError(String(e));
      return [];
    }
  }, []);

  async function ensureScansLoaded(version: VersionItem) {
    if (scansByVersion[version.project_path]) return;
    setLoadingPath(version.project_path);
    try {
      await refreshScans(version.project_path);
    } finally {
      setLoadingPath(null);
    }
  }

  async function ensureVulnerabilitiesLoaded(project: ProjectContainer) {
    if (vulnerabilitiesByProject[project.project_path]) return;
    setLoadingVulnerabilityPath(project.project_path);
    try {
      await refreshVulnerabilities(project);
    } finally {
      setLoadingVulnerabilityPath(null);
    }
  }

  const applyRouteFromSearch = useCallback(
    async (search: string) => {
      const params = new URLSearchParams(search);
      const page = params.get("page") || "dashboard";

      applyingRouteRef.current = true;
      try {
        if (page === "dashboard") {
          setSelection({ kind: "dashboard" });
          return;
        }
        if (page === "queue") {
          setSelection({ kind: "queue" });
          return;
        }
        if (page === "projects") {
          setSelection({ kind: "projects" });
          return;
        }
        if (page === "project-new") {
          setSelection({ kind: "project-new" });
          return;
        }
        if (page === "logs") {
          setSelection({ kind: "logs" });
          return;
        }
        if (page === "llm-settings") {
          setSelection({ kind: "llm-settings" });
          return;
        }
        if (page === "settings") {
          setSelection({ kind: "settings" });
          return;
        }
        if (page === "prompt") {
          const name = params.get("name");
          setSelection(name ? { kind: "prompt", name } : { kind: "dashboard" });
          return;
        }
        if (page === "skill" || page === "sink") {
          const language = params.get("language");
          if (!language) {
            setSelection({ kind: "dashboard" });
            return;
          }
          const languageLabel = bilingualLang(language).zh;
          setSelection(
            page === "skill"
              ? { kind: "skill", language, languageLabel }
              : { kind: "sink", language, languageLabel }
          );
          return;
        }
        if (page === "project") {
          const projectPath = params.get("project_path");
          const project = findProjectByPath(projects, projectPath);
          if (!project) {
            if (projectPath) setError(`未找到项目：${projectPath}`);
            setSelection({ kind: "dashboard" });
            return;
          }
          setSelection({ kind: "project", project });
          return;
        }
        if (page === "version") {
          const projectPath = params.get("project_path");
          const found = findVersionByPath(projects, projectPath);
          if (!found) {
            if (projectPath) setError(`未找到版本：${projectPath}`);
            setSelection({ kind: "dashboard" });
            return;
          }
          setSelection({ kind: "version", project: found.project, version: found.version });
          return;
        }
        if (page === "scan") {
          const projectPath = params.get("project_path");
          const scanId = params.get("scan_id");
          const found = findVersionByPath(projects, projectPath);
          if (!found || !projectPath || !scanId) {
            if (projectPath) setError(`未找到扫描所属版本：${projectPath}`);
            setSelection({ kind: "dashboard" });
            return;
          }
          if (
            selection.kind === "scan" &&
            selection.version.project_path === projectPath &&
            selection.scan.scan_id === scanId
          ) {
            return;
          }

          let scans = scansByVersion[projectPath];
          if (!scans) scans = await refreshScans(projectPath);
          let scan = scans.find((item) => item.scan_id === scanId);
          if (!scan && scansByVersion[projectPath]) {
            scans = await refreshScans(projectPath);
            scan = scans.find((item) => item.scan_id === scanId);
          }
          if (!scan) {
            setError(`未找到扫描：${scanId}`);
            setSelection({ kind: "version", project: found.project, version: found.version });
            return;
          }
          setSelection({
            kind: "scan",
            project: found.project,
            version: found.version,
            scan,
          });
          return;
        }
        if (page === "vulnerability") {
          const projectPath = params.get("project_path");
          const vulnerabilityId = params.get("vulnerability_id");
          const project = findProjectByPath(projects, projectPath);
          if (!project || !vulnerabilityId) {
            if (projectPath) setError(`未找到漏洞所属项目：${projectPath}`);
            setSelection({ kind: "dashboard" });
            return;
          }
          if (
            selection.kind === "vulnerability" &&
            selection.project.project_path === project.project_path &&
            selection.vulnerability.vulnerability_id === vulnerabilityId
          ) {
            return;
          }
          let vulnerabilities = vulnerabilitiesByProject[project.project_path];
          if (!vulnerabilities) vulnerabilities = await refreshVulnerabilities(project);
          let vulnerability = vulnerabilities.find(
            (item) => item.vulnerability_id === vulnerabilityId
          );
          if (!vulnerability && vulnerabilitiesByProject[project.project_path]) {
            vulnerabilities = await refreshVulnerabilities(project);
            vulnerability = vulnerabilities.find(
              (item) => item.vulnerability_id === vulnerabilityId
            );
          }
          if (!vulnerability) {
            setError(`未找到漏洞：${vulnerabilityId}`);
            setSelection({ kind: "project", project });
            return;
          }
          setSelection({ kind: "vulnerability", project, vulnerability });
          return;
        }
        setSelection({ kind: "dashboard" });
      } finally {
        applyingRouteRef.current = false;
      }
    },
    [
      projects,
      refreshScans,
      refreshVulnerabilities,
      scansByVersion,
      selection,
      vulnerabilitiesByProject,
    ]
  );

  useEffect(() => {
    if (!projectsLoaded || routeHydrated) return;
    applyRouteFromSearch(window.location.search).finally(() => setRouteHydrated(true));
  }, [applyRouteFromSearch, projectsLoaded, routeHydrated]);

  useEffect(() => {
    if (!routeHydrated) return;
    function onPopState() {
      void applyRouteFromSearch(window.location.search);
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [applyRouteFromSearch, routeHydrated]);

  useEffect(() => {
    if (!routeHydrated || applyingRouteRef.current) return;
    const nextSearch = searchForSelection(selection, window.location.search);
    if (nextSearch === window.location.search) return;
    const nextUrl = `${window.location.pathname}${nextSearch}${window.location.hash}`;
    window.history.pushState(null, "", nextUrl);
  }, [routeHydrated, selection]);

  useEffect(() => {
    const project =
      selection.kind === "project" ||
      selection.kind === "version" ||
      selection.kind === "scan" ||
      selection.kind === "vulnerability"
        ? selection.project
        : null;
    if (project && !vulnerabilitiesByProject[project.project_path]) {
      void ensureVulnerabilitiesLoaded(project);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selection, vulnerabilitiesByProject]);

  function selectScan(project: ProjectContainer, version: VersionItem, scan: ScanItem) {
    setSelection({ kind: "scan", project, version, scan });
  }

  async function newScan(project: ProjectContainer, version: VersionItem) {
    try {
      const created = await createScan({
        project_path: version.project_path,
        name: "",
        target_mode: "all",
        target_rel_dir: null,
        agents: ["treescan", "callscan", "auditor"],
      });
      const updated = await refreshScans(version.project_path);
      await refreshProjects({ full: true });
      const scan = updated.find((s) => s.scan_id === created.scan_id) ?? created;
      setSelection({ kind: "scan", project, version, scan });
    } catch (e) {
      setError(String(e));
    }
  }

  async function deleteSidebarScan(
    project: ProjectContainer,
    version: VersionItem,
    scan: ScanItem
  ) {
    if (!window.confirm(`确定删除扫描「${scan.name}」？此操作会清除所有产物文件。`)) {
      return;
    }
    try {
      const result = await deleteScan(version.project_path, scan.scan_id);
      if (!result.ok) throw new Error("删除扫描失败");
      await refreshScans(version.project_path);
      await refreshProjects({ full: true });
      setSelection((current) => {
        if (
          current.kind === "scan" &&
          current.version.project_path === version.project_path &&
          current.scan.scan_id === scan.scan_id
        ) {
          return { kind: "version", project, version };
        }
        return current;
      });
    } catch (e) {
      setError(String(e));
    }
  }

  async function newVulnerability(project: ProjectContainer) {
    try {
      const created = await createVulnerability(project, { name: "未命名漏洞" } as any);
      await refreshVulnerabilities(project);
      setSelection({ kind: "vulnerability", project, vulnerability: created });
    } catch (e) {
      setError(String(e));
    }
  }

  async function renameSidebarVulnerability(
    project: ProjectContainer,
    vulnerability: VulnerabilityItem,
    name: string
  ) {
    try {
      const updated = await updateVulnerability(project, vulnerability.vulnerability_id, {
        name,
      } as any);
      await refreshVulnerabilities(project);
      setSelection((current) => {
        if (
          current.kind === "vulnerability" &&
          current.project.project_path === project.project_path &&
          current.vulnerability.vulnerability_id === vulnerability.vulnerability_id
        ) {
          return { kind: "vulnerability", project, vulnerability: updated };
        }
        return current;
      });
    } catch (e) {
      setError(String(e));
    }
  }

  async function deleteSidebarVulnerability(
    project: ProjectContainer,
    vulnerability: VulnerabilityItem
  ) {
    if (!window.confirm(`确定删除漏洞「${vulnerability.name}」？此操作会删除该漏洞目录。`)) {
      return;
    }
    try {
      const result = await deleteVulnerability(project, vulnerability.vulnerability_id);
      if (!result.ok) throw new Error("删除漏洞失败");
      await refreshVulnerabilities(project);
      setSelection((current) => {
        if (
          current.kind === "vulnerability" &&
          current.project.project_path === project.project_path &&
          current.vulnerability.vulnerability_id === vulnerability.vulnerability_id
        ) {
          return { kind: "project", project };
        }
        return current;
      });
    } catch (e) {
      setError(String(e));
    }
  }

  const crumbs: Crumb[] = useMemo(() => {
    switch (selection.kind) {
      case "queue":
        return [{ label: "首页" }, { label: "任务队列", active: true }];
      case "projects":
        return [{ label: "项目" }, { label: "项目列表", active: true }];
      case "project-new":
        return [{ label: "项目" }, { label: "新建项目", active: true }];
      case "project":
        return [{ label: "项目" }, { label: selection.project.project_path, active: true }];
      case "version":
        return [
          { label: "项目" },
          { label: selection.project.project_path },
          { label: selection.version.version, active: true },
        ];
      case "scan":
        return [
          { label: "项目" },
          { label: selection.project.project_path },
          { label: selection.version.version },
          { label: selection.scan.name, active: true },
        ];
      case "vulnerability":
        return [
          { label: "项目" },
          { label: selection.project.project_path },
          { label: "漏洞项" },
          { label: selection.vulnerability.name, active: true },
        ];
      case "logs":
        return [{ label: "系统" }, { label: "对话日志", active: true }];
      case "llm-settings":
        return [{ label: "系统" }, { label: "LLM 设置", active: true }];
      case "settings":
        return [{ label: "系统" }, { label: "通用设置", active: true }];
      case "prompt":
        return [{ label: "提示词" }, { label: "Agent 提示词" }, { label: selection.name, active: true }];
      case "skill":
        return [{ label: "提示词" }, { label: "技能集" }, { label: selection.languageLabel, active: true }];
      case "sink":
        return [{ label: "提示词" }, { label: "汇聚点规则" }, { label: selection.languageLabel, active: true }];
      default:
        return [{ label: "首页" }, { label: "仪表盘", active: true }];
    }
  }, [selection]);

  function findVersion(projectPath: string): { project: ProjectContainer; version: VersionItem } | null {
    for (const project of projects) {
      const version = project.versions.find((v) => v.project_path === projectPath);
      if (version) return { project, version };
    }
    return null;
  }

  return (
    <div className="dm-shell">
      <header className="dm-topbar">
        <div className={`dm-topbar-logo ${collapsed ? "collapsed" : ""}`}>
          <button
            className="dm-brand-btn"
            onClick={() => setSelection({ kind: "dashboard" })}
            title="返回仪表盘"
          >
            <span className="dm-brand-mark">
              <Bug size={16} strokeWidth={2.25} aria-hidden />
            </span>
            {!collapsed && (
              <div className="dm-brand">
                <div>
                  <div className="dm-brand-text">DefectMine</div>
                  <div className="dm-brand-sub">控制台</div>
                </div>
              </div>
            )}
          </button>
        </div>
        <button
          className="dm-collapse-btn"
          onClick={() => setCollapsed((v) => !v)}
          title={collapsed ? "展开侧栏" : "折叠侧栏"}
        >
          {collapsed ? (
            <PanelLeft size={18} strokeWidth={2} aria-hidden />
          ) : (
            <PanelLeftClose size={18} strokeWidth={2} aria-hidden />
          )}
        </button>
        <nav className="dm-breadcrumb">
          {crumbs.map((c, i) => (
            <span key={i} style={{ display: "inline-flex", alignItems: "center" }}>
              {i > 0 && <span className="dm-breadcrumb-sep">/</span>}
              <span className={`dm-breadcrumb-item ${c.active ? "active" : ""}`}>
                {c.label}
              </span>
            </span>
          ))}
        </nav>
        <button
          className="dm-btn dm-btn-ghost"
          onClick={() => setSelection({ kind: "dashboard" })}
        >
          仪表盘
        </button>
        <button
          className="dm-btn dm-btn-ghost"
          onClick={() => {
            void refreshProjects({ full: true }).then(() => setRefreshKey((k) => k + 1));
          }}
          title="刷新项目列表（含扫描摘要）"
        >
          刷新
        </button>
      </header>

      <div className="dm-body">
        <Sidebar
          collapsed={collapsed}
          scansByVersion={scansByVersion}
          vulnerabilitiesByProject={vulnerabilitiesByProject}
          loadingPath={loadingPath}
          loadingVulnerabilityPath={loadingVulnerabilityPath}
          selection={selection}
          onSelectProject={(project) => setSelection({ kind: "project", project })}
          onSelectVersion={(project, version) => setSelection({ kind: "version", project, version })}
          onSelectScan={selectScan}
          onSelectVulnerability={(project, vulnerability) =>
            setSelection({ kind: "vulnerability", project, vulnerability })
          }
          onExpandVersion={ensureScansLoaded}
          onNewScan={newScan}
          onDeleteScan={deleteSidebarScan}
          onNewVulnerability={newVulnerability}
          onRenameVulnerability={renameSidebarVulnerability}
          onDeleteVulnerability={deleteSidebarVulnerability}
          onSelectLogs={() => setSelection({ kind: "logs" })}
          onSelectLlmSettings={() => setSelection({ kind: "llm-settings" })}
          onSelectSettings={() => setSelection({ kind: "settings" })}
          onSelectPrompt={(name) => setSelection({ kind: "prompt", name })}
          onSelectSkill={(language, languageLabel) =>
            setSelection({ kind: "skill", language, languageLabel })
          }
          onSelectSink={(language, languageLabel) =>
            setSelection({ kind: "sink", language, languageLabel })
          }
          onSelectDashboard={() => setSelection({ kind: "dashboard" })}
          onSelectQueue={() => setSelection({ kind: "queue" })}
          onSelectProjects={() => setSelection({ kind: "projects" })}
          onRefreshScans={refreshScans}
          onRefreshVulnerabilities={(project) => {
            void refreshVulnerabilities(project);
          }}
        />

        <main className="dm-main">
          {error && (
            <div className="dm-banner-error" onClick={() => setError(null)}>
              {error} <span className="dm-banner-hint">（点击关闭）</span>
            </div>
          )}
          {selection.kind === "dashboard" && <DashboardView />}
          {selection.kind === "queue" && (
            <QueueView
              onSelectScan={(scan) => {
                const found = findVersion(scan.project_path);
                if (found) {
                  setSelection({ kind: "scan", project: found.project, version: found.version, scan });
                }
              }}
            />
          )}
          {selection.kind === "projects" && (
            <ProjectListView
              projects={projects}
              onSelectProject={(project) => setSelection({ kind: "project", project })}
              onNewProject={() => setSelection({ kind: "project-new" })}
              onRefresh={() => {
                void refreshProjects({ full: true }).then(() => setRefreshKey((k) => k + 1));
              }}
            />
          )}
          {selection.kind === "project-new" && (
            <NewProjectPanel
              onCreated={async (project) => {
                await refreshProjects();
                setSelection({ kind: "project", project });
              }}
            />
          )}
          {selection.kind === "project" && (
            <ProjectPanel
              project={selection.project}
              onProjectChanged={async (project) => {
                await refreshProjects();
                setSelection({ kind: "project", project });
              }}
              onVersionCreated={async (version) => {
                const all = await refreshProjects();
                const project =
                  all.find((p) => p.project_path === selection.project.project_path) ??
                  selection.project;
                const freshVersion =
                  project.versions.find((v) => v.project_path === version.project_path) ?? version;
                setSelection({ kind: "version", project, version: freshVersion });
              }}
              onSelectVulnerability={(vulnerability) =>
                setSelection({
                  kind: "vulnerability",
                  project: selection.project,
                  vulnerability,
                })
              }
              onVulnerabilitiesChanged={async () => {
                await refreshVulnerabilities(selection.project);
              }}
            />
          )}
          {selection.kind === "version" && (
            <VersionPanel
              project={selection.project}
              version={selection.version}
              onVersionChanged={async (version) => {
                const all = await refreshProjects();
                const project =
                  all.find((p) => p.project_path === selection.project.project_path) ??
                  selection.project;
                setSelection({ kind: "version", project, version });
              }}
              onVersionDeleted={async () => {
                await refreshProjects();
                setSelection({ kind: "project", project: selection.project });
              }}
              onNewScan={async () => newScan(selection.project, selection.version)}
              onSelectVulnerability={(vulnerability) =>
                setSelection({
                  kind: "vulnerability",
                  project: selection.project,
                  vulnerability,
                })
              }
              onVulnerabilitiesChanged={async () => {
                await refreshVulnerabilities(selection.project);
              }}
            />
          )}
          {selection.kind === "scan" && (
            <ScanView
              key={`${selection.version.project_path}::${selection.scan.scan_id}`}
              project={selection.version}
              projectContainer={selection.project}
              scan={selection.scan}
              onScanChanged={async (next, opts) => {
                if (next) {
                  const projectPath = selection.version.project_path;
                  setScansByVersion((prev) => {
                    const list = prev[projectPath];
                    if (!list) return prev;
                    const idx = list.findIndex((s) => s.scan_id === next.scan_id);
                    if (idx < 0) return prev;
                    const updated = [...list];
                    updated[idx] = next;
                    return { ...prev, [projectPath]: updated };
                  });
                  setSelection({
                    kind: "scan",
                    project: selection.project,
                    version: selection.version,
                    scan: next,
                  });
                }
                if (opts?.syncLists) {
                  await refreshScans(selection.version.project_path);
                  await refreshProjects({ full: true });
                }
              }}
              onScanDeleted={async () => {
                await refreshScans(selection.version.project_path);
                await refreshProjects({ full: true });
                setSelection({ kind: "version", project: selection.project, version: selection.version });
              }}
              onVulnerabilityCreated={async (vulnerability) => {
                await refreshVulnerabilities(selection.project);
                setSelection({
                  kind: "vulnerability",
                  project: selection.project,
                  vulnerability,
                });
              }}
              onSelectVulnerability={(vulnerability) =>
                setSelection({
                  kind: "vulnerability",
                  project: selection.project,
                  vulnerability,
                })
              }
              onVulnerabilitiesChanged={async () => {
                await refreshVulnerabilities(selection.project);
              }}
              onProjectChanged={async () => {
                const all = await refreshProjects({ full: true });
                const project =
                  all.find((p) => p.project_path === selection.project.project_path) ??
                  selection.project;
                setSelection((current) =>
                  current.kind === "scan" &&
                  current.project.project_path === selection.project.project_path &&
                  current.scan.scan_id === selection.scan.scan_id
                    ? { ...current, project }
                    : current
                );
              }}
            />
          )}
          {selection.kind === "vulnerability" && (
            <VulnerabilityView
              project={selection.project}
              vulnerability={selection.vulnerability}
              onVulnerabilityChanged={async (next) => {
                await refreshVulnerabilities(selection.project);
                setSelection({
                  kind: "vulnerability",
                  project: selection.project,
                  vulnerability: next,
                });
              }}
              onSelectVersion={(projectPath) => {
                const found = findVersion(projectPath);
                if (found) {
                  setSelection({
                    kind: "version",
                    project: found.project,
                    version: found.version,
                  });
                }
              }}
              onSelectScan={async (projectPath, scanId) => {
                const found = findVersion(projectPath);
                if (!found) return;
                const scans =
                  scansByVersion[projectPath] ?? (await refreshScans(projectPath));
                const scan = scans.find((item) => item.scan_id === scanId);
                if (scan) {
                  setSelection({
                    kind: "scan",
                    project: found.project,
                    version: found.version,
                    scan,
                  });
                }
              }}
            />
          )}
          {selection.kind === "logs" && <LogsView />}
          {selection.kind === "llm-settings" && <LlmSettingsView />}
          {selection.kind === "settings" && <SettingsView />}
          {selection.kind === "prompt" && <PromptView key={selection.name} name={selection.name} />}
          {selection.kind === "skill" && (
            <SkillsView
              key={selection.language}
              language={selection.language}
              languageLabel={selection.languageLabel}
            />
          )}
          {selection.kind === "sink" && (
            <SinksView
              key={selection.language}
              language={selection.language}
              languageLabel={selection.languageLabel}
            />
          )}
        </main>
      </div>
    </div>
  );
}
