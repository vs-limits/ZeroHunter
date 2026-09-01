import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Crosshair,
  FileText,
  FolderKanban,
  Folders,
  GraduationCap,
  LayoutDashboard,
  ListTodo,
  ScrollText,
  Settings,
  ShieldAlert,
} from "lucide-react";
import { ReactNode, useEffect, useState, type MouseEvent } from "react";
import {
  ProjectContainer,
  PromptFile,
  ScanItem,
  SkillGroup,
  SinkGroup,
  VulnerabilityItem,
  VersionItem,
  listPrompts,
  listSkills,
  listSinks,
} from "../api";
import { bilingualLang, bilingualPrompt } from "../i18n";
import type { Selection } from "../App";
import { NavIcon } from "./ui/NavIcon";
import "../styles/sidebar.css";

interface Props {
  collapsed?: boolean;
  scansByVersion: Record<string, ScanItem[]>;
  vulnerabilitiesByProject: Record<string, VulnerabilityItem[]>;
  loadingPath: string | null;
  loadingVulnerabilityPath: string | null;
  selection: Selection;
  onSelectProject: (project: ProjectContainer) => void;
  onSelectVersion: (project: ProjectContainer, version: VersionItem) => void;
  onSelectScan: (project: ProjectContainer, version: VersionItem, scan: ScanItem) => void;
  onSelectVulnerability: (
    project: ProjectContainer,
    vulnerability: VulnerabilityItem
  ) => void;
  onExpandVersion: (version: VersionItem) => void;
  onNewScan: (project: ProjectContainer, version: VersionItem) => void;
  onDeleteScan: (
    project: ProjectContainer,
    version: VersionItem,
    scan: ScanItem
  ) => void | Promise<void>;
  onNewVulnerability: (project: ProjectContainer) => void | Promise<void>;
  onRenameVulnerability: (
    project: ProjectContainer,
    vulnerability: VulnerabilityItem,
    name: string
  ) => void | Promise<void>;
  onDeleteVulnerability: (
    project: ProjectContainer,
    vulnerability: VulnerabilityItem
  ) => void | Promise<void>;
  onSelectLogs: () => void;
  onSelectLlmSettings: () => void;
  onSelectSettings: () => void;
  onSelectPrompt: (name: string) => void;
  onSelectSkill: (language: string, languageLabel: string) => void;
  onSelectSink: (language: string, languageLabel: string) => void;
  onSelectDashboard: () => void;
  onSelectQueue: () => void;
  onSelectProjects: () => void;
  onRefreshScans: (projectPath: string) => void;
  onRefreshVulnerabilities: (project: ProjectContainer) => void | Promise<void>;
}

type GroupKey = "overview" | "current" | "prompts" | "system";

export function Sidebar(props: Props) {
  const { collapsed, selection } = props;
  const [groupOpen, setGroupOpen] = useState<Record<GroupKey, boolean>>({
    overview: true,
    current: true,
    prompts: true,
    system: true,
  });

  function toggleGroup(k: GroupKey) {
    setGroupOpen((prev) => ({ ...prev, [k]: !prev[k] }));
  }

  const currentProject =
    selection.kind === "project" ||
    selection.kind === "version" ||
    selection.kind === "scan" ||
    selection.kind === "vulnerability"
      ? selection.project
      : null;

  return (
    <nav className={`dm-sidebar ${collapsed ? "collapsed" : ""}`}>
      <Group
        groupKey="overview"
        title="概览"
        open={groupOpen.overview}
        onToggle={toggleGroup}
        collapsed={collapsed}
      >
        <NavItem
          icon={LayoutDashboard}
          label="仪表盘"
          active={selection.kind === "dashboard"}
          onClick={props.onSelectDashboard}
        />
        <NavItem
          icon={ListTodo}
          label="任务队列"
          active={selection.kind === "queue"}
          onClick={props.onSelectQueue}
        />
        <NavItem
          icon={Folders}
          label="项目列表"
          active={selection.kind === "projects" || selection.kind === "project-new"}
          onClick={props.onSelectProjects}
        />
      </Group>

      {currentProject && (
        <Group
          groupKey="current"
          title="当前项目"
          open={groupOpen.current}
          onToggle={toggleGroup}
          collapsed={collapsed}
        >
          <SingleProjectTree
            project={currentProject}
            scansByVersion={props.scansByVersion}
            vulnerabilitiesByProject={props.vulnerabilitiesByProject}
            loadingPath={props.loadingPath}
            loadingVulnerabilityPath={props.loadingVulnerabilityPath}
            selection={selection}
            onSelectProject={props.onSelectProject}
            onSelectVersion={props.onSelectVersion}
            onSelectScan={props.onSelectScan}
            onSelectVulnerability={props.onSelectVulnerability}
            onExpandVersion={props.onExpandVersion}
            onNewScan={props.onNewScan}
            onDeleteScan={props.onDeleteScan}
            onNewVulnerability={props.onNewVulnerability}
            onRenameVulnerability={props.onRenameVulnerability}
            onDeleteVulnerability={props.onDeleteVulnerability}
            onSelectProjects={props.onSelectProjects}
            onRefreshScans={props.onRefreshScans}
            onRefreshVulnerabilities={props.onRefreshVulnerabilities}
          />
        </Group>
      )}

      <Group
        groupKey="prompts"
        title="提示词"
        open={groupOpen.prompts}
        onToggle={toggleGroup}
        collapsed={collapsed}
      >
        <PromptsBlock
          selection={selection}
          onSelectPrompt={props.onSelectPrompt}
          onSelectSkill={props.onSelectSkill}
          onSelectSink={props.onSelectSink}
        />
      </Group>

      <Group
        groupKey="system"
        title="系统"
        open={groupOpen.system}
        onToggle={toggleGroup}
        collapsed={collapsed}
      >
        <NavItem
          icon={Settings}
          label="通用设置"
          active={selection.kind === "settings"}
          onClick={props.onSelectSettings}
        />
        <NavItem
          icon={ScrollText}
          label="对话日志"
          active={selection.kind === "logs"}
          onClick={props.onSelectLogs}
        />
        <NavItem
          icon={Bot}
          label="LLM 设置"
          active={selection.kind === "llm-settings"}
          onClick={props.onSelectLlmSettings}
        />
      </Group>
    </nav>
  );
}

function Group({
  groupKey,
  title,
  open,
  onToggle,
  collapsed,
  count,
  children,
}: {
  groupKey: GroupKey;
  title: string;
  open: boolean;
  onToggle: (k: GroupKey) => void;
  collapsed?: boolean;
  count?: number;
  children: ReactNode;
}) {
  if (collapsed) {
    return <div className="dm-side-group collapsed">{children}</div>;
  }
  return (
    <div className={`dm-side-group ${open ? "open" : "closed"}`}>
      <button className="dm-group-header" onClick={() => onToggle(groupKey)}>
        <span className={`dm-group-caret ${open ? "open" : ""}`}>▸</span>
        <span className="dm-group-title">{title}</span>
        {count !== undefined && count > 0 && <span className="dm-group-count">{count}</span>}
      </button>
      {open && <div className="dm-group-body">{children}</div>}
    </div>
  );
}

function NavItem({
  icon,
  label,
  active,
  onClick,
  hasCaret,
  caretOpen,
  onCaretClick,
  trailing,
}: {
  icon: LucideIcon;
  label: string;
  active?: boolean;
  onClick?: () => void;
  hasCaret?: boolean;
  caretOpen?: boolean;
  onCaretClick?: () => void;
  trailing?: ReactNode;
}) {
  return (
    <div className={`dm-nav-item ${active ? "active" : ""}`}>
      {hasCaret ? (
        <button
          className={`dm-nav-caret ${caretOpen ? "open" : ""}`}
          onClick={(e) => {
            e.stopPropagation();
            onCaretClick?.();
          }}
        >
          ▸
        </button>
      ) : (
        <span className="dm-nav-caret-placeholder" />
      )}
      <button className="dm-nav-body" onClick={onClick} title={label}>
        <NavIcon icon={icon} />
        <span className="dm-nav-label">
          <span className="dm-nav-zh">{label}</span>
        </span>
        {trailing}
      </button>
    </div>
  );
}

function SingleProjectTree({
  project,
  scansByVersion,
  vulnerabilitiesByProject,
  loadingPath,
  loadingVulnerabilityPath,
  selection,
  onSelectProject,
  onSelectVersion,
  onSelectScan,
  onSelectVulnerability,
  onExpandVersion,
  onNewScan,
  onDeleteScan,
  onNewVulnerability,
  onRenameVulnerability,
  onDeleteVulnerability,
  onSelectProjects,
  onRefreshScans,
  onRefreshVulnerabilities,
}: {
  project: ProjectContainer;
  scansByVersion: Record<string, ScanItem[]>;
  vulnerabilitiesByProject: Record<string, VulnerabilityItem[]>;
  loadingPath: string | null;
  loadingVulnerabilityPath: string | null;
  selection: Selection;
  onSelectProject: (project: ProjectContainer) => void;
  onSelectVersion: (project: ProjectContainer, version: VersionItem) => void;
  onSelectScan: (project: ProjectContainer, version: VersionItem, scan: ScanItem) => void;
  onSelectVulnerability: (
    project: ProjectContainer,
    vulnerability: VulnerabilityItem
  ) => void;
  onExpandVersion: (version: VersionItem) => void;
  onNewScan: (project: ProjectContainer, version: VersionItem) => void;
  onDeleteScan: (
    project: ProjectContainer,
    version: VersionItem,
    scan: ScanItem
  ) => void | Promise<void>;
  onNewVulnerability: (project: ProjectContainer) => void | Promise<void>;
  onRenameVulnerability: (
    project: ProjectContainer,
    vulnerability: VulnerabilityItem,
    name: string
  ) => void | Promise<void>;
  onDeleteVulnerability: (
    project: ProjectContainer,
    vulnerability: VulnerabilityItem
  ) => void | Promise<void>;
  onSelectProjects: () => void;
  onRefreshScans: (projectPath: string) => void;
  onRefreshVulnerabilities: (project: ProjectContainer) => void | Promise<void>;
}) {
  const [openVersions, setOpenVersions] = useState<Set<string>>(new Set());
  const [scanMenu, setScanMenu] = useState<{
    x: number;
    y: number;
    project: ProjectContainer;
    version: VersionItem;
    scan: ScanItem;
  } | null>(null);
  const [vulnerabilityMenu, setVulnerabilityMenu] = useState<{
    x: number;
    y: number;
    project: ProjectContainer;
    vulnerability: VulnerabilityItem;
  } | null>(null);

  useEffect(() => {
    if (selection.kind === "version" || selection.kind === "scan") {
      setOpenVersions((prev) => new Set(prev).add(selection.version.project_path));
    }
  }, [selection]);

  useEffect(() => {
    if (!scanMenu && !vulnerabilityMenu) return;
    function closeMenu() {
      setScanMenu(null);
      setVulnerabilityMenu(null);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") closeMenu();
    }
    window.addEventListener("click", closeMenu);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", closeMenu);
    window.addEventListener("scroll", closeMenu, true);
    return () => {
      window.removeEventListener("click", closeMenu);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", closeMenu);
      window.removeEventListener("scroll", closeMenu, true);
    };
  }, [scanMenu, vulnerabilityMenu]);

  function toggleVersion(version: VersionItem) {
    const next = new Set(openVersions);
    if (next.has(version.project_path)) {
      next.delete(version.project_path);
    } else {
      next.add(version.project_path);
      onExpandVersion(version);
    }
    setOpenVersions(next);
  }

  function openScanMenu(
    e: MouseEvent,
    project: ProjectContainer,
    version: VersionItem,
    scan: ScanItem
  ) {
    e.preventDefault();
    setScanMenu({
      x: Math.max(8, Math.min(e.clientX, window.innerWidth - 148)),
      y: Math.max(8, Math.min(e.clientY, window.innerHeight - 44)),
      project,
      version,
      scan,
    });
  }

  function openVulnerabilityMenu(
    e: MouseEvent,
    project: ProjectContainer,
    vulnerability: VulnerabilityItem
  ) {
    e.preventDefault();
    setVulnerabilityMenu({
      x: Math.max(8, Math.min(e.clientX, window.innerWidth - 156)),
      y: Math.max(8, Math.min(e.clientY, window.innerHeight - 80)),
      project,
      vulnerability,
    });
  }

  const projectActive = selection.kind === "project";
  const vulnerabilities = vulnerabilitiesByProject[project.project_path] || [];
  const vulnerabilityLoading = loadingVulnerabilityPath === project.project_path;

  return (
    <>
      <button type="button" className="dm-side-back" onClick={onSelectProjects}>
        <span className="dm-side-back-arrow">≪</span>
        <span>返回项目列表</span>
      </button>
      <ul className="dm-side-list">
        <li>
          <NavItem
            icon={FolderKanban}
            label={project.name || project.repo}
            active={projectActive}
            onClick={() => onSelectProject(project)}
            trailing={<span className="dm-tag-count">{project.version_count}</span>}
          />
          <div className="dm-project-zones">
            <div className="dm-project-zone dm-project-zone-versions">
              <div className="dm-project-zone-head">
                <span>版本 / 扫描项</span>
                <span className="dm-tag-count">{project.versions.length}</span>
              </div>
              <div className="dm-subtree">
                {project.versions.length === 0 && (
                  <div className="dm-subtree-tip">还没有版本</div>
                )}
                {project.versions.map((version) => {
                  const versionOpen = openVersions.has(version.project_path);
                  const scans = scansByVersion[version.project_path] || [];
                  const active =
                    (selection.kind === "version" &&
                      selection.version.project_path === version.project_path) ||
                    (selection.kind === "scan" &&
                      selection.version.project_path === version.project_path);
                  return (
                    <div key={version.project_path}>
                      <button
                        className={`dm-subtree-item dm-version-item ${active ? "active" : ""}`}
                        onClick={() => {
                          onSelectVersion(project, version);
                          if (!versionOpen) toggleVersion(version);
                        }}
                        title={version.project_path}
                      >
                        <span
                          className={`dm-subtree-caret ${versionOpen ? "open" : ""}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleVersion(version);
                          }}
                        >
                          ▸
                        </span>
                        <span className="dm-subtree-label">{version.version}</span>
                      </button>
                      {versionOpen && (
                        <div className="dm-subtree dm-version-scans">
                          <button
                            className="dm-subtree-action"
                            onClick={() => onNewScan(project, version)}
                          >
                            <span className="dm-subtree-bullet">+</span>
                            <span>新建扫描</span>
                          </button>
                          {loadingPath === version.project_path && scans.length === 0 && (
                            <div className="dm-subtree-tip">加载中...</div>
                          )}
                          {scans.length === 0 && loadingPath !== version.project_path && (
                            <div className="dm-subtree-tip">还没有扫描</div>
                          )}
                          {scans.map((scan) => {
                            const scanActive =
                              selection.kind === "scan" &&
                              selection.scan.scan_id === scan.scan_id &&
                              selection.version.project_path === version.project_path;
                            return (
                              <button
                                key={scan.scan_id}
                                className={`dm-subtree-item ${scanActive ? "active" : ""}`}
                                onClick={() => onSelectScan(project, version, scan)}
                                onContextMenu={(e) => openScanMenu(e, project, version, scan)}
                                title={`scan_id=${scan.scan_id}\nstatus=${scan.status}`}
                              >
                                <ScanStatusDot status={scan.status} legacy={scan.legacy} />
                                <span className="dm-subtree-label">{scan.name}</span>
                                {scan.target.mode === "directory" && (
                                  <span className="dm-subtree-target" title={scan.target.rel_dir ?? ""}>
                                    {scan.target.rel_dir}
                                  </span>
                                )}
                              </button>
                            );
                          })}
                          {scans.length > 0 && (
                            <button
                              className="dm-subtree-refresh"
                              onClick={() => onRefreshScans(version.project_path)}
                            >
                              刷新
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="dm-project-zone dm-project-zone-vulnerabilities">
              <div className="dm-project-zone-head">
                <span>漏洞项</span>
                <span className="dm-tag-count">{vulnerabilities.length}</span>
              </div>
              <div className="dm-subtree">
                <button
                  className="dm-subtree-action"
                  onClick={() => onNewVulnerability(project)}
                >
                  <span className="dm-subtree-bullet">+</span>
                  <span>新建漏洞</span>
                </button>
                {vulnerabilityLoading && vulnerabilities.length === 0 && (
                  <div className="dm-subtree-tip">加载中...</div>
                )}
                {!vulnerabilityLoading && vulnerabilities.length === 0 && (
                  <div className="dm-subtree-tip">还没有漏洞</div>
                )}
                {vulnerabilities.map((vulnerability) => {
                  const active =
                    selection.kind === "vulnerability" &&
                    selection.vulnerability.vulnerability_id ===
                      vulnerability.vulnerability_id;
                  return (
                    <button
                      key={vulnerability.vulnerability_id}
                      className={`dm-subtree-item dm-vuln-item ${active ? "active" : ""}`}
                      onClick={() => onSelectVulnerability(project, vulnerability)}
                      onContextMenu={(e) => openVulnerabilityMenu(e, project, vulnerability)}
                      title={vulnerability.vulnerability_id}
                    >
                      <ShieldAlert size={13} strokeWidth={2} aria-hidden />
                      <span className="dm-subtree-label">{vulnerability.name}</span>
                      <span className={`dm-vuln-sev-dot sev-${vulnerability.severity}`} />
                    </button>
                  );
                })}
                {vulnerabilities.length > 0 && (
                  <button
                    className="dm-subtree-refresh"
                    onClick={() => onRefreshVulnerabilities(project)}
                  >
                    刷新
                  </button>
                )}
              </div>
            </div>
          </div>
        </li>
      </ul>
      {scanMenu && (
        <div
          className="dm-scan-context-menu"
          role="menu"
          style={{ left: scanMenu.x, top: scanMenu.y }}
          onClick={(e) => e.stopPropagation()}
          onContextMenu={(e) => e.preventDefault()}
        >
          <button
            type="button"
            className="dm-scan-context-danger"
            role="menuitem"
            onClick={() => {
              const { project, version, scan } = scanMenu;
              setScanMenu(null);
              void onDeleteScan(project, version, scan);
            }}
          >
            删除扫描项
          </button>
        </div>
      )}
      {vulnerabilityMenu && (
        <div
          className="dm-scan-context-menu"
          role="menu"
          style={{ left: vulnerabilityMenu.x, top: vulnerabilityMenu.y }}
          onClick={(e) => e.stopPropagation()}
          onContextMenu={(e) => e.preventDefault()}
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              const { project, vulnerability } = vulnerabilityMenu;
              setVulnerabilityMenu(null);
              const next = window.prompt("漏洞名称", vulnerability.name);
              if (next && next.trim() && next.trim() !== vulnerability.name) {
                void onRenameVulnerability(project, vulnerability, next.trim());
              }
            }}
          >
            重命名漏洞
          </button>
          <button
            type="button"
            className="dm-scan-context-danger"
            role="menuitem"
            onClick={() => {
              const { project, vulnerability } = vulnerabilityMenu;
              setVulnerabilityMenu(null);
              void onDeleteVulnerability(project, vulnerability);
            }}
          >
            删除漏洞
          </button>
        </div>
      )}
    </>
  );
}

function ScanStatusDot({ status, legacy }: { status: string; legacy?: boolean }) {
  if (legacy) return <span className="dm-scan-dot dm-scan-dot-legacy" title="历史记录" />;
  return <span className={`dm-scan-dot dm-scan-dot-${status}`} title={status} />;
}

function PromptsBlock({
  selection,
  onSelectPrompt,
  onSelectSkill,
  onSelectSink,
}: {
  selection: Selection;
  onSelectPrompt: (name: string) => void;
  onSelectSkill: (language: string, languageLabel: string) => void;
  onSelectSink: (language: string, languageLabel: string) => void;
}) {
  const [open, setOpen] = useState({ prompts: false, skills: false, sinks: false });
  const [prompts, setPrompts] = useState<PromptFile[] | null>(null);
  const [skills, setSkills] = useState<SkillGroup[] | null>(null);
  const [sinks, setSinks] = useState<SinkGroup[] | null>(null);

  useEffect(() => {
    if (open.prompts && prompts === null) {
      listPrompts().then((r) => setPrompts(r.items)).catch(() => setPrompts([]));
    }
  }, [open.prompts, prompts]);
  useEffect(() => {
    if (open.skills && skills === null) {
      listSkills().then((r) => setSkills(r.groups)).catch(() => setSkills([]));
    }
  }, [open.skills, skills]);
  useEffect(() => {
    if (open.sinks && sinks === null) {
      listSinks().then((r) => setSinks(r.groups)).catch(() => setSinks([]));
    }
  }, [open.sinks, sinks]);

  function toggle(k: keyof typeof open) {
    setOpen((prev) => ({ ...prev, [k]: !prev[k] }));
  }

  return (
    <ul className="dm-side-list">
      <li>
        <NavItem
          icon={FileText}
          label="Agent 提示词"
          hasCaret
          caretOpen={open.prompts}
          onCaretClick={() => toggle("prompts")}
          onClick={() => toggle("prompts")}
        />
        {open.prompts && (
          <div className="dm-subtree">
            {prompts === null && <div className="dm-subtree-tip">加载中...</div>}
            {prompts && prompts.length === 0 && <div className="dm-subtree-tip">暂无文件</div>}
            {prompts?.map((p) => {
              const bi = bilingualPrompt(p.name);
              const active = selection.kind === "prompt" && selection.name === p.name;
              return (
                <button
                  key={p.name}
                  className={`dm-subtree-item ${active ? "active" : ""}`}
                  onClick={() => onSelectPrompt(p.name)}
                >
                  <span className="dm-subtree-bullet">-</span>
                  <span className="dm-subtree-label">{bi.zh}</span>
                </button>
              );
            })}
          </div>
        )}
      </li>
      <li>
        <NavItem
          icon={GraduationCap}
          label="技能集"
          hasCaret
          caretOpen={open.skills}
          onCaretClick={() => toggle("skills")}
          onClick={() => toggle("skills")}
        />
        {open.skills && (
          <div className="dm-subtree">
            {skills === null && <div className="dm-subtree-tip">加载中...</div>}
            {skills?.map((g) => {
              const bi = bilingualLang(g.language);
              const active = selection.kind === "skill" && selection.language === g.language;
              return (
                <button
                  key={g.language}
                  className={`dm-subtree-item ${active ? "active" : ""}`}
                  onClick={() => onSelectSkill(g.language, bi.zh)}
                >
                  <span className="dm-subtree-bullet">-</span>
                  <span className="dm-subtree-label">{bi.zh}</span>
                  <span className="dm-tag-count">{g.files.length}</span>
                </button>
              );
            })}
          </div>
        )}
      </li>
      <li>
        <NavItem
          icon={Crosshair}
          label="汇聚点规则"
          hasCaret
          caretOpen={open.sinks}
          onCaretClick={() => toggle("sinks")}
          onClick={() => toggle("sinks")}
        />
        {open.sinks && (
          <div className="dm-subtree">
            {sinks === null && <div className="dm-subtree-tip">加载中...</div>}
            {sinks?.map((g) => {
              const bi = bilingualLang(g.language);
              const active = selection.kind === "sink" && selection.language === g.language;
              return (
                <button
                  key={g.language}
                  className={`dm-subtree-item ${active ? "active" : ""}`}
                  onClick={() => onSelectSink(g.language, bi.zh)}
                >
                  <span className="dm-subtree-bullet">-</span>
                  <span className="dm-subtree-label">{bi.zh}</span>
                  <span className="dm-tag-count">{g.files.length}</span>
                </button>
              );
            })}
          </div>
        )}
      </li>
    </ul>
  );
}

export { bilingualLang };
