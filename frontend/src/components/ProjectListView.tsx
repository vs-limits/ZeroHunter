import { useMemo, useState } from "react";
import { FolderKanban, Star } from "lucide-react";
import { ProjectContainer, ScanItem, updateProject } from "../api";
import "../styles/project-list.css";

interface Props {
  projects: ProjectContainer[];
  onSelectProject: (project: ProjectContainer) => void;
  onNewProject: () => void;
  onRefresh: () => void;
}

type SortMode = "name" | "time";

const STATUS_LABELS: Record<string, string> = {
  not_started: "未开始",
  scanning: "扫描中",
  manual_review: "人工复核中",
  completed: "已完成",
  tracking: "持续跟踪",
};

export function ProjectListView({ projects, onSelectProject, onNewProject, onRefresh }: Props) {
  const [query, setQuery] = useState("");
  const [sortMode, setSortMode] = useState<SortMode>("time");
  const [message, setMessage] = useState<string | null>(null);

  const visibleProjects = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = !q
      ? projects
      : projects.filter((project) => {
          const haystack = [
            project.name,
            project.source,
            project.owner,
            project.repo,
            project.project_path,
            project.description,
            ...(project.tags || []),
          ]
            .join(" ")
            .toLowerCase();
          return haystack.includes(q);
        });
    return [...filtered].sort((a, b) => {
      if (sortMode === "name") {
        return (a.name || a.repo).localeCompare(b.name || b.repo, "zh-Hans-CN");
      }
      return timestampOfProject(b) - timestampOfProject(a);
    });
  }, [projects, query, sortMode]);

  async function toggleFavorite(project: ProjectContainer) {
    setMessage(null);
    try {
      await updateProject(project, { favorite: !project.favorite });
      onRefresh();
    } catch (e) {
      setMessage(String(e));
    }
  }

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">项目列表</h2>
          <div className="dm-pageheader-extra">
            <button className="dm-btn dm-btn-ghost" onClick={onRefresh}>
              ↻ 刷新
            </button>
            <button className="dm-btn dm-btn-primary" onClick={onNewProject}>
              + 新建项目
            </button>
          </div>
        </div>
      </div>

      <div className="dm-tab-content">
        <div className="dm-project-toolbar">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索项目名称 / 仓库 / 标签 / 描述"
          />
          <select value={sortMode} onChange={(e) => setSortMode(e.target.value as SortMode)}>
            <option value="time">按时间排序</option>
            <option value="name">按名称排序</option>
          </select>
          <span className="dm-meta-line">
            显示 {visibleProjects.length} / {projects.length}
          </span>
          {message && <span className="dm-meta-line">{message}</span>}
        </div>
        <div className="dm-project-grid">
          <button
            type="button"
            className="dm-project-card dm-project-card-add"
            onClick={onNewProject}
          >
            <span className="dm-project-add-plus">+</span>
            <span className="dm-project-add-label">新建项目</span>
          </button>

          {visibleProjects.map((project) => (
            <ProjectCard
              key={project.project_path}
              project={project}
              onSelect={onSelectProject}
              onToggleFavorite={toggleFavorite}
            />
          ))}
        </div>
      </div>
    </>
  );
}

function ProjectCard({
  project,
  onSelect,
  onToggleFavorite,
}: {
  project: ProjectContainer;
  onSelect: (project: ProjectContainer) => void;
  onToggleFavorite: (project: ProjectContainer) => void | Promise<void>;
}) {
  const latest = latestScan(project);
  const updatedLabel = formatRelative(project.updated_at);
  return (
    <div
      role="button"
      tabIndex={0}
      className="dm-project-card"
      onClick={() => onSelect(project)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(project);
        }
      }}
      title={project.project_path}
    >
      <div className="dm-project-card-head">
        <span className="dm-project-card-icon">
          <FolderKanban size={18} strokeWidth={2} aria-hidden />
        </span>
        <div className="dm-project-card-title">
          <div className="dm-project-card-name">{project.name || project.repo}</div>
          <div className="dm-project-card-repo">
            {project.source}/{project.owner}/{project.repo}
          </div>
        </div>
        <button
          type="button"
          className={`dm-project-star ${project.favorite ? "on" : ""}`}
          onClick={(e) => {
            e.stopPropagation();
            void onToggleFavorite(project);
          }}
          title={project.favorite ? "取消关注" : "关注项目"}
        >
          <Star size={16} fill={project.favorite ? "currentColor" : "none"} aria-hidden />
        </button>
      </div>

      {(project.description || project.tags?.length > 0 || project.audit_status) && (
        <div className="dm-project-card-info">
          {project.description && (
            <div className="dm-project-card-desc">{project.description}</div>
          )}
          <div className="dm-project-card-tags">
            {project.audit_status && (
              <span className="dm-tag">
                {STATUS_LABELS[project.audit_status] ?? project.audit_status}
              </span>
            )}
            {(project.tags || []).slice(0, 4).map((tag) => (
              <span key={tag} className="dm-tag">{tag}</span>
            ))}
          </div>
        </div>
      )}

      <div className="dm-project-card-stats">
        <span>
          <strong>{project.version_count}</strong> 版本
        </span>
        <span className="dm-project-card-stats-sep">·</span>
        <span>
          <strong>{project.scan_count}</strong> 扫描
        </span>
      </div>

      <div className="dm-project-card-meta">
        <span className="dm-project-card-updated" title={project.updated_at ?? ""}>
          {updatedLabel ? `最近更新 ${updatedLabel}` : "尚未更新"}
        </span>
        {latest && (
          <span className="dm-project-card-scan" title={`${latest.name} · ${latest.status}`}>
            <span
              className={`dm-scan-dot dm-scan-dot-${latest.status}${latest.legacy ? " dm-scan-dot-legacy" : ""}`}
            />
            <span className="dm-project-card-scan-name">{latest.name}</span>
          </span>
        )}
      </div>
    </div>
  );
}

function timestampOfProject(project: ProjectContainer): number {
  const raw = project.updated_at || project.created_at;
  if (!raw) return 0;
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : 0;
}

function latestScan(project: ProjectContainer): ScanItem | null {
  let best: { scan: ScanItem; ts: number } | null = null;
  for (const version of project.versions) {
    const scan = version.latest_scan;
    if (!scan) continue;
    const ts = timestampOf(scan);
    if (ts === null) continue;
    if (!best || ts > best.ts) best = { scan, ts };
  }
  return best?.scan ?? null;
}

function timestampOf(scan: ScanItem): number | null {
  const raw = scan.finished_at || scan.started_at || scan.scheduled_at || scan.created_at;
  if (!raw) return null;
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : null;
}

function formatRelative(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const diff = Date.now() - ms;
  if (diff < 0) return "刚刚";
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;
  if (diff < minute) return "刚刚";
  if (diff < hour) return `${Math.floor(diff / minute)} 分钟前`;
  if (diff < day) return `${Math.floor(diff / hour)} 小时前`;
  if (diff < 30 * day) return `${Math.floor(diff / day)} 天前`;
  const d = new Date(ms);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}
