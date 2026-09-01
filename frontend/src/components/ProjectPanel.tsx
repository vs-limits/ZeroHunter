import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  GitRefItem,
  ImportJob,
  ProjectContainer,
  VersionItem,
  ProjectProfile,
  VulnerabilityItem,
  createVersion,
  getImportJob,
  importStreamUrl,
  listGitRefs,
  retryImportJob,
  startGitVersionImport,
  stopImportJob,
  updateProject,
} from "../api";
import { ScanConsole } from "./ScanConsole";
import { Descriptions } from "./ui/Descriptions";
import { FormRow } from "./ui/FormRow";
import { Section } from "./ui/Section";
import { VulnerabilityAssociations } from "./VulnerabilityAssociations";
import "../styles/control.css";
import "../styles/treescan.css";

interface Props {
  project: ProjectContainer;
  onProjectChanged: (project: ProjectContainer) => void | Promise<void>;
  onVersionCreated: (version: VersionItem) => void | Promise<void>;
  onSelectVulnerability: (vulnerability: VulnerabilityItem) => void;
  onVulnerabilitiesChanged?: () => void | Promise<void>;
}

type VersionMode = "git" | "manual" | "copy" | "local";
type ProjectTab = "info" | "versions" | "profile";

const MODE_META: Record<VersionMode, { label: string }> = {
  git: { label: "Git" },
  manual: { label: "空白" },
  copy: { label: "复制" },
  local: { label: "本地导入" },
};

const ROLE_OPTIONS = ["baseline", "vulnerable", "fixed", "variant"];
const PROJECT_STATUS_OPTIONS = [
  { value: "not_started", label: "未开始" },
  { value: "scanning", label: "扫描中" },
  { value: "manual_review", label: "人工复核中" },
  { value: "completed", label: "已完成" },
  { value: "tracking", label: "持续跟踪" },
];

export function ProjectPanel({
  project,
  onProjectChanged,
  onVersionCreated,
  onSelectVulnerability,
  onVulnerabilitiesChanged,
}: Props) {
  // 项目元信息表单
  const [tab, setTab] = useState<ProjectTab>("info");
  const [name, setName] = useState(project.name);
  const [notes, setNotes] = useState(project.notes || "");
  const [description, setDescription] = useState(project.description || "");
  const [tagsText, setTagsText] = useState((project.tags || []).join("\n"));
  const [auditStatus, setAuditStatus] = useState(project.audit_status || "not_started");
  const [saving, setSaving] = useState(false);

  // 版本创建表单
  const [mode, setMode] = useState<VersionMode>("git");
  const [version, setVersion] = useState("");
  const [role, setRole] = useState("baseline");
  const [versionNotes, setVersionNotes] = useState("");
  const [sourceVersion, setSourceVersion] = useState(
    project.versions[0]?.version ?? ""
  );
  const [localPath, setLocalPath] = useState("");
  const [gitUrl, setGitUrl] = useState(
    project.versions.find((v) => v.git?.remote)?.git?.remote ?? ""
  );
  const [gitRef, setGitRef] = useState("HEAD");
  const [gitRefs, setGitRefs] = useState<GitRefItem[]>([]);
  const [gitRefsLoading, setGitRefsLoading] = useState(false);
  const [gitRefsMessage, setGitRefsMessage] = useState<string | null>(null);
  const [gitRefFilter, setGitRefFilter] = useState("");
  const [depth, setDepth] = useState("");
  const [singleBranch, setSingleBranch] = useState(false);
  const [submodules, setSubmodules] = useState(false);
  const [overwrite, setOverwrite] = useState(false);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [job, setJob] = useState<ImportJob | null>(null);
  const [jobLines, setJobLines] = useState<string[]>([]);
  const streamRef = useRef<EventSource | null>(null);
  const consoleRef = useRef<HTMLDivElement | null>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    setName(project.name);
    setNotes(project.notes || "");
    setDescription(project.description || "");
    setTagsText((project.tags || []).join("\n"));
    setAuditStatus(project.audit_status || "not_started");
    setSourceVersion(project.versions[0]?.version ?? "");
    const remote = project.versions.find((v) => v.git?.remote)?.git?.remote;
    if (remote && !gitUrl) setGitUrl(remote);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.project_path, project.versions.length]);

  useEffect(() => {
    setGitRefs([]);
    setGitRefsMessage(null);
    setGitRefFilter("");
  }, [gitUrl, project.project_path]);

  useEffect(() => () => streamRef.current?.close(), []);

  function scrollConsoleToBottom() {
    requestAnimationFrame(() => {
      const el = consoleRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  // SSE 可能丢包或 git 长时间无输出；轮询兜底保证终端与状态会更新
  useEffect(() => {
    if (!job || job.status === "done" || job.status === "error" || job.status === "killed") {
      if (pollRef.current) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }
    pollRef.current = window.setInterval(async () => {
      try {
        const fresh = await getImportJob(job.job_id);
        setJob(fresh);
        setJobLines(fresh.lines ?? []);
        scrollConsoleToBottom();
      } catch {
        /* ignore */
      }
    }, 2000);
    return () => {
      if (pollRef.current) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [job?.job_id, job?.status]);

  const projectDirty =
    name !== project.name ||
    (notes || "") !== (project.notes || "") ||
    (description || "") !== (project.description || "") ||
    tagsText !== (project.tags || []).join("\n") ||
    auditStatus !== (project.audit_status || "not_started");

  async function saveProject() {
    setSaving(true);
    setMessage(null);
    try {
      const updated = await updateProject(project, {
        name,
        notes,
        description,
        tags: lines(tagsText),
        audit_status: auditStatus,
      });
      await onProjectChanged(updated);
    } catch (e) {
      setMessage(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function submitVersion() {
    setBusy(true);
    setMessage(null);
    try {
      if (mode === "git") {
        const created = await startGitVersionImport(project, {
          git_url: gitUrl,
          ref: gitRef || "HEAD",
          version,
          notes: versionNotes,
          role,
          overwrite,
          depth: depth ? Number(depth) : null,
          single_branch: singleBranch,
          recurse_submodules: submodules,
        });
        setJob(created);
        setJobLines(created.lines ?? []);
        attachImportStream(created.job_id);
      } else {
        const created = await createVersion(project, {
          kind: mode,
          version,
          notes: versionNotes,
          role,
          overwrite,
          source_version: mode === "copy" ? sourceVersion : null,
          local_path: mode === "local" ? localPath : null,
        });
        await onVersionCreated(created);
      }
    } catch (e) {
      setMessage(String(e));
    } finally {
      setBusy(false);
    }
  }

  function attachImportStream(jobId: string) {
    streamRef.current?.close();
    const es = new EventSource(importStreamUrl(jobId));
    streamRef.current = es;
    es.onmessage = async (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "stdout") {
          setJobLines((prev) => [...prev, msg.line]);
          scrollConsoleToBottom();
        } else if (msg.type === "error") {
          setJobLines((prev) => [...prev, `[error] ${msg.message ?? "stream error"}`]);
          scrollConsoleToBottom();
        } else if (msg.type === "status") {
          setJob((prev) => ({ ...(prev ?? {}), ...msg } as ImportJob));
          if (msg.status === "done" && msg.project_path) {
            const versionName = String(msg.version || "").trim();
            const created =
              project.versions.find((v) => v.version === versionName) ??
              ({
                project_path: msg.project_path,
                source: project.source,
                owner: project.owner,
                repo: project.repo,
                version: versionName,
                name: versionName,
                notes: versionNotes,
                role,
                kind: "git",
                created_at: null,
                project_root: "",
                has_artifacts: true,
                scan_count: 0,
                git: msg.git ?? null,
              } as VersionItem);
            await onVersionCreated(created);
          }
        } else if (msg.type === "end") {
          es.close();
          try {
            const fresh = await getImportJob(jobId);
            setJob(fresh);
            setJobLines(fresh.lines ?? []);
            scrollConsoleToBottom();
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* ignore */
      }
    };
    es.onerror = () => {
      getImportJob(jobId)
        .then((fresh) => {
          setJob(fresh);
          setJobLines(fresh.lines ?? []);
          scrollConsoleToBottom();
        })
        .catch(() => {});
    };
  }

  async function stopJob() {
    if (!job) return;
    await stopImportJob(job.job_id);
  }

  async function retryJob() {
    if (!job) return;
    const next = await retryImportJob(job.job_id);
    setJob(next);
    setJobLines(next.lines ?? []);
    attachImportStream(next.job_id);
  }

  async function loadGitRefs(refresh = false) {
    setGitRefsLoading(true);
    setGitRefsMessage(null);
    try {
      const refs = await listGitRefs(project, {
        git_url: gitUrl.trim() || undefined,
        refresh,
      });
      setGitRefs(refs.items);
      setGitRefsMessage(
        refs.items.length
          ? `${refs.branches} branches · ${refs.tags} tags`
          : "未找到 branch 或 tag"
      );
    } catch (e) {
      setGitRefsMessage(String(e));
    } finally {
      setGitRefsLoading(false);
    }
  }

  const hasGitHistory = project.versions.some(
    (item) => item.kind === "git" || !!item.git
  );

  const filteredGitRefs = useMemo(() => {
    const q = gitRefFilter.trim().toLowerCase();
    if (!q) return gitRefs;
    return gitRefs.filter(
      (item) =>
        item.name.toLowerCase().includes(q) ||
        item.kind.toLowerCase().includes(q) ||
        item.short_commit.toLowerCase().includes(q)
    );
  }, [gitRefs, gitRefFilter]);

  const visibleGitRefs = filteredGitRefs.slice(0, 120);

  const versionFormValid = useMemo(() => {
    if (mode === "git") return !!gitUrl;
    if (mode === "copy") return !!sourceVersion && !!version;
    if (mode === "local") return !!localPath && !!version;
    return !!version; // manual
  }, [mode, version, sourceVersion, localPath, gitUrl]);

  return (
    <>
      <div className="dm-card">
        <div className="dm-segctrl">
          <button
            className={`dm-segctrl-item ${tab === "info" ? "active" : ""}`}
            onClick={() => setTab("info")}
          >
            项目信息
          </button>
          <button
            className={`dm-segctrl-item ${tab === "versions" ? "active" : ""}`}
            onClick={() => setTab("versions")}
          >
            版本控制
          </button>
          <button
            className={`dm-segctrl-item ${tab === "profile" ? "active" : ""}`}
            onClick={() => setTab("profile")}
          >
            项目画像
          </button>
        </div>
      </div>

      {/* —— 项目元信息 —— */}
      {tab === "info" && (
      <>
      <Section
        title="项目信息"
        extra={<span className="dm-tag">{project.version_count} 版本</span>}
        footer={
          <>
            <Descriptions
              columns={2}
              items={[
                {
                  label: "项目路径",
                  value: (
                    <code className="dm-code-inline">{project.project_path}</code>
                  ),
                },
                {
                  label: "创建时间",
                  value: <span className="dm-meta-line">{formatTs(project.created_at)}</span>,
                },
              ]}
            />
            <div className="dm-spacer" />
            <button
              className="dm-btn dm-btn-primary"
              disabled={saving || !projectDirty}
              onClick={saveProject}
            >
              {saving ? "保存中…" : "保存"}
            </button>
          </>
        }
      >
        {message && (
          <div className="dm-banner-error" style={{ borderRadius: 6, marginBottom: 12 }}>
            {message}
          </div>
        )}

        <FormRow label="名称">
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </FormRow>
        <FormRow label="描述" align="top">
          <textarea
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </FormRow>
        <FormRow label="标签" align="top">
          <textarea
            rows={4}
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            placeholder="一行一个标签"
          />
          <div className="dm-pf-badges">
            {lines(tagsText).map((tag) => (
              <span key={tag} className="dm-pf-tag">{tag}</span>
            ))}
          </div>
        </FormRow>
        <FormRow label="项目状态">
          <select value={auditStatus} onChange={(e) => setAuditStatus(e.target.value)}>
            {PROJECT_STATUS_OPTIONS.map((status) => (
              <option key={status.value} value={status.value}>
                {status.label}
              </option>
            ))}
          </select>
        </FormRow>
        <FormRow label="备注" align="top">
          <textarea
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </FormRow>
      </Section>
      <VulnerabilityAssociations
        project={project}
        target={{ kind: "project" }}
        onSelectVulnerability={onSelectVulnerability}
        onChanged={onVulnerabilitiesChanged}
      />
      </>
      )}

      {/* —— 新建版本 —— */}
      {tab === "versions" && (
      <>
      <Section title="新建版本">
        <FormRow label="导入方式" align="top">
          <div className="dm-mode-grid">
            {(Object.keys(MODE_META) as VersionMode[]).map((m) => (
              <label
                key={m}
                className={`dm-mode-card ${mode === m ? "on" : ""}`}
              >
                <input
                  type="radio"
                  name="dm-version-mode"
                  checked={mode === m}
                  onChange={() => setMode(m)}
                />
                <div>
                  <div className="dm-mode-card-title">{MODE_META[m].label}</div>
                </div>
              </label>
            ))}
          </div>
        </FormRow>

        {mode === "git" && (
          <>
            <FormRow label="Git URL" required>
              <input
                value={gitUrl}
                onChange={(e) => setGitUrl(e.target.value)}
                placeholder="https://github.com/owner/repo.git"
              />
            </FormRow>
            <FormRow label="Ref">
              <input
                value={gitRef}
                onChange={(e) => setGitRef(e.target.value)}
                placeholder="main / v4.5.0 / abcdef1"
                style={{ flex: 1 }}
              />
              <input
                value={depth}
                onChange={(e) => setDepth(e.target.value)}
                placeholder="depth"
                style={{ maxWidth: 110, flex: "0 0 110px" }}
                title="只克隆最近 N 次提交"
              />
            </FormRow>
            <FormRow label="版本选择" align="top">
              <div className="dm-git-ref-picker">
                <div className="dm-git-ref-toolbar">
                  <button
                    type="button"
                    className="dm-btn dm-btn-primary"
                    disabled={gitRefsLoading || (!gitUrl.trim() && !hasGitHistory)}
                    onClick={() => void loadGitRefs(false)}
                  >
                    {gitRefsLoading ? "获取中..." : "获取版本"}
                  </button>
                  <button
                    type="button"
                    className="dm-btn"
                    disabled={gitRefsLoading || (!gitUrl.trim() && !hasGitHistory)}
                    onClick={() => void loadGitRefs(true)}
                  >
                    刷新
                  </button>
                  <input
                    value={gitRefFilter}
                    onChange={(e) => setGitRefFilter(e.target.value)}
                    placeholder="过滤 branch / tag / commit"
                  />
                  {gitRefs.length > 0 && (
                    <span className="dm-git-ref-count">
                      {filteredGitRefs.length}/{gitRefs.length}
                    </span>
                  )}
                </div>
                {gitRefsMessage && (
                  <div className="dm-git-ref-message">{gitRefsMessage}</div>
                )}
                {visibleGitRefs.length > 0 && (
                  <div className="dm-git-ref-list">
                    {visibleGitRefs.map((item) => (
                      <button
                        type="button"
                        key={item.full_ref}
                        className={`dm-git-ref-item ${gitRef === item.ref ? "on" : ""}`}
                        onClick={() => setGitRef(item.ref)}
                        title={`${item.full_ref}\n${item.commit}`}
                      >
                        <span className={`dm-git-ref-kind ${item.kind}`}>
                          {item.kind}
                        </span>
                        <span className="dm-git-ref-name">{item.name}</span>
                        <code className="dm-git-ref-commit">{item.short_commit}</code>
                      </button>
                    ))}
                    {filteredGitRefs.length > visibleGitRefs.length && (
                      <div className="dm-git-ref-more">
                        还有 {filteredGitRefs.length - visibleGitRefs.length} 项
                      </div>
                    )}
                  </div>
                )}
              </div>
            </FormRow>
            <FormRow label="Git 选项">
              <label className="dm-inline-check">
                <input
                  type="checkbox"
                  checked={singleBranch}
                  onChange={(e) => setSingleBranch(e.target.checked)}
                />
                single branch
              </label>
              <label className="dm-inline-check">
                <input
                  type="checkbox"
                  checked={submodules}
                  onChange={(e) => setSubmodules(e.target.checked)}
                />
                recurse submodules
              </label>
            </FormRow>
          </>
        )}

        {mode === "copy" && (
          <FormRow label="来源版本" required>
            <select
              value={sourceVersion}
              onChange={(e) => setSourceVersion(e.target.value)}
            >
              {project.versions.length === 0 && <option value="">（无可用版本）</option>}
              {project.versions.map((v) => (
                <option key={v.version} value={v.version}>
                  {v.version} · {v.role}
                </option>
              ))}
            </select>
          </FormRow>
        )}

        {mode === "local" && (
          <FormRow label="本地路径" required>
            <input
              value={localPath}
              onChange={(e) => setLocalPath(e.target.value)}
              placeholder="D:\\code\\target"
            />
          </FormRow>
        )}

        <FormRow label="版本名" required={mode !== "git"}>
          <input
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder={mode === "git" ? "默认 main__abcdef" : "default__manual"}
          />
        </FormRow>

        <FormRow label="角色">
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLE_OPTIONS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <label className="dm-inline-check">
            <input
              type="checkbox"
              checked={overwrite}
              onChange={(e) => setOverwrite(e.target.checked)}
            />
            允许覆盖同名版本
          </label>
        </FormRow>

        <FormRow label="版本备注" align="top">
          <textarea
            rows={2}
            value={versionNotes}
            onChange={(e) => setVersionNotes(e.target.value)}
            placeholder="例如：CVE-2024-12345 修复前的 commit"
          />
        </FormRow>

        <div className="dm-srow">
          <div className="dm-srow-label" />
          <div className="dm-srow-control">
            <button
              className="dm-btn dm-btn-primary"
              disabled={busy || !versionFormValid}
              onClick={submitVersion}
            >
              {busy
                ? "提交中…"
                : mode === "git"
                  ? "拉取并创建版本"
                  : "创建版本"}
            </button>
          </div>
        </div>
      </Section>

      {/* —— Git 导入任务 —— */}
      {job && (
        <Section
          title="Git 导入任务"
          extra={
            <>
              <span className={`dm-run-status ${job.status}`}>{job.status}</span>
              {job.status === "running" && (
                <button className="dm-btn dm-btn-danger dm-btn-sm" onClick={stopJob}>
                  停止
                </button>
              )}
              {(job.status === "error" || job.status === "killed") && (
                <button className="dm-btn dm-btn-sm" onClick={retryJob}>
                  重新开始
                </button>
              )}
            </>
          }
        >
          {job.error && (
            <div className="dm-banner-error" style={{ borderRadius: 6, marginBottom: 10 }}>
              {job.error}
            </div>
          )}
          <div ref={consoleRef} className="dm-console">
            <ScanConsole lines={jobLines} emptyText="等待 Git 输出…" />
          </div>
        </Section>
      )}
      </>
      )}

      {tab === "profile" && <ProjectProfilePanel profile={project.project_profile || {}} />}
    </>
  );
}

function formatTs(value: string | null | undefined): string {
  if (!value) return "—";
  return value.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "");
}

function lines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function ProjectProfilePanel({ profile }: { profile: ProjectProfile }) {
  const hasProfile = Object.keys(profile || {}).length > 0;
  if (!hasProfile) {
    return (
      <Section title="项目画像">
        <div className="dm-empty-tip">暂无项目画像，可在某次扫描的“目录画像”中同步到项目。</div>
      </Section>
    );
  }
  return (
    <>
      <Section title="项目画像">
        <div className="dm-pf-grid">
          <ProfileField label="项目类型">{profile.project_type || "—"}</ProfileField>
          <ProfileField label="架构风格">{profile.architecture_style || "—"}</ProfileField>
          <ProfileField label="仓库形态">{profile.repository_shape || "—"}</ProfileField>
          <ProfileField label="项目功能">{profile.project_function || "—"}</ProfileField>
        </div>
        <div className="dm-pf-field" style={{ marginTop: 12 }}>
          <span className="dm-pf-label">摘要</span>
          <div className="dm-pf-summary">{profile.summary || "—"}</div>
        </div>
      </Section>
      <Section title="对外形态 / 执行模型">
        <div className="dm-pf-pairs">
          <ProfileBadgeList label="对外形态" values={profile.interface_shape || []} />
          <ProfileBadgeList label="执行模型" values={profile.execution_model || []} />
        </div>
      </Section>
      <Section title="技术栈">
        <div className="dm-pf-pairs">
          {Object.entries(profile.technology_stack || {}).map(([key, values]) => (
            <ProfileBadgeList
              key={key}
              label={STACK_LABELS[key] || key}
              values={Array.isArray(values) ? values : []}
            />
          ))}
        </div>
      </Section>
      <Section title="工程上下文">
        <ProfileBadgeList values={profile.engineering_context || []} />
      </Section>
    </>
  );
}

function ProfileField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="dm-pf-field">
      <span className="dm-pf-label">{label}</span>
      <span className="dm-pf-value">{children}</span>
    </div>
  );
}

function ProfileBadgeList({ label, values }: { label?: string; values: string[] }) {
  return (
    <div className="dm-pf-field">
      {label && <span className="dm-pf-label">{label}</span>}
      <div className="dm-pf-badges">
        {values.length === 0 ? (
          <span className="dm-tag">空</span>
        ) : (
          values.map((value) => (
            <span key={value} className="dm-pf-tag">{value}</span>
          ))
        )}
      </div>
    </div>
  );
}

const STACK_LABELS: Record<string, string> = {
  frontend: "前端",
  backend: "后端",
  database: "数据库",
  template_engine: "模板引擎",
  runtime: "运行环境",
  deployment: "部署形态",
};
