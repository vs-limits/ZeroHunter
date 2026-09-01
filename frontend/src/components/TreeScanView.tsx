import { useEffect, useState } from "react";
import { ProjectContainer, ProjectItem, ProjectProfile, readArtifactJson, updateProject } from "../api";
import "../styles/treescan.css";

interface Props {
  project: ProjectItem;
  projectContainer?: ProjectContainer;
  runId: string | null;
  onProjectProfileSynced?: () => void | Promise<void>;
}

interface Profile {
  project_name?: string;
  project_function?: string;
  summary?: string;
  project_type?: string;
  architecture_style?: string;
  repository_shape?: string;
  interface_shape?: string[];
  execution_model?: string[];
  technology_stack?: Record<string, string[]>;
  engineering_context?: string[];
  confidence?: { overall?: string; notes?: string[] };
  limits?: string[];
}

const SYNC_FIELDS: Array<{ key: keyof ProjectProfile; label: string }> = [
  { key: "project_function", label: "项目功能" },
  { key: "summary", label: "摘要" },
  { key: "project_type", label: "项目类型" },
  { key: "architecture_style", label: "架构风格" },
  { key: "repository_shape", label: "仓库形态" },
  { key: "interface_shape", label: "对外形态" },
  { key: "execution_model", label: "执行模型" },
  { key: "technology_stack", label: "技术栈" },
  { key: "engineering_context", label: "工程上下文" },
];

export function TreeScanView({
  project,
  projectContainer,
  runId,
  onProjectProfileSynced,
}: Props) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncOpen, setSyncOpen] = useState(false);
  const [selectedFields, setSelectedFields] = useState<Set<string>>(
    () => new Set(SYNC_FIELDS.map((field) => String(field.key)))
  );
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  useEffect(() => {
    setProfile(null);
    setError(null);
    readArtifactJson<Profile>(project.project_path, "treescan_agent.json", runId)
      .then((r) => setProfile(r.data))
      .catch((e) => setError(String(e)));
  }, [project.project_path, runId]);

  if (error)
    return (
      <div className="dm-empty">
        <div className="dm-empty-title">未找到 treescan_agent.json</div>
        <div className="dm-empty-tip">{error}</div>
      </div>
    );
  if (!profile) return <div className="dm-empty">读取中…</div>;

  return (
    <>
      <div className="dm-card dm-card-treescan">
        <div className="dm-card-head">
          <h3 className="dm-card-title">仓库画像</h3>
          <div className="dm-spacer" />
          {projectContainer && (
            <button className="dm-btn dm-btn-primary" onClick={() => setSyncOpen(true)}>
              同步至项目画像
            </button>
          )}
        </div>
        {syncMessage && (
          <div className="dm-meta-line" style={{ marginBottom: 10 }}>
            {syncMessage}
          </div>
        )}

        <div className="dm-pf-grid">
          <Field label="项目名">{profile.project_name ?? "—"}</Field>
          <Field label="项目类型">{profile.project_type ?? "—"}</Field>
          <Field label="架构风格">{profile.architecture_style ?? "—"}</Field>
          <Field label="仓库形态">{profile.repository_shape ?? "—"}</Field>
          <Field label="项目功能">{profile.project_function ?? "—"}</Field>
          <Field label="可信度">
            {profile.confidence?.overall ?? "—"}
            {profile.confidence?.notes && profile.confidence.notes.length > 0 && (
              <ul className="dm-pf-notes">
                {profile.confidence.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            )}
          </Field>
        </div>

        <div className="dm-pf-field">
          <span className="dm-pf-label">摘要</span>
          <div className="dm-pf-summary">{profile.summary ?? "—"}</div>
        </div>
      </div>

      <div className="dm-card">
        <h3 className="dm-card-title">对外形态 / 执行模型</h3>
        <div className="dm-pf-pairs">
          <BadgeList label="对外形态" values={profile.interface_shape ?? []} />
          <BadgeList label="执行模型" values={profile.execution_model ?? []} />
        </div>
      </div>

      <div className="dm-card">
        <h3 className="dm-card-title">技术栈</h3>
        <div className="dm-pf-pairs">
          {Object.entries(profile.technology_stack ?? {}).map(([k, v]) => (
            <BadgeList key={k} label={STACK_LABELS[k] ?? k} values={v} />
          ))}
        </div>
      </div>

      <div className="dm-card">
        <h3 className="dm-card-title">工程上下文</h3>
        <BadgeList values={profile.engineering_context ?? []} />
      </div>

      <div className="dm-card">
        <h3 className="dm-card-title">边界 / 限制</h3>
        <BadgeList values={profile.limits ?? []} />
      </div>

      {syncOpen && projectContainer && (
        <div className="dm-modal-backdrop" onClick={() => setSyncOpen(false)}>
          <div className="dm-link-modal" onClick={(e) => e.stopPropagation()}>
            <div className="dm-card-head">
              <h3 className="dm-card-title">同步字段到项目画像</h3>
              <div className="dm-spacer" />
              <button className="dm-btn dm-btn-ghost" onClick={() => setSyncOpen(false)}>
                关闭
              </button>
            </div>
            <div className="dm-sync-field-grid">
              {SYNC_FIELDS.map((field) => (
                <label key={String(field.key)} className="dm-sync-field-row">
                  <input
                    type="checkbox"
                    checked={selectedFields.has(String(field.key))}
                    onChange={(e) => {
                      setSelectedFields((prev) => {
                        const next = new Set(prev);
                        if (e.target.checked) next.add(String(field.key));
                        else next.delete(String(field.key));
                        return next;
                      });
                    }}
                  />
                  <span>{field.label}</span>
                </label>
              ))}
            </div>
            <div className="dm-modal-actions">
              <button className="dm-btn" onClick={() => setSyncOpen(false)}>
                取消
              </button>
              <button
                className="dm-btn dm-btn-primary"
                onClick={async () => {
                  const projectProfile: ProjectProfile = {};
                  for (const field of SYNC_FIELDS) {
                    if (!selectedFields.has(String(field.key))) continue;
                    const value = profile[field.key as keyof Profile];
                    if (value !== undefined) {
                      (projectProfile as Record<string, unknown>)[String(field.key)] = value;
                    }
                  }
                  try {
                    await updateProject(projectContainer, {
                      project_profile: projectProfile,
                    });
                    setSyncMessage("已同步至项目画像");
                    setSyncOpen(false);
                    await onProjectProfileSynced?.();
                  } catch (e) {
                    setSyncMessage(String(e));
                  }
                }}
              >
                同步
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="dm-pf-field">
      <span className="dm-pf-label">{label}</span>
      <span className="dm-pf-value">{children}</span>
    </div>
  );
}

function BadgeList({
  label,
  values,
}: {
  label?: string;
  values: string[];
}) {
  return (
    <div className="dm-pf-field">
      {label && <span className="dm-pf-label">{label}</span>}
      <div className="dm-pf-badges">
        {values.length === 0 ? (
          <span className="dm-tag">空</span>
        ) : (
          values.map((v) => (
            <span key={v} className="dm-pf-tag">
              {v}
            </span>
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
