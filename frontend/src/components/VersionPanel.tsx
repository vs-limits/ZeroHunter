import { useEffect, useState } from "react";
import {
  ProjectContainer,
  VulnerabilityItem,
  VersionItem,
  deleteVersion,
  updateVersion,
} from "../api";
import { Descriptions } from "./ui/Descriptions";
import { FormRow } from "./ui/FormRow";
import { Section } from "./ui/Section";
import { Statistic } from "./ui/Statistic";
import { VulnerabilityAssociations } from "./VulnerabilityAssociations";
import { RUN_STATUS_LABELS } from "../i18n";
import "../styles/control.css";

interface Props {
  project: ProjectContainer;
  version: VersionItem;
  onVersionChanged: (version: VersionItem) => void | Promise<void>;
  onVersionDeleted: () => void | Promise<void>;
  onNewScan: () => void | Promise<void>;
  onSelectVulnerability: (vulnerability: VulnerabilityItem) => void;
  onVulnerabilitiesChanged?: () => void | Promise<void>;
}

const ROLE_OPTIONS = ["baseline", "vulnerable", "fixed", "variant"];

export function VersionPanel({
  project,
  version,
  onVersionChanged,
  onVersionDeleted,
  onNewScan,
  onSelectVulnerability,
  onVulnerabilitiesChanged,
}: Props) {
  const [name, setName] = useState(version.name);
  const [notes, setNotes] = useState(version.notes || "");
  const [role, setRole] = useState(version.role || "baseline");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState("");

  useEffect(() => {
    setName(version.name);
    setNotes(version.notes || "");
    setRole(version.role || "baseline");
    setConfirmText("");
  }, [version.project_path]);

  const dirty =
    name !== version.name ||
    (notes || "") !== (version.notes || "") ||
    role !== (version.role || "baseline");

  async function save() {
    setBusy(true);
    setMessage(null);
    try {
      const updated = await updateVersion(version, { name, notes, role });
      await onVersionChanged(updated);
    } catch (e) {
      setMessage(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (confirmText !== version.version) return;
    setBusy(true);
    setMessage(null);
    try {
      await deleteVersion(version);
      await onVersionDeleted();
    } catch (e) {
      setMessage(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {/* —— 基本信息 —— */}
      <Section
        title="版本信息"
        extra={
          <>
            <span className="dm-tag">{version.kind}</span>
            <span className="dm-tag verdict-uncertain">{version.role}</span>
            <button className="dm-btn dm-btn-primary" onClick={onNewScan}>
              ＋ 新建扫描
            </button>
          </>
        }
        footer={
          <>
            <span className="dm-meta-line">
              共 {version.scan_count} 次扫描
              {version.latest_scan && (
                <>
                  {" · 最新 "}
                  <code className="dm-code-inline">
                    {version.latest_scan.name}
                  </code>{" "}
                  <span className={`dm-run-status ${version.latest_scan.status}`}>
                    {RUN_STATUS_LABELS[version.latest_scan.status] ??
                      version.latest_scan.status}
                  </span>
                </>
              )}
            </span>
            <div className="dm-spacer" />
            <button
              className="dm-btn dm-btn-primary"
              disabled={busy || !dirty}
              onClick={save}
            >
              {busy ? "保存中…" : "保存"}
            </button>
          </>
        }
      >
        {message && (
          <div className="dm-banner-error" style={{ borderRadius: 6, marginBottom: 12 }}>
            {message}
          </div>
        )}

        <Descriptions
          columns={2}
          items={[
            {
              label: "项目",
              value: <code className="dm-code-inline">{project.project_path}</code>,
            },
            {
              label: "版本路径",
              value: <code className="dm-code-inline">{version.project_path}</code>,
            },
            {
              label: "导入方式",
              value: version.kind,
            },
            {
              label: "创建时间",
              value: <span className="dm-meta-line">{formatTs(version.created_at)}</span>,
            },
          ]}
        />

        <hr className="dm-divider" />

        <FormRow label="名称">
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </FormRow>
        <FormRow label="角色">
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLE_OPTIONS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </FormRow>
        <FormRow label="备注" align="top">
          <textarea
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder=""
          />
        </FormRow>
      </Section>

      {/* —— 扫描概览 —— */}
      <Section title="扫描概览">
        <div className="dm-kpi-grid">
          <Statistic
            label="扫描次数"
            value={version.scan_count}
            accent="primary"
          />
          <Statistic
            label="存在漏洞"
            value={version.audit_summary?.vulnerable ?? 0}
            accent="danger"
          />
          <Statistic
            label="不确定"
            value={version.audit_summary?.uncertain ?? 0}
            accent="warning"
          />
          <Statistic
            label="候选链"
            value={version.callscan_summary?.candidate_chains ?? 0}
            accent="muted"
          />
        </div>
        {!version.latest_scan && (
          <div className="dm-empty-tip" style={{ marginTop: 12 }}>
            暂无扫描
          </div>
        )}
      </Section>

      <VulnerabilityAssociations
        project={project}
        target={{
          kind: "version",
          projectPath: version.project_path,
          versionName: version.version,
        }}
        onSelectVulnerability={onSelectVulnerability}
        onChanged={onVulnerabilitiesChanged}
      />

      {/* —— Git provenance —— */}
      <Section title="Git 信息">
        {version.git ? (
          <Descriptions
            columns={2}
            items={[
              {
                label: "remote",
                value: <code className="dm-code-inline">{version.git.remote || "—"}</code>,
                span: "full",
              },
              {
                label: "ref / branch",
                value: (
                  <code className="dm-code-inline">
                    {version.git.ref || version.git.branch || "—"}
                  </code>
                ),
              },
              {
                label: "commit",
                value: (
                  <code className="dm-code-inline">{version.git.commit || "—"}</code>
                ),
              },
              {
                label: "describe",
                value: (
                  <code className="dm-code-inline">{version.git.describe || "—"}</code>
                ),
              },
              {
                label: "worktree",
                value: version.git.worktree ? "是" : "否",
              },
            ]}
          />
        ) : (
          <div className="dm-empty-tip">无 Git 信息</div>
        )}
      </Section>

      {/* —— 危险区 —— */}
      <Section title="危险操作" variant="danger">
        <FormRow
          label="确认版本名"
          description={
            <>
              请输入版本名 <code className="dm-code-inline">{version.version}</code>
              {" "}以确认删除
            </>
          }
        >
          <input
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder={version.version}
            style={{ maxWidth: 320 }}
          />
          <button
            className="dm-btn dm-btn-danger"
            disabled={busy || confirmText !== version.version}
            onClick={remove}
          >
            删除版本
          </button>
        </FormRow>
      </Section>
    </>
  );
}

function formatTs(value: string | null | undefined): string {
  if (!value) return "—";
  return value.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "");
}
