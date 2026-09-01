import { useMemo, useState } from "react";
import { ProjectContainer, createProject } from "../api";
import { Section } from "./ui/Section";
import { FormRow } from "./ui/FormRow";
import "../styles/control.css";

interface Props {
  onCreated: (project: ProjectContainer) => void | Promise<void>;
}

const SOURCE_PRESETS = ["github", "gitlab", "dataset", "local", "myself"];

export function NewProjectPanel({ onCreated }: Props) {
  const [source, setSource] = useState("github");
  const [owner, setOwner] = useState("");
  const [repo, setRepo] = useState("");
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const valid = source && owner && repo;
  const previewPath = useMemo(
    () =>
      `${source || "<source>"}/${owner || "<owner>"}/${
        repo || "<repo>"
      }`,
    [source, owner, repo]
  );

  async function submit() {
    setBusy(true);
    setMessage(null);
    try {
      const project = await createProject({ source, owner, repo, name, notes });
      await onCreated(project);
    } catch (e) {
      setMessage(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section
      title="新建项目"
      footer={
        <>
          <span className="dm-meta-line">
            预览路径：<code className="dm-code-inline">repo/{previewPath}</code>
          </span>
          <div className="dm-spacer" />
          <button
            className="dm-btn dm-btn-primary"
            disabled={busy || !valid}
            onClick={submit}
          >
            {busy ? "创建中…" : "创建项目"}
          </button>
        </>
      }
    >
      {message && (
        <div className="dm-banner-error" style={{ borderRadius: 6, marginBottom: 12 }}>
          {message}
        </div>
      )}

      <FormRow label="来源" required>
        <input
          list="dm-source-presets"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          placeholder="github"
        />
        <datalist id="dm-source-presets">
          {SOURCE_PRESETS.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      </FormRow>

      <FormRow label="所有人" required>
        <input
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="yeswiki"
        />
      </FormRow>

      <FormRow label="仓库名" required>
        <input
          value={repo}
          onChange={(e) => setRepo(e.target.value)}
          placeholder="yeswiki"
        />
      </FormRow>

      <FormRow label="显示名">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={repo || "可选"}
        />
      </FormRow>

      <FormRow label="备注" align="top">
        <textarea
          rows={3}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </FormRow>
    </Section>
  );
}
