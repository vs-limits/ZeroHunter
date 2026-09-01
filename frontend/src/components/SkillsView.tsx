import { useEffect, useState } from "react";
import {
  SkillDetail,
  SkillFileEntry,
  SkillGroup,
  listSkills,
  listSkillHistory,
  readSkill,
  readSkillVersion,
  writeSkill,
} from "../api";
import { bilingualVuln } from "../i18n";
import { ContentEditor } from "./ContentEditor";

interface Props {
  language: string;
  languageLabel: string;
}

export function SkillsView({ language, languageLabel }: Props) {
  const [files, setFiles] = useState<SkillFileEntry[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [detail, setDetail] = useState<(SkillDetail & { history_count?: number }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    setFiles([]);
    setActive(null);
    setDetail(null);
    listSkills()
      .then((r) => {
        const group = r.groups.find((g: SkillGroup) => g.language === language);
        const list = group?.files ?? [];
        setFiles(list);
        if (list.length > 0) setActive(list[0].name);
      })
      .catch((e) => setError(String(e)));
  }, [language]);

  useEffect(() => {
    if (!active) return;
    setDetail(null);
    readSkill(language, active)
      .then((r) => setDetail(r as any))
      .catch((e) => setError(String(e)));
  }, [language, active, version]);

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">
            技能集 · {languageLabel}
          </h2>
          <div className="dm-pageheader-extra">
            <span className="dm-meta-line">{files.length} 个技能文件</span>
          </div>
        </div>
      </div>

      <div className="dm-subnav">
        <div className="dm-subnav-tabs">
          {files.map((f) => {
            const stem = f.name.replace(/\.md$/, "");
            const bi = bilingualVuln(stem);
            const isActive = f.name === active;
            return (
              <button
                key={f.name}
                className={`dm-subnav-tab ${isActive ? "active" : ""}`}
                onClick={() => setActive(f.name)}
                title={f.name}
              >
                <span className="dm-subnav-tab-zh">{bi.zh}</span>
              </button>
            );
          })}
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
        {!active && (
          <div className="dm-empty">
            <div className="dm-empty-title">该语言下暂无技能文件</div>
          </div>
        )}
        {active && detail && (
          <ContentEditor
            key={`${language}/${active}`}
            title={bilingualVuln(active.replace(/\.md$/, "")).zh}
            subtitle={active}
            path={detail.path}
            size={detail.size}
            language="markdown"
            content={detail.content}
            historyCount={(detail as any).history_count}
            onSave={async (content, reason) => {
              await writeSkill(language, active, content, reason);
              setVersion((v) => v + 1);
            }}
            loadHistory={async () => (await listSkillHistory(language, active)).items}
            loadHistoryVersion={async (v) =>
              (await readSkillVersion(language, active, v)).content
            }
          />
        )}
      </div>
    </>
  );
}
