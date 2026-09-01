import { useEffect, useState } from "react";
import {
  SinkDetail,
  SinkFileEntry,
  SinkGroup,
  listSinkHistory,
  listSinks,
  readSink,
  readSinkVersion,
  writeSink,
  writeSinkRules,
} from "../api";
import { bilingualVuln } from "../i18n";
import { ContentEditor } from "./ContentEditor";
import { SinkRulesEditor } from "./SinkRulesEditor";

interface Props {
  language: string;
  languageLabel: string;
}

export function SinksView({ language, languageLabel }: Props) {
  const [files, setFiles] = useState<SinkFileEntry[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [detail, setDetail] = useState<(SinkDetail & { history_count?: number; parse_error?: string | null }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    setFiles([]);
    setActive(null);
    setDetail(null);
    setError(null);
    listSinks()
      .then((r) => {
        const group = r.groups.find((g: SinkGroup) => g.language === language);
        const list = group?.files ?? [];
        setFiles(list);
        if (list.length > 0) setActive(list[0].name);
      })
      .catch((e) => setError(String(e)));
  }, [language]);

  useEffect(() => {
    if (!active) return;
    setDetail(null);
    readSink(language, active)
      .then((r) => setDetail(r as any))
      .catch((e) => setError(String(e)));
  }, [language, active, version]);

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">汇聚点规则 · {languageLabel}</h2>
          <div className="dm-pageheader-extra">
            <span className="dm-meta-line">{files.length} 类</span>
          </div>
        </div>
      </div>

      <div className="dm-subnav">
        <div className="dm-subnav-tabs">
          {files.map((f) => {
            const bi = bilingualVuln(f.name);
            const isActive = f.name === active;
            return (
              <button
                key={f.name}
                className={`dm-subnav-tab ${isActive ? "active" : ""}`}
                onClick={() => setActive(f.name)}
                title={f.filename}
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
            <div className="dm-empty-title">该语言下暂无规则文件</div>
          </div>
        )}
        {active && detail && (
          <ContentEditor
            key={`${language}/${active}`}
            title={(detail.vulnerability ? bilingualVuln(detail.vulnerability).zh : detail.name) || detail.name}
            subtitle={detail.filename}
            path={detail.path}
            size={detail.size}
            language="python"
            content={detail.raw_source}
            historyCount={(detail as any).history_count}
            renderPreview={() => (
              <SinkRulesEditor
                vulnerability={detail.vulnerability}
                rules={detail.rules}
                parseError={(detail as any).parse_error}
                idPrefix={`${language}-${active.split("_")[0] || active}`}
                onSave={async (vuln, rules, reason) => {
                  await writeSinkRules(language, active, vuln, rules, reason);
                  setVersion((v) => v + 1);
                }}
              />
            )}
            onSave={async (content, reason) => {
              await writeSink(language, active, content, reason);
              setVersion((v) => v + 1);
            }}
            loadHistory={async () => (await listSinkHistory(language, active)).items}
            loadHistoryVersion={async (v) =>
              (await readSinkVersion(language, active, v)).content
            }
          />
        )}
      </div>
    </>
  );
}

function SinkPreview({ detail: _detail }: { detail: SinkDetail }) {
  // 占位：preview 现在由 <SinkRulesEditor /> 负责
  return null;
}
// 让 TS 知道 SinkPreview 已存在但允许被忽略
void SinkPreview;
