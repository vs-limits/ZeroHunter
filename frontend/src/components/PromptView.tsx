import { useEffect, useState } from "react";
import {
  PromptDetail,
  listPromptHistory,
  readPrompt,
  readPromptVersion,
  writePrompt,
} from "../api";
import { bilingualPrompt } from "../i18n";
import { ContentEditor } from "./ContentEditor";

interface Props {
  name: string;
}

export function PromptView({ name }: Props) {
  const [data, setData] = useState<(PromptDetail & { history_count?: number }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    setData(null);
    setError(null);
    readPrompt(name)
      .then((r) => setData(r as any))
      .catch((e) => setError(String(e)));
  }, [name, version]);

  const bi = bilingualPrompt(name);

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">{bi.zh}</h2>
          <div className="dm-pageheader-extra">
            {data && (
              <span className="dm-meta-line">
                {Math.round((data.size ?? 0) / 1024)} KB · {data.path}
              </span>
            )}
          </div>
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
        {data && (
          <ContentEditor
            title={bi.zh}
            subtitle={bi.en}
            path={data.path}
            size={data.size}
            language="markdown"
            content={data.content}
            historyCount={(data as any).history_count}
            onSave={async (content, reason) => {
              await writePrompt(name, content, reason);
              setVersion((v) => v + 1);
            }}
            loadHistory={async () => (await listPromptHistory(name)).items}
            loadHistoryVersion={async (v) => (await readPromptVersion(name, v)).content}
          />
        )}
      </div>
    </>
  );
}
