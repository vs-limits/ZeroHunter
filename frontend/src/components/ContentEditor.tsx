/**
 * 通用内容编辑器：用于 Prompts / Skills / Sinks。
 *
 * 功能：
 * - 预览 / 编辑 / 历史 三视图切换
 * - 编辑态使用 textarea，支持记录"原始 / 当前"差异
 * - 历史侧栏：自动归档版本号 + 时间，可点击查看回滚
 */

import { useEffect, useMemo, useState } from "react";
import { HistoryEntry } from "../api";
import { useDirtyGuard } from "../hooks/useDirtyGuard";
import { Markdown } from "./Markdown";
import "../styles/editor.css";

export type ContentMode = "preview" | "edit" | "history";

export interface ContentEditorProps {
  /** 文件标题（中文） */
  title: string;
  /** 文件英文/原始名 */
  subtitle: string;
  /** 文件路径，仅展示用 */
  path?: string;
  /** 文件大小，仅展示用 */
  size?: number;
  /** 文件类型（影响预览渲染策略） */
  language: "markdown" | "python";
  /** 当前服务端最新内容，用于初始化与重置 */
  content: string;
  /** 历史版本数量提示 */
  historyCount?: number;
  /** 渲染自定义预览（python 解析后的卡片视图等）。若不传，markdown 用 Markdown 组件渲染，python 落回源码 */
  renderPreview?: () => React.ReactNode;
  /** 保存：提交内容 + 备注，返回新的内容（一般是同步回 textarea） */
  onSave: (newContent: string, reason: string) => Promise<void>;
  /** 加载历史索引 */
  loadHistory: () => Promise<HistoryEntry[]>;
  /** 加载某一版的历史内容 */
  loadHistoryVersion: (version: number) => Promise<string>;
}

export function ContentEditor(props: ContentEditorProps) {
  const {
    title,
    subtitle,
    path,
    size,
    language,
    content,
    historyCount,
    renderPreview,
    onSave,
    loadHistory,
    loadHistoryVersion,
  } = props;

  const [mode, setMode] = useState<ContentMode>("preview");
  const [draft, setDraft] = useState(content);
  const [original, setOriginal] = useState(content);
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [history, setHistory] = useState<HistoryEntry[] | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [activeVersion, setActiveVersion] = useState<number | null>(null);
  const [versionContent, setVersionContent] = useState<string>("");
  const [versionLoading, setVersionLoading] = useState(false);

  // 切换文件时重置
  useEffect(() => {
    setDraft(content);
    setOriginal(content);
    setReason("");
    setMode("preview");
    setHistory(null);
    setActiveVersion(null);
  }, [content]);

  const dirty = draft !== original;
  const { confirmLeave } = useDirtyGuard(dirty);

  // 切换 mode 前提示
  function tryChangeMode(next: ContentMode) {
    if (mode === "edit" && dirty && next !== "edit") {
      if (!confirmLeave()) return;
    }
    setMode(next);
  }

  async function ensureHistoryLoaded(forceReload = false) {
    if (history && !forceReload) return;
    try {
      const items = await loadHistory();
      setHistory(items);
      if (items.length > 0 && activeVersion == null) {
        await openVersion(items[0].version);
      }
    } catch (err) {
      setHistoryError(String(err));
    }
  }

  useEffect(() => {
    if (mode === "history") {
      ensureHistoryLoaded();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  async function openVersion(version: number) {
    setActiveVersion(version);
    setVersionLoading(true);
    setVersionContent("");
    try {
      const txt = await loadHistoryVersion(version);
      setVersionContent(txt);
    } catch (err) {
      setVersionContent(`[读取失败] ${String(err)}`);
    } finally {
      setVersionLoading(false);
    }
  }

  async function save() {
    if (!dirty || saving) return;
    setSaving(true);
    setError(null);
    try {
      await onSave(draft, reason);
      setOriginal(draft);
      setReason("");
      // 保存后刷新历史
      setHistory(null);
      if (mode === "history") {
        await ensureHistoryLoaded(true);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  function discard() {
    if (!dirty) return;
    if (!window.confirm("确定放弃所有未保存的修改？")) return;
    setDraft(original);
    setReason("");
  }

  function copyVersionToDraft() {
    if (!versionContent) return;
    if (
      dirty &&
      !window.confirm("当前编辑器有未保存修改，是否覆盖为该历史版本内容？")
    ) {
      return;
    }
    setDraft(versionContent);
    setMode("edit");
  }

  return (
    <div className="dm-card">
      <div className="dm-card-head">
        <h3 className="dm-card-title">{title}</h3>
        {dirty && <span className="dm-tag verdict-uncertain">未保存</span>}
        <div className="dm-spacer" />
        <div className="dm-segctrl">
          <button
            className={`dm-segctrl-item ${mode === "preview" ? "active" : ""}`}
            onClick={() => tryChangeMode("preview")}
          >
            预览
          </button>
          <button
            className={`dm-segctrl-item ${mode === "edit" ? "active" : ""}`}
            onClick={() => tryChangeMode("edit")}
          >
            编辑
          </button>
          <button
            className={`dm-segctrl-item ${mode === "history" ? "active" : ""}`}
            onClick={() => tryChangeMode("history")}
          >
            历史 {historyCount ? <span className="dm-tag-count">{historyCount}</span> : null}
          </button>
        </div>
      </div>
      <div className="dm-card-sub">
        {path}
        {size != null && ` · ${(size / 1024).toFixed(1)} KB`}
      </div>

      {error && (
        <div className="dm-banner-error" style={{ borderRadius: 6, marginBottom: 12 }}>
          {error}
        </div>
      )}

      {mode === "preview" && (
        <div className="dm-md">
          {renderPreview ? (
            renderPreview()
          ) : language === "markdown" ? (
            <Markdown source={content} />
          ) : (
            <pre className="dm-source-block">{content}</pre>
          )}
        </div>
      )}

      {mode === "edit" && (
        <div className="dm-editor">
          <textarea
            className={`dm-editor-area lang-${language}`}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            spellCheck={false}
            placeholder="在此编辑内容…"
          />
          <div className="dm-editor-actions">
            <input
              type="text"
              className="dm-editor-reason"
              placeholder="本次修改备注（可选，将作为版本说明保存）"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <span className="dm-editor-stat">
              {draft.length.toLocaleString()} 字符
              {dirty && <> · {Math.abs(draft.length - original.length)} 字差</>}
            </span>
            <button
              className="dm-btn"
              onClick={discard}
              disabled={!dirty || saving}
            >
              放弃
            </button>
            <button
              className="dm-btn dm-btn-primary"
              onClick={save}
              disabled={!dirty || saving}
            >
              {saving ? "保存中…" : "保存（自动归档为新版本）"}
            </button>
          </div>
        </div>
      )}

      {mode === "history" && (
        <HistoryView
          history={history}
          historyError={historyError}
          activeVersion={activeVersion}
          versionContent={versionContent}
          versionLoading={versionLoading}
          onSelectVersion={openVersion}
          onApplyVersion={copyVersionToDraft}
          previewLanguage={language}
        />
      )}
    </div>
  );
}

function HistoryView({
  history,
  historyError,
  activeVersion,
  versionContent,
  versionLoading,
  onSelectVersion,
  onApplyVersion,
  previewLanguage,
}: {
  history: HistoryEntry[] | null;
  historyError: string | null;
  activeVersion: number | null;
  versionContent: string;
  versionLoading: boolean;
  onSelectVersion: (v: number) => void;
  onApplyVersion: () => void;
  previewLanguage: "markdown" | "python";
}) {
  const activeEntry = useMemo(
    () => history?.find((e) => e.version === activeVersion) ?? null,
    [history, activeVersion]
  );

  if (historyError) {
    return (
      <div className="dm-meta-line" style={{ color: "var(--color-error)" }}>
        {historyError}
      </div>
    );
  }
  if (!history) {
    return <div className="dm-empty-tip">读取中…</div>;
  }
  if (history.length === 0) {
    return (
      <div className="dm-empty-tip">
        尚无历史版本（首次保存后会自动归档）
      </div>
    );
  }

  return (
    <div className="dm-history-layout">
      <div className="dm-history-list">
        {history.map((e) => (
          <button
            key={e.version}
            className={`dm-history-item ${activeVersion === e.version ? "active" : ""}`}
            onClick={() => onSelectVersion(e.version)}
          >
            <div className="dm-history-item-head">
              <span className="dm-history-version">v{e.version}</span>
              <span className="dm-history-size">
                {(e.size / 1024).toFixed(1)} KB
              </span>
            </div>
            <div className="dm-history-time">{formatTs(e.timestamp)}</div>
            {e.reason && <div className="dm-history-reason">{e.reason}</div>}
          </button>
        ))}
      </div>

      <div className="dm-history-detail">
        {activeEntry && (
          <div className="dm-history-detail-head">
            <span className="dm-history-version">v{activeEntry.version}</span>
            <span className="dm-meta-line">{formatTs(activeEntry.timestamp)}</span>
            {activeEntry.reason && (
              <span className="dm-meta-line">备注：{activeEntry.reason}</span>
            )}
            <div className="dm-spacer" />
            <button className="dm-btn dm-btn-sm" onClick={onApplyVersion}>
              恢复到编辑器
            </button>
          </div>
        )}
        {versionLoading ? (
          <div className="dm-empty-tip">读取版本…</div>
        ) : (
          <pre className={`dm-source-block lang-${previewLanguage}`}>
            {versionContent}
          </pre>
        )}
      </div>
    </div>
  );
}

function formatTs(ts: string): string {
  if (!ts) return "";
  return ts.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "");
}
