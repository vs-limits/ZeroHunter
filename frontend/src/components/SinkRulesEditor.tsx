/**
 * 汇聚点规则的"结构化可视化编辑器"。
 *
 * - 直接以卡片表单形式展示每条 SinkRule，所有字段双击进入编辑模式
 * - 支持新增 / 复制 / 删除规则
 * - 修改后右上角出现「保存（自动归档）」按钮，归档版本号
 * - 内置脏检查：父组件可读取 dirty 状态用于切换拦截
 */

import { useEffect, useMemo, useState } from "react";
import { SinkRuleDict } from "../api";
import { SEVERITY_LABELS, VULN_LABELS, bilingualVuln } from "../i18n";
import { useDirtyGuard } from "../hooks/useDirtyGuard";
import "../styles/sink-editor.css";

type Severity = "critical" | "high" | "medium" | "low";

interface Props {
  vulnerability: string | null;
  rules: SinkRuleDict[];
  parseError?: string | null;
  /** 新增规则时的 id 前缀，例如 ``c-auth`` */
  idPrefix: string;
  onSave: (
    nextVuln: string,
    nextRules: SinkRuleDict[],
    reason: string
  ) => Promise<void>;
}

export function SinkRulesEditor({
  vulnerability,
  rules,
  parseError,
  idPrefix,
  onSave,
}: Props) {
  const [vuln, setVuln] = useState(vulnerability || "");
  const [items, setItems] = useState<SinkRuleDict[]>(rules);
  const [original, setOriginal] = useState({ vuln: vulnerability || "", rules });
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 当外层切换文件 / 重新读取后重置
  useEffect(() => {
    setVuln(vulnerability || "");
    setItems(rules);
    setOriginal({ vuln: vulnerability || "", rules });
    setReason("");
    setError(null);
  }, [vulnerability, rules]);

  const dirty = useMemo(() => {
    if (vuln !== original.vuln) return true;
    if (JSON.stringify(items) !== JSON.stringify(original.rules)) return true;
    return false;
  }, [vuln, items, original]);

  useDirtyGuard(dirty, "汇聚点规则编辑有未保存修改，确定离开吗？");

  function patchRule(index: number, patch: Partial<SinkRuleDict>) {
    setItems((prev) => {
      const next = [...prev];
      next[index] = { ...next[index], ...patch } as SinkRuleDict;
      return next;
    });
  }

  function addRule() {
    const idx = items.length + 1;
    const id = `${idPrefix}-rule-${String(idx).padStart(3, "0")}`;
    const empty: SinkRuleDict = {
      id,
      function: "新规则",
      call_regex: "",
      description: "",
      argument_roles: [],
      extensions: [],
      severity: "medium",
      require_dynamic: false,
    };
    setItems((prev) => [...prev, empty]);
  }

  function duplicateRule(i: number) {
    const src = items[i];
    const copy: SinkRuleDict = {
      ...src,
      id: `${src.id}-copy`,
    };
    setItems((prev) => [
      ...prev.slice(0, i + 1),
      copy,
      ...prev.slice(i + 1),
    ]);
  }

  function removeRule(i: number) {
    if (!window.confirm(`确定删除规则「${items[i].id}」？`)) return;
    setItems((prev) => prev.filter((_, idx) => idx !== i));
  }

  function moveRule(i: number, delta: number) {
    const target = i + delta;
    if (target < 0 || target >= items.length) return;
    setItems((prev) => {
      const next = [...prev];
      [next[i], next[target]] = [next[target], next[i]];
      return next;
    });
  }

  function discard() {
    if (!dirty) return;
    if (!window.confirm("确定放弃所有未保存的规则修改？")) return;
    setVuln(original.vuln);
    setItems(original.rules);
    setReason("");
  }

  async function save() {
    if (!dirty || saving) return;
    // 简单校验
    const ids = new Set<string>();
    for (const r of items) {
      if (!r.id?.trim()) {
        setError("有规则的 id 为空");
        return;
      }
      if (ids.has(r.id)) {
        setError(`规则 id 重复：${r.id}`);
        return;
      }
      ids.add(r.id);
      if (!r.call_regex?.trim()) {
        setError(`规则 ${r.id} 的 call_regex 不能为空`);
        return;
      }
    }
    setError(null);
    setSaving(true);
    try {
      await onSave(vuln, items, reason);
      setOriginal({ vuln, rules: items });
      setReason("");
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  const sevCount = useMemo(() => {
    const c: Record<string, number> = {};
    items.forEach((r) => {
      c[r.severity] = (c[r.severity] ?? 0) + 1;
    });
    return c;
  }, [items]);

  return (
    <div className="dm-sink-edit">
      {parseError && (
        <div className="dm-banner-error" style={{ borderRadius: 6, marginBottom: 12 }}>
          源码解析失败：{parseError}（请通过「编辑」标签直接修改源码后再切回结构化视图）
        </div>
      )}

      {/* 头部：vulnerability + 操作 */}
      <div className="dm-sink-edit-head">
        <div className="dm-sink-edit-vuln">
          <label className="dm-pf-label">漏洞类型</label>
          <select
            className="dm-sink-edit-vuln-input"
            value={vuln}
            onChange={(e) => setVuln(e.target.value)}
          >
            {Object.entries(VULN_LABELS).map(([k, zh]) => (
              <option key={k} value={k}>
                {zh}（{k}）
              </option>
            ))}
          </select>
        </div>
        <div className="dm-spacer" />
        {dirty && <span className="dm-tag verdict-uncertain">未保存</span>}
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

      {/* 备注 + 统计 */}
      <div className="dm-sink-edit-meta">
        <input
          type="text"
          className="dm-sink-edit-reason"
          placeholder="本次修改备注（可选）"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <div className="dm-sink-edit-stats">
          <span className="dm-tag">总数 {items.length}</span>
          {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
            <span key={s} className={`dm-tag sev-${s}`}>
              {SEVERITY_LABELS[s]} {sevCount[s] ?? 0}
            </span>
          ))}
        </div>
      </div>

      {error && (
        <div className="dm-banner-error" style={{ borderRadius: 6, margin: "8px 0" }}>
          {error}
        </div>
      )}

      <div className="dm-sink-edit-list">
        {items.map((r, i) => (
          <RuleEditor
            key={i}
            rule={r}
            index={i}
            total={items.length}
            onChange={(patch) => patchRule(i, patch)}
            onDuplicate={() => duplicateRule(i)}
            onRemove={() => removeRule(i)}
            onMove={(delta) => moveRule(i, delta)}
          />
        ))}
      </div>

      <button className="dm-sink-add" onClick={addRule}>
        ＋ 新增规则
      </button>
    </div>
  );
}

// =============================================================
// 单条规则编辑卡
// =============================================================

const SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low"];

function RuleEditor({
  rule,
  index,
  total,
  onChange,
  onDuplicate,
  onRemove,
  onMove,
}: {
  rule: SinkRuleDict;
  index: number;
  total: number;
  onChange: (patch: Partial<SinkRuleDict>) => void;
  onDuplicate: () => void;
  onRemove: () => void;
  onMove: (delta: number) => void;
}) {
  return (
    <div className={`dm-sink-rule dm-row-sev-${rule.severity}`}>
      <div className="dm-sink-rule-head">
        <span className="dm-sink-rule-no">#{index + 1}</span>
        <EditableText
          value={rule.id}
          onChange={(v) => onChange({ id: v })}
          className="dm-sink-rule-id"
          placeholder="rule-id"
        />
        <SeveritySelect
          value={rule.severity}
          onChange={(v) => onChange({ severity: v })}
        />
        <label className="dm-sink-toggle">
          <input
            type="checkbox"
            checked={!!rule.require_dynamic}
            onChange={(e) => onChange({ require_dynamic: e.target.checked })}
          />
          <span>需动态信号</span>
        </label>
        <div className="dm-spacer" />
        <button
          className="dm-btn dm-btn-ghost dm-btn-sm"
          onClick={() => onMove(-1)}
          disabled={index === 0}
          title="上移"
        >
          ↑
        </button>
        <button
          className="dm-btn dm-btn-ghost dm-btn-sm"
          onClick={() => onMove(1)}
          disabled={index === total - 1}
          title="下移"
        >
          ↓
        </button>
        <button
          className="dm-btn dm-btn-ghost dm-btn-sm"
          onClick={onDuplicate}
          title="复制为新规则"
        >
          复制
        </button>
        <button
          className="dm-btn dm-btn-ghost dm-btn-sm"
          onClick={onRemove}
          style={{ color: "var(--color-error)" }}
        >
          删除
        </button>
      </div>

      <div className="dm-sink-rule-body">
        <Field label="函数 / 形态" full>
          <EditableText
            value={rule.function}
            onChange={(v) => onChange({ function: v })}
            mono
          />
        </Field>
        <Field label="正则" full mono>
          <EditableText
            value={rule.call_regex}
            onChange={(v) => onChange({ call_regex: v })}
            mono
            multiline
          />
        </Field>
        <Field label="参数角色">
          <EditableList
            values={rule.argument_roles ?? []}
            onChange={(v) => onChange({ argument_roles: v })}
            placeholder="例如 query, params"
          />
        </Field>
        <Field label="文件后缀">
          <EditableList
            values={rule.extensions ?? []}
            onChange={(v) => onChange({ extensions: v })}
            placeholder=".c, .h"
          />
        </Field>
        <Field label="附加正则" full mono>
          <EditableLines
            values={rule.extra_match_regex ?? []}
            onChange={(v) => onChange({ extra_match_regex: v })}
            placeholder="每行一个正则；留空表示不需要"
          />
        </Field>
        <Field label="说明" full>
          <EditableText
            value={rule.description}
            onChange={(v) => onChange({ description: v })}
            multiline
          />
        </Field>
      </div>
    </div>
  );
}

function Field({
  label,
  full,
  mono,
  children,
}: {
  label: string;
  full?: boolean;
  mono?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className={`dm-sink-field ${full ? "full" : ""} ${mono ? "mono" : ""}`}>
      <div className="dm-sink-field-label">
        <span>{label}</span>
      </div>
      <div className="dm-sink-field-body">{children}</div>
    </div>
  );
}

// =============================================================
// 内嵌可编辑控件
// =============================================================

function EditableText({
  value,
  onChange,
  className,
  placeholder,
  mono,
  multiline,
}: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
  placeholder?: string;
  mono?: boolean;
  multiline?: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  function commit() {
    if (draft !== value) onChange(draft);
    setEditing(false);
  }
  function cancel() {
    setDraft(value);
    setEditing(false);
  }

  if (editing) {
    if (multiline) {
      return (
        <textarea
          className={`dm-inline-input ${mono ? "mono" : ""} ${className ?? ""}`}
          value={draft}
          autoFocus
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Escape") cancel();
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) commit();
          }}
          rows={Math.max(2, draft.split("\n").length)}
        />
      );
    }
    return (
      <input
        type="text"
        className={`dm-inline-input ${mono ? "mono" : ""} ${className ?? ""}`}
        value={draft}
        autoFocus
        placeholder={placeholder}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Escape") cancel();
          if (e.key === "Enter") commit();
        }}
      />
    );
  }

  return (
    <span
      className={`dm-inline-text ${mono ? "mono" : ""} ${
        !value ? "empty" : ""
      } ${className ?? ""}`}
      tabIndex={0}
      title="双击编辑"
      onDoubleClick={() => setEditing(true)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === "F2") setEditing(true);
      }}
    >
      {value || placeholder || "（空）"}
    </span>
  );
}

function SeveritySelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: Severity) => void;
}) {
  return (
    <select
      className={`dm-inline-input dm-sev-select sev-${value}`}
      value={value}
      onChange={(e) => onChange(e.target.value as Severity)}
    >
      {SEVERITY_OPTIONS.map((s) => (
        <option key={s} value={s}>
          {SEVERITY_LABELS[s]}（{s}）
        </option>
      ))}
    </select>
  );
}

function EditableList({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState("");
  return (
    <div className="dm-chips">
      {values.map((v, i) => (
        <span key={i} className="dm-chip">
          <span>{v}</span>
          <button
            className="dm-chip-remove"
            onClick={() => onChange(values.filter((_, idx) => idx !== i))}
            title="删除"
          >
            ×
          </button>
        </span>
      ))}
      <input
        type="text"
        className="dm-chip-input"
        value={draft}
        placeholder={values.length === 0 ? placeholder : "回车添加"}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && draft.trim()) {
            e.preventDefault();
            const v = draft.trim();
            if (!values.includes(v)) onChange([...values, v]);
            setDraft("");
          } else if (e.key === "Backspace" && draft === "" && values.length > 0) {
            onChange(values.slice(0, -1));
          }
        }}
      />
    </div>
  );
}

function EditableLines({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(values.join("\n"));

  useEffect(() => {
    setDraft(values.join("\n"));
  }, [values]);

  function commit() {
    const next = draft
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    if (next.length !== values.length || next.some((v, i) => v !== values[i])) {
      onChange(next);
    }
    setEditing(false);
  }

  if (editing) {
    return (
      <textarea
        className="dm-inline-input mono"
        value={draft}
        autoFocus
        rows={Math.max(2, draft.split("\n").length + 1)}
        placeholder={placeholder}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            setDraft(values.join("\n"));
            setEditing(false);
          }
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) commit();
        }}
      />
    );
  }

  if (values.length === 0) {
    return (
      <span
        className="dm-inline-text mono empty"
        tabIndex={0}
        title="双击编辑"
        onDoubleClick={() => setEditing(true)}
      >
        {placeholder || "（无）"}
      </span>
    );
  }

  return (
    <div
      className="dm-rule-codeblock"
      tabIndex={0}
      title="双击编辑"
      onDoubleClick={() => setEditing(true)}
    >
      {values.map((v, i) => (
        <code key={i} className="dm-rule-code dm-rule-block">
          {v}
        </code>
      ))}
    </div>
  );
}
