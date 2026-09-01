import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  LlmConcurrentTestResult,
  LlmInput,
  MiniCustomConfig,
  LlmProfile,
  LlmSettingsResponse,
  LlmTestResult,
  createLlm,
  deleteLlm,
  listLlms,
  selectLlm,
  testLlm,
  testLlmConcurrent,
  updateLlm,
} from "../api";
import { Section } from "./ui/Section";
import "../styles/llm-settings.css";

const MINI_CONFIG_DEFAULTS: MiniCustomConfig = {
  thinking: false,
  reasoning_effort: "high",
  top_k: -1,
  min_p: 0,
  repetition_penalty: 1,
};

const EMPTY_FORM: LlmInput = {
  name: "",
  notes: "",
  base_url: "",
  api_key: "",
  model_name: "",
  protocol: "openai",
  config_type: "standard",
  mini_config: MINI_CONFIG_DEFAULTS,
};

interface TestState {
  target: string;
  result?: LlmTestResult;
  concurrentResult?: LlmConcurrentTestResult;
  error?: string;
}

export function LlmSettingsView() {
  const [data, setData] = useState<LlmSettingsResponse | null>(null);
  const [form, setForm] = useState<LlmInput>({
    ...EMPTY_FORM,
    mini_config: { ...MINI_CONFIG_DEFAULTS },
  });
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testState, setTestState] = useState<TestState | null>(null);
  const [concurrentCount, setConcurrentCount] = useState(5);
  const [successThreshold, setSuccessThreshold] = useState(5);

  const activeProfile = useMemo(
    () => data?.items.find((item) => item.id === data.active_id) ?? null,
    [data]
  );

  const editingProfile = useMemo(
    () => data?.items.find((item) => item.id === editingId) ?? null,
    [data, editingId]
  );

  function load() {
    setLoading(true);
    setError(null);
    listLlms()
      .then((r) => setData(r))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, []);

  function patchForm(patch: Partial<LlmInput>) {
    setForm((prev) => ({ ...prev, ...patch }));
  }

  function resetForm() {
    setEditingId(null);
    setForm({ ...EMPTY_FORM, mini_config: { ...MINI_CONFIG_DEFAULTS } });
  }

  function startEdit(profile: LlmProfile) {
    setEditingId(profile.id);
    setTestState(null);
    setError(null);
    setForm({
      name: profile.name,
      notes: profile.notes,
      base_url: profile.base_url,
      api_key: "",
      model_name: profile.model_name,
      protocol: profile.protocol,
      config_type: profile.config_type || "standard",
      mini_config: { ...MINI_CONFIG_DEFAULTS, ...(profile.mini_config || {}) },
    });
  }

  function patchMiniConfig(patch: Partial<MiniCustomConfig>) {
    setForm((prev) => ({
      ...prev,
      mini_config: {
        ...MINI_CONFIG_DEFAULTS,
        ...(prev.mini_config || {}),
        ...patch,
      },
    }));
  }

  function onConfigTypeChange(configType: string) {
    setForm((prev) => {
      if (configType !== "mini_custom") {
        return { ...prev, config_type: configType };
      }
      return {
        ...prev,
        config_type: "mini_custom",
        name: prev.name || "Mini自定义配置",
        base_url: prev.base_url || "https://apiai.sztu.edu.cn/v1",
        model_name: prev.model_name || "deepseek-v4-pro",
        protocol: "openai",
        mini_config: {
          ...MINI_CONFIG_DEFAULTS,
          ...(prev.mini_config || {}),
        },
      };
    });
  }

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      if (editingId) {
        await updateLlm(editingId, form);
      } else {
        await createLlm(form);
      }
      resetForm();
      await listLlms().then((r) => setData(r));
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  async function onSelect(profile: LlmProfile) {
    setError(null);
    try {
      await selectLlm(profile.id);
      await listLlms().then((r) => setData(r));
    } catch (err) {
      setError(String(err));
    }
  }

  async function onDelete(profile: LlmProfile) {
    if (!window.confirm(`确定删除 LLM「${profile.name}」？`)) return;
    setError(null);
    try {
      const next = await deleteLlm(profile.id);
      setData(next);
      if (editingId === profile.id) {
        resetForm();
      }
    } catch (err) {
      setError(String(err));
    }
  }

  async function onTestProfile(profile: LlmProfile) {
    setTesting(profile.id);
    setTestState(null);
    try {
      const result = await testLlm({ llm_id: profile.id });
      setTestState({ target: profile.name, result });
    } catch (err) {
      setTestState({ target: profile.name, error: String(err) });
    } finally {
      setTesting(null);
    }
  }

  async function onTestDraft() {
    setTesting("draft");
    setTestState(null);
    try {
      const payload = editingId ? { ...form, llm_id: editingId } : form;
      const result = await testLlm(payload);
      setTestState({ target: form.name || "未保存配置", result });
    } catch (err) {
      setTestState({ target: form.name || "未保存配置", error: String(err) });
    } finally {
      setTesting(null);
    }
  }

  function concurrentParams() {
    const count = clampInt(concurrentCount, 1, 50, 5);
    return {
      count,
      success_threshold: clampInt(successThreshold, 1, count, count),
    };
  }

  async function onConcurrentProfile(profile: LlmProfile) {
    setTesting(`concurrent:${profile.id}`);
    setTestState(null);
    try {
      const result = await testLlmConcurrent({
        llm_id: profile.id,
        ...concurrentParams(),
      });
      setTestState({ target: `${profile.name} 并发测试`, concurrentResult: result });
    } catch (err) {
      setTestState({ target: `${profile.name} 并发测试`, error: String(err) });
    } finally {
      setTesting(null);
    }
  }

  async function onConcurrentDraft() {
    setTesting("concurrent:draft");
    setTestState(null);
    try {
      const payload = editingId ? { ...form, llm_id: editingId } : form;
      const result = await testLlmConcurrent({
        ...payload,
        ...concurrentParams(),
      });
      setTestState({
        target: `${form.name || "未保存配置"} 并发测试`,
        concurrentResult: result,
      });
    } catch (err) {
      setTestState({
        target: `${form.name || "未保存配置"} 并发测试`,
        error: String(err),
      });
    } finally {
      setTesting(null);
    }
  }

  const canSubmit = Boolean(
    form.name &&
      form.base_url &&
      form.model_name &&
      form.protocol &&
      (form.api_key || (editingId && editingProfile?.has_api_key))
  );
  const miniConfig = { ...MINI_CONFIG_DEFAULTS, ...(form.mini_config || {}) };

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">LLM 设置</h2>
          <div className="dm-pageheader-extra">
            <button className="dm-btn dm-btn-ghost" onClick={load} disabled={loading}>
              刷新
            </button>
          </div>
        </div>
      </div>

      <div className="dm-tab-content dm-llm-settings">
        {error && <div className="dm-banner-inline dm-banner-inline-error">{error}</div>}
        {testState && <TestResult state={testState} />}
        <div className="dm-llm-test-controls">
          <label>
            <span>并发次数</span>
            <input
              type="number"
              min={1}
              max={50}
              step={1}
              value={concurrentCount}
              onChange={(e) => {
                const next = clampInt(Number(e.target.value), 1, 50, 5);
                setConcurrentCount(next);
                setSuccessThreshold((prev) => clampInt(prev, 1, next, next));
              }}
            />
          </label>
          <label>
            <span>验收成功数</span>
            <input
              type="number"
              min={1}
              max={concurrentCount}
              step={1}
              value={successThreshold}
              onChange={(e) =>
                setSuccessThreshold(
                  clampInt(Number(e.target.value), 1, concurrentCount, concurrentCount)
                )
              }
            />
          </label>
        </div>

        <Section title="当前模型">
          {activeProfile ? (
            <ProfileSummary profile={activeProfile} />
          ) : (
            <div className="dm-empty-tip">暂无激活 LLM</div>
          )}
        </Section>

        <Section
          title="LLM 列表"
          extra={
            <span className="dm-meta-line">
              {data?.store_path ? `store: ${data.store_path}` : ""}
            </span>
          }
        >
          <div className="dm-llm-list">
            {data?.items.map((profile) => (
              <div
                key={profile.id}
                className={`dm-llm-profile ${profile.active ? "active" : ""}`}
              >
                <div className="dm-llm-profile-main">
                  <div className="dm-llm-profile-head">
                    <span className="dm-llm-profile-name">{profile.name}</span>
                    <span className="dm-tag">{configTypeLabel(profile.config_type)}</span>
                    {profile.active && <span className="dm-tag dm-llm-active-tag">当前</span>}
                  </div>
                  <div className="dm-llm-profile-model">
                    {profile.protocol}/{profile.model_name}
                  </div>
                  <div className="dm-llm-profile-meta">{profile.base_url}</div>
                  <div className="dm-llm-profile-meta">
                    API Key: {profile.api_key_masked || "-"}
                  </div>
                  {profile.notes && <div className="dm-llm-notes">{profile.notes}</div>}
                </div>
                <div className="dm-llm-profile-actions">
                  <button
                    className="dm-btn dm-btn-ghost"
                    onClick={() => onTestProfile(profile)}
                    disabled={testing !== null}
                  >
                    {testing === profile.id ? "测试中" : "测试连接"}
                  </button>
                  <button
                    className="dm-btn dm-btn-ghost"
                    onClick={() => onConcurrentProfile(profile)}
                    disabled={testing !== null}
                  >
                    {testing === `concurrent:${profile.id}` ? "并发测试中" : "并发测试"}
                  </button>
                  <button className="dm-btn dm-btn-ghost" onClick={() => startEdit(profile)}>
                    编辑
                  </button>
                  <button
                    className="dm-btn"
                    onClick={() => onSelect(profile)}
                    disabled={profile.active}
                  >
                    设为当前
                  </button>
                  <button
                    className="dm-btn dm-btn-danger"
                    onClick={() => onDelete(profile)}
                  >
                    删除
                  </button>
                </div>
              </div>
            ))}
            {data && data.items.length === 0 && (
              <div className="dm-empty-tip">暂无 LLM 配置</div>
            )}
          </div>
        </Section>

        <Section title={editingId ? "编辑 LLM" : "新增 LLM"}>
          <form onSubmit={onSave}>
            <div className="dm-llm-form-grid">
              <label>
                <span>命名</span>
                <input
                  value={form.name}
                  onChange={(e) => patchForm({ name: e.target.value })}
                  placeholder="例如 MiMo Token Plan"
                />
              </label>
              <label>
                <span>配置类型</span>
                <select
                  value={form.config_type}
                  onChange={(e) => onConfigTypeChange(e.target.value)}
                >
                  <option value="standard">标准配置</option>
                  <option value="mini_custom">Mini自定义配置</option>
                </select>
              </label>
              <label>
                <span>协议格式</span>
                <input
                  list="dm-llm-protocols"
                  value={form.protocol}
                  onChange={(e) => patchForm({ protocol: e.target.value })}
                  placeholder="openai"
                />
                <datalist id="dm-llm-protocols">
                  <option value="openai" />
                  <option value="anthropic" />
                  <option value="deepseek" />
                  <option value="azure" />
                  <option value="ollama" />
                </datalist>
              </label>
              <label>
                <span>Base URL</span>
                <input
                  value={form.base_url}
                  onChange={(e) => patchForm({ base_url: e.target.value })}
                  placeholder="https://token-plan-sgp.xiaomimimo.com/v1"
                />
              </label>
              <label>
                <span>模型名称</span>
                <input
                  value={form.model_name}
                  onChange={(e) => patchForm({ model_name: e.target.value })}
                  placeholder="mimo-v2.5-pro"
                />
              </label>
              <label className="dm-llm-form-wide">
                <span>API Key</span>
                <input
                  type="password"
                  value={form.api_key}
                  onChange={(e) => patchForm({ api_key: e.target.value })}
                  placeholder={editingId ? "留空则保留原 API Key" : "tp-... / sk-..."}
                />
              </label>
              {form.config_type === "mini_custom" && (
                <div className="dm-llm-mini-grid">
                  <label className="dm-llm-mini-toggle">
                    <input
                      type="checkbox"
                      checked={miniConfig.thinking}
                      onChange={(e) => patchMiniConfig({ thinking: e.target.checked })}
                    />
                    <span>开启推理</span>
                  </label>
                  <label>
                    <span>推理强度</span>
                    <select
                      value={miniConfig.reasoning_effort}
                      onChange={(e) =>
                        patchMiniConfig({ reasoning_effort: e.target.value })
                      }
                    >
                      <option value="high">Think High</option>
                      <option value="max">Think Max</option>
                    </select>
                  </label>
                  <label>
                    <span>top_k</span>
                    <input
                      type="number"
                      step={1}
                      min={-1}
                      value={miniConfig.top_k}
                      onChange={(e) => patchMiniConfig({ top_k: Number(e.target.value) })}
                    />
                  </label>
                  <label>
                    <span>min_p</span>
                    <input
                      type="number"
                      step={0.01}
                      min={0}
                      value={miniConfig.min_p}
                      onChange={(e) => patchMiniConfig({ min_p: Number(e.target.value) })}
                    />
                  </label>
                  <label>
                    <span>repetition_penalty</span>
                    <input
                      type="number"
                      step={0.01}
                      min={0.01}
                      value={miniConfig.repetition_penalty}
                      onChange={(e) =>
                        patchMiniConfig({ repetition_penalty: Number(e.target.value) })
                      }
                    />
                  </label>
                </div>
              )}
              <label className="dm-llm-form-wide">
                <span>备注</span>
                <textarea
                  value={form.notes}
                  onChange={(e) => patchForm({ notes: e.target.value })}
                  placeholder="用途、额度或环境说明"
                  rows={3}
                />
              </label>
            </div>
            <div className="dm-llm-form-actions">
              {editingId && (
                <button type="button" className="dm-btn dm-btn-ghost" onClick={resetForm}>
                  取消编辑
                </button>
              )}
              <button
                type="button"
                className="dm-btn"
                onClick={onTestDraft}
                disabled={!canSubmit || testing !== null}
              >
                {testing === "draft" ? "测试中" : "测试连接"}
              </button>
              <button
                type="button"
                className="dm-btn"
                onClick={onConcurrentDraft}
                disabled={!canSubmit || testing !== null}
              >
                {testing === "concurrent:draft" ? "并发测试中" : "并发测试"}
              </button>
              <button
                type="submit"
                className="dm-btn dm-btn-primary"
                disabled={!canSubmit || saving}
              >
                {saving ? "保存中" : editingId ? "保存修改" : "新增 LLM"}
              </button>
            </div>
          </form>
        </Section>

        {data?.file_config && (
          <Section title=".env 生效配置">
            <div className="dm-llm-env-grid">
              <EnvCell label=".env" value={data.file_config.exists ? "存在" : "未找到"} />
              <EnvCell label="完整性" value={data.file_config.complete ? "完整" : "缺失"} />
              <EnvCell label="协议格式" value={data.file_config.protocol || "-"} />
              <EnvCell label="模型名称" value={data.file_config.model_name || "-"} />
              <EnvCell label="Base URL" value={data.file_config.base_url || "-"} wide />
              <EnvCell label="API Key" value={data.file_config.api_key_masked || "-"} />
            </div>
          </Section>
        )}
      </div>
    </>
  );
}

function configTypeLabel(configType: string | undefined) {
  return configType === "mini_custom" ? "Mini自定义配置" : "标准配置";
}

function clampInt(value: number, min: number, max: number, fallback: number) {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

function ProfileSummary({ profile }: { profile: LlmProfile }) {
  return (
    <div className="dm-llm-current">
      <div>
        <div className="dm-llm-current-name">{profile.name}</div>
        <div className="dm-llm-current-model">
          {profile.protocol}/{profile.model_name}
          <span className="dm-tag dm-llm-config-tag">{configTypeLabel(profile.config_type)}</span>
        </div>
      </div>
      <div className="dm-llm-current-url">{profile.base_url}</div>
    </div>
  );
}

function TestResult({ state }: { state: TestState }) {
  const concurrent = state.concurrentResult;
  const ok = concurrent ? concurrent.ok : Boolean(state.result);
  return (
    <div className={`dm-banner-inline ${ok ? "dm-banner-inline-ok" : "dm-banner-inline-error"}`}>
      <strong>{state.target}</strong>
      {concurrent
        ? ` 成功 ${concurrent.success_count}/${concurrent.total}，验收 ${
            concurrent.success_threshold
          } 个，失败 ${concurrent.failure_count} 个，总耗时 ${concurrent.latency_ms} ms`
        : ok
          ? ` 连接成功：${state.result?.latency_ms ?? 0} ms，返回：${state.result?.message ?? ""}`
          : ` 连接失败：${state.error}`}
    </div>
  );
}

function EnvCell({
  label,
  value,
  wide,
}: {
  label: string;
  value: string;
  wide?: boolean;
}) {
  return (
    <div className={`dm-llm-env-cell ${wide ? "wide" : ""}`}>
      <div className="dm-llm-env-label">{label}</div>
      <div className="dm-llm-env-value">{value}</div>
    </div>
  );
}
