import { useEffect, useState } from "react";
import { VulnerabilitySettings, getSettings, updateSettings } from "../api";
import { ExpandMode, useExpandMode } from "../lib/preferences";
import "../styles/list.css";

export function SettingsView() {
  const [expandMode, setExpandMode] = useExpandMode();
  const [settings, setSettings] = useState<VulnerabilitySettings | null>(null);
  const [tagText, setTagText] = useState("");
  const [envPresetText, setEnvPresetText] = useState("");
  const [pocPresetText, setPocPresetText] = useState("");
  const [pocParamText, setPocParamText] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    getSettings()
      .then((next) => {
        setSettings(next);
        setTagText(next.vulnerability_tags.join("\n"));
        setEnvPresetText(next.environment_file_presets.join("\n"));
        setPocPresetText(next.poc_file_presets.join("\n"));
        setPocParamText(JSON.stringify(next.poc_parameter_presets, null, 2));
      })
      .catch((e) => setMessage(String(e)));
  }, []);

  async function saveServerSettings() {
    setMessage(null);
    try {
      const next = await updateSettings({
        vulnerability_tags: lines(tagText),
        environment_file_presets: lines(envPresetText),
        poc_file_presets: lines(pocPresetText),
        poc_parameter_presets: JSON.parse(pocParamText || "[]"),
      });
      setSettings(next);
      setTagText(next.vulnerability_tags.join("\n"));
      setEnvPresetText(next.environment_file_presets.join("\n"));
      setPocPresetText(next.poc_file_presets.join("\n"));
      setPocParamText(JSON.stringify(next.poc_parameter_presets, null, 2));
      setMessage("已保存通用设置");
    } catch (e) {
      setMessage(String(e));
    }
  }

  return (
    <>
      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">通用设置</h3>
        </div>
        <div className="dm-meta-line" style={{ marginTop: 4 }}>
          详情展开方式保存在当前浏览器；漏洞标签和预设会保存到后端 .defectmine/settings.json。
        </div>
      </div>

      <div className="dm-card">
        <div className="dm-settings-row">
          <div className="dm-settings-row-info">
            <div className="dm-settings-row-title">详情展开方式</div>
            <div className="dm-settings-row-desc">
              "扫描"页 / 漏洞审计列表中，点击一条记录时如何打开它的详情。
            </div>
          </div>
          <div className="dm-spacer" />
          <div className="dm-segctrl">
            <ModeOption
              value="inline"
              current={expandMode}
              onPick={setExpandMode}
              label="向下展开"
              desc="行内展开（默认）"
            />
            <ModeOption
              value="drawer"
              current={expandMode}
              onPick={setExpandMode}
              label="右侧抽屉"
              desc="右侧滑出大图详情"
            />
          </div>
        </div>
      </div>

      <div className="dm-card">
        <div className="dm-card-head">
          <h3 className="dm-card-title">漏洞标签与文件预设</h3>
          <div className="dm-spacer" />
          <button className="dm-btn dm-btn-primary" onClick={saveServerSettings}>
            保存通用设置
          </button>
        </div>
        {message && (
          <div className="dm-meta-line" style={{ marginBottom: 12 }}>
            {message}
          </div>
        )}
        {!settings ? (
          <div className="dm-empty-tip">读取中...</div>
        ) : (
          <div className="dm-settings-grid">
            <SettingTextarea
              label="漏洞标签"
              value={tagText}
              onChange={setTagText}
              rows={8}
            />
            <SettingTextarea
              label="环境部署文件预设"
              value={envPresetText}
              onChange={setEnvPresetText}
              rows={8}
            />
            <SettingTextarea
              label="PoC 文件预设"
              value={pocPresetText}
              onChange={setPocPresetText}
              rows={8}
            />
            <SettingTextarea
              label="PoC 参数预设（JSON）"
              value={pocParamText}
              onChange={setPocParamText}
              rows={12}
              mono
            />
          </div>
        )}
      </div>
    </>
  );
}

function ModeOption({
  value,
  current,
  onPick,
  label,
  desc,
}: {
  value: ExpandMode;
  current: ExpandMode;
  onPick: (next: ExpandMode) => void;
  label: string;
  desc: string;
}) {
  const active = value === current;
  return (
    <button
      className={`dm-segctrl-item ${active ? "active" : ""}`}
      onClick={() => onPick(value)}
      title={desc}
    >
      {label}
    </button>
  );
}

function SettingTextarea({
  label,
  value,
  onChange,
  rows,
  mono,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  rows: number;
  mono?: boolean;
}) {
  return (
    <label className="dm-settings-textarea">
      <span>{label}</span>
      <textarea
        rows={rows}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={mono ? { fontFamily: "var(--mono)" } : undefined}
      />
    </label>
  );
}

function lines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}
