import { useEffect, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  FolderTree,
  FileCode2,
  GitBranch,
  Link2,
  MessageSquare,
  ScanSearch,
  Settings2,
  Share2,
  ShieldAlert,
} from "lucide-react";
import {
  ProjectContainer,
  ProjectItem,
  ScanChangeOptions,
  ScanItem,
  VulnerabilityDetail,
  VulnerabilityItem,
} from "../api";
import { ScanControlPanel } from "./ScanControlPanel";
import { TreeView } from "./TreeView";
import { TreeScanView } from "./TreeScanView";
import { CallScanView } from "./CallScanView";
import { DataFlowScanView } from "./DataFlowScanView";
import { VulnerabilityCodeView } from "./VulnerabilityCodeView";
import { AuditView } from "./AuditView";
import { WorkflowView } from "./WorkflowView";
import { ConversationsView } from "./ConversationsView";
import { VulnerabilityAssociations } from "./VulnerabilityAssociations";
import "../styles/tabs.css";

export type ScanTab =
  | "control"
  | "workflow"
  | "conversations"
  | "tree"
  | "treescan"
  | "callscan"
  | "vulncode"
  | "dataflowscan"
  | "audit";

interface Props {
  project: ProjectItem;
  projectContainer: ProjectContainer;
  scan: ScanItem;
  onScanChanged: (next?: ScanItem, opts?: ScanChangeOptions) => void | Promise<void>;
  onScanDeleted: () => void | Promise<void>;
  onVulnerabilityCreated: (vulnerability: VulnerabilityDetail) => void | Promise<void>;
  onSelectVulnerability: (vulnerability: VulnerabilityItem) => void;
  onVulnerabilitiesChanged?: () => void | Promise<void>;
  onProjectChanged?: () => void | Promise<void>;
}

interface TabDef {
  key: ScanTab;
  label: string;
  icon: LucideIcon;
}

const TABS: TabDef[] = [
  { key: "control", label: "控制面板", icon: Settings2 },
  { key: "workflow", label: "工作流", icon: GitBranch },
  { key: "conversations", label: "对话流", icon: MessageSquare },
  { key: "tree", label: "目录树", icon: FolderTree },
  { key: "treescan", label: "目录画像", icon: ScanSearch },
  { key: "callscan", label: "调用扫描", icon: Link2 },
  { key: "vulncode", label: "漏洞代码", icon: FileCode2 },
  { key: "dataflowscan", label: "数据流恢复", icon: Share2 },
  { key: "audit", label: "漏洞审计", icon: ShieldAlert },
];

const TAB_KEYS = new Set<ScanTab>(TABS.map((t) => t.key));

export function isScanTab(value: string | null): value is ScanTab {
  return !!value && TAB_KEYS.has(value as ScanTab);
}

function readScanTabFromLocation(): ScanTab {
  const params = new URLSearchParams(window.location.search);
  const tab = params.get("tab");
  return isScanTab(tab) ? tab : "control";
}

function writeScanTabToLocation(
  projectPath: string,
  scanId: string,
  tab: ScanTab,
  replace = false
) {
  const params = new URLSearchParams(window.location.search);
  params.set("page", "scan");
  params.set("project_path", projectPath);
  params.set("scan_id", scanId);
  params.set("tab", tab);
  if (tab !== "audit") params.delete("audit_view");
  const next = `${window.location.pathname}?${params.toString()}${window.location.hash}`;
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (next === current) return;
  if (replace) window.history.replaceState(null, "", next);
  else window.history.pushState(null, "", next);
}

export function ScanView({
  project,
  projectContainer,
  scan,
  onScanChanged,
  onScanDeleted,
  onVulnerabilityCreated,
  onSelectVulnerability,
  onVulnerabilitiesChanged,
  onProjectChanged,
}: Props) {
  const [tab, setTab] = useState<ScanTab>(() => readScanTabFromLocation());

  // 对应旧 runId 概念：传给 TreeView/CallScanView/AuditView 等
  const runId = scan.scan_id;

  useEffect(() => {
    const next = readScanTabFromLocation();
    setTab(next);
    const params = new URLSearchParams(window.location.search);
    if (params.get("page") === "scan" && !isScanTab(params.get("tab"))) {
      writeScanTabToLocation(project.project_path, scan.scan_id, next, true);
    }
  }, [project.project_path, scan.scan_id]);

  useEffect(() => {
    function onPopState() {
      setTab(readScanTabFromLocation());
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  function selectTab(next: ScanTab) {
    setTab(next);
    writeScanTabToLocation(project.project_path, scan.scan_id, next);
  }

  return (
    <>
      <div className="dm-pageheader">
        <div className="dm-pageheader-row">
          <h2 className="dm-pageheader-title">{scan.name}</h2>
          <ScanStatusTag status={scan.status} legacy={scan.legacy} />
          {scan.target.mode === "all" ? (
            <span className="dm-tag">全仓库</span>
          ) : (
            <span className="dm-tag" title={scan.target.rel_dir ?? ""}>
              目录 · {scan.target.rel_dir}
            </span>
          )}
          <div className="dm-pageheader-extra">
            <span className="dm-meta-line">{scan.scan_id}</span>
            <span className="dm-meta-line">{project.project_path}</span>
          </div>
        </div>
      </div>

      <div className="dm-tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            className={`dm-tab ${tab === t.key ? "active" : ""}`}
            onClick={() => selectTab(t.key)}
          >
            <span className="dm-tab-icon">
              <t.icon size={15} strokeWidth={2} aria-hidden />
            </span>
            {t.label}
          </button>
        ))}
      </div>

      <div className="dm-tab-content">
        {tab === "control" && (
          <>
            <VulnerabilityAssociations
              project={projectContainer}
              target={{
                kind: "scan",
                projectPath: project.project_path,
                scanId: scan.scan_id,
                scanName: scan.name,
              }}
              onSelectVulnerability={onSelectVulnerability}
              onChanged={onVulnerabilitiesChanged}
            />
            <ScanControlPanel
              project={project}
              scan={scan}
              onScanChanged={onScanChanged}
              onScanDeleted={onScanDeleted}
            />
          </>
        )}
        {tab === "workflow" && (
          <WorkflowView project={project} runId={runId} scanStatus={scan.status} />
        )}
        {tab === "conversations" && (
          <ConversationsView project={project} runId={runId} scanStatus={scan.status} />
        )}
        {tab === "tree" && <TreeView project={project} runId={runId} />}
        {tab === "treescan" && (
          <TreeScanView
            project={project}
            projectContainer={projectContainer}
            runId={runId}
            onProjectProfileSynced={onProjectChanged}
          />
        )}
        {tab === "callscan" && <CallScanView project={project} runId={runId} />}
        {tab === "vulncode" && <VulnerabilityCodeView project={project} runId={runId} />}
        {tab === "dataflowscan" && <DataFlowScanView project={project} runId={runId} />}
        {tab === "audit" && (
          <AuditView
            project={project}
            projectContainer={projectContainer}
            runId={runId}
            scanId={scan.scan_id}
            onVulnerabilityCreated={onVulnerabilityCreated}
          />
        )}
      </div>
    </>
  );
}

function ScanStatusTag({ status, legacy }: { status: string; legacy?: boolean }) {
  if (legacy) return <span className="dm-tag">历史</span>;
  const cls =
    status === "running"
      ? "verdict-uncertain"
      : status === "done"
        ? "verdict-safe"
        : status === "error"
          ? "verdict-vulnerable"
          : "";
  const label =
    status === "running"
      ? "运行中"
      : status === "done"
        ? "已完成"
        : status === "error"
          ? "失败"
          : "待执行";
  return <span className={`dm-tag ${cls}`}>{label}</span>;
}
