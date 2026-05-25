export type ArtifactStat = { size: number; mtime: number };

export type RunStatus = "pending" | "running" | "done" | "error" | "killed";

export interface ProjectSummary {
  project_path: string;
  project_root: string;
  name: string;
  project_name?: string;
  project_type?: string;
  project_function?: string;
  has_artifacts: boolean;
  artifacts: Record<string, ArtifactStat>;
  scan_count: number;
  latest_scan?: ScanRecord | null;
  audit_summary: AuditSummary;
  callscan_summary: { candidate_chains: number };
}

export interface ScanRecord {
  scan_id: string;
  name: string;
  project_path: string;
  status: RunStatus;
  step?: string;
  created_at?: string;
  updated_at?: string;
  started_at?: string | null;
  finished_at?: string | null;
  last_run_id?: string | null;
  audit_limit?: number | null;
  priority_chain_limit?: number | null;
  audit_dry_run?: boolean;
  artifacts_dir?: string;
  artifacts?: Record<string, ArtifactStat>;
  audit_summary?: AuditSummary;
  callscan_summary?: { candidate_chains: number };
}

export interface ProjectListResponse {
  items: ProjectSummary[];
}

export interface DashboardResponse {
  projects: number | ProjectSummary[];
  scans?: number;
  artifacts_ready?: number;
  totals?: Record<string, number>;
  audit_summary: AuditSummary;
  items: ProjectSummary[];
}

export interface AuditSummary {
  total_chains: number;
  total_audited: number;
  vulnerable: number;
  uncertain: number;
  safe: number;
  errors: number;
  by_vulnerability: Record<string, number>;
  by_severity: Record<string, number>;
}

export interface ArtifactJsonResponse<T> {
  path: string;
  size: number;
  mtime: number;
  data: T;
}

export interface JsonlResponse<T = unknown> {
  path: string;
  offset: number;
  limit: number;
  total: number;
  items: T[];
}

export interface MarkdownResponse {
  path: string;
  head: string;
  sections: string[];
  offset: number;
  limit: number;
  total: number;
}

export interface AuditResponse<T = unknown> {
  path: string;
  head: Record<string, unknown>;
  findings: T[];
  offset: number;
  limit: number;
  total: number;
}

export interface CreateScanInput {
  project_path: string;
  name?: string;
  step?: string;
  audit_limit?: number;
  priority_chain_limit?: number;
  audit_dry_run?: boolean;
}

export interface UpdateScanInput {
  name?: string;
  step?: string;
  audit_limit?: number | null;
  priority_chain_limit?: number;
  audit_dry_run?: boolean;
}

export interface StartScanInput {
  project_path: string;
  step?: string;
  audit_limit?: number | null;
  priority_chain_limit?: number;
  audit_dry_run?: boolean;
}

export interface StartScanResult {
  run_id: string;
  scan_id: string;
  status: RunStatus;
  cmd: string[];
  priority_chain_limit?: number | null;
  audit_limit?: number | null;
  audit_dry_run?: boolean;
}

export interface RunInfo {
  run_id: string;
  scan_id: string;
  project_path: string;
  status: RunStatus;
  return_code?: number | null;
  started_at?: number;
  finished_at?: number | null;
  elapsed_seconds?: number;
  log_path?: string;
  last_message?: string;
  error_message?: string;
  cmd?: string[];
  priority_chain_limit?: number | null;
  audit_limit?: number | null;
  audit_dry_run?: boolean;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  return (await res.json()) as T;
}

function emptyAudit(): AuditSummary {
  return {
    total_chains: 0,
    total_audited: 0,
    vulnerable: 0,
    uncertain: 0,
    safe: 0,
    errors: 0,
    by_vulnerability: {},
    by_severity: {},
  };
}

function normalizeAuditSummary(raw: any): AuditSummary {
  const summary = emptyAudit();
  if (!raw || typeof raw !== "object") return summary;
  summary.total_chains = Number(raw.total_chains ?? raw.chains ?? raw.candidate_chains ?? 0);
  summary.total_audited = Number(raw.total_audited ?? raw.audited ?? 0);
  summary.vulnerable = Number(raw.vulnerable ?? 0);
  summary.uncertain = Number(raw.uncertain ?? 0) + Number(raw.needs_review ?? 0) + Number(raw.inconclusive ?? 0);
  summary.safe = Number(raw.safe ?? raw.not_vulnerable ?? 0);
  summary.errors = Number(raw.errors ?? raw.error ?? 0);
  summary.by_vulnerability = raw.by_vulnerability ?? raw.vulnerability_counts ?? {};
  summary.by_severity = raw.by_severity ?? raw.severity_counts ?? {};
  return summary;
}

function normalizeProject(raw: any): ProjectSummary {
  const audit = normalizeAuditSummary(raw.audit_summary);
  const callscan = raw.callscan_summary ?? {};
  return {
    ...raw,
    name: raw.name || raw.project_name || raw.project_path,
    scan_count: Number(raw.scan_count ?? 0),
    audit_summary: audit,
    callscan_summary: {
      candidate_chains: Number(callscan.candidate_chains ?? callscan.priority_chains ?? raw.priority_chain_count ?? 0),
    },
  };
}

function normalizeDashboard(raw: any): DashboardResponse {
  const items = Array.isArray(raw.items)
    ? raw.items.map(normalizeProject)
    : Array.isArray(raw.projects)
      ? raw.projects.map(normalizeProject)
      : [];
  const mergedAudit = normalizeAuditSummary(raw.audit_summary);
  if (raw.totals && typeof raw.totals === "object") {
    mergedAudit.total_chains = Number(raw.totals.candidate_chains ?? mergedAudit.total_chains);
    mergedAudit.total_audited = Number(raw.totals.audited ?? mergedAudit.total_audited);
    mergedAudit.vulnerable = Number(raw.totals.vulnerable ?? mergedAudit.vulnerable);
    mergedAudit.uncertain = Number(raw.totals.uncertain ?? 0) + Number(raw.totals.needs_review ?? 0) + Number(raw.totals.inconclusive ?? 0);
    mergedAudit.safe = Number(raw.totals.safe ?? raw.totals.not_vulnerable ?? mergedAudit.safe);
    mergedAudit.errors = Number(raw.totals.errors ?? mergedAudit.errors);
  }
  if (raw.by_vulnerability) mergedAudit.by_vulnerability = raw.by_vulnerability;
  if (raw.by_severity) mergedAudit.by_severity = raw.by_severity;
  return {
    ...raw,
    projects: typeof raw.projects === "number" ? raw.projects : items.length,
    scans: Number(raw.scans ?? 0),
    artifacts_ready: Number(raw.artifacts_ready ?? raw.totals?.with_artifacts ?? 0),
    audit_summary: mergedAudit,
    items,
  };
}

export const api = {
  health: () => request<{ ok: boolean }>("/api/health"),
  projects: async () => {
    const raw = await request<{ items: any[] }>("/api/projects");
    return { items: (raw.items ?? []).map(normalizeProject) };
  },
  project: (projectPath: string) =>
    request<any>(`/api/projects/${encodeURIComponent(projectPath)}`).then(normalizeProject),
  importProject: (projectPath: string) =>
    request<any>("/api/projects/import", {
      method: "POST",
      body: JSON.stringify({ project_path: projectPath }),
    }).then(normalizeProject),
  dashboard: () => request<any>("/api/dashboard").then(normalizeDashboard),
  scans: (projectPath: string) =>
    request<{ items: ScanRecord[] }>(`/api/scans?project_path=${encodeURIComponent(projectPath)}`),
  createScan: (input: CreateScanInput) =>
    request<ScanRecord>("/api/scans", { method: "POST", body: JSON.stringify(input) }),
  updateScan: (scanId: string, projectPath: string, input: UpdateScanInput) =>
    request<ScanRecord>(
      `/api/scans/${encodeURIComponent(scanId)}?project_path=${encodeURIComponent(projectPath)}`,
      { method: "PATCH", body: JSON.stringify(input) }
    ),
  deleteScan: (scanId: string, projectPath: string) =>
    request<{ ok: boolean; scan_id: string }>(
      `/api/scans/${encodeURIComponent(scanId)}?project_path=${encodeURIComponent(projectPath)}`,
      { method: "DELETE" }
    ),
  startScan: (scanId: string, input: StartScanInput) =>
    request<StartScanResult>(`/api/scans/${encodeURIComponent(scanId)}/start`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  stopScan: (scanId: string, projectPath: string) =>
    request<{ ok: boolean; scan_id: string }>(
      `/api/scans/${encodeURIComponent(scanId)}/stop?project_path=${encodeURIComponent(projectPath)}`,
      { method: "POST" }
    ),
  run: (runId: string) => request<RunInfo>(`/api/runs/${encodeURIComponent(runId)}`),
  readConsole: (projectPath: string, scanId: string, tail = 2000) =>
    request<{ path: string; size: number; lines: string[] }>(
      `/api/scans/${encodeURIComponent(scanId)}/console?project_path=${encodeURIComponent(projectPath)}&tail=${tail}`
    ),
  artifactJson: <T = unknown>(projectPath: string, filename: string, scanId?: string) => {
    const params = new URLSearchParams({ project_path: projectPath, filename });
    if (scanId) params.set("scan_id", scanId);
    return request<ArtifactJsonResponse<T>>(`/api/artifacts/json?${params.toString()}`);
  },
  artifactJsonl: <T = unknown>(
    projectPath: string,
    filename: string,
    scanId: string | undefined,
    offset: number,
    limit: number
  ) => {
    const params = new URLSearchParams({
      project_path: projectPath,
      filename,
      offset: String(offset),
      limit: String(limit),
    });
    if (scanId) params.set("scan_id", scanId);
    return request<JsonlResponse<T>>(`/api/artifacts/jsonl?${params.toString()}`);
  },
  artifactMarkdown: (
    projectPath: string,
    filename: string,
    scanId: string | undefined,
    offset: number,
    limit: number,
    keyword?: string
  ) => {
    const params = new URLSearchParams({
      project_path: projectPath,
      filename,
      offset: String(offset),
      limit: String(limit),
    });
    if (scanId) params.set("scan_id", scanId);
    if (keyword) params.set("keyword", keyword);
    return request<MarkdownResponse>(`/api/artifacts/markdown?${params.toString()}`);
  },
  audit: <T = unknown>(
    projectPath: string,
    scanId: string | undefined,
    offset: number,
    limit: number,
    severity?: string,
    verdict?: string,
    keyword?: string,
    vulnerabilityType?: string
  ) => {
    const params = new URLSearchParams({
      project_path: projectPath,
      offset: String(offset),
      limit: String(limit),
    });
    if (scanId) params.set("scan_id", scanId);
    if (severity) params.set("severity", severity);
    if (verdict) params.set("verdict", verdict);
    if (keyword) params.set("keyword", keyword);
    if (vulnerabilityType) params.set("vulnerability_type", vulnerabilityType);
    return request<AuditResponse<T>>(`/api/artifacts/audit?${params.toString()}`);
  },
};
