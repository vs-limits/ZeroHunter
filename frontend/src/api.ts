// 后端 API 基础封装。

export interface VersionItem {
  project_path: string;
  source: string;
  owner: string;
  repo: string;
  version: string;
  name: string;
  notes: string;
  role: string;
  kind: "manual" | "copy" | "local" | "git" | string;
  created_at: string | null;
  updated_at?: string | null;
  project_root: string;
  has_artifacts: boolean;
  scan_count: number;
  latest_scan?: ScanItem | null;
  audit_summary?: ScanItem["audit_summary"];
  callscan_summary?: ScanItem["callscan_summary"];
  git?: {
    remote?: string | null;
    ref?: string | null;
    branch?: string | null;
    commit?: string | null;
    short_commit?: string | null;
    describe?: string | null;
    worktree?: boolean;
  } | null;
}

export type ProjectItem = VersionItem;

export interface ProjectContainer {
  project_key: string;
  project_path: string;
  source: string;
  owner: string;
  repo: string;
  name: string;
  notes: string;
  description: string;
  tags: string[];
  audit_status: ProjectAuditStatus;
  favorite: boolean;
  project_profile: ProjectProfile;
  created_at: string | null;
  updated_at?: string | null;
  project_root: string;
  versions: VersionItem[];
  version_count: number;
  scan_count: number;
}

export type ProjectAuditStatus =
  | "not_started"
  | "scanning"
  | "manual_review"
  | "completed"
  | "tracking"
  | string;

export interface ProjectProfile {
  project_function?: string;
  summary?: string;
  project_type?: string;
  architecture_style?: string;
  repository_shape?: string;
  interface_shape?: string[];
  execution_model?: string[];
  technology_stack?: Record<string, string[]>;
  engineering_context?: string[];
  [key: string]: unknown;
}

export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low" | string;
export type VulnerabilityStatus =
  | "draft"
  | "confirmed"
  | "reproducing"
  | "reproduced"
  | "archived"
  | string;
export type VulnerabilitySource = "manual" | "scan" | "import" | string;

export interface VulnerabilityScanLink {
  project_path: string;
  scan_id: string;
  name: string;
}

export interface VulnerabilityExternalLink {
  name: string;
  url: string;
}

export interface VulnerabilityLinks {
  version_project_paths: string[];
  scans: VulnerabilityScanLink[];
  external: VulnerabilityExternalLink[];
}

export interface VulnerabilityFileEntry {
  filename: string;
  content: string;
  size: number;
  mtime: number;
}

export interface PocParameter {
  name: string;
  type: string;
  default: string;
  required: boolean;
}

export interface PocCommands {
  template: string;
  parameters: PocParameter[];
}

export type VulnerabilityAiSection = "info" | "environment" | "reproduction" | "poc";
export type VulnerabilityExportFormat = "html" | "docx" | "pdf";
export type VulnerabilityExportSection =
  | "meta"
  | "details"
  | "fix"
  | "reproduction"
  | "environment"
  | "environment_commands"
  | "environment_files"
  | "poc"
  | "poc_commands"
  | "poc_files"
  | "references"
  | "source_finding";

export interface VulnerabilityAiFileSuggestion {
  filename: string;
  content: string;
}

export interface VulnerabilityAiResult {
  section: VulnerabilityAiSection;
  web_search_used: boolean;
  confidence: number;
  summary: string;
  suggestions: string[];
  warnings: string[];
  info?: {
    name?: string;
    details?: string;
    tags?: string[];
    location?: string;
    affected_version?: string;
    severity?: VulnerabilitySeverity | "";
    status?: VulnerabilityStatus | "";
    cve?: string;
    references?: string[];
    source?: VulnerabilitySource | "";
  };
  environment?: {
    files: VulnerabilityAiFileSuggestion[];
    commands: { windows: string; linux: string };
  };
  reproduction?: {
    markdown: string;
  };
  poc?: {
    files: VulnerabilityAiFileSuggestion[];
    commands: PocCommands;
  };
}

export interface VulnerabilityItem {
  vulnerability_id: string;
  project_key: string;
  name: string;
  severity: VulnerabilitySeverity;
  status: VulnerabilityStatus;
  source: VulnerabilitySource;
  tags: string[];
  created_at: string | null;
  updated_at: string | null;
  path: string;
  links: VulnerabilityLinks;
}

export interface VulnerabilityDetail extends VulnerabilityItem {
  details: string;
  location: string;
  affected_version: string;
  cve: string;
  references: string[];
  source_finding: Record<string, unknown> | null;
  code_regions: VulnerabilityCodeRegion[];
  meta: Record<string, unknown>;
  environment: {
    files: VulnerabilityFileEntry[];
    commands: { windows: string; linux: string };
  };
  reproduction: string;
  poc: {
    files: VulnerabilityFileEntry[];
    commands: PocCommands;
  };
}

export interface VulnerabilitySettings {
  vulnerability_tags: string[];
  environment_file_presets: string[];
  poc_file_presets: string[];
  poc_parameter_presets: PocParameter[];
}

export interface LinkVersionTarget {
  project_path: string;
  version: string;
  name: string;
}

export interface LinkScanTarget {
  project_path: string;
  version: string;
  scan_id: string;
  name: string;
  status: string;
}

export interface LinkTargetsResponse {
  versions: LinkVersionTarget[];
  scans: LinkScanTarget[];
}

export interface VulnerabilityAssetUpload {
  filename: string;
  size: number;
  content_type: string;
  markdown: string;
}

export interface VulnerabilityCodeRegion {
  id: string;
  title: string;
  role: string;
  file: string;
  line: number | null;
  line_start: number;
  line_end: number;
  language: string;
  description: string;
  code: string;
}

export interface ArtifactStat {
  size: number;
  mtime: number;
}

export interface SpecificRun {
  run_id: string;
  target_rel_dir: string | null;
  created_at: string | null;
  mode: string;
  artifacts: Record<string, ArtifactStat>;
}

export interface ProjectRunsResponse {
  project: {
    project_path: string;
    project_root: string;
    has_artifacts: boolean;
    artifacts: Record<string, ArtifactStat>;
  };
  runs: SpecificRun[];
}

export interface ProjectSourceFile {
  project_path: string;
  path: string;
  rel_path: string;
  size: number;
  mtime: number;
  encoding: string;
  truncated: boolean;
  content: string;
}

export interface RunInfo {
  run_id: string;
  cmd: string[];
  status: "pending" | "running" | "done" | "error" | "killed";
  return_code: number | null;
  started_at: number | null;
  finished_at: number | null;
  detected_run_id?: string | null;
  detected_target_rel_dir?: string | null;
  detected_artifacts_dir?: string | null;
  lines?: string[];
}

export interface LlmProfile {
  id: string;
  name: string;
  notes: string;
  base_url: string;
  model_name: string;
  protocol: string;
  config_type: LlmConfigType;
  mini_config: MiniCustomConfig;
  has_api_key: boolean;
  api_key_masked: string;
  active: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface LlmFileConfig {
  path: string;
  exists: boolean;
  base_url: string;
  model_name: string;
  protocol: string;
  has_api_key: boolean;
  api_key_masked: string;
  complete: boolean;
}

export type LlmConfigType = "standard" | "mini_custom" | string;

export interface MiniCustomConfig {
  thinking: boolean;
  reasoning_effort: "high" | "max" | string;
  top_k: number;
  min_p: number;
  repetition_penalty: number;
}

export interface LlmSettingsResponse {
  active_id: string | null;
  items: LlmProfile[];
  file_config: LlmFileConfig;
  store_path: string;
}

export interface LlmInput {
  name: string;
  notes?: string;
  base_url: string;
  api_key: string;
  model_name: string;
  protocol: string;
  config_type: LlmConfigType;
  mini_config: MiniCustomConfig;
}

export interface LlmTestResult {
  ok: boolean;
  model: string;
  base_url: string;
  latency_ms: number;
  message: string;
}

export interface LlmConcurrentTestResult {
  ok: boolean;
  model: string;
  base_url: string;
  total: number;
  success_threshold: number;
  success_count: number;
  failure_count: number;
  latency_ms: number;
  results: Array<{
    index: number;
    ok: boolean;
    latency_ms?: number;
    message?: string;
    error?: string;
  }>;
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  return res.json();
}

async function post<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  return res.json();
}

async function del<T>(url: string): Promise<T> {
  const res = await fetch(url, { method: "DELETE" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function patch<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  return res.json();
}

function projectApiBase(project: Pick<ProjectContainer, "source" | "owner" | "repo">): string {
  return `/api/projects/${encodeURIComponent(project.source)}/${encodeURIComponent(project.owner)}/${encodeURIComponent(project.repo)}`;
}

function filenameFromContentDisposition(header: string | null): string | null {
  if (!header) return null;
  const encoded = header.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) {
    try {
      return decodeURIComponent(encoded);
    } catch {
      return encoded;
    }
  }
  const plain = header.match(/filename="?([^";]+)"?/i)?.[1];
  return plain || null;
}

export function listProjects(opts?: { summary?: boolean }) {
  const params = new URLSearchParams();
  if (opts?.summary) params.set("summary", "true");
  const q = params.toString();
  return get<{ items: ProjectContainer[] }>(
    q ? `/api/projects?${q}` : "/api/projects"
  );
}

export function listLlms() {
  return get<LlmSettingsResponse>("/api/llms");
}

export function createLlm(input: LlmInput) {
  return post<LlmProfile>("/api/llms", input);
}

export function updateLlm(llmId: string, input: LlmInput) {
  return patch<LlmProfile>(`/api/llms/${encodeURIComponent(llmId)}`, input);
}

export function deleteLlm(llmId: string) {
  return del<LlmSettingsResponse>(`/api/llms/${encodeURIComponent(llmId)}`);
}

export function selectLlm(llmId: string) {
  return post<LlmProfile>("/api/llms/select", { llm_id: llmId });
}

export function testLlm(input: ({ llm_id: string } & Partial<LlmInput>) | LlmInput) {
  return post<LlmTestResult>("/api/llms/test", input);
}

export function testLlmConcurrent(
  input: (({ llm_id: string } & Partial<LlmInput>) | LlmInput) & {
    count: number;
    success_threshold?: number;
  }
) {
  return post<LlmConcurrentTestResult>("/api/llms/test-concurrent", input);
}

export function getProjectRuns(projectPath: string) {
  const [src, owner, repo, version] = projectPath.split("/");
  return get<ProjectRunsResponse>(
    `/api/projects/${encodeURIComponent(src)}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(version)}/runs`
  );
}

export function readProjectSourceFile(projectPath: string, relPath: string) {
  const [src, owner, repo, version] = projectPath.split("/");
  const params = new URLSearchParams({ path: relPath });
  return get<ProjectSourceFile>(
    `/api/projects/${encodeURIComponent(src)}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(version)}/source?${params.toString()}`
  );
}

export function createProject(input: {
  source: string;
  owner: string;
  repo: string;
  name?: string;
  notes?: string;
}) {
  return post<ProjectContainer>("/api/projects", input);
}

export function updateProject(
  project: ProjectContainer,
  input: {
    name?: string;
    notes?: string;
    description?: string;
    tags?: string[];
    audit_status?: string;
    favorite?: boolean;
    project_profile?: ProjectProfile;
  }
) {
  return fetch(
    `/api/projects/${encodeURIComponent(project.source)}/${encodeURIComponent(project.owner)}/${encodeURIComponent(project.repo)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    }
  ).then(async (r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText} ${await r.text().catch(() => "")}`);
    return (await r.json()) as ProjectContainer;
  });
}

export function getSettings() {
  return get<VulnerabilitySettings>("/api/settings");
}

export function updateSettings(input: Partial<VulnerabilitySettings>) {
  return patch<VulnerabilitySettings>("/api/settings", input);
}

export function listVulnerabilities(project: ProjectContainer) {
  return get<{ items: VulnerabilityItem[] }>(
    `${projectApiBase(project)}/vulnerabilities`
  );
}

export function createVulnerability(
  project: ProjectContainer,
  input: Partial<VulnerabilityDetail> = {}
) {
  return post<VulnerabilityDetail>(`${projectApiBase(project)}/vulnerabilities`, input);
}

export function getVulnerability(project: ProjectContainer, vulnerabilityId: string) {
  return get<VulnerabilityDetail>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}`
  );
}

export function analyzeVulnerability(
  project: ProjectContainer,
  vulnerabilityId: string,
  section: VulnerabilityAiSection
) {
  return post<VulnerabilityAiResult>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/ai/analyze`,
    { section }
  );
}

export function updateVulnerability(
  project: ProjectContainer,
  vulnerabilityId: string,
  input: Partial<VulnerabilityDetail> & {
    environment_commands?: { windows: string; linux: string };
    reproduction?: string;
    poc_commands?: PocCommands;
  }
) {
  return patch<VulnerabilityDetail>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}`,
    input
  );
}

export function deleteVulnerability(project: ProjectContainer, vulnerabilityId: string) {
  return del<{ ok: boolean; vulnerability_id: string; meta: Record<string, unknown> }>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}`
  );
}

export function convertFindingToVulnerability(
  project: ProjectContainer,
  input: {
    project_path: string;
    scan_id: string;
    chain_id: string;
    duplicate?: boolean;
  }
) {
  return post<{ duplicate: boolean; item: VulnerabilityDetail }>(
    `${projectApiBase(project)}/vulnerabilities/from-finding`,
    input
  );
}

export function getLinkTargets(project: ProjectContainer) {
  return get<LinkTargetsResponse>(`${projectApiBase(project)}/link-targets`);
}

export function listVulnerabilityFiles(
  project: ProjectContainer,
  vulnerabilityId: string,
  section: "environment" | "poc"
) {
  const params = new URLSearchParams({ section });
  return get<{ items: VulnerabilityFileEntry[] }>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/files?${params.toString()}`
  );
}

export function writeVulnerabilityFile(
  project: ProjectContainer,
  vulnerabilityId: string,
  input: { section: "environment" | "poc"; filename: string; content: string }
) {
  return put<VulnerabilityFileEntry>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/files`,
    input
  );
}

export function renameVulnerabilityFile(
  project: ProjectContainer,
  vulnerabilityId: string,
  input: { section: "environment" | "poc"; filename: string; new_filename: string }
) {
  return patch<VulnerabilityFileEntry>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/files`,
    input
  );
}

export function deleteVulnerabilityFile(
  project: ProjectContainer,
  vulnerabilityId: string,
  section: "environment" | "poc",
  filename: string
) {
  const params = new URLSearchParams({ section, filename });
  return del<{ ok: boolean; filename: string }>(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/files?${params.toString()}`
  );
}

export function uploadVulnerabilityAsset(
  project: ProjectContainer,
  vulnerabilityId: string,
  file: File
) {
  const form = new FormData();
  form.set("file", file);
  return fetch(
    `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/assets`,
    { method: "POST", body: form }
  ).then(async (r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText} ${await r.text().catch(() => "")}`);
    return (await r.json()) as VulnerabilityAssetUpload;
  });
}

export function vulnerabilityAssetUrl(
  project: ProjectContainer,
  vulnerabilityId: string,
  filename: string
) {
  return `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/assets/${encodeURIComponent(filename)}`;
}

export function vulnerabilityExportUrl(
  project: ProjectContainer,
  vulnerabilityId: string,
  format: VulnerabilityExportFormat,
  sections?: VulnerabilityExportSection[]
) {
  const params = new URLSearchParams({ format });
  for (const section of sections || []) params.append("sections", section);
  return `${projectApiBase(project)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/export?${params.toString()}`;
}

export async function downloadVulnerabilityExport(
  project: ProjectContainer,
  vulnerabilityId: string,
  format: VulnerabilityExportFormat,
  sections?: VulnerabilityExportSection[]
) {
  const res = await fetch(vulnerabilityExportUrl(project, vulnerabilityId, format, sections));
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  const blob = await res.blob();
  const filename =
    filenameFromContentDisposition(res.headers.get("Content-Disposition")) ??
    `${vulnerabilityId}.${format}`;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function createVersion(
  project: ProjectContainer,
  input: {
    kind: "manual" | "copy" | "local";
    version: string;
    name?: string;
    notes?: string;
    role?: string;
    overwrite?: boolean;
    source_version?: string | null;
    local_path?: string | null;
  }
) {
  return post<VersionItem>(
    `/api/projects/${encodeURIComponent(project.source)}/${encodeURIComponent(project.owner)}/${encodeURIComponent(project.repo)}/versions`,
    input
  );
}

export function updateVersion(
  version: VersionItem,
  input: { name?: string; notes?: string; role?: string }
) {
  return fetch(
    `/api/projects/${encodeURIComponent(version.source)}/${encodeURIComponent(version.owner)}/${encodeURIComponent(version.repo)}/versions/${encodeURIComponent(version.version)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    }
  ).then(async (r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText} ${await r.text().catch(() => "")}`);
    return (await r.json()) as VersionItem;
  });
}

export function deleteVersion(version: VersionItem) {
  return del<{ ok: boolean; version: string }>(
    `/api/projects/${encodeURIComponent(version.source)}/${encodeURIComponent(version.owner)}/${encodeURIComponent(version.repo)}/versions/${encodeURIComponent(version.version)}`
  );
}

export interface ImportJob {
  job_id: string;
  project_key: string;
  requested_project_path?: string | null;
  status: "pending" | "running" | "done" | "error" | "killed";
  return_code: number | null;
  started_at: number | null;
  finished_at: number | null;
  error?: string | null;
  version?: string | null;
  project_path?: string | null;
  git?: VersionItem["git"];
  lines?: string[];
}

export interface GitRefItem {
  kind: "branch" | "tag" | string;
  name: string;
  ref: string;
  full_ref: string;
  commit: string;
  short_commit: string;
  peeled?: boolean;
}

export interface GitRefsResponse {
  project_key: string;
  remote: string;
  source: "remote" | "mirror" | string;
  count: number;
  branches: number;
  tags: number;
  items: GitRefItem[];
}

export function startGitVersionImport(
  project: ProjectContainer,
  input: {
    git_url: string;
    ref?: string;
    version?: string;
    name?: string;
    notes?: string;
    role?: string;
    overwrite?: boolean;
    depth?: number | null;
    single_branch?: boolean;
    recurse_submodules?: boolean;
  }
) {
  return post<ImportJob>(
    `/api/projects/${encodeURIComponent(project.source)}/${encodeURIComponent(project.owner)}/${encodeURIComponent(project.repo)}/versions/git-import`,
    input
  );
}

export function listGitRefs(
  project: ProjectContainer,
  input?: { git_url?: string; refresh?: boolean }
) {
  const params = new URLSearchParams();
  if (input?.git_url) params.set("git_url", input.git_url);
  if (input?.refresh) params.set("refresh", "true");
  const q = params.toString();
  return get<GitRefsResponse>(
    `/api/projects/${encodeURIComponent(project.source)}/${encodeURIComponent(project.owner)}/${encodeURIComponent(project.repo)}/versions/git-refs${q ? `?${q}` : ""}`
  );
}

export function getImportJob(jobId: string) {
  return get<ImportJob>(`/api/imports/${encodeURIComponent(jobId)}`);
}

export function stopImportJob(jobId: string) {
  return post<{ ok: boolean; job_id: string }>(
    `/api/imports/${encodeURIComponent(jobId)}/stop`,
    {}
  );
}

export function retryImportJob(jobId: string) {
  return post<ImportJob>(`/api/imports/${encodeURIComponent(jobId)}/retry`, {});
}

export function importStreamUrl(jobId: string): string {
  return `/api/imports/${encodeURIComponent(jobId)}/stream`;
}

export function readArtifactJson<T = unknown>(
  projectPath: string,
  filename: string,
  runId?: string | null
) {
  const params = new URLSearchParams({ project_path: projectPath, filename });
  if (runId) params.set("run_id", runId);
  return get<{ path: string; size: number; mtime: number; data: T }>(
    `/api/artifacts/json?${params.toString()}`
  );
}

export interface AuditChunk {
  path: string;
  size: number;
  mtime: number;
  head: Record<string, unknown>;
  total: number;
  offset: number;
  limit: number;
  findings: AuditFinding[];
}

export interface AuditFinding {
  chain_id: string;
  index: number;
  language: string;
  vulnerability_type: string;
  verdict: string;
  confidence: number;
  title: string;
  cwe_guess?: string;
  severity: string;
  principle?: string;
  source?: Record<string, unknown>;
  sink?: { file?: string; line?: number; expr?: string };
  data_flow?: unknown[];
  exploit_poc?: string;
  fix_suggestion?: string;
  refuted_by?: string;
  missing_info?: unknown[];
  evidence?: unknown[];
  [key: string]: unknown;
}

export function readAuditAgent(
  projectPath: string,
  runId: string | null,
  opts: {
    offset: number;
    limit: number;
    severity?: string;
    verdict?: string;
    keyword?: string;
  }
) {
  const params = new URLSearchParams({
    project_path: projectPath,
    offset: String(opts.offset),
    limit: String(opts.limit),
  });
  if (runId) params.set("run_id", runId);
  if (opts.severity) params.set("severity", opts.severity);
  if (opts.verdict) params.set("verdict", opts.verdict);
  if (opts.keyword) params.set("keyword", opts.keyword);
  return get<AuditChunk>(`/api/artifacts/audit?${params.toString()}`);
}

export interface JsonlChunk {
  path: string;
  size: number;
  mtime: number;
  meta: Record<string, unknown> | null;
  total: number;
  offset: number;
  limit: number;
  items: Record<string, unknown>[];
}

export function readJsonl(
  projectPath: string,
  filename: string,
  runId: string | null,
  offset: number,
  limit: number
) {
  const params = new URLSearchParams({
    project_path: projectPath,
    filename,
    offset: String(offset),
    limit: String(limit),
  });
  if (runId) params.set("run_id", runId);
  return get<JsonlChunk>(`/api/artifacts/jsonl?${params.toString()}`);
}

export interface MarkdownChunk {
  path: string;
  size: number;
  mtime: number;
  head: string;
  total: number;
  offset: number;
  limit: number;
  sections: string[];
}

export function readMarkdown(
  projectPath: string,
  filename: string,
  runId: string | null,
  offset: number,
  limit: number,
  keyword?: string
) {
  const params = new URLSearchParams({
    project_path: projectPath,
    filename,
    offset: String(offset),
    limit: String(limit),
  });
  if (runId) params.set("run_id", runId);
  if (keyword) params.set("keyword", keyword);
  return get<MarkdownChunk>(`/api/artifacts/markdown?${params.toString()}`);
}

export interface LogIndexItem {
  name: string;
  size: number;
  mtime: number;
}

export function listLogs() {
  return get<{ items: LogIndexItem[] }>("/api/logs");
}

export interface LogRound {
  ts: string | null;
  agent: string | null;
  model: string | null;
  request: Record<string, unknown> | null;
  response: Record<string, unknown> | null;
  error: Record<string, unknown> | null;
}

export interface LogRoundsResponse {
  path: string;
  size: number;
  mtime: number;
  total: number;
  offset: number;
  limit: number;
  rounds: LogRound[];
}

export function readLogRounds(
  name: string,
  offset: number,
  limit: number,
  agent?: string
) {
  const params = new URLSearchParams({
    offset: String(offset),
    limit: String(limit),
  });
  if (agent) params.set("agent", agent);
  return get<LogRoundsResponse>(`/api/logs/${encodeURIComponent(name)}?${params.toString()}`);
}

// ----- 命令 -----

export function getRunDetail(runId: string) {
  return get<RunInfo>(`/api/run/${encodeURIComponent(runId)}`);
}

export function killRun(runId: string) {
  return del<{ ok: boolean }>(`/api/run/${encodeURIComponent(runId)}`);
}

export function streamUrl(runId: string): string {
  return `/api/run/${encodeURIComponent(runId)}/stream`;
}


// ===== 提示词 / 技能 / Sink =====

export interface PromptFile {
  name: string;
  size: number;
  mtime: number;
}

export interface PromptDetail extends PromptFile {
  path: string;
  content: string;
}

export interface SkillFileEntry {
  name: string;
  size: number;
  mtime: number;
}

export interface SkillGroup {
  language: string;
  label: string;
  files: SkillFileEntry[];
}

export interface SkillDetail {
  language: string;
  name: string;
  path: string;
  size: number;
  mtime: number;
  content: string;
}

export interface SinkFileEntry {
  name: string;
  filename: string;
  size: number;
  mtime: number;
}

export interface SinkGroup {
  language: string;
  label: string;
  files: SinkFileEntry[];
}

export interface SinkRuleDict {
  id: string;
  function: string;
  call_regex: string;
  description: string;
  argument_roles: string[];
  extensions: string[];
  severity: "low" | "medium" | "high" | "critical";
  require_dynamic?: boolean;
  extra_match_regex?: string[];
  [k: string]: unknown;
}

export interface SinkDetail {
  language: string;
  name: string;
  filename: string;
  path: string;
  size: number;
  mtime: number;
  vulnerability: string | null;
  rules_count: number;
  rules: SinkRuleDict[];
  raw_source: string;
}

export function listPrompts() {
  return get<{ items: PromptFile[] }>("/api/prompts");
}

export function readPrompt(name: string) {
  return get<PromptDetail>(`/api/prompts/${encodeURIComponent(name)}`);
}

export function listSkills() {
  return get<{ groups: SkillGroup[] }>("/api/skills");
}

export function readSkill(language: string, name: string) {
  return get<SkillDetail>(
    `/api/skills/${encodeURIComponent(language)}/${encodeURIComponent(name)}`
  );
}

export function listSinks() {
  return get<{ groups: SinkGroup[] }>("/api/sinks");
}

export function readSink(language: string, name: string) {
  return get<SinkDetail>(
    `/api/sinks/${encodeURIComponent(language)}/${encodeURIComponent(name)}`
  );
}


// ===== 可观测性 =====

export interface DashboardOverview {
  projects: Array<{
    project_path: string;
    scan_count?: number;
    has_artifacts?: boolean;
    runs?: number;
    specific_runs?: number;
    total_audited?: number;
    vulnerable?: number;
    uncertain?: number;
    safe?: number;
    candidate_chains?: number;
  }>;
  totals: {
    projects: number;
    runs?: number;
    scans?: number;
    audited: number;
    vulnerable: number;
    uncertain: number;
    safe: number;
    candidate_chains: number;
    tokens: { prompt: number; completion: number };
  };
  by_severity: Record<string, number>;
  by_vulnerability: Record<string, number>;
  by_language: Record<string, number>;
  agent_tokens: Record<
    string,
    { prompt: number; completion: number; turns: number }
  >;
  agent_avg_elapsed?: Record<string, number | null>;
  series?: DashboardSeriesPoint[];
  quality?: DashboardQuality;
}

export interface WorkflowNode {
  id: string;
  label: string;
  en?: string;
  desc?: string;
  kind: "pipeline" | "agent" | "input" | "output";
  status: "pending" | "running" | "done" | "error" | "ready";
  turns?: number;
  tokens?: { prompt: number; completion: number };
  elapsed?: number | null;
  started_at?: string | null;
  ended_at?: string | null;
  summary?: Record<string, unknown> | null;
  error?: string | null;
  outputs?: string[];
  outputs_present?: string[];
  path?: string;
}

export interface WorkflowEdge {
  from: string;
  to: string;
  label?: string;
}

export interface WorkflowGraph {
  project_path: string;
  run_id: string | null;
  artifacts_dir: string;
  pipeline_status: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
}

export interface RunEvent {
  ts: string;
  type: string;
  agent?: string | null;
  session_id?: string;
  run_id?: string | null;
  [k: string]: unknown;
}

export interface EventsChunk {
  path: string;
  total: number;
  offset: number;
  limit: number;
  events: RunEvent[];
}

export interface ConversationTurnIndex {
  turn: number;
  ts: string;
  agent: string;
  model: string;
  status: "pending" | "ok" | "error";
  finish_reason?: string;
  has_tool_calls?: boolean;
  usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
  error_type?: string;
  error?: string;
}

export interface ConversationAgentBucket {
  agent: string;
  turns_count: number;
  prompt_tokens: number;
  completion_tokens: number;
  turns: ConversationTurnIndex[];
}

export interface ConversationTurnDetail {
  path: string;
  agent: string;
  turn: number;
  request?: {
    session_id: string;
    agent: string;
    turn: number;
    ts: string;
    model: string;
    temperature: number;
    max_tokens: number;
    tool_choice?: unknown;
    tools?: unknown[];
    messages: Array<{ role: string; content: string; tool_calls?: unknown[] }>;
  };
  response?: {
    ts: string;
    model: string;
    raw: Record<string, unknown>;
  };
  error?: {
    ts: string;
    model: string;
    error_type: string;
    error: string;
  };
}

export function getDashboard(opts?: { refresh?: boolean }) {
  const params = new URLSearchParams();
  if (opts?.refresh) params.set("refresh", "true");
  const q = params.toString();
  return get<DashboardOverview>(q ? `/api/dashboard?${q}` : "/api/dashboard");
}

export function getWorkflow(projectPath: string, runId?: string | null) {
  const params = new URLSearchParams({ project_path: projectPath });
  if (runId) params.set("run_id", runId);
  return get<WorkflowGraph>(`/api/workflow?${params.toString()}`);
}

export function getEvents(
  projectPath: string,
  runId: string | null,
  offset = 0,
  limit = 500
) {
  const params = new URLSearchParams({
    project_path: projectPath,
    offset: String(offset),
    limit: String(limit),
  });
  if (runId) params.set("run_id", runId);
  return get<EventsChunk>(`/api/events?${params.toString()}`);
}

export function listConversations(projectPath: string, runId: string | null) {
  const params = new URLSearchParams({ project_path: projectPath });
  if (runId) params.set("run_id", runId);
  return get<{ artifacts_dir: string; agents: ConversationAgentBucket[] }>(
    `/api/conversations?${params.toString()}`
  );
}

export function readConversationTurn(
  projectPath: string,
  runId: string | null,
  agent: string,
  turn: number
) {
  const params = new URLSearchParams({ project_path: projectPath });
  if (runId) params.set("run_id", runId);
  return get<ConversationTurnDetail>(
    `/api/conversations/${encodeURIComponent(agent)}/${turn}?${params.toString()}`
  );
}

export interface ConversationByChainResponse {
  artifacts_dir: string;
  agent: string;
  chain_id: string;
  turns: ConversationTurnDetail[];
}

export function readConversationByChain(
  projectPath: string,
  runId: string | null,
  chainId: string,
  agent: string = "auditor"
) {
  const params = new URLSearchParams({
    project_path: projectPath,
    chain_id: chainId,
    agent,
  });
  if (runId) params.set("run_id", runId);
  return get<ConversationByChainResponse>(
    `/api/conversations/by-chain?${params.toString()}`
  );
}


// ===== 扫描（Scan）=====

export type ScanStatus =
  | "pending"
  | "running"
  | "done"
  | "error"
  | "stopped";

/** 扫描状态回调选项：默认只更新当前页，不触发全量列表刷新。 */
export interface ScanChangeOptions {
  /** 同步侧栏 scans 与项目版本摘要（扫描结束、停止等时机再用） */
  syncLists?: boolean;
}

export interface ScanGroundTruth {
  expected_total: number | null;
  missed: number | null;
  notes: string;
}

export interface ScanOptions {
  callscan_use_llm: boolean;
  callscan_concurrency?: number;
  auditor_concurrency?: number;
}

export interface ScanItem {
  scan_id: string;
  name: string;
  project_path: string;
  project_root: string;
  target: { mode: "all" | "directory"; rel_dir: string | null };
  agents: string[];
  options?: ScanOptions;
  status: ScanStatus;
  current_agent: string | null;
  completed_agents?: string[];
  last_error?: string | null;
  scheduled_at?: string | null;
  console_log?: string;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  last_run_id: string | null;
  ground_truth: ScanGroundTruth;
  legacy?: boolean;
  artifacts?: Record<string, { size: number; mtime: number }>;
  audit_summary?: {
    total_audited?: number;
    vulnerable?: number;
    uncertain?: number;
    safe?: number;
    llm_failed?: number;
    by_severity?: Record<string, number>;
    by_vulnerability?: Record<string, number>;
  } | null;
  audit_failure_count?: number;
  callscan_summary?: {
    sink_hits?: number;
    candidate_chains?: number;
    by_severity?: Record<string, number>;
    by_vulnerability?: Record<string, number>;
  } | null;
  dataflow_summary?: {
    nodes?: number;
    edges?: number;
    source_nodes?: number;
    storage_nodes?: number;
    sink_nodes?: number;
    write_edges?: number;
    read_edges?: number;
    total_chains?: number;
    cross_request_chains?: number;
    recovered_partial?: number;
    by_vulnerability?: Record<string, number>;
    by_chain_kind?: Record<string, number>;
    by_storage_kind?: Record<string, number>;
    breakpoints?: number;
  } | null;
}

export type ReviewTrack = "codex" | "manual" | "cc";
export type ReviewVerdict =
  | "true_positive"
  | "false_positive"
  | "uncertain";

export interface ScanMark {
  "Codex核验"?: ReviewVerdict | "";
  "Codex-Review"?: string;
  "Codex核验时间"?: string;
  "人工核验"?: ReviewVerdict | "";
  "人工-Review"?: string;
  "人工核验时间"?: string;
  "CC核验"?: ReviewVerdict | "";
  "CC-Review"?: string;
  "CC核验时间"?: string;
  user_verdict?: ReviewVerdict | null;
  note?: string;
  marked_at?: string;
  favorite?: boolean;
  [key: string]: unknown;
}

export function listScans(projectPath: string) {
  const params = new URLSearchParams({ project_path: projectPath });
  return get<{ items: ScanItem[] }>(`/api/scans?${params.toString()}`);
}

export function createScan(input: {
  project_path: string;
  name?: string;
  target_mode: "all" | "directory";
  target_rel_dir?: string | null;
  agents: string[];
  callscan_use_llm?: boolean;
}) {
  return post<ScanItem>("/api/scans", input);
}

export function getScan(projectPath: string, scanId: string) {
  const params = new URLSearchParams({ project_path: projectPath });
  return get<ScanItem>(`/api/scans/${encodeURIComponent(scanId)}?${params.toString()}`);
}

export function updateScan(
  projectPath: string,
  scanId: string,
  fields: {
    name?: string;
    agents?: string[];
    target?: { mode: "all" | "directory"; rel_dir: string | null };
    ground_truth?: ScanGroundTruth;
    options?: Partial<ScanOptions>;
  }
) {
  const params = new URLSearchParams({ project_path: projectPath });
  return fetch(
    `/api/scans/${encodeURIComponent(scanId)}?${params.toString()}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fields),
    }
  ).then(async (r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText} ${await r.text().catch(() => "")}`);
    return (await r.json()) as ScanItem;
  });
}

export function deleteScan(projectPath: string, scanId: string) {
  const params = new URLSearchParams({ project_path: projectPath });
  return fetch(
    `/api/scans/${encodeURIComponent(scanId)}?${params.toString()}`,
    { method: "DELETE" }
  ).then(async (r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText} ${await r.text().catch(() => "")}`);
    return (await r.json()) as { ok: boolean; scan_id: string; stopped: boolean };
  });
}

export function startScan(input: {
  project_path: string;
  scan_id: string;
  agents?: string[] | null;
  resume?: boolean;
}) {
  return post<{ run_id: string; scan_id: string; agents: string[]; status: string }>(
    `/api/scans/${encodeURIComponent(input.scan_id)}/start`,
    input
  );
}

export function retryAuditFailures(input: {
  project_path: string;
  scan_id: string;
}) {
  return post<{
    run_id: string;
    scan_id: string;
    agents: string[];
    status: string;
    failure_count: number;
  }>(`/api/scans/${encodeURIComponent(input.scan_id)}/retry-audit-failures`, input);
}

export function stopScan(projectPath: string, scanId: string) {
  const params = new URLSearchParams({ project_path: projectPath });
  return post<{ ok: boolean; scan_id: string }>(
    `/api/scans/${encodeURIComponent(scanId)}/stop?${params.toString()}`,
    {}
  );
}

export function scheduleScan(input: {
  project_path: string;
  scan_id: string;
  scheduled_at: string | null;
  agents?: string[] | null;
}) {
  return post<ScanItem>(
    `/api/scans/${encodeURIComponent(input.scan_id)}/schedule`,
    input
  );
}

export interface ConsoleLog {
  path: string;
  size: number;
  mtime?: number;
  lines: string[];
}

export function readScanConsole(
  projectPath: string,
  scanId: string,
  tail: number = 2000
) {
  const params = new URLSearchParams({
    project_path: projectPath,
    tail: String(tail),
  });
  return get<ConsoleLog>(
    `/api/scans/${encodeURIComponent(scanId)}/console?${params.toString()}`
  );
}

export function listQueue() {
  return get<{ items: ScanItem[] }>("/api/queue");
}

export function listMarks(projectPath: string, scanId: string) {
  const params = new URLSearchParams({ project_path: projectPath });
  return get<{ items: Record<string, ScanMark> }>(
    `/api/scans/${encodeURIComponent(scanId)}/marks?${params.toString()}`
  );
}

export function upsertMark(input: {
  project_path: string;
  scan_id: string;
  chain_id: string;
  reviewer?: ReviewTrack;
  verdict?: ReviewVerdict | "clear" | null;
  review?: string | null;
  user_verdict?: "true_positive" | "false_positive" | "uncertain" | "clear" | null;
  note?: string | null;
  favorite?: boolean | null;
}) {
  return post<{ items: Record<string, ScanMark> }>(
    `/api/scans/${encodeURIComponent(input.scan_id)}/marks`,
    input
  );
}

// 扩展 Dashboard 数据结构
export interface DashboardSeriesPoint {
  date: string;
  scans: number;
  audited: number;
  vulnerable: number;
  tokens_in: number;
  tokens_out: number;
}

export interface DashboardQuality {
  total_vulnerable_findings: number;
  total_marked_findings?: number;
  true_positives: number;
  false_positives: number;
  uncertain: number;
  missed: number;
  expected_total: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}


// ===== 内容编辑 + 历史 =====

export interface HistoryEntry {
  version: number;
  timestamp: string;
  filename: string;
  size: number;
  reason: string;
}

async function put<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText} ${text}`);
  }
  return res.json();
}

export function writePrompt(name: string, content: string, reason: string = "") {
  return put<{ path: string; size: number; mtime: number; archived?: HistoryEntry; history_count: number }>(
    `/api/prompts/${encodeURIComponent(name)}`,
    { content, reason }
  );
}

export function listPromptHistory(name: string) {
  return get<{ items: HistoryEntry[] }>(
    `/api/prompts/${encodeURIComponent(name)}/history`
  );
}

export function readPromptVersion(name: string, version: number) {
  return get<{ name: string; version: number; content: string }>(
    `/api/prompts/${encodeURIComponent(name)}/history/${version}`
  );
}

export function writeSkill(
  language: string,
  name: string,
  content: string,
  reason: string = ""
) {
  return put<{ path: string; size: number; mtime: number; archived?: HistoryEntry; history_count: number }>(
    `/api/skills/${encodeURIComponent(language)}/${encodeURIComponent(name)}`,
    { content, reason }
  );
}

export function listSkillHistory(language: string, name: string) {
  return get<{ items: HistoryEntry[] }>(
    `/api/skills/${encodeURIComponent(language)}/${encodeURIComponent(name)}/history`
  );
}

export function readSkillVersion(language: string, name: string, version: number) {
  return get<{ language: string; name: string; version: number; content: string }>(
    `/api/skills/${encodeURIComponent(language)}/${encodeURIComponent(name)}/history/${version}`
  );
}

export function writeSink(
  language: string,
  name: string,
  content: string,
  reason: string = ""
) {
  return put<{ path: string; size: number; mtime: number; archived?: HistoryEntry; history_count: number }>(
    `/api/sinks/${encodeURIComponent(language)}/${encodeURIComponent(name)}`,
    { content, reason }
  );
}

export function listSinkHistory(language: string, name: string) {
  return get<{ items: HistoryEntry[] }>(
    `/api/sinks/${encodeURIComponent(language)}/${encodeURIComponent(name)}/history`
  );
}

export function readSinkVersion(language: string, name: string, version: number) {
  return get<{ language: string; name: string; version: number; content: string }>(
    `/api/sinks/${encodeURIComponent(language)}/${encodeURIComponent(name)}/history/${version}`
  );
}


export function writeSinkRules(
  language: string,
  name: string,
  vulnerability: string,
  rules: SinkRuleDict[],
  reason: string = ""
) {
  return put<{
    path: string;
    size: number;
    mtime: number;
    archived?: HistoryEntry;
    history_count: number;
  }>(
    `/api/sinks/${encodeURIComponent(language)}/${encodeURIComponent(name)}/rules`,
    { vulnerability, rules, reason }
  );
}
