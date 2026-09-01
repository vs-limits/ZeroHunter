// 中英映射字典：在界面上以中文为主，英文作为小字辅助。

/** 漏洞类型 → 中文。来自 backend/app/scanner/sink/types.py 与既有产物。 */
export const VULN_LABELS: Record<string, string> = {
  auth_bypass: "鉴权绕过",
  buffer_overflow: "缓冲区溢出",
  code_execution: "代码执行",
  command_execution: "命令执行",
  crlf_injection: "CRLF 注入",
  csrf: "跨站请求伪造",
  deserialization: "反序列化",
  file_download: "文件下载",
  file_inclusion: "文件包含",
  file_path: "文件路径",
  file_upload: "文件上传",
  graphql_injection: "GraphQL 注入",
  info_disclosure: "信息泄漏",
  ldap_injection: "LDAP 注入",
  nosql_injection: "NoSQL 注入",
  path_traversal: "路径穿越",
  sql_injection: "SQL 注入",
  sql_semantics: "SQL 语义",
  ssrf: "服务端请求伪造",
  ssti: "服务端模板注入",
  unauthorized_access: "未授权访问",
  weak_credential: "弱口令",
  xpath_injection: "XPath 注入",
  xss: "跨站脚本",
  xxe: "外部实体注入",
};

/** 编程语言 → 中文（保留主名 + 中文短称）。 */
export const LANG_LABELS: Record<string, string> = {
  c: "C",
  cpp: "C++",
  go: "Go",
  html: "HTML",
  java: "Java",
  javascript: "JavaScript",
  php: "PHP",
  python: "Python",
  rust: "Rust",
  typescript: "TypeScript",
  _root: "通用",
};

/** Agent 角色 → 中文。 */
export const AGENT_LABELS: Record<string, string> = {
  treescan: "目录画像",
  callscan: "调用扫描",
  dataflowscan: "数据流恢复",
  auditor: "漏洞审计",
};

/** 提示词文件 → 中文标题。 */
export const PROMPT_LABELS: Record<string, string> = {
  "treescan.md": "目录画像",
  "callscan.md": "调用扫描",
  "auditor.md": "漏洞审计",
  "checker.md": "漏洞复核",
  "_shared_output_rules.md": "通用输出规约",
};

/** Severity → 中文。 */
export const SEVERITY_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

/** Verdict → 中文。 */
export const VERDICT_LABELS: Record<string, string> = {
  vulnerable: "存在漏洞",
  uncertain: "不确定",
  safe: "安全",
};

/** Run 状态 → 中文。 */
export const RUN_STATUS_LABELS: Record<string, string> = {
  pending: "待扫描",
  running: "正在扫描",
  done: "扫描完成",
  error: "出错",
  killed: "已终止",
  stopped: "已停止",
};

/** 通用工具：将 stem 翻译成中文，并保留原英文小字辅助。 */
export interface Bilingual {
  zh: string;
  en: string;
}

export function bilingualVuln(stem: string): Bilingual {
  const zh = VULN_LABELS[stem] ?? stem.replace(/_/g, " ");
  return { zh, en: stem };
}

export function bilingualLang(stem: string): Bilingual {
  const zh = LANG_LABELS[stem] ?? stem;
  return { zh, en: stem };
}

export function bilingualPrompt(name: string): Bilingual {
  const zh = PROMPT_LABELS[name] ?? name.replace(/\.md$/, "");
  return { zh, en: name };
}
