"""答辩用指标聚合脚本。

扫 repo/<source>/<owner>/<repo>/<version>/.defectmine/scans/*/，读取
scan.json + treescan_agent.json + callscan_agent.json + audit_agent.json，
按多个维度聚合后输出：

- aggregate/dashboard.json   全部结构化数据（喂前端 / 后续脚本）
- aggregate/dashboard.md     人类可读 Markdown 报告
- aggregate/funnel.csv       逐扫描漏斗数据（便于 Excel 画图）
- aggregate/findings.jsonl   全部 vulnerable findings 平铺（便于人工抽检）

用法：
    python backend/scripts/aggregate_metrics.py
    python backend/scripts/aggregate_metrics.py --out my_dashboard/
    python backend/scripts/aggregate_metrics.py --strategy latest    # 默认
    python backend/scripts/aggregate_metrics.py --strategy union     # 跨所有 scan 求并集
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT / "repo"
DEFAULT_OUT = PROJECT_ROOT / "aggregate"

ARTIFACTS_DIRNAME = ".defectmine"
SCANS_DIRNAME = "scans"

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class ScanRecord:
    project_path: str
    project_key: str
    version: str
    scan_id: str
    scan_dir: Path

    status: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None
    options: dict[str, Any] = field(default_factory=dict)
    completed_agents: list[str] = field(default_factory=list)

    languages: list[str] = field(default_factory=list)
    project_type: str | None = None
    primary_language: str | None = None

    files_total: int = 0
    sink_hits: int = 0
    candidate_chains: int = 0
    with_call_chain: int = 0
    callscan_by_severity: dict[str, int] = field(default_factory=dict)
    callscan_by_vuln: dict[str, int] = field(default_factory=dict)
    filter_stats: dict[str, int] = field(default_factory=dict)

    audited: int = 0
    vulnerable: int = 0
    uncertain: int = 0
    safe: int = 0
    llm_failed: int = 0
    audit_by_severity: dict[str, int] = field(default_factory=dict)
    audit_by_vuln: dict[str, int] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)

    has_audit: bool = False
    has_callscan: bool = False
    has_treescan: bool = False

    @property
    def sort_key(self) -> str:
        # scan_id 形如 20260520-204819-242392，字典序即时间序
        return self.scan_id


# ── 收集 ───────────────────────────────────────────────────────────────────


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _count_files(node: dict[str, Any]) -> int:
    """递归数 tree.json 的 files 总数（不含 binary 聚合块）。"""
    total = 0
    files = node.get("files")
    if isinstance(files, list):
        total += len(files)
    dirs = node.get("dirs")
    if isinstance(dirs, dict):
        for child in dirs.values():
            if isinstance(child, dict):
                total += _count_files(child)
    # binary 聚合块只算 total
    binary = node.get("binary")
    if isinstance(binary, dict):
        total += int(binary.get("total") or 0)
    return total


def _walk_scan_dirs() -> Iterable[tuple[str, str, Path]]:
    """yield (project_path, scan_id, scan_dir)。"""
    if not REPO_ROOT.is_dir():
        return
    for source in sorted(REPO_ROOT.iterdir()):
        if not source.is_dir() or source.name.startswith("."):
            continue
        for owner in sorted(source.iterdir()):
            if not owner.is_dir() or owner.name.startswith("."):
                continue
            for repo in sorted(owner.iterdir()):
                if not repo.is_dir() or repo.name.startswith("."):
                    continue
                for version in sorted(repo.iterdir()):
                    if not version.is_dir() or version.name.startswith("."):
                        continue
                    scans_root = version / ARTIFACTS_DIRNAME / SCANS_DIRNAME
                    if not scans_root.is_dir():
                        continue
                    for scan_dir in sorted(scans_root.iterdir()):
                        if not scan_dir.is_dir() or scan_dir.name.startswith("."):
                            continue
                        project_path = (
                            f"{source.name}/{owner.name}/{repo.name}/{version.name}"
                        )
                        yield project_path, scan_dir.name, scan_dir


def _load_scan_record(project_path: str, scan_id: str, scan_dir: Path) -> ScanRecord:
    parts = project_path.split("/")
    record = ScanRecord(
        project_path=project_path,
        project_key="/".join(parts[:3]) if len(parts) >= 3 else project_path,
        version=parts[3] if len(parts) >= 4 else "",
        scan_id=scan_id,
        scan_dir=scan_dir,
    )

    scan_meta = _safe_read_json(scan_dir / "scan.json") or {}
    record.status = scan_meta.get("status")
    record.started_at = scan_meta.get("started_at")
    record.finished_at = scan_meta.get("finished_at")
    duration = scan_meta.get("duration_seconds")
    record.duration_seconds = float(duration) if isinstance(duration, (int, float)) else None
    record.options = scan_meta.get("options") or {}
    record.completed_agents = list(scan_meta.get("completed_agents") or [])

    tree = _safe_read_json(scan_dir / "tree.json")
    if tree:
        record.files_total = _count_files(tree)

    treescan = _safe_read_json(scan_dir / "treescan_agent.json")
    if treescan:
        record.has_treescan = True
        record.project_type = treescan.get("project_type")
        stack = treescan.get("technology_stack") or {}
        # primary = backend[0] if exists, else first non-empty
        languages: list[str] = []
        for key in ("backend", "frontend", "runtime"):
            value = stack.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        norm = item.strip().lower()
                        if norm and norm not in languages:
                            languages.append(norm)
        record.languages = languages
        backend_langs = stack.get("backend") or []
        if isinstance(backend_langs, list) and backend_langs:
            first = backend_langs[0]
            if isinstance(first, str):
                record.primary_language = first.strip().lower() or None

    callscan = _safe_read_json(scan_dir / "callscan_agent.json")
    if callscan:
        record.has_callscan = True
        summary = callscan.get("summary") or {}
        record.sink_hits = int(summary.get("sink_hits") or 0)
        record.candidate_chains = int(summary.get("candidate_chains") or 0)
        record.with_call_chain = int(summary.get("with_call_chain") or 0)
        record.callscan_by_severity = dict(summary.get("by_severity") or {})
        record.callscan_by_vuln = dict(summary.get("by_vulnerability") or {})
        record.filter_stats = dict(summary.get("filter_stats") or {})
        cs_langs = callscan.get("languages") or []
        if isinstance(cs_langs, list):
            for lang in cs_langs:
                if isinstance(lang, str):
                    norm = lang.strip().lower()
                    if norm and norm not in record.languages:
                        record.languages.append(norm)

    audit = _safe_read_json(scan_dir / "audit_agent.json")
    if audit:
        record.has_audit = True
        summary = audit.get("summary") or {}
        record.audited = int(summary.get("total_audited") or 0)
        record.vulnerable = int(summary.get("vulnerable") or 0)
        record.uncertain = int(summary.get("uncertain") or 0)
        record.safe = int(summary.get("safe") or 0)
        record.llm_failed = int(summary.get("llm_failed") or 0)
        record.audit_by_severity = dict(summary.get("by_severity") or {})
        record.audit_by_vuln = dict(summary.get("by_vulnerability") or {})
        findings = audit.get("findings")
        if isinstance(findings, list):
            record.findings = [f for f in findings if isinstance(f, dict)]

    return record


def collect_scans() -> list[ScanRecord]:
    out: list[ScanRecord] = []
    for project_path, scan_id, scan_dir in _walk_scan_dirs():
        out.append(_load_scan_record(project_path, scan_id, scan_dir))
    return out


# ── 聚合 ───────────────────────────────────────────────────────────────────


def _latest_per_project(records: list[ScanRecord]) -> dict[str, ScanRecord]:
    """对每个 project_path，取最新一次有 audit 的 scan；若都没 audit，取最新的。"""
    by_project: dict[str, list[ScanRecord]] = defaultdict(list)
    for r in records:
        by_project[r.project_path].append(r)
    out: dict[str, ScanRecord] = {}
    for project, items in by_project.items():
        items_sorted = sorted(items, key=lambda r: r.sort_key, reverse=True)
        chosen = next((r for r in items_sorted if r.has_audit), items_sorted[0])
        out[project] = chosen
    return out


def _aggregate_findings(records: Iterable[ScanRecord]) -> dict[str, Any]:
    by_cwe: Counter[str] = Counter()
    by_cwe_vuln: Counter[str] = Counter()
    by_severity_vuln: Counter[str] = Counter()
    by_vuln_type: Counter[str] = Counter()
    by_vuln_type_vuln: Counter[str] = Counter()
    by_language: dict[str, Counter[str]] = defaultdict(Counter)
    cwe_by_repo: dict[str, set[str]] = defaultdict(set)

    all_findings: list[dict[str, Any]] = []
    vuln_findings: list[dict[str, Any]] = []

    for rec in records:
        for f in rec.findings:
            verdict = (f.get("verdict") or "").lower()
            cwe = (f.get("cwe_guess") or "").upper() or "UNKNOWN"
            severity = (f.get("severity") or "").lower() or "unknown"
            vuln = (f.get("vulnerability_type") or "").lower() or "unknown"
            language = (f.get("language") or "").lower() or "unknown"

            by_cwe[cwe] += 1
            by_vuln_type[vuln] += 1
            by_language[language][verdict] += 1
            by_language[language]["__total"] += 1
            cwe_by_repo[cwe].add(rec.project_key)

            entry = {
                "project_path": rec.project_path,
                "scan_id": rec.scan_id,
                "chain_id": f.get("chain_id"),
                "verdict": verdict,
                "cwe": cwe,
                "severity": severity,
                "vulnerability_type": vuln,
                "language": language,
                "confidence": f.get("confidence"),
                "title": f.get("title"),
                "sink_file": (f.get("sink") or {}).get("file"),
                "sink_line": (f.get("sink") or {}).get("line"),
            }
            all_findings.append(entry)

            if verdict == "vulnerable":
                by_cwe_vuln[cwe] += 1
                by_severity_vuln[severity] += 1
                by_vuln_type_vuln[vuln] += 1
                vuln_findings.append(entry)

    return {
        "by_cwe": {
            cwe: {
                "total": count,
                "vulnerable": by_cwe_vuln.get(cwe, 0),
                "repos": sorted(cwe_by_repo[cwe]),
            }
            for cwe, count in by_cwe.most_common()
        },
        "by_severity_vulnerable": dict(by_severity_vuln.most_common()),
        "by_vulnerability_type": {
            vuln: {
                "total": count,
                "vulnerable": by_vuln_type_vuln.get(vuln, 0),
            }
            for vuln, count in by_vuln_type.most_common()
        },
        "by_language": {
            lang: {
                "total": counts.get("__total", 0),
                "vulnerable": counts.get("vulnerable", 0),
                "uncertain": counts.get("uncertain", 0),
                "safe": counts.get("safe", 0),
            }
            for lang, counts in sorted(by_language.items())
        },
        "all_findings": all_findings,
        "vulnerable_findings": vuln_findings,
    }


def _funnel_sums(records: Iterable[ScanRecord]) -> dict[str, Any]:
    files = sink_hits = candidates = with_chain = audited = vulnerable = 0
    uncertain = safe = 0
    rg_raw = filtered_by_comment = filtered_by_dynamic = 0
    filtered_by_extra = kept = dedup_dropped = 0
    for r in records:
        files += r.files_total
        sink_hits += r.sink_hits
        candidates += r.candidate_chains
        with_chain += r.with_call_chain
        audited += r.audited
        vulnerable += r.vulnerable
        uncertain += r.uncertain
        safe += r.safe
        rg_raw += int(r.filter_stats.get("rg_raw") or 0)
        filtered_by_comment += int(r.filter_stats.get("filtered_by_comment") or 0)
        filtered_by_dynamic += int(r.filter_stats.get("filtered_by_dynamic") or 0)
        filtered_by_extra += int(r.filter_stats.get("filtered_by_extra") or 0)
        kept += int(r.filter_stats.get("kept") or 0)
        dedup_dropped += int(r.filter_stats.get("dedup_dropped") or 0)

    def _ratio(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    return {
        "files": files,
        "rg_raw_sink_hits": rg_raw,
        "sink_hits_kept": sink_hits,
        "candidate_chains": candidates,
        "with_call_chain": with_chain,
        "audited": audited,
        "vulnerable": vulnerable,
        "uncertain": uncertain,
        "safe": safe,
        "rates": {
            "sink_per_file": _ratio(sink_hits, files),
            "rg_kept_ratio": _ratio(sink_hits, rg_raw),
            "chain_per_sink": _ratio(candidates, sink_hits),
            "with_chain_ratio": _ratio(with_chain, candidates),
            "audit_per_chain": _ratio(audited, candidates),
            "vuln_per_audit": _ratio(vulnerable, audited),
            "vuln_per_candidate": _ratio(vulnerable, candidates),
        },
        "filter_stats_sum": {
            "rg_raw": rg_raw,
            "filtered_by_comment": filtered_by_comment,
            "filtered_by_dynamic": filtered_by_dynamic,
            "filtered_by_extra": filtered_by_extra,
            "kept": kept,
            "dedup_dropped": dedup_dropped,
        },
    }


def aggregate(records: list[ScanRecord], *, strategy: str = "latest") -> dict[str, Any]:
    latest_per_project = _latest_per_project(records)
    if strategy == "latest":
        selected = list(latest_per_project.values())
    else:
        selected = records

    languages_seen: set[str] = set()
    for r in selected:
        for lang in r.languages:
            languages_seen.add(lang)

    finding_agg = _aggregate_findings(selected)
    funnel = _funnel_sums(selected)

    by_repo = []
    for project_path, rec in sorted(latest_per_project.items()):
        all_for_repo = [r for r in records if r.project_path == project_path]
        best_vuln = max(all_for_repo, key=lambda r: r.vulnerable, default=rec)
        by_repo.append(
            {
                "project_path": project_path,
                "project_key": rec.project_key,
                "version": rec.version,
                "scan_count": len(all_for_repo),
                "primary_language": rec.primary_language,
                "languages": rec.languages,
                "project_type": rec.project_type,
                "latest_scan_id": rec.scan_id,
                "latest_status": rec.status,
                "latest": {
                    "files": rec.files_total,
                    "sink_hits": rec.sink_hits,
                    "candidate_chains": rec.candidate_chains,
                    "with_call_chain": rec.with_call_chain,
                    "audited": rec.audited,
                    "vulnerable": rec.vulnerable,
                    "uncertain": rec.uncertain,
                    "safe": rec.safe,
                    "duration_seconds": rec.duration_seconds,
                },
                "best_vuln_scan": {
                    "scan_id": best_vuln.scan_id,
                    "vulnerable": best_vuln.vulnerable,
                },
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "strategy": strategy,
        "coverage": {
            "repos_total": len(latest_per_project),
            "scans_total": len(records),
            "scans_with_audit": sum(1 for r in records if r.has_audit),
            "languages": sorted(languages_seen),
            "languages_count": len(languages_seen),
            "cwe_types_count": len(finding_agg["by_cwe"]),
            "vulnerability_types_count": len(finding_agg["by_vulnerability_type"]),
        },
        "funnel": funnel,
        "by_repo": by_repo,
        "by_cwe": finding_agg["by_cwe"],
        "by_severity_vulnerable": finding_agg["by_severity_vulnerable"],
        "by_vulnerability_type": finding_agg["by_vulnerability_type"],
        "by_language": finding_agg["by_language"],
        "scans": [
            {
                "project_path": r.project_path,
                "scan_id": r.scan_id,
                "status": r.status,
                "completed_agents": r.completed_agents,
                "files": r.files_total,
                "sink_hits": r.sink_hits,
                "candidate_chains": r.candidate_chains,
                "audited": r.audited,
                "vulnerable": r.vulnerable,
                "uncertain": r.uncertain,
                "safe": r.safe,
                "duration_seconds": r.duration_seconds,
                "primary_language": r.primary_language,
            }
            for r in sorted(records, key=lambda r: (r.project_path, r.scan_id))
        ],
        "_findings_for_jsonl": finding_agg["all_findings"],
        "_vulnerable_findings_top": sorted(
            finding_agg["vulnerable_findings"],
            key=lambda f: (
                -SEVERITY_RANK.get(f.get("severity") or "", 0),
                -(f.get("confidence") or 0),
            ),
        )[:50],
    }


# ── 渲染 Markdown ──────────────────────────────────────────────────────────


def _fmt_int(n: int | float | None) -> str:
    if n is None:
        return "—"
    if isinstance(n, float) and not n.is_integer():
        return f"{n:.2f}"
    return f"{int(n):,}"


def _fmt_ratio(r: float | None) -> str:
    if r is None:
        return "—"
    return f"{r * 100:.2f}%"


def render_markdown(d: dict[str, Any]) -> str:
    lines: list[str] = []
    cov = d["coverage"]
    funnel = d["funnel"]
    rates = funnel["rates"]

    lines.append("# DefectMine 答辩指标报告\n")
    lines.append(f"_生成时间：{d['generated_at']}（策略：{d['strategy']}）_\n")

    lines.append("## 1. 覆盖维度\n")
    lines.append("| 维度 | 数值 |")
    lines.append("|---|---|")
    lines.append(f"| 仓库数 | {cov['repos_total']} |")
    lines.append(f"| 总扫描数 | {cov['scans_total']} |")
    lines.append(f"| 含 Auditor 结果的扫描数 | {cov['scans_with_audit']} |")
    lines.append(f"| 编程语言覆盖 | {cov['languages_count']}（{', '.join(cov['languages'])}）|")
    lines.append(f"| CWE 类型覆盖 | {cov['cwe_types_count']} |")
    lines.append(f"| 漏洞类型覆盖 | {cov['vulnerability_types_count']} |")
    lines.append("")

    lines.append("## 2. 漏斗收敛（取每仓最新有效扫描求和）\n")
    lines.append("```")
    lines.append(f"文件总数            {_fmt_int(funnel['files']):>12}")
    lines.append(f"  ↓ ripgrep 原始命中 {_fmt_int(funnel['rg_raw_sink_hits']):>12}  ({_fmt_ratio(rates['rg_kept_ratio'])} kept)")
    lines.append(f"  ↓ 过滤后 sink 命中 {_fmt_int(funnel['sink_hits_kept']):>12}  ({_fmt_ratio(rates['sink_per_file'])} of files)")
    lines.append(f"  ↓ 候选调用链       {_fmt_int(funnel['candidate_chains']):>12}  ({_fmt_ratio(rates['chain_per_sink'])} of sinks)")
    lines.append(f"  ↓ 含完整调用链     {_fmt_int(funnel['with_call_chain']):>12}  ({_fmt_ratio(rates['with_chain_ratio'])} of chains)")
    lines.append(f"  ↓ 送审 Auditor     {_fmt_int(funnel['audited']):>12}  ({_fmt_ratio(rates['audit_per_chain'])} of chains)")
    lines.append(f"  ↓ Auditor: vuln    {_fmt_int(funnel['vulnerable']):>12}  ({_fmt_ratio(rates['vuln_per_audit'])} of audited)")
    lines.append(f"    Auditor: uncert  {_fmt_int(funnel['uncertain']):>12}")
    lines.append(f"    Auditor: safe    {_fmt_int(funnel['safe']):>12}")
    lines.append("```\n")
    lines.append(
        f"_漏报/误报相关：候选 → vulnerable 整体收敛比 "
        f"**{_fmt_ratio(rates['vuln_per_candidate'])}**。_\n"
    )

    lines.append("## 3. 按语言（基于 finding.language）\n")
    lines.append("| 语言 | 送审 | vulnerable | uncertain | safe |")
    lines.append("|---|---:|---:|---:|---:|")
    for lang, c in d["by_language"].items():
        lines.append(
            f"| {lang} | {c['total']} | {c['vulnerable']} | {c['uncertain']} | {c['safe']} |"
        )
    lines.append("")

    lines.append("## 4. 按 CWE\n")
    lines.append("| CWE | 出现总数 | vulnerable | 涉及仓库 |")
    lines.append("|---|---:|---:|---|")
    for cwe, c in d["by_cwe"].items():
        repos = ", ".join(c["repos"]) if c["repos"] else "—"
        lines.append(f"| {cwe} | {c['total']} | {c['vulnerable']} | {repos} |")
    lines.append("")

    lines.append("## 5. 按严重度（仅 vulnerable）\n")
    lines.append("| 严重度 | 数量 |")
    lines.append("|---|---:|")
    for sev in ("critical", "high", "medium", "low", "unknown"):
        if sev in d["by_severity_vulnerable"]:
            lines.append(f"| {sev} | {d['by_severity_vulnerable'][sev]} |")
    lines.append("")

    lines.append("## 6. 按漏洞类型（前 15）\n")
    lines.append("| 漏洞类型 | 出现总数 | vulnerable |")
    lines.append("|---|---:|---:|")
    for vuln, c in list(d["by_vulnerability_type"].items())[:15]:
        lines.append(f"| {vuln} | {c['total']} | {c['vulnerable']} |")
    lines.append("")

    lines.append("## 7. 按仓库（最新 scan）\n")
    lines.append(
        "| 仓库 | 语言 | files | sink | chain | 送审 | vuln | uncert | safe | scan 数 |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in d["by_repo"]:
        lat = r["latest"]
        lines.append(
            f"| {r['project_key']}/{r['version']} | "
            f"{r['primary_language'] or '—'} | "
            f"{_fmt_int(lat['files'])} | {_fmt_int(lat['sink_hits'])} | "
            f"{_fmt_int(lat['candidate_chains'])} | {_fmt_int(lat['audited'])} | "
            f"{_fmt_int(lat['vulnerable'])} | {_fmt_int(lat['uncertain'])} | "
            f"{_fmt_int(lat['safe'])} | {r['scan_count']} |"
        )
    lines.append("")

    top = d.get("_vulnerable_findings_top") or []
    if top:
        lines.append("## 8. Top vulnerable findings（按严重度 + 置信度排序，前 50）\n")
        lines.append(
            "| # | 严重度 | CWE | 类型 | 语言 | 置信 | 标题 | sink |"
        )
        lines.append("|---:|---|---|---|---|---:|---|---|")
        for i, f in enumerate(top, 1):
            sink_loc = f"{f.get('sink_file') or '—'}:{f.get('sink_line') or ''}"
            title = (f.get("title") or "").replace("|", "/")[:80]
            conf = f.get("confidence")
            conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else "—"
            lines.append(
                f"| {i} | {f.get('severity') or '—'} | {f.get('cwe') or '—'} | "
                f"{f.get('vulnerability_type') or '—'} | {f.get('language') or '—'} | "
                f"{conf_s} | {title} | `{sink_loc}` |"
            )
        lines.append("")

    return "\n".join(lines) + "\n"


# ── 写出 ───────────────────────────────────────────────────────────────────


def write_outputs(dashboard: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 拆出私有字段
    findings_for_jsonl = dashboard.pop("_findings_for_jsonl", [])
    _ = dashboard.pop("_vulnerable_findings_top", None)

    # 重新塞回 top（render 时已用，但 JSON 也保留一份）
    dashboard["top_vulnerable"] = _ or []

    (out_dir / "dashboard.json").write_text(
        json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"  wrote {out_dir / 'dashboard.json'}")

    md_path = out_dir / "dashboard.md"
    # 临时把 top 还原给 render 用
    dashboard["_vulnerable_findings_top"] = dashboard["top_vulnerable"]
    md_path.write_text(render_markdown(dashboard), encoding="utf-8")
    dashboard.pop("_vulnerable_findings_top", None)
    print(f"  wrote {md_path}")

    # funnel CSV：逐扫描
    csv_path = out_dir / "funnel.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "project_path",
                "scan_id",
                "status",
                "primary_language",
                "files",
                "sink_hits",
                "candidate_chains",
                "audited",
                "vulnerable",
                "uncertain",
                "safe",
                "duration_seconds",
            ],
        )
        writer.writeheader()
        for s in dashboard["scans"]:
            writer.writerow(s)
    print(f"  wrote {csv_path}")

    # findings JSONL（便于人工抽样标注）
    jsonl_path = out_dir / "findings.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fp:
        for f in findings_for_jsonl:
            fp.write(json.dumps(f, ensure_ascii=False) + "\n")
    print(f"  wrote {jsonl_path}  ({len(findings_for_jsonl)} findings)")


# ── CLI ────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aggregate_metrics",
        description="聚合所有 .defectmine/scans/ 产物为答辩指标报告",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"输出目录（默认 {DEFAULT_OUT}）",
    )
    parser.add_argument(
        "--strategy",
        choices=["latest", "union"],
        default="latest",
        help="latest=每仓最新一次；union=跨所有扫描合并",
    )
    args = parser.parse_args(argv)

    print(f"扫描 {REPO_ROOT}/")
    records = collect_scans()
    print(f"  发现 {len(records)} 次扫描")
    print(f"  其中 {sum(1 for r in records if r.has_audit)} 次有 Auditor 产物")

    dashboard = aggregate(records, strategy=args.strategy)

    print(f"\n汇总：")
    cov = dashboard["coverage"]
    print(f"  仓库={cov['repos_total']}  scan={cov['scans_total']}  语言={cov['languages_count']}  CWE={cov['cwe_types_count']}")
    fn = dashboard["funnel"]
    print(
        f"  漏斗: files={fn['files']:,} → sink={fn['sink_hits']:,} "
        f"→ chain={fn['candidate_chains']:,} → audit={fn['audited']:,} "
        f"→ vuln={fn['vulnerable']:,}"
    )

    print(f"\n写出到 {args.out}/")
    write_outputs(dashboard, args.out)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
