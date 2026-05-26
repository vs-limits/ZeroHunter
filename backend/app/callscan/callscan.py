from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.callscan.batch import (
    CALLSCAN_ALL_CHAINS_FILENAME,
    CALLSCAN_COVERAGE_FILENAME,
    CALLSCAN_DISCOVERY_META_FILENAME,
    CALLSCAN_PARTIAL_CHAINS_FILENAME,
    build_callscan_coverage,
)
from app.callscan.paths import RepoPathContext
from app.callscan.priority_schema import (
    priority_chain_record_from_audit_pack,
    validate_priority_chain_records,
)
from app.callscan.rules import (
    RG_EXCLUDE_GLOBS,
    infer_languages_from_technology_stack,
    should_skip_scan_path,
)
from app.callscan.rank import attach_rank_to_audit_pack, rank_impact_paths, select_scanner_queue
from app.callscan.slice import (
    CodeSlicer,
    build_tldr_impact_paths,
    extract_call_arguments,
    filter_complete_impact_paths,
    format_audit_pack,
)
from app.scanner.sink import (
    LoadedSinkRule as SinkRule,
    line_is_dynamic,
    load_sink_rules,
    matches_extra,
    rg_pattern_for_rules,
    rules_as_dicts,
)


CALLSCAN_REPORT_FILENAME = "callscan_agent.json"
CALLSCAN_PRIORITY_CHAINS_FILENAME = "callscan_chains.priority.jsonl"
TREESCAN_PROFILE_FILENAME = "treescan_agent.json"
ProgressReporter = Callable[[dict[str, Any]], None]
TldrResolver = Callable[[list[dict[str, Any]]], dict[str, Any] | list[dict[str, Any]]]
FALLBACK_CONTEXT_RADIUS = 30


#----------- CallScan 阶段结果：当前先定义行为理解产物，不伪造还未追踪到的调用链 ------------#
@dataclass(frozen=True, slots=True)
class CallScanResult:
    root: Path
    artifacts_dir: Path
    report: dict[str, Any]

    def state_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "artifacts_dir": str(self.artifacts_dir),
            "artifacts": {
                "report": str(self.artifacts_dir / CALLSCAN_REPORT_FILENAME),
                "priority_chains": str(self.artifacts_dir / CALLSCAN_PRIORITY_CHAINS_FILENAME),
                "all_chains": str(self.artifacts_dir / CALLSCAN_ALL_CHAINS_FILENAME),
                "partial_chains": str(self.artifacts_dir / CALLSCAN_PARTIAL_CHAINS_FILENAME),
                "coverage": str(self.artifacts_dir / CALLSCAN_COVERAGE_FILENAME),
            },
            "summary": self.report.get("summary", {}),
        }


def run_callscan(
    project_path: str | Path,
    *,
    artifacts_dir: str | Path | None = None,
    treescan_profile_path: str | Path | None = None,
    persist: bool = True,
    progress_reporter: ProgressReporter | None = None,
    tldr_resolver: TldrResolver | None = None,
    priority_chain_limit: int = 20,
    reuse_discovery: bool = False,
    force_discover: bool = False,
) -> CallScanResult:
    """
    Build the CallScan artifact from TreeScan output.

    This stage prepares the schema, path policy, sink rule set, rg sink search,
    local traces, and optional static TLDR call-graph enrichment.
    """
    started_at = time.perf_counter()
    context = RepoPathContext.from_project(project_path, artifacts_dir=artifacts_dir)
    profile_path = _resolve_profile_path(context, treescan_profile_path)

    _report_progress(
        progress_reporter,
        {
            "event": "callscan_started",
            "project_root": str(context.root),
            "treescan_profile": str(profile_path),
        },
    )

    treescan_profile = _read_json(profile_path)
    scanner_hints = _object_or_empty(treescan_profile.get("scanner_hints"))
    # 根据 TreeScan 输出的技术栈正则命中语言；命中后加载该语言全部 sink 规则，
    # 不在 CallScan 预筛阶段提前判断漏洞类型，避免漏掉后续审计入口。
    sink_languages = (
        infer_languages_from_technology_stack(scanner_hints.get("sink_languages"))
        or _infer_sink_languages(treescan_profile)
    )
    sink_rules = load_sink_rules(
        languages=sink_languages,
    )
    cache_meta = _build_discovery_meta(
        context=context,
        treescan_profile_path=profile_path,
        sink_rules=rules_as_dicts(sink_rules),
        report=None,
    )
    if reuse_discovery and not force_discover and _discovery_cache_is_valid(context, cache_meta):
        report = _read_json(context.artifact_path(CALLSCAN_REPORT_FILENAME))
        _report_progress(
            progress_reporter,
            {
                "event": "callscan_discovery_reused",
                "artifact": str(context.artifact_path(CALLSCAN_ALL_CHAINS_FILENAME)),
                "summary": report.get("summary", {}),
            },
        )
        return CallScanResult(root=context.root, artifacts_dir=context.artifacts_dir, report=report)

    sink_hits = _collect_sink_hits(
        context=context,
        sink_rules=sink_rules,
        scanner_hints=scanner_hints,
        progress_reporter=progress_reporter,
    )
    sink_analyses, function_pool = _build_sink_analyses(
        context=context,
        sink_hits=sink_hits,
        progress_reporter=progress_reporter,
    )
    _report_progress(
        progress_reporter,
        {
            "event": "callscan_sink_pipeline_completed",
            "total": len(sink_analyses),
        },
    )
    mcp_tasks = _build_static_tldr_tasks(sink_analyses)
    resolver = tldr_resolver or _default_tldr_cache_resolver(context)
    tldr_result = _run_tldr_mcp_tasks(mcp_tasks, resolver, progress_reporter)
    report = build_callscan_report(
        context=context,
        treescan_profile=treescan_profile,
        treescan_profile_path=profile_path,
        sink_rules=rules_as_dicts(sink_rules),
        sink_hits=sink_hits,
        sink_analyses=sink_analyses,
        mcp_tasks=mcp_tasks,
        tldr_result=tldr_result,
        function_pool=function_pool,
        elapsed_seconds=round(time.perf_counter() - started_at, 4),
        priority_chain_limit=priority_chain_limit,
    )
    report["discovery_meta"] = _build_discovery_meta(
        context=context,
        treescan_profile_path=profile_path,
        sink_rules=rules_as_dicts(sink_rules),
        report=report,
    )

    if persist:
        context.artifacts_dir.mkdir(parents=True, exist_ok=True)
        _write_jsonl(
            report.get("priority_chains", []),
            context.artifact_path(CALLSCAN_PRIORITY_CHAINS_FILENAME),
        )
        # Discovery artifacts separate the expensive full candidate pool from the
        # small compatibility queue consumed by the legacy Scanner entrypoint.
        _write_jsonl(report.get("_all_chains", []), context.artifact_path(CALLSCAN_ALL_CHAINS_FILENAME))
        _write_jsonl(report.get("_partial_chains", []), context.artifact_path(CALLSCAN_PARTIAL_CHAINS_FILENAME))
        report.pop("_all_chains", None)
        report.pop("_partial_chains", None)
        _write_json(report.get("coverage", {}), context.artifact_path(CALLSCAN_COVERAGE_FILENAME))
        _write_json(report.get("discovery_meta", {}), context.artifact_path(CALLSCAN_DISCOVERY_META_FILENAME))
        _write_json(report, context.artifact_path(CALLSCAN_REPORT_FILENAME))

    _report_progress(
        progress_reporter,
        {
            "event": "callscan_completed",
            "artifact": str(context.artifact_path(CALLSCAN_REPORT_FILENAME)),
            "priority_chains_artifact": str(context.artifact_path(CALLSCAN_PRIORITY_CHAINS_FILENAME)),
            "all_chains_artifact": str(context.artifact_path(CALLSCAN_ALL_CHAINS_FILENAME)),
            "summary": report.get("summary", {}),
        },
    )

    return CallScanResult(
        root=context.root,
        artifacts_dir=context.artifacts_dir,
        report=report,
    )


#----------- CallScan JSON 契约：定义行为理解层的稳定结构，rg 和静态 TLDR 只填充对应数组 ------------#
def build_callscan_report(
    *,
    context: RepoPathContext,
    treescan_profile: dict[str, Any],
    treescan_profile_path: Path,
    sink_rules: list[dict[str, Any]],
    sink_hits: list[dict[str, Any]],
    sink_analyses: list[dict[str, Any]],
    mcp_tasks: list[dict[str, Any]],
    tldr_result: dict[str, Any],
    function_pool: dict[str, Any],
    elapsed_seconds: float,
    priority_chain_limit: int = 20,
) -> dict[str, Any]:
    scanner_hints = _object_or_empty(treescan_profile.get("scanner_hints"))
    technology_stack = _object_or_empty(treescan_profile.get("technology_stack"))
    local_call_edges = _local_edges_from_analyses(sink_analyses)
    traces = _local_traces_from_analyses(sink_analyses)
    cross_file_edges = _list_of_dicts(tldr_result.get("cross_file_edges"))
    tldr_impact_paths = build_tldr_impact_paths(
        sink_analyses=sink_analyses,
        cross_file_edges=cross_file_edges,
    )
    complete_impact_paths = filter_complete_impact_paths(tldr_impact_paths)
    # Rank complete chains before rendering Scanner input. The full candidate set
    # stays in complete_impact_paths; only the highest-value chains enter the queue.
    ranked_impact_paths = rank_impact_paths(
        complete_impact_paths=complete_impact_paths,
        sink_analyses=sink_analyses,
        sink_rules=sink_rules,
    )
    scanner_queue_paths = select_scanner_queue(
        ranked_impact_paths,
        limit=max(int(priority_chain_limit or 0), 0),
        per_analysis_limit=1,
    )
    audit_packs = [
        attach_rank_to_audit_pack(
            format_audit_pack(candidate_path=ranked_path["path"], function_pool=function_pool),
            ranked_path,
        )
        for ranked_path in scanner_queue_paths
    ]
    # JSONL 中间产物：每行是一条完整优先级调用链，Scanner 可按行流式消费。
    priority_chains = _priority_chain_records(audit_packs)
    validate_priority_chain_records(priority_chains)
    # Full discovery pool: CallScan renders every complete ranked path once so
    # later audit batches can be scheduled without re-running sink discovery.
    all_audit_packs = [
        attach_rank_to_audit_pack(
            format_audit_pack(candidate_path=ranked_path["path"], function_pool=function_pool),
            ranked_path,
        )
        for ranked_path in ranked_impact_paths
    ]
    all_chains = _priority_chain_records(all_audit_packs)
    validate_priority_chain_records(all_chains)
    partial_chains = _partial_chain_records(
        tldr_impact_paths=tldr_impact_paths,
        complete_impact_paths=complete_impact_paths,
        sink_analyses=sink_analyses,
    )
    coverage = build_callscan_coverage(all_chains, partial_chains)
    entry_nodes = _list_of_dicts(tldr_result.get("entry_nodes"))
    uncertain_edges = [
        *_uncertain_edges_from_analyses(sink_analyses),
        *_list_of_dicts(tldr_result.get("uncertain_edges")),
    ]

    return {
        "schema_version": "defectmine.callscan.v2",
        "status": "local_traces_built",
        "project": {
            "root_name": context.root.name,
            "root_path": str(context.root),
            "project_name": treescan_profile.get("project_name", "unknown"),
            "project_function": treescan_profile.get("project_function", "unknown"),
            "project_type": treescan_profile.get("project_type", "unknown"),
            "technology_stack": technology_stack,
        },
        "inputs": {
            "treescan_profile": context.relative(treescan_profile_path),
            "scanner_hints": scanner_hints,
            "sink_rules": sink_rules,
        },
        "outputs": {
            "report": context.relative(context.artifact_path(CALLSCAN_REPORT_FILENAME)),
            "priority_chains": context.relative(context.artifact_path(CALLSCAN_PRIORITY_CHAINS_FILENAME)),
            "all_chains": context.relative(context.artifact_path(CALLSCAN_ALL_CHAINS_FILENAME)),
            "partial_chains": context.relative(context.artifact_path(CALLSCAN_PARTIAL_CHAINS_FILENAME)),
            "coverage": context.relative(context.artifact_path(CALLSCAN_COVERAGE_FILENAME)),
            "discovery_meta": context.relative(context.artifact_path(CALLSCAN_DISCOVERY_META_FILENAME)),
            "priority_chain_limit": max(int(priority_chain_limit or 0), 0),
        },
        "path_policy": {
            "style": "repo-relative-posix",
            "root": str(context.root),
            "artifacts_dir": context.relative(context.artifacts_dir),
            "excluded_prefixes": _string_list(scanner_hints.get("exclude_paths")) + [".defectmine/"],
        },
        "tool_strategy": {
            "rg": {
                "enabled": True,
                "role": "full-repository sink preselection",
                "command_shape": "rg -u --json -n --column -S -e <sink-pattern> -g <include> -g <exclude> <repo-root>",
                "output_target": ".defectmine/callscan_agent.json:sink_hits",
            },
            "static_tldr": {
                "enabled": bool(tldr_result.get("enabled")),
                "status": tldr_result.get("status", "not_configured"),
                "role": "static call-graph cache resolver",
                "limits": [
                    "depends on the freshness of .tldr/cache/call_graph.json",
                    "does not cover every technology stack",
                    "does not replace local evidence verification",
                ],
                "scheduling_policy": [
                    "consume callscan_agent.json:mcp_tasks as static TLDR lookup jobs",
                    "resolve cross-file callers for sink scopes found by local analysis",
                    "verify every returned static edge before trusting it",
                    "mark dynamic or unresolved edges as uncertain_edges",
                ],
                "future_inputs": [
                    "sink_analyses[].enclosing_scope",
                    "sink_analyses[].backward_slice",
                    "sink_analyses[].same_file_callers",
                    "mcp_tasks[]",
                ],
            },
        },
        "sink_hits": sink_hits,
        "sink_analyses": sink_analyses,
        "local_call_edges": local_call_edges,
        "cross_file_edges": cross_file_edges,
        "entry_nodes": entry_nodes,
        "tldr_impact_paths": tldr_impact_paths,
        "complete_impact_paths": complete_impact_paths,
        "ranked_impact_paths": ranked_impact_paths,
        "all_candidate_preview": all_chains[:20],
        "partial_chain_preview": partial_chains[:20],
        "coverage": coverage,
        "function_pool": function_pool,
        "audit_packs": audit_packs,
        "scanner_audit_queue": audit_packs,
        "_all_chains": all_chains,
        "_partial_chains": partial_chains,
        "priority_chains": priority_chains,
        "traces": traces,
        "uncertain_edges": uncertain_edges,
        "mcp_tasks": mcp_tasks,
        "mcp_results": tldr_result,
        "summary": {
            "sink_rules": len(sink_rules),
            "sink_hits": len(sink_hits),
            "sink_analyses": len(sink_analyses),
            "local_call_edges": len(local_call_edges),
            "cross_file_edges": len(cross_file_edges),
            "entry_nodes": len(entry_nodes),
            "tldr_impact_paths": len(tldr_impact_paths),
            "complete_impact_paths": len(complete_impact_paths),
            "ranked_impact_paths": len(ranked_impact_paths),
            "all_chains": len(all_chains),
            "partial_chains": len(partial_chains),
            "function_pool": len(function_pool),
            "audit_packs": len(audit_packs),
            "scanner_audit_queue": len(audit_packs),
            "priority_chains": len(priority_chains),
            "traces": len(traces),
            "uncertain_edges": len(uncertain_edges),
            "mcp_tasks": len(mcp_tasks),
            "elapsed_seconds": elapsed_seconds,
        },
    }


#----------- Step 1：使用 rg.exe -u --json 对 sink 规则做全仓库预筛，并生成 sink_hits ------------#
def _collect_sink_hits(
    *,
    context: RepoPathContext,
    sink_rules: list[SinkRule],
    scanner_hints: dict[str, Any],
    progress_reporter: ProgressReporter | None,
) -> list[dict[str, Any]]:
    rg_command = _resolve_rg_command()
    hint_include_globs = _string_list(scanner_hints.get("rg_include_globs"))
    exclude_globs = _unique([*RG_EXCLUDE_GLOBS, *_string_list(scanner_hints.get("rg_exclude_globs"))])

    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int, str]] = set()

    for rule in sink_rules:
        pattern = rg_pattern_for_rules([rule])
        if not pattern:
            continue

        _report_progress(
            progress_reporter,
            {
                "event": "callscan_rg_rule_started",
                "sink_rule": rule.id,
                "language": rule.language,
                "category": rule.category,
            },
        )
        completed = _run_rg(
            rg_command=rg_command,
            root=context.root,
            pattern=pattern,
            # Run each rule only against its own language extensions. This keeps
            # broad multi-stack scans from matching JavaScript sinks in PHP files.
            include_globs=_include_globs_for_rules([rule]) or hint_include_globs,
            exclude_globs=exclude_globs,
        )
        rule_hits = _parse_rg_matches(
            context=context,
            rule=rule,
            stdout=completed.stdout,
        )
        for hit in rule_hits:
            key = (
                hit["sink_id"],
                hit["file"],
                int(hit["line"]),
                int(hit["column"]),
                hit["match"],
            )
            if key in seen:
                continue
            seen.add(key)
            hits.append(hit)

        _report_progress(
            progress_reporter,
            {
                "event": "callscan_rg_rule_completed",
                "sink_rule": rule.id,
                "matches": len(rule_hits),
                "returncode": completed.returncode,
            },
        )

    return sorted(
        hits,
        key=lambda item: (item["file"], int(item["line"]), int(item["column"]), item["sink_id"]),
    )


def _run_rg(
    *,
    rg_command: str,
    root: Path,
    pattern: str,
    include_globs: list[str],
    exclude_globs: list[str],
) -> subprocess.CompletedProcess[str]:
    command = [
        rg_command,
        "-u",
        "--json",
        "-n",
        "--column",
        "-S",
        "-e",
        pattern,
    ]
    for glob in include_globs:
        command.extend(["-g", glob])
    for glob in exclude_globs:
        command.extend(["-g", glob])
    command.append(str(root))

    completed = subprocess.run(
        command,
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(
            f"rg sink scan failed with code {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed


def _parse_rg_matches(
    *,
    context: RepoPathContext,
    rule: SinkRule,
    stdout: str,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue

        data = _object_or_empty(event.get("data"))
        raw_path = _object_or_empty(data.get("path")).get("text", "")
        if not raw_path:
            continue
        normalized = context.normalize(raw_path)
        if normalized["is_artifact"]:
            continue
        if should_skip_scan_path(str(normalized["path"])):
            continue

        line_number = int(data.get("line_number", 0) or 0)
        line_text = str(_object_or_empty(data.get("lines")).get("text", "")).rstrip("\r\n")
        if rule.require_dynamic and not line_is_dynamic(line_text):
            continue
        if not matches_extra(rule, line_text):
            continue
        for submatch in data.get("submatches", []):
            if not isinstance(submatch, dict):
                continue
            matched_text = str(_object_or_empty(submatch.get("match")).get("text", ""))
            start = int(submatch.get("start", 0) or 0)
            hits.append(
                {
                    "sink_id": rule.id,
                    "function": rule.function,
                    "language": rule.language,
                    "category": rule.category,
                    "vulnerability": rule.vulnerability,
                    "file": normalized["path"],
                    "line": line_number,
                    "column": start + 1,
                    "match": matched_text,
                    "evidence": line_text.strip(),
                    "confidence": "raw-hit",
                }
            )
    return hits


#----------- Step 2：本地解析 sink 所在作用域，生成 sink_analyses 行为画像 ------------#
def _build_sink_analyses(
    *,
    context: RepoPathContext,
    sink_hits: list[dict[str, Any]],
    progress_reporter: ProgressReporter | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    slicer = CodeSlicer(context.root)
    block_cache: dict[str, list[dict[str, Any]]] = {}
    analyses: list[dict[str, Any]] = []

    for index, hit in enumerate(sink_hits, start=1):
        relative_path = str(hit.get("file", ""))
        if not relative_path:
            continue

        lines = slicer.read_source_lines(relative_path)
        if not lines:
            continue

        if relative_path not in block_cache:
            block_cache[relative_path] = _build_block_index(lines, str(hit.get("language", "")))

        blocks = block_cache[relative_path]
        block = _extract_enclosing_block(lines, hit, blocks)
        _report_sink_pipeline_event(progress_reporter, index, len(sink_hits), hit, block)
        analyses.append(
            _sink_analysis_from_block(
                hit=hit,
                block=block,
                lines=lines,
                blocks=blocks,
                slicer=slicer,
            )
        )

        if index % 100 == 0:
            _report_progress(
                progress_reporter,
                {
                    "event": "callscan_sink_analyses_progress",
                    "processed": index,
                    "total": len(sink_hits),
                },
            )

    return analyses, slicer.function_pool.as_dict()


def _report_sink_pipeline_event(
    progress_reporter: ProgressReporter | None,
    index: int,
    total: int,
    hit: dict[str, Any],
    block: dict[str, Any],
) -> None:
    if progress_reporter is None:
        return
    if not _should_report_sink_pipeline_item(index, total):
        if index == 16 and total > 30:
            _report_progress(
                progress_reporter,
                {
                    "event": "callscan_sink_pipeline_omitted",
                    "omitted": total - 30,
                },
            )
        return

    _report_progress(
        progress_reporter,
        {
            "event": "callscan_sink_pipeline_item",
            "index": index,
            "total": total,
            "sink": _display_sink_name(hit),
            "sink_id": hit.get("sink_id", ""),
            "file": hit.get("file", ""),
            "line": hit.get("line", 0),
            "scope": block.get("symbol", ""),
            "category": hit.get("category", ""),
        },
    )


def _should_report_sink_pipeline_item(index: int, total: int) -> bool:
    if total <= 30:
        return True
    return index <= 15 or index > total - 15


def _display_sink_name(hit: dict[str, Any]) -> str:
    function = str(hit.get("function", "")).strip()
    if function:
        return function
    sink_id = str(hit.get("sink_id", ""))
    match = str(hit.get("match", "")).strip()
    if sink_id:
        tail = sink_id.split(":")[-1].split("-")[-1]
        if tail and len(tail) <= 32:
            return tail
    if match:
        return match.split("(", 1)[0].strip().strip(".`$") or match
    return "sink"


def _build_block_index(lines: list[str], language: str) -> list[dict[str, Any]]:
    language = language.casefold()
    if language == "python":
        return _build_python_blocks(lines)
    return _build_brace_blocks(lines)


def _extract_enclosing_block(
    lines: list[str],
    hit: dict[str, Any],
    blocks: list[dict[str, Any]],
) -> dict[str, Any]:
    sink_line = int(hit.get("line", 0) or 0)
    candidates = [
        block
        for block in blocks
        if int(block["start_line"]) <= sink_line <= int(block["end_line"])
    ]
    if candidates:
        function_like = [
            item
            for item in candidates
            if item.get("confidence") == "high" or _looks_like_function_signature(str(item.get("signature", "")))
        ]
        pool = function_like or candidates
        return min(pool, key=lambda item: int(item["end_line"]) - int(item["start_line"]))
    return _extract_fallback_block(lines, sink_line)


def _build_brace_blocks(lines: list[str]) -> list[dict[str, Any]]:
    stack: list[tuple[int, int]] = []
    blocks: list[dict[str, Any]] = []

    for line_index, line in enumerate(lines, start=1):
        for column, char in enumerate(line, start=1):
            if char == "{":
                stack.append((line_index, column))
                continue
            if char != "}" or not stack:
                continue

            start_line, start_column = stack.pop()
            signature_start = _find_signature_start(lines, start_line)
            signature = _signature_text(lines, signature_start, start_line)
            blocks.append(
                {
                    "start_line": signature_start,
                    "end_line": line_index,
                    "start_column": start_column,
                    "signature": signature,
                    "symbol": _parse_symbol(signature),
                    "kind": "brace-block",
                    "extraction_method": "brace_enclosing_block",
                    "confidence": "high" if _looks_like_function_signature(signature) else "medium",
                }
            )

    return blocks


def _build_python_blocks(lines: list[str]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        match = _python_signature_match(line)
        if not match:
            continue

        base_indent = len(line) - len(line.lstrip())
        end_line = len(lines)
        for end_index in range(index + 1, len(lines) + 1):
            candidate = lines[end_index - 1]
            candidate_stripped = candidate.strip()
            if not candidate_stripped or candidate_stripped.startswith("#"):
                continue
            indent = len(candidate) - len(candidate.lstrip())
            if indent <= base_indent:
                end_line = end_index - 1
                break

        blocks.append(
            {
                "start_line": index,
                "end_line": max(index, end_line),
                "start_column": base_indent + 1,
                "signature": stripped,
                "symbol": match.group("name"),
                "kind": "python-function",
                "extraction_method": "python_indentation",
                "confidence": "high",
            }
        )

    return blocks


def _extract_python_block(lines: list[str], sink_line: int) -> dict[str, Any]:
    for block in _build_python_blocks(lines):
        if int(block["start_line"]) <= sink_line <= int(block["end_line"]):
            return block
    return _extract_fallback_block(lines, sink_line)


def _extract_fallback_block(lines: list[str], sink_line: int) -> dict[str, Any]:
    start_line = max(1, sink_line - FALLBACK_CONTEXT_RADIUS)
    end_line = min(len(lines), sink_line + FALLBACK_CONTEXT_RADIUS)
    return {
        "start_line": start_line,
        "end_line": end_line,
        "start_column": 1,
        "signature": "",
        "symbol": "",
        "kind": "context-window",
        "extraction_method": "line_window_fallback",
        "confidence": "low",
    }


def _sink_analysis_from_block(
    *,
    hit: dict[str, Any],
    block: dict[str, Any],
    lines: list[str],
    blocks: list[dict[str, Any]],
    slicer: CodeSlicer,
) -> dict[str, Any]:
    # Step 3 的核心产物：保存可追踪、可给 TLDR 消费的最小行为画像，避免在 JSON 中写入完整函数源码。
    start_line = int(block["start_line"])
    end_line = int(block["end_line"])
    sink_line = int(hit.get("line", 0) or 0)
    analysis_id = _context_id(hit)
    scope_symbol = str(block.get("symbol", ""))
    function_ref = slicer.add_function_from_block(
        file=str(hit.get("file", "")),
        block=block,
        lines=lines,
    )
    scope_params = slicer.parse_parameters(str(block.get("signature", "")), str(hit.get("language", "")))
    backward_slice = slicer.build_backward_slice(
        lines=lines,
        block=block,
        hit=hit,
        scope_params=scope_params,
    )
    same_file_callers = _find_same_file_callers(
        lines=lines,
        blocks=blocks,
        callee_symbol=scope_symbol,
        callee_params=scope_params,
        callee_block=block,
    )
    trace = _build_local_trace(
        analysis_id=analysis_id,
        hit=hit,
        block=block,
        backward_slice=backward_slice,
        same_file_callers=same_file_callers,
    )

    return {
        "analysis_id": analysis_id,
        "schema_version": "defectmine.callscan.sink_analysis.v1",
        "language": hit.get("language", "unknown"),
        "status": trace["status"],
        "location": {
            "file": hit.get("file", ""),
            "start_line": start_line,
            "end_line": end_line,
            "sink_line": sink_line,
        },
        "enclosing_scope": {
            "name": scope_symbol,
            "signature": block.get("signature", ""),
            "kind": block.get("kind", "unknown"),
            "parameters": scope_params,
            "function_ref": function_ref,
        },
        "sink": {
            "sink_id": hit.get("sink_id", ""),
            "category": hit.get("category", ""),
            "vulnerability": hit.get("vulnerability", ""),
            "line": hit.get("line", 0),
            "column": hit.get("column", 0),
            "match": hit.get("match", ""),
            "evidence": hit.get("evidence", ""),
            "line_text": _line_at(lines, sink_line).strip(),
        },
        "backward_slice": backward_slice,
        "same_file_callers": same_file_callers,
        "local_trace": trace,
        "tldr_seed": {
            "needs_cross_file_resolution": bool(scope_symbol),
            "symbol": scope_symbol,
            "file": hit.get("file", ""),
            "line": start_line,
        },
        "extraction": {
            "method": block.get("extraction_method", "unknown"),
            "confidence": block.get("confidence", "low"),
            "tldr_ready": True,
            "notes": _analysis_notes(block, backward_slice, same_file_callers),
        },
    }


def _build_backward_slice(
    *,
    lines: list[str],
    block: dict[str, Any],
    hit: dict[str, Any],
    scope_params: list[str],
) -> dict[str, Any]:
    # 轻量级 backward slice：先在函数内追 sink 参数依赖，跨函数/跨文件交给 caller 和 TLDR 阶段继续扩展。
    sink_line = int(hit.get("line", 0) or 0)
    start_line = int(block["start_line"])
    sink_text = _line_at(lines, sink_line)
    language = str(hit.get("language", ""))
    sink_argument = _extract_sink_argument(sink_text, str(hit.get("match", "")), int(hit.get("column", 1) or 1))
    tracked_symbols = _extract_identifiers(sink_argument, language)
    assignments: list[dict[str, Any]] = []
    source_candidates: list[dict[str, Any]] = []
    unresolved_symbols: set[str] = set(tracked_symbols)
    pending = list(tracked_symbols)
    visited: set[str] = set()

    while pending and len(visited) < 40:
        symbol = pending.pop(0)
        if symbol in visited:
            continue
        visited.add(symbol)
        assignment = _find_previous_assignment(lines, start_line, sink_line, symbol)
        if not assignment:
            continue
        assignments.append(assignment)
        unresolved_symbols.discard(symbol)
        if _looks_like_source(assignment["text"]):
            source_candidates.append(_source_candidate_from_line(assignment, "assignment-source"))
        for dependency in _extract_identifiers(assignment["rhs"], language):
            if dependency in scope_params:
                source_candidates.append(
                    {
                        "kind": "function-parameter",
                        "symbol": dependency,
                        "line": int(block["start_line"]),
                        "evidence": str(block.get("signature", "")),
                        "confidence": "medium",
                    }
                )
                unresolved_symbols.discard(dependency)
                continue
            if dependency not in visited and dependency not in pending:
                pending.append(dependency)
                unresolved_symbols.add(dependency)

    for symbol in tracked_symbols:
        if symbol in scope_params:
            source_candidates.append(
                {
                    "kind": "function-parameter",
                    "symbol": symbol,
                    "line": int(block["start_line"]),
                    "evidence": str(block.get("signature", "")),
                    "confidence": "medium",
                }
            )
            unresolved_symbols.discard(symbol)

    if _looks_like_source(sink_argument) or _looks_like_source(sink_text):
        source_candidates.append(
            {
                "kind": "direct-source",
                "symbol": "",
                "line": sink_line,
                "evidence": sink_text.strip(),
                "confidence": "medium",
            }
        )

    deduped_sources = _dedupe_dicts(source_candidates, ("kind", "symbol", "line", "evidence"))
    return {
        "sink_argument": sink_argument.strip(),
        "tracked_symbols": tracked_symbols,
        "assignments": assignments,
        "source_candidates": deduped_sources,
        "unresolved_symbols": sorted(unresolved_symbols),
        "confidence": _slice_confidence(assignments, deduped_sources, unresolved_symbols),
        "notes": _slice_notes(tracked_symbols, assignments, deduped_sources),
    }


def _find_same_file_callers(
    *,
    lines: list[str],
    blocks: list[dict[str, Any]],
    callee_symbol: str,
    callee_params: list[str],
    callee_block: dict[str, Any],
) -> list[dict[str, Any]]:
    # 同文件 caller 是跨文件调用链前的局部扩展点：先找本文件调用者，再把剩余缺口交给静态 TLDR 图。
    if not callee_symbol:
        return []

    callers: list[dict[str, Any]] = []
    call_pattern = re.compile(rf"\b{re.escape(callee_symbol)}\s*\(")
    callee_start = int(callee_block["start_line"])
    callee_end = int(callee_block["end_line"])

    for line_number, line in enumerate(lines, start=1):
        if callee_start <= line_number <= callee_end:
            continue
        if not call_pattern.search(line):
            continue

        caller_block = _extract_enclosing_block(lines, {"line": line_number}, blocks)
        call_args = _extract_call_arguments(line, callee_symbol)
        callers.append(
            {
                "caller_scope": {
                    "name": caller_block.get("symbol", ""),
                    "signature": caller_block.get("signature", ""),
                    "start_line": caller_block.get("start_line", line_number),
                    "end_line": caller_block.get("end_line", line_number),
                    "kind": caller_block.get("kind", "unknown"),
                },
                "callee": callee_symbol,
                "call_line": line_number,
                "call_text": line.strip(),
                "argument_mapping": _map_arguments(callee_params, call_args),
                "edge_type": "same-file-call",
                "confidence": "medium" if caller_block.get("symbol") else "low",
            }
        )
        if len(callers) >= 30:
            break

    return callers


def _build_local_trace(
    *,
    analysis_id: str,
    hit: dict[str, Any],
    block: dict[str, Any],
    backward_slice: dict[str, Any],
    same_file_callers: list[dict[str, Any]],
) -> dict[str, Any]:
    scope_name = str(block.get("symbol", ""))
    source_candidates = backward_slice.get("source_candidates", [])
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    sink_node_id = f"sink:{analysis_id}"
    scope_node_id = f"scope:{hit.get('file', '')}:{block.get('start_line', 0)}:{scope_name or 'anonymous'}"
    nodes.append({"node_id": sink_node_id, "kind": "sink", "file": hit.get("file", ""), "line": hit.get("line", 0), "label": hit.get("sink_id", "")})
    nodes.append({"node_id": scope_node_id, "kind": "function", "file": hit.get("file", ""), "line": block.get("start_line", 0), "label": scope_name})
    edges.append({"from": scope_node_id, "to": sink_node_id, "kind": "contains-sink", "evidence": hit.get("evidence", ""), "confidence": backward_slice.get("confidence", "low")})

    for index, source in enumerate(source_candidates):
        source_node_id = f"source:{analysis_id}:{index}"
        nodes.append(
            {
                "node_id": source_node_id,
                "kind": source.get("kind", "source-candidate"),
                "file": hit.get("file", ""),
                "line": source.get("line", 0),
                "label": source.get("symbol", "") or source.get("kind", "source"),
            }
        )
        edges.append({"from": source_node_id, "to": scope_node_id, "kind": "data-dependency", "evidence": source.get("evidence", ""), "confidence": source.get("confidence", "low")})

    for caller in same_file_callers:
        caller_node_id = f"caller:{hit.get('file', '')}:{caller.get('call_line', 0)}:{caller.get('caller_scope', {}).get('name', '')}"
        nodes.append(
            {
                "node_id": caller_node_id,
                "kind": "same-file-caller",
                "file": hit.get("file", ""),
                "line": caller.get("call_line", 0),
                "label": caller.get("caller_scope", {}).get("name", ""),
            }
        )
        edges.append({"from": caller_node_id, "to": scope_node_id, "kind": "same-file-call", "evidence": caller.get("call_text", ""), "confidence": caller.get("confidence", "low")})

    if source_candidates:
        status = "source_candidate_found"
    elif same_file_callers:
        status = "caller_found_needs_parent_slice"
    else:
        status = "needs_cross_file_resolution" if scope_name else "unresolved_local_context"

    return {
        "trace_id": f"trace:{analysis_id}",
        "status": status,
        "nodes": nodes,
        "edges": edges,
        "confidence": _trace_confidence(backward_slice, same_file_callers),
        "next_steps": _trace_next_steps(status),
    }


def _build_static_tldr_tasks(sink_analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # 静态 TLDR 模式：只生成可被 .tldr/cache/call_graph.json 消费的符号查询任务，不做动态 MCP 调用。
    tasks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for analysis in sink_analyses:
        seed = _object_or_empty(analysis.get("tldr_seed"))
        symbol = str(seed.get("symbol", ""))
        file_path = str(seed.get("file", ""))
        line = int(seed.get("line", 0) or 0)
        if not symbol or not file_path or line <= 0:
            continue
        key = (symbol, file_path, line)
        if key in seen:
            continue
        seen.add(key)
        tasks.append(
            {
                "task_id": f"static-tldr:{file_path}:{line}:{symbol}",
                "status": "pending_static_tldr_lookup",
                "tool": "static_tldr_cache",
                "action": "resolve_cross_file_callers_from_cache",
                "target": {
                    "symbol": symbol,
                    "file": file_path,
                    "line": line,
                    "signature": analysis.get("enclosing_scope", {}).get("signature", ""),
                },
                "inputs": {
                    "analysis_id": analysis.get("analysis_id", ""),
                    "sink": analysis.get("sink", {}),
                    "backward_slice": analysis.get("backward_slice", {}),
                    "same_file_callers": analysis.get("same_file_callers", []),
                },
                "expected_output": {
                    "cross_file_edges": "caller -> callee edges with file, line, evidence, confidence",
                    "entry_nodes": "route/API/hook/framework entrypoints when discovered",
                    "uncertain_edges": "reflection/dynamic/unresolved calls that need later validation",
                },
            }
        )
        if len(tasks) >= 200:
            break
    return tasks


def _run_tldr_mcp_tasks(
    tasks: list[dict[str, Any]],
    resolver: TldrResolver | None,
    progress_reporter: ProgressReporter | None,
) -> dict[str, Any]:
    # 静态 TLDR 查询执行器：默认读取 .tldr/cache/call_graph.json；外部 resolver 也必须返回同一结果契约。
    if resolver is None or not tasks:
        return {
            "enabled": False,
            "status": "not_configured" if tasks else "no_tasks",
            "cross_file_edges": [],
            "entry_nodes": [],
            "uncertain_edges": [],
            "notes": ["Static TLDR cache was not found; mcp_tasks are persisted for later cache lookup."],
        }

    _report_progress(
        progress_reporter,
        {
            "event": "callscan_tldr_mcp_started",
            "tasks": len(tasks),
        },
    )
    raw_result = resolver(tasks)
    if isinstance(raw_result, list):
        result = {"cross_file_edges": raw_result}
    elif isinstance(raw_result, dict):
        result = raw_result
    else:
        result = {}

    normalized = {
        "enabled": True,
        "status": result.get("status", "completed"),
        "cross_file_edges": _list_of_dicts(result.get("cross_file_edges")),
        "entry_nodes": _list_of_dicts(result.get("entry_nodes")),
        "uncertain_edges": _list_of_dicts(result.get("uncertain_edges")),
        "raw_summary": result.get("summary", {}),
    }
    _report_progress(
        progress_reporter,
        {
            "event": "callscan_tldr_mcp_completed",
            "cross_file_edges": len(normalized["cross_file_edges"]),
            "entry_nodes": len(normalized["entry_nodes"]),
            "uncertain_edges": len(normalized["uncertain_edges"]),
        },
    )
    return normalized


def _default_tldr_cache_resolver(context: RepoPathContext) -> TldrResolver | None:
    cache_path = _find_tldr_call_graph_path(context.root)
    if cache_path is None:
        return None

    def resolve(tasks: list[dict[str, Any]]) -> dict[str, Any]:
        graph = _read_tldr_call_graph(cache_path)
        return _resolve_tasks_from_tldr_graph(tasks, graph, context)

    return resolve


def _find_tldr_call_graph_path(project_root: Path) -> Path | None:
    candidates = [
        project_root / ".tldr" / "cache" / "call_graph.json",
        project_root.parents[2] / ".tldr" / "cache" / "call_graph.json" if len(project_root.parents) >= 3 else None,
        Path.cwd() / ".tldr" / "cache" / "call_graph.json",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.exists():
            return candidate.resolve()
    return None


def _read_tldr_call_graph(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"edges": []}
    return data if isinstance(data, dict) else {"edges": []}


def _resolve_tasks_from_tldr_graph(
    tasks: list[dict[str, Any]],
    graph: dict[str, Any],
    context: RepoPathContext,
) -> dict[str, Any]:
    edges = _list_of_dicts(graph.get("edges"))
    edges_by_callee: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        callee = str(edge.get("to_func", ""))
        if not callee:
            continue
        edges_by_callee.setdefault(callee, []).append(edge)

    cross_file_edges: list[dict[str, Any]] = []
    uncertain_edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for task in tasks:
        target = _object_or_empty(task.get("target"))
        symbol = str(target.get("symbol", ""))
        if not symbol:
            continue
        candidate_edges = edges_by_callee.get(symbol, [])
        if not candidate_edges:
            uncertain_edges.append(
                {
                    "task_id": task.get("task_id", ""),
                    "kind": "tldr-no-caller-edge",
                    "symbol": symbol,
                    "file": target.get("file", ""),
                    "line": target.get("line", 0),
                    "confidence": "low",
                }
            )
            continue

        for edge in candidate_edges[:20]:
            caller_file = _safe_graph_path(context, edge.get("from_file", ""))
            callee_file = _safe_graph_path(context, edge.get("to_file", ""))
            item = {
                "task_id": task.get("task_id", ""),
                "from": {
                    "file": caller_file,
                    "function": edge.get("from_func", ""),
                },
                "to": {
                    "file": callee_file,
                    "function": edge.get("to_func", ""),
                },
                "kind": "tldr-cache-call",
                "confidence": "medium" if caller_file and callee_file else "low",
                "evidence": f"{edge.get('from_func', '')} -> {edge.get('to_func', '')}",
            }
            key = (
                str(item["from"]["file"]),
                str(item["from"]["function"]),
                str(item["to"]["file"]),
                str(item["to"]["function"]),
            )
            if key in seen:
                continue
            seen.add(key)
            cross_file_edges.append(item)

    return {
        "status": "completed_from_tldr_cache",
        "summary": {
            "tasks": len(tasks),
            "graph_edges": len(edges),
            "matched_edges": len(cross_file_edges),
        },
        "cross_file_edges": cross_file_edges,
        "entry_nodes": [],
        "uncertain_edges": uncertain_edges,
    }


def _safe_graph_path(context: RepoPathContext, value: Any) -> str:
    raw = str(value).strip()
    if not raw:
        return ""
    normalized = raw.replace("\\", "/")
    marker = "repo_code/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]
        parts = normalized.split("/")
        if len(parts) > 2:
            normalized = "/".join(parts[2:])
    try:
        return context.relative(normalized)
    except Exception:
        return normalized


def _local_edges_from_analyses(sink_analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for analysis in sink_analyses:
        trace = _object_or_empty(analysis.get("local_trace"))
        for edge in trace.get("edges", []):
            if isinstance(edge, dict):
                edges.append(edge)
    return edges


def _local_traces_from_analyses(sink_analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for analysis in sink_analyses:
        trace = _object_or_empty(analysis.get("local_trace"))
        if trace:
            traces.append(trace)
    return traces


def _uncertain_edges_from_analyses(sink_analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    uncertain: list[dict[str, Any]] = []
    for analysis in sink_analyses:
        scope = _object_or_empty(analysis.get("enclosing_scope"))
        backward_slice = _object_or_empty(analysis.get("backward_slice"))
        for symbol in backward_slice.get("unresolved_symbols", []):
            uncertain.append(
                {
                    "analysis_id": analysis.get("analysis_id", ""),
                    "kind": "unresolved-data-dependency",
                    "symbol": symbol,
                    "file": analysis.get("location", {}).get("file", ""),
                    "line": analysis.get("location", {}).get("sink_line", 0),
                    "confidence": "low",
                }
            )
        if _looks_dynamic(str(scope.get("signature", ""))) or _looks_dynamic(str(analysis.get("sink", {}).get("line_text", ""))):
            uncertain.append(
                {
                    "analysis_id": analysis.get("analysis_id", ""),
                    "kind": "dynamic-call-or-reflection",
                    "symbol": scope.get("name", ""),
                    "file": analysis.get("location", {}).get("file", ""),
                    "line": analysis.get("location", {}).get("sink_line", 0),
                    "confidence": "low",
                }
            )
    return uncertain


def _slice_source_lines(lines: list[str], start_line: int, end_line: int) -> str:
    selected = lines[start_line - 1 : end_line]
    return "".join(selected)


def _line_at(lines: list[str], line_number: int) -> str:
    if line_number <= 0 or line_number > len(lines):
        return ""
    return lines[line_number - 1]


def _parse_parameters(signature: str, language: str) -> list[str]:
    match = re.search(r"\((?P<params>.*)\)", signature)
    if not match:
        return []
    params = _split_arguments(match.group("params"))
    parsed: list[str] = []
    for param in params:
        cleaned = param.strip()
        if not cleaned:
            continue
        cleaned = cleaned.split("=")[0].strip()
        cleaned = cleaned.replace("*", " ").replace("&", " ")
        identifiers = _extract_identifiers(cleaned, language)
        if identifiers:
            parsed.append(identifiers[-1])
    return _unique(parsed)


def _extract_sink_argument(line: str, matched_text: str, column: int) -> str:
    call_start = max(column - 1, 0)
    if matched_text:
        found = line.find(matched_text, max(call_start - 4, 0))
        if found >= 0:
            call_start = found
    paren = line.find("(", call_start)
    if paren < 0:
        return line.strip()
    close = _find_matching_paren(line, paren)
    if close < 0:
        return line[paren + 1 :].strip()
    args = _split_arguments(line[paren + 1 : close])
    return args[0] if args else line[paren + 1 : close].strip()


def _extract_call_arguments(line: str, callee_symbol: str) -> list[str]:
    match = re.search(rf"\b{re.escape(callee_symbol)}\s*\(", line)
    if not match:
        return []
    paren = line.find("(", match.start())
    close = _find_matching_paren(line, paren)
    if close < 0:
        return _split_arguments(line[paren + 1 :])
    return _split_arguments(line[paren + 1 : close])


def _split_arguments(text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    for char in text:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            depth = max(depth - 1, 0)
            current.append(char)
            continue
        if char == "," and depth == 0:
            value = "".join(current).strip()
            if value:
                args.append(value)
            current = []
            continue
        current.append(char)
    value = "".join(current).strip()
    if value:
        args.append(value)
    return args


def _find_matching_paren(text: str, start: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _extract_identifiers(text: str, language: str) -> list[str]:
    stripped = re.sub(r"(['\"`]).*?\1", " ", text)
    if language.casefold() == "php":
        variables = [item.lstrip("$") for item in re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", stripped)]
    else:
        variables = []
    identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped)
    ignored = {
        "and",
        "as",
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "def",
        "else",
        "false",
        "for",
        "foreach",
        "function",
        "if",
        "import",
        "in",
        "let",
        "new",
        "none",
        "null",
        "or",
        "return",
        "self",
        "static",
        "this",
        "true",
        "var",
        "void",
        "while",
    }
    return _unique([*variables, *(item for item in identifiers if item.casefold() not in ignored)])


def _find_previous_assignment(lines: list[str], start_line: int, sink_line: int, symbol: str) -> dict[str, Any] | None:
    symbol_pattern = re.escape(symbol)
    patterns = [
        re.compile(rf"(?P<lhs>\${symbol_pattern})\s*=\s*(?P<rhs>.+)"),
        re.compile(rf"\b(?:let|const|var)\s+(?P<lhs>{symbol_pattern})\s*=\s*(?P<rhs>.+)"),
        re.compile(rf"\b(?P<lhs>{symbol_pattern})\s*(?::=|=)\s*(?P<rhs>.+)"),
        re.compile(rf"\b(?P<lhs>{symbol_pattern})\s*:\s*[^=]+=\s*(?P<rhs>.+)"),
    ]
    for line_number in range(sink_line - 1, max(start_line - 1, 0), -1):
        text = lines[line_number - 1].strip()
        if not text or text.startswith(("#", "//", "*")):
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if not match:
                continue
            return {
                "symbol": symbol,
                "line": line_number,
                "text": text,
                "rhs": match.group("rhs").strip().rstrip(";"),
                "confidence": "medium",
            }
    return None


def _looks_like_source(text: str) -> bool:
    lowered = text.casefold()
    markers = (
        "$_get",
        "$_post",
        "$_request",
        "$_cookie",
        "$_files",
        "request.",
        "request->",
        "request[",
        "req.",
        "req[",
        "input(",
        "input.",
        "param",
        "query",
        "body",
        "cookie",
        "header",
        "getenv",
        "os.environ",
        "stdin",
        "formfile",
        "multipart",
        "url.query",
    )
    return any(marker in lowered for marker in markers)


def _source_candidate_from_line(assignment: dict[str, Any], kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "symbol": assignment.get("symbol", ""),
        "line": assignment.get("line", 0),
        "evidence": assignment.get("text", ""),
        "confidence": "medium",
    }


def _map_arguments(parameters: list[str], arguments: list[str]) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for index, argument in enumerate(arguments):
        parameter = parameters[index] if index < len(parameters) else f"arg{index + 1}"
        mappings.append(
            {
                "parameter": parameter,
                "argument": argument,
                "argument_symbols": _extract_identifiers(argument, ""),
                "position": index,
            }
        )
    return mappings


def _slice_confidence(
    assignments: list[dict[str, Any]],
    source_candidates: list[dict[str, Any]],
    unresolved_symbols: set[str],
) -> str:
    if source_candidates and not unresolved_symbols:
        return "high"
    if source_candidates or assignments:
        return "medium"
    return "low"


def _slice_notes(
    tracked_symbols: list[str],
    assignments: list[dict[str, Any]],
    source_candidates: list[dict[str, Any]],
) -> list[str]:
    notes: list[str] = []
    if not tracked_symbols:
        notes.append("sink argument did not expose a simple local symbol")
    if tracked_symbols and not assignments:
        notes.append("no local assignment found before sink line")
    if source_candidates:
        notes.append("source candidate found by local lexical markers")
    return notes


def _trace_confidence(backward_slice: dict[str, Any], same_file_callers: list[dict[str, Any]]) -> str:
    slice_confidence = str(backward_slice.get("confidence", "low"))
    if slice_confidence == "high":
        return "high"
    if slice_confidence == "medium" or same_file_callers:
        return "medium"
    return "low"


def _trace_next_steps(status: str) -> list[str]:
    if status == "source_candidate_found":
        return ["verify sanitizer and data type before reporting vulnerability"]
    if status == "caller_found_needs_parent_slice":
        return ["repeat backward slice in caller scope", "continue to route/API/hook entrypoint"]
    if status == "needs_cross_file_resolution":
        return ["resolve mcp_tasks against static TLDR call graph for cross-file callers"]
    return ["manual review or language-specific resolver required"]


def _analysis_notes(
    block: dict[str, Any],
    backward_slice: dict[str, Any],
    same_file_callers: list[dict[str, Any]],
) -> list[str]:
    notes: list[str] = []
    if block.get("kind") == "context-window":
        notes.append("enclosing function was not identified; fallback context window used")
    notes.extend(str(item) for item in backward_slice.get("notes", []))
    if same_file_callers:
        notes.append("same-file callers found; cross-file resolver can start from these edges")
    return notes


def _looks_dynamic(text: str) -> bool:
    lowered = text.casefold()
    markers = ("eval", "reflect", "reflection", "call_user_func", "getmethod", "invoke", "function(", "new function")
    return any(marker in lowered for marker in markers)


def _dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    unique_items: list[dict[str, Any]] = []
    for item in items:
        key = tuple(item.get(name) for name in keys)
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)
    return unique_items


def _read_source_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return []


def _find_signature_start(lines: list[str], brace_line: int) -> int:
    start = max(1, brace_line - 8)
    for index in range(brace_line, start - 1, -1):
        stripped = lines[index - 1].strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if stripped.startswith(("@", "#[")):
            continue
        return index
    return brace_line


def _signature_text(lines: list[str], start_line: int, brace_line: int) -> str:
    return " ".join(line.strip() for line in lines[start_line - 1 : brace_line]).strip()


def _parse_symbol(signature: str) -> str:
    patterns = [
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b(?:public|private|protected|static|final|async)\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?:async\s*)?function\b",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, signature)
        if match:
            return match.group(1)
    return ""


def _looks_like_function_signature(signature: str) -> bool:
    lowered = signature.casefold()
    markers = ("function ", "=>", " def ", "public ", "private ", "protected ", "static ", "async ")
    return any(marker in f" {lowered}" for marker in markers) and "(" in signature


def _python_signature_match(line: str):
    return re.match(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", line)


def _context_id(hit: dict[str, Any]) -> str:
    return (
        f"{hit.get('sink_id', 'sink')}:"
        f"{hit.get('file', '')}:"
        f"{hit.get('line', 0)}:"
        f"{hit.get('column', 0)}"
    )


def _resolve_rg_command() -> str:
    return shutil.which("rg.exe") or shutil.which("rg") or "rg.exe"


def _include_globs_for_rules(rules: list[SinkRule]) -> list[str]:
    by_language = {
        "c": ["*.c", "*.h"],
        "cpp": ["*.cc", "*.cpp", "*.cxx", "*.hpp", "*.hh", "*.hxx", "*.h"],
        "go": ["*.go"],
        "html": ["*.html", "*.htm", "*.vue", "*.svelte", "*.twig", "*.blade.php", "*.erb"],
        "java": ["*.java", "*.jsp", "*.jspx"],
        "php": ["*.php", "*.twig"],
        "javascript": ["*.js", "*.mjs", "*.cjs", "*.jsx"],
        "python": ["*.py"],
        "rust": ["*.rs"],
        "typescript": ["*.ts", "*.tsx"],
    }
    globs: list[str] = []
    for rule in rules:
        if getattr(rule, "extensions", None):
            globs.extend(f"*{extension}" for extension in rule.extensions)
            continue
        globs.extend(by_language.get(rule.language, []))
    return _unique(globs)


def _infer_sink_languages(treescan_profile: dict[str, Any]) -> list[str]:
    stack = _object_or_empty(treescan_profile.get("technology_stack"))
    return _unique(infer_languages_from_technology_stack(stack))


def _resolve_profile_path(
    context: RepoPathContext,
    treescan_profile_path: str | Path | None,
) -> Path:
    if treescan_profile_path is None:
        return context.artifact_path(TREESCAN_PROFILE_FILENAME)
    return context.absolute(treescan_profile_path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"TreeScan profile not found: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return data


def _partial_chain_records(
    *,
    tldr_impact_paths: list[dict[str, Any]],
    complete_impact_paths: list[dict[str, Any]],
    sink_analyses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    complete_ids = {str(item.get("path_id", "")) for item in complete_impact_paths}
    analyses_by_id = {
        str(item.get("analysis_id", "")): item
        for item in sink_analyses
        if isinstance(item, dict)
    }
    records: list[dict[str, Any]] = []
    for index, path in enumerate(tldr_impact_paths, start=1):
        path_id = str(path.get("path_id", ""))
        if not path_id or path_id in complete_ids:
            continue
        analysis = analyses_by_id.get(str(path.get("analysis_id", "")), {})
        sink = _object_or_empty(analysis.get("sink"))
        location = _object_or_empty(analysis.get("location"))
        vuln = str(sink.get("vulnerability_type") or sink.get("vulnerability") or "unknown")
        records.append(
            {
                "schema_version": "defectmine.callscan.partial_chain.v1",
                "partial_index": index,
                "path_id": path_id,
                "analysis_id": str(path.get("analysis_id", "")),
                "status": str(path.get("status", "unknown")),
                "termination": str(path.get("termination", "unknown")),
                "complete": False,
                "language": str(analysis.get("language") or sink.get("language") or "unknown"),
                "vulnerability_type": vuln,
                "sink": {
                    "sink_id": sink.get("sink_id", ""),
                    "file": location.get("file", ""),
                    "line": sink.get("line", location.get("sink_line", 0)),
                    "function": sink.get("match", ""),
                    "vulnerability_type": vuln,
                },
                "depth": int(path.get("depth", 0) or 0),
                "nodes": _list_of_dicts(path.get("nodes")),
                "reason": _partial_reason(path),
            }
        )
    return records


def _partial_reason(path: dict[str, Any]) -> str:
    termination = str(path.get("termination", "unknown"))
    if termination == "no_caller":
        return "no caller found before reaching a route/API/framework entry"
    if termination == "cycle":
        return "call graph cycle prevented a complete entry-to-sink chain"
    return f"incomplete impact path: {termination}"


def _build_discovery_meta(
    *,
    context: RepoPathContext,
    treescan_profile_path: Path,
    sink_rules: list[dict[str, Any]],
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    return {
        "schema_version": "defectmine.callscan.discovery_meta.v1",
        "project_fingerprint": _project_fingerprint(context.root),
        "treescan_profile_fingerprint": _file_fingerprint(treescan_profile_path),
        "sink_rules_fingerprint": _stable_fingerprint(sink_rules),
        "callscan_version": "v2",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "total_candidates": int(summary.get("all_chains", 0) or 0),
        "complete_candidates": int(summary.get("all_chains", 0) or 0),
        "partial_candidates": int(summary.get("partial_chains", 0) or 0),
    }


def _discovery_cache_is_valid(context: RepoPathContext, expected: dict[str, Any]) -> bool:
    meta_path = context.artifact_path(CALLSCAN_DISCOVERY_META_FILENAME)
    required = [
        context.artifact_path(CALLSCAN_REPORT_FILENAME),
        context.artifact_path(CALLSCAN_ALL_CHAINS_FILENAME),
        context.artifact_path(CALLSCAN_COVERAGE_FILENAME),
    ]
    if not all(path.is_file() for path in required):
        return False
    try:
        current = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    for key in ("project_fingerprint", "treescan_profile_fingerprint", "sink_rules_fingerprint", "callscan_version"):
        if current.get(key) != expected.get(key):
            return False
    return True


def _project_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith(".defectmine/") or should_skip_scan_path(relative):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(relative.encode("utf-8", errors="ignore"))
        digest.update(str(stat.st_size).encode())
        digest.update(str(stat.st_mtime_ns).encode())
    return digest.hexdigest()


def _file_fingerprint(path: Path) -> str:
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    try:
        digest.update(path.read_bytes())
    except OSError:
        return ""
    return digest.hexdigest()


def _stable_fingerprint(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(text + "\n", encoding="utf-8")


def _write_jsonl(items: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = items if isinstance(items, list) else []
    lines = [json.dumps(record, ensure_ascii=False, separators=(",", ":")) for record in records]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _priority_chain_records(audit_packs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, pack in enumerate(audit_packs, start=1):
        if not isinstance(pack, dict):
            continue
        records.append(priority_chain_record_from_audit_pack(index, pack))
    return records


def _report_progress(
    progress_reporter: ProgressReporter | None,
    payload: dict[str, Any],
) -> None:
    if progress_reporter is not None:
        progress_reporter(payload)


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique_values.append(value)
    return unique_values
