from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.agent import AgentType, ToolLoopAdapter, load_skill, run_agent
from app.callscan.priority_schema import load_priority_chain_jsonl
from app.scanner.audit_schema import (
    AUDIT_RESULT_JSON_SCHEMA,
    audit_system_schema_prompt,
    error_audit_result,
    parse_audit_result,
)


ARTIFACTS_DIRNAME = ".defectmine"
SCANNER_TARGETS_FILENAME = "scanner_targets.json"
SCANNER_RAW_RESULTS_FILENAME = "scanner_agent.raw.json"
SCANNER_REPORT_FILENAME = "scanner_agent.json"
AUDIT_AGENT_FILENAME = "audit_agent.json"
AUDIT_FINDINGS_FILENAME = "audit_findings.md"
CALLSCAN_PRIORITY_CHAINS_FILENAME = "callscan_chains.priority.jsonl"
TREESCAN_PROFILE_FILENAME = "treescan_agent.json"
# Scanner 默认只允许少量补充上下文轮次：首轮必须先基于 CallScan 提供的完整链进行审计，
# 只有缺少 source / sanitizer / 调用方等关键证据时才进入工具循环，避免每条链反复调用 LLM。
MAX_AUDIT_TOOL_ROUNDS = 2
DEFAULT_AUDIT_CONCURRENCY = 4

MAX_SCAN_TARGETS = 12
MAX_FILE_BYTES = 16000
ALLOWED_SOURCE_SUFFIXES = {
    ".php",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".java",
    ".go",
    ".rb",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".twig",
    ".html",
    ".sql",
    ".xml",
}

ProgressReporter = Callable[[dict[str, Any]], None]
AuditAgentRunner = Callable[..., str]


#----------- Scanner 结果结构：统一返回目标文件、原始输出与聚合报告 ------------#
@dataclass(frozen=True)
class ScannerResult:
    root: Path
    artifacts_dir: Path
    targets: list[dict[str, Any]]
    raw_results: list[dict[str, Any]]
    report: dict[str, Any]

    def state_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "artifacts_dir": str(self.artifacts_dir),
            "artifacts": {
                "targets": str(self.artifacts_dir / SCANNER_TARGETS_FILENAME),
                "raw_results": str(self.artifacts_dir / SCANNER_RAW_RESULTS_FILENAME),
                "report": str(self.artifacts_dir / SCANNER_REPORT_FILENAME),
            },
            "summary": self.report.get("summary", {}),
            "scanned_files": len(self.targets),
        }


@dataclass(frozen=True, slots=True)
class AuditScannerResult:
    root: Path
    artifacts_dir: Path
    chains: list[dict[str, Any]]
    raw_results: list[dict[str, Any]]
    report: dict[str, Any]
    markdown: str

    def state_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "artifacts_dir": str(self.artifacts_dir),
            "artifacts": {
                "report": str(self.artifacts_dir / AUDIT_AGENT_FILENAME),
                "markdown": str(self.artifacts_dir / AUDIT_FINDINGS_FILENAME),
            },
            "summary": self.report.get("summary", {}),
            "chains": len(self.chains),
        }


#----------- Audit Scanner 入口：消费 CallScan 优先级链，失败隔离、并发审计、集中写出 ------------#
def run_audit_scanner(
    project_path: str | Path,
    *,
    artifacts_dir: str | Path | None = None,
    priority_chains_path: str | Path | None = None,
    audit_limit: int | None = None,
    concurrency: int = DEFAULT_AUDIT_CONCURRENCY,
    persist: bool = True,
    allow_active_poc: bool = False,
    enable_llm_audit: bool = True,
    agent_runner: AuditAgentRunner = run_agent,
    enable_mcp_tools: bool = True,
    progress_reporter: ProgressReporter | None = None,
) -> AuditScannerResult:
    root = Path(project_path).expanduser().resolve()
    output_dir = _resolve_artifacts_dir(root, artifacts_dir)
    profile_path = output_dir / TREESCAN_PROFILE_FILENAME
    chain_path = _resolve_priority_chains_path(root, output_dir, priority_chains_path)
    chains = _sort_priority_chains(load_priority_chain_jsonl(chain_path))
    if audit_limit is not None:
        chains = chains[: max(int(audit_limit), 0)]
    # Keep audit execution automatic: callers do not need to choose a mode or
    # pass a CLI flag, while the scanner still runs enough parallel chains for
    # practical MVP scans.
    concurrency = max(int(concurrency or DEFAULT_AUDIT_CONCURRENCY), 1)
    project_cognition = _load_project_cognition(profile_path)

    _report_progress(
        progress_reporter,
        {
            "event": "audit_scanner_started",
            "project_root": str(root),
            "priority_chains": str(chain_path),
            "total": len(chains),
            "concurrency": concurrency,
            "allow_active_poc": allow_active_poc,
            "enable_llm_audit": enable_llm_audit,
        },
    )

    audit_tasks = _build_audit_tasks(
        root=root,
        chains=chains,
        project_cognition=project_cognition,
        allow_active_poc=allow_active_poc,
    )
    if enable_llm_audit:
        raw_results = _audit_chains_concurrently(
            root=root,
            chains=chains,
            project_cognition=project_cognition,
            concurrency=concurrency,
            allow_active_poc=allow_active_poc,
            agent_runner=agent_runner,
            enable_mcp_tools=enable_mcp_tools,
            progress_reporter=progress_reporter,
        )
    else:
        raw_results = _pending_audit_results(audit_tasks, progress_reporter=progress_reporter)

    report = _build_audit_report(
        root=root,
        chains=chains,
        audit_tasks=audit_tasks,
        raw_results=raw_results,
        chain_path=chain_path,
        profile_path=profile_path,
        project_cognition=project_cognition,
        allow_active_poc=allow_active_poc,
        enable_llm_audit=enable_llm_audit,
        enable_mcp_tools=enable_mcp_tools,
        concurrency=concurrency,
    )
    markdown = _render_audit_markdown(report)

    # 并发任务只返回内存结果；统一在主线程集中写文件，避免 JSON/Markdown 被并发写坏。
    if persist:
        output_dir.mkdir(parents=True, exist_ok=True)
        _write_json(report, output_dir / AUDIT_AGENT_FILENAME)
        (output_dir / AUDIT_FINDINGS_FILENAME).write_text(markdown, encoding="utf-8")

    _report_progress(
        progress_reporter,
        {
            "event": "audit_scanner_completed",
            "artifact": str(output_dir / AUDIT_AGENT_FILENAME),
            "markdown": str(output_dir / AUDIT_FINDINGS_FILENAME),
            "summary": report.get("summary", {}),
        },
    )

    return AuditScannerResult(
        root=root,
        artifacts_dir=output_dir,
        chains=chains,
        raw_results=raw_results,
        report=report,
        markdown=markdown,
    )


#----------- Scanner 主入口：挑选高价值文件、调用 Agent，并汇总漏洞结果 ------------#
def run_scanner(
    project_path: str | Path,
    *,
    tree: dict[str, Any],
    profile: dict[str, Any],
    artifacts_dir: str | Path | None = None,
    persist: bool = True,
    progress_reporter: ProgressReporter | None = None,
) -> ScannerResult:
    root = Path(project_path).expanduser().resolve()
    output_dir = _resolve_artifacts_dir(root, artifacts_dir)

    if persist:
        output_dir.mkdir(parents=True, exist_ok=True)

    #----------- Scanner 目标选择：只选择最值得优先审计的源码文件 ------------#
    targets = _select_scan_targets(root, tree)
    if persist:
        _write_json(targets, output_dir / SCANNER_TARGETS_FILENAME)

    raw_results: list[dict[str, Any]] = []
    total_targets = len(targets)

    #----------- Scanner Agent 调用：逐文件注入源码与项目画像上下文 ------------#
    for index, target in enumerate(targets, start=1):
        _report_progress(
            progress_reporter,
            {
                "event": "scanner_file_started",
                "stage": "scanner",
                "current": index,
                "total": total_targets,
                "path": target["path"],
                "kind": target.get("kind", "unknown"),
            },
        )

        prompt_payload = _build_scanner_input(
            root=root,
            tree=tree,
            profile=profile,
            target=target,
        )
        raw_output = run_agent(
            AgentType.SCANNER,
            json.dumps(prompt_payload, ensure_ascii=False, indent=2),
        )
        parsed = _parse_scanner_output(raw_output, target["path"])
        raw_results.append(
            {
                "target": target,
                "input": prompt_payload,
                "raw_output": raw_output,
                "parsed": parsed,
            }
        )

        _report_progress(
            progress_reporter,
            {
                "event": "scanner_file_completed",
                "stage": "scanner",
                "current": index,
                "total": total_targets,
                "path": target["path"],
                "findings": len(parsed.get("findings", [])),
            },
        )

    #----------- Scanner 聚合输出：把逐文件结果整理成统一的 scanner_agent.json ------------#
    report = _merge_scanner_results(raw_results)

    if persist:
        _write_json(raw_results, output_dir / SCANNER_RAW_RESULTS_FILENAME)
        _write_json(report, output_dir / SCANNER_REPORT_FILENAME)

    return ScannerResult(
        root=root,
        artifacts_dir=output_dir,
        targets=targets,
        raw_results=raw_results,
        report=report,
    )


def _audit_chains_concurrently(
    *,
    root: Path,
    chains: list[dict[str, Any]],
    project_cognition: dict[str, Any],
    concurrency: int,
    allow_active_poc: bool,
    agent_runner: AuditAgentRunner,
    enable_mcp_tools: bool,
    progress_reporter: ProgressReporter | None,
) -> list[dict[str, Any]]:
    if not chains:
        return []

    indexed_results: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(concurrency, 1)) as executor:
        futures = {
            executor.submit(
                _audit_one_chain_safely,
                root=root,
                chain=chain,
                project_cognition=project_cognition,
                index=index,
                total=len(chains),
                allow_active_poc=allow_active_poc,
                agent_runner=agent_runner,
                enable_mcp_tools=enable_mcp_tools,
                progress_reporter=progress_reporter,
            ): index
            for index, chain in enumerate(chains, start=1)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                indexed_results[index] = future.result()
            except Exception as exc:  # Defensive isolation: a worker failure never aborts the run.
                chain = chains[index - 1]
                parsed = error_audit_result(
                    chain_id=str(chain.get("path_id", "")),
                    analysis_id=str(chain.get("analysis_id", "")),
                    message=f"unhandled audit worker error: {exc}",
                    severity=str(_object_or_empty(chain.get("rank")).get("risk_level", "unknown")),
                )
                indexed_results[index] = {
                    "chain": chain,
                    "raw_output": "",
                    "parsed": parsed,
                    "status": "error",
                    "error": str(exc),
                }

    return [indexed_results[index] for index in sorted(indexed_results)]


def _build_audit_tasks(
    *,
    root: Path,
    chains: list[dict[str, Any]],
    project_cognition: dict[str, Any],
    allow_active_poc: bool,
) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    for index, chain in enumerate(chains, start=1):
        payload = _build_audit_prompt_payload(
            root=root,
            chain=chain,
            project_cognition=project_cognition,
            allow_active_poc=allow_active_poc,
        )
        sink = _object_or_empty(chain.get("sink"))
        rank = _object_or_empty(chain.get("rank"))
        skill = _object_or_empty(payload.get("skill"))
        tasks.append(
            {
                "task_id": f"audit-task-{index:04d}",
                "status": "pending",
                "priority_index": int(chain.get("priority_index", index) or index),
                "chain_id": str(chain.get("path_id", "")),
                "analysis_id": str(chain.get("analysis_id", "")),
                "language": str(chain.get("language", "unknown")),
                "vulnerability_type": str(chain.get("vulnerability_type", "unknown")),
                "rank": rank,
                "sink": sink,
                "entry": _object_or_empty(chain.get("entry")),
                "skill": {
                    "language": skill.get("language", "unknown"),
                    "vulnerability_type": skill.get("vulnerability_type", "unknown"),
                    "fallback_used": bool(skill.get("fallback_used", False)),
                },
                "safety": payload.get("safety", {}),
                "tool_contract": payload.get("tool_contract", {}),
                "input_schema": payload.get("input_schema", {}),
                "audit_input": payload,
                "priority_chain": chain,
            }
        )
    return tasks


def _run_audit_tool_loop(
    *,
    root: Path,
    prompt_payload: dict[str, Any],
    agent_runner: AuditAgentRunner,
    enable_mcp_tools: bool,
    progress_reporter: ProgressReporter | None,
    chain_id: str,
    index: int,
    total: int,
) -> dict[str, Any]:
    tool_rounds: list[dict[str, Any]] = []
    current_payload = dict(prompt_payload)
    current_payload["tool_results"] = []
    current_payload["tool_round_summaries"] = []
    current_payload["tool_instructions"] = {
        "enabled": bool(enable_mcp_tools),
        "protocol": (
            "First produce a verdict from the supplied chain and functions whenever possible. "
            "Only if a key fact is missing, return exactly one JSON object with "
            '{"tool_calls":[{"tool":"read_file_window","arguments":{...}}]}. '
            "Do not request tools for broad exploration. When ready, return the final audit JSON matching output_schema."
        ),
    }

    last_output = ""
    llm_calls = 0
    adapter = ToolLoopAdapter(root) if enable_mcp_tools else None
    for round_index in range(1, MAX_AUDIT_TOOL_ROUNDS + 1):
        llm_calls += 1
        last_output = _call_audit_agent(
            agent_runner,
            json.dumps(current_payload, ensure_ascii=False, indent=2),
        )
        tool_calls = _extract_tool_calls(last_output)
        if tool_calls and adapter is not None:
            results = [adapter.run(call).as_dict() for call in tool_calls]
            round_payload = {
                "round": round_index,
                "tool_calls": tool_calls,
                "tool_results": results,
            }
            tool_rounds.append(round_payload)
            current_payload["tool_results"] = [_compact_tool_round(round_payload)]
            current_payload["tool_round_summaries"] = [
                _compact_tool_round(item) for item in tool_rounds[-3:]
            ]
            current_payload["tool_instructions"]["last_round_note"] = (
                "Use the latest tool_results and summaries. Either request another tool round or return final audit JSON."
            )
            _report_progress(
                progress_reporter,
                {
                    "event": "audit_tool_round_completed",
                    "current": index,
                    "total": total,
                    "chain_id": chain_id,
                    "round": round_index,
                    "tool_calls": len(tool_calls),
                },
            )
            continue

        if adapter is None:
            return {"raw_output": last_output, "tool_rounds": tool_rounds, "llm_calls": llm_calls}

        parsed_output = _try_parse_json_object(last_output)
        if not _needs_more_context(parsed_output):
            return {"raw_output": last_output, "tool_rounds": tool_rounds, "llm_calls": llm_calls}
        if round_index >= MAX_AUDIT_TOOL_ROUNDS:
            return {"raw_output": last_output, "tool_rounds": tool_rounds, "llm_calls": llm_calls}

        fallback_calls = _build_context_tool_calls(
            root=root,
            prompt_payload=prompt_payload,
            parsed_output=parsed_output,
            tool_rounds=tool_rounds,
        )
        if not fallback_calls:
            return {"raw_output": last_output, "tool_rounds": tool_rounds, "llm_calls": llm_calls}

        results = [adapter.run(call).as_dict() for call in fallback_calls]
        round_payload = {
            "round": round_index,
            "tool_calls": fallback_calls,
            "tool_results": results,
            "auto_generated": True,
        }
        tool_rounds.append(round_payload)
        current_payload["tool_results"] = [_compact_tool_round(round_payload)]
        current_payload["tool_round_summaries"] = [
            _compact_tool_round(item) for item in tool_rounds[-3:]
        ]
        current_payload["tool_instructions"]["last_round_note"] = (
            "The previous answer still lacked context. Use the latest tool results, then return final audit JSON."
        )
        _report_progress(
            progress_reporter,
            {
                "event": "audit_tool_round_completed",
                "current": index,
                "total": total,
                "chain_id": chain_id,
                "round": round_index,
                "tool_calls": len(fallback_calls),
            },
        )

    return {"raw_output": last_output, "tool_rounds": tool_rounds, "llm_calls": llm_calls}


def _compact_tool_round(round_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "round": round_payload.get("round", 0),
        "tool_calls": _list_of_dicts(round_payload.get("tool_calls")),
        "tool_results": [
            {
                "tool": result.get("tool", ""),
                "ok": bool(result.get("ok", False)),
                "error": result.get("error", ""),
                "data": _compact_tool_result_data(result.get("data")),
            }
            for result in _list_of_dicts(round_payload.get("tool_results"))
        ],
    }


def _compact_tool_result_data(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}

    compact: dict[str, Any] = {}
    for key in ("file_path", "absolute_path", "start_line", "end_line", "total_lines", "match_count", "source", "cache_path"):
        if key in data:
            compact[key] = data.get(key)
    for key in ("functions", "matches", "paths", "windows"):
        value = data.get(key)
        if isinstance(value, list) and value:
            compact[key] = value[:5]
    if "text" in data and isinstance(data["text"], str):
        compact["text"] = data["text"][:1200]
    if "summary" in data and isinstance(data["summary"], dict):
        compact["summary"] = data["summary"]
    if "impact_paths" in data and isinstance(data["impact_paths"], list):
        compact["impact_paths"] = data["impact_paths"][:5]
    return compact


def _try_parse_json_object(raw_output: str) -> dict[str, Any] | None:
    try:
        parsed = _parse_json_object(raw_output)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _needs_more_context(parsed_output: dict[str, Any] | None) -> bool:
    if not parsed_output:
        return True

    verdict = str(parsed_output.get("verdict", "")).strip().lower()
    missing_info = parsed_output.get("missing_info", [])
    evidence = parsed_output.get("evidence", [])

    # uncertain 是合法结论，不应仅因为结论不确定就继续消耗工具轮次。
    # 只有明确列出缺失上下文时，才进入 read_file / rg / TLDR 补证据流程。
    if isinstance(missing_info, list) and any(str(item).strip() for item in missing_info):
        return True
    if verdict == "vulnerable" and not isinstance(evidence, list):
        return True
    return False


def _build_context_tool_calls(
    *,
    root: Path,
    prompt_payload: dict[str, Any],
    parsed_output: dict[str, Any] | None,
    tool_rounds: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chain = _object_or_empty(prompt_payload.get("call_chain_record"))
    sink = _object_or_empty(chain.get("sink"))
    entry = _object_or_empty(chain.get("entry"))
    functions = _list_of_dicts(prompt_payload.get("functions"))
    missing_info = []
    if parsed_output and isinstance(parsed_output.get("missing_info"), list):
        missing_info = [str(item).lower() for item in parsed_output.get("missing_info", []) if str(item).strip()]

    calls: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[tuple[str, Any], ...]]] = set()

    def add(tool: str, **arguments: Any) -> None:
        normalized = _normalize_tool_name(tool)
        clean_arguments = {key: value for key, value in arguments.items() if value is not None}
        payload = {"tool": normalized, "arguments": _normalize_tool_arguments(normalized, clean_arguments)}
        key = (payload["tool"], tuple(sorted(payload["arguments"].items())))
        if key in seen:
            return
        seen.add(key)
        calls.append(payload)

    sink_file = str(sink.get("file", "")).strip()
    sink_line = int(sink.get("line", 0) or 0)
    sink_function = str(sink.get("function", "")).strip()
    sink_ref = str(sink.get("function_ref", "")).strip()

    if sink_file:
        add("read_file_window", file_path=sink_file, center_line=sink_line or 1, before=80, after=140)
        add(
            "tldr__tldr_extract",
            file_path=sink_file,
            function_name=sink_function or None,
            function_ref=sink_ref or None,
            line=sink_line or None,
        )
        add(
            "tldr__tldr_impact",
            file_path=sink_file,
            function_name=sink_function or None,
            function_ref=sink_ref or None,
            line=sink_line or None,
            max_depth=8,
        )

    entry_file = str(entry.get("file", "")).strip()
    entry_function = str(entry.get("function", "")).strip()
    entry_ref = str(entry.get("function_ref", "")).strip()
    if entry_file:
        add("read_file_window", file_path=entry_file, center_line=1, start_line=1, end_line=220)
    if entry_file or entry_function or entry_ref:
        add(
            "tldr__tldr_extract",
            file_path=entry_file or sink_file or None,
            function_name=entry_function or sink_function or None,
            function_ref=entry_ref or None,
            line=1,
        )
        add(
            "tldr__tldr_impact",
            file_path=entry_file or sink_file or None,
            function_name=entry_function or sink_function or None,
            function_ref=entry_ref or None,
            line=1,
            max_depth=8,
        )

    if functions:
        for item in functions[:2]:
            file_path = str(item.get("file", "")).strip()
            function_name = str(item.get("name", "")).strip()
            function_ref = str(item.get("function_ref", "")).strip()
            start_line = int(item.get("start_line", 0) or 0)
            if file_path:
                add(
                    "read_file_window",
                    file_path=file_path,
                    center_line=start_line or sink_line or 1,
                    before=50,
                    after=110,
                )
                add(
                    "tldr__tldr_extract",
                    file_path=file_path,
                    function_name=function_name or None,
                    function_ref=function_ref or None,
                    line=start_line or None,
                )

    if any("caller" in item or "source" in item or "route" in item or "entry" in item for item in missing_info):
        search_terms = [term for term in [sink_function, entry_function, str(sink.get("vulnerability_type", ""))] if term]
        for term in search_terms[:2]:
            add("ripgrep__search", pattern=term, glob="**/*", max_matches=40, fixed_strings=True)

    return calls[:6]


def _extract_tool_calls(raw_output: str) -> list[dict[str, Any]]:
    try:
        parsed = _parse_json_object(raw_output)
    except (json.JSONDecodeError, ValueError):
        return []

    calls = parsed.get("tool_calls") or parsed.get("tools") or parsed.get("mcp_tool_calls")
    if not isinstance(calls, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in calls:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("tool") or item.get("name") or "").strip()
        arguments = item.get("arguments") or item.get("args") or {}
        if not tool_name:
            continue
        if not isinstance(arguments, dict):
            arguments = {}
        normalized.append(
            {
                "tool": _normalize_tool_name(tool_name),
                "arguments": _normalize_tool_arguments(tool_name, arguments),
            }
        )
    return normalized[:8]


def _normalize_tool_name(tool_name: str) -> str:
    mapping = {
        "search_code": "ripgrep__search",
        "ripgrep_search": "ripgrep__search",
        "rg": "ripgrep__search",
        "extract_function": "tldr__tldr_extract",
        "trace_impact": "tldr__tldr_impact",
    }
    return mapping.get(tool_name.strip(), tool_name.strip())


def _normalize_tool_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    normalized_tool = _normalize_tool_name(tool_name)
    args = dict(arguments)

    if normalized_tool == "ripgrep__search" and "pattern" not in args and "query" in args:
        args["pattern"] = args.pop("query")

    if normalized_tool == "read_file_window":
        if "center_line" not in args and "line" in args:
            args["center_line"] = args.pop("line")
        if "before" not in args and "radius" in args:
            args["before"] = args["radius"]
        if "after" not in args and "radius" in args:
            args["after"] = args["radius"]
        args.pop("radius", None)

    if normalized_tool in {"tldr__tldr_extract", "tldr__tldr_impact"}:
        if "function_name" not in args and "function" in args:
            args["function_name"] = args.pop("function")

    return args


def _merge_tool_rounds(
    parsed_rounds: Any,
    executed_rounds: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if isinstance(parsed_rounds, list) and parsed_rounds:
        return [*_list_of_dicts(parsed_rounds), *executed_rounds]
    return executed_rounds


def _pending_audit_results(
    audit_tasks: list[dict[str, Any]],
    *,
    progress_reporter: ProgressReporter | None,
) -> list[dict[str, Any]]:
    """Build scanner.md-compatible dry-run audit rows without invoking the LLM."""
    results: list[dict[str, Any]] = []
    total = len(audit_tasks)
    for index, task in enumerate(audit_tasks, start=1):
        chain = _object_or_empty(task.get("priority_chain"))
        sink = _object_or_empty(task.get("sink"))
        rank = _object_or_empty(task.get("rank"))
        severity = str(rank.get("risk_level") or sink.get("severity") or "unknown")
        _report_progress(
            progress_reporter,
            {
                "event": "audit_task_prepared",
                "current": index,
                "total": total,
                "task_id": task.get("task_id", ""),
                "chain_id": task.get("chain_id", ""),
                "sink": sink.get("sink_id", ""),
            },
        )
        parsed = {
            "schema_version": "defectmine.audit.result.v2",
            "chain_id": str(task.get("chain_id", "")),
            "analysis_id": str(task.get("analysis_id", "")),
            "verdict": "uncertain",
            "confidence": 0.0,
            "confidence_label": "low",
            "severity": severity,
            "title": "Dry-run 审计任务已生成",
            "cwe_guess": str(chain.get("vulnerability_type") or sink.get("vulnerability_type") or "unknown"),
            "principle": "Dry-run 模式只构建第三阶段审计输入，尚未调用 LLM 进行漏洞判断。",
            "source": {"file": None, "line": None, "expr": None},
            "sink": {
                "file": str(sink.get("file", "")),
                "line": int(sink.get("line", 0) or 0),
                "expr": str(sink.get("expr") or sink.get("sink_name") or sink.get("sink_id") or ""),
            },
            "data_flow": [],
            "exploit_poc": "当前未生成 PoC。默认策略只允许生成静态 PoC 描述，不执行任何请求、命令或写入操作。",
            "fix_suggestion": "去掉 --audit-dry-run 后重新运行 --audit，让 Scanner 调用 LLM 完成可利用性判断与修复建议生成。",
            "refuted_by": None,
            "missing_info": ["当前使用 --audit-dry-run，LLM 审计未启用。"],
            "evidence": [],
            "tool_rounds": [],
            "meta": {
                "chain_id": str(task.get("chain_id", "")),
                "analysis_id": str(task.get("analysis_id", "")),
                "severity": severity,
                "status": "prepared",
            },
        }
        results.append(
            {
                "task_id": task.get("task_id", ""),
                "chain": chain,
                "audit_task": task,
                "raw_output": "",
                "parsed": parsed,
                "status": "prepared",
                "error": "",
            }
        )
    return results


def _audit_one_chain_safely(
    *,
    root: Path,
    chain: dict[str, Any],
    project_cognition: dict[str, Any],
    index: int,
    total: int,
    allow_active_poc: bool,
    agent_runner: AuditAgentRunner,
    enable_mcp_tools: bool,
    progress_reporter: ProgressReporter | None,
) -> dict[str, Any]:
    _report_progress(
        progress_reporter,
        {
            "event": "audit_chain_started",
            "current": index,
            "total": total,
            "chain_id": chain.get("path_id", ""),
            "sink": _object_or_empty(chain.get("sink")).get("sink_id", ""),
        },
    )
    prompt_payload: dict[str, Any] = {}
    raw_output = ""
    try:
        prompt_payload = _build_audit_prompt_payload(
            root=root,
            chain=chain,
            project_cognition=project_cognition,
            allow_active_poc=allow_active_poc,
        )
        audit_run = _run_audit_tool_loop(
            root=root,
            prompt_payload=prompt_payload,
            agent_runner=agent_runner,
            enable_mcp_tools=enable_mcp_tools,
            progress_reporter=progress_reporter,
            chain_id=str(chain.get("path_id", "")),
            index=index,
            total=total,
        )
        raw_output = audit_run["raw_output"]
        parsed, raw_output, repair_error = _parse_or_repair_audit_result(
            raw_output=raw_output,
            prompt_payload=prompt_payload,
            agent_runner=agent_runner,
            chain_id=str(chain.get("path_id", "")),
            analysis_id=str(chain.get("analysis_id", "")),
        )
        parsed["tool_rounds"] = _merge_tool_rounds(parsed.get("tool_rounds", []), audit_run["tool_rounds"])
        api_calls = int(audit_run.get("llm_calls", 1) or 1)
        if repair_error:
            api_calls += 1
            parsed.setdefault("missing_info", []).append(repair_error)
        parsed = _normalize_audit_language(parsed)
        parsed["api_calls"] = api_calls
        meta = parsed.get("meta") if isinstance(parsed.get("meta"), dict) else {}
        parsed["meta"] = {**meta, "api_calls": api_calls, "status": "completed"}
        status = "completed"
        error = ""
    except Exception as exc:
        parsed = error_audit_result(
            chain_id=str(chain.get("path_id", "")),
            analysis_id=str(chain.get("analysis_id", "")),
            message=str(exc),
            severity=str(_object_or_empty(chain.get("rank")).get("risk_level", "unknown")),
        )
        parsed["api_calls"] = 0
        status = "error"
        error = str(exc)
        api_calls = 0

    _report_progress(
        progress_reporter,
        {
            "event": "audit_chain_completed",
            "current": index,
            "total": total,
            "chain_id": chain.get("path_id", ""),
            "verdict": parsed.get("verdict", "error"),
            "status": status,
        },
    )
    return {
        "chain": chain,
        "audit_input": prompt_payload,
        "raw_output": raw_output,
        "parsed": parsed,
        "tool_rounds": parsed.get("tool_rounds", []),
        "api_calls": api_calls,
        "status": status,
        "error": error,
    }


def _parse_or_repair_audit_result(
    *,
    raw_output: str,
    prompt_payload: dict[str, Any],
    agent_runner: AuditAgentRunner,
    chain_id: str,
    analysis_id: str,
) -> tuple[dict[str, Any], str, str]:
    """Parse Scanner output, then ask one repair pass to match scanner.md schema."""
    try:
        return (
            parse_audit_result(raw_output, chain_id=chain_id, analysis_id=analysis_id),
            raw_output,
            "",
        )
    except Exception as exc:
        repaired_output = _call_audit_agent(
            agent_runner,
            json.dumps(
                {
                    "task": "修复上一轮 Scanner 审计输出为严格 JSON。不要重新审计，不要输出 Markdown，只返回一个 JSON object。",
                    "error": str(exc),
                    "required_schema": AUDIT_RESULT_JSON_SCHEMA,
                    "required_verdict_values": ["vulnerable", "uncertain", "safe"],
                    "confidence_policy": "confidence 必须是 0.0 到 1.0 之间的浮点数。",
                    "chain_id": chain_id,
                    "analysis_id": analysis_id,
                    "original_output": raw_output,
                    "language_policy": "title、principle、data_flow、exploit_poc、fix_suggestion、refuted_by、missing_info、evidence.detail 必须使用中文。",
                    "original_audit_input_brief": {
                        "project_cognition": prompt_payload.get("project_cognition", {}),
                        "call_chain_record": prompt_payload.get("call_chain_record", {}),
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
        return (
            parse_audit_result(repaired_output, chain_id=chain_id, analysis_id=analysis_id),
            repaired_output,
            f"首轮 JSON 解析失败，已按 scanner.md schema 进行一次格式修复：{exc}",
        )


def _call_audit_agent(agent_runner: AuditAgentRunner, content: str) -> str:
    try:
        return agent_runner(AgentType.SCANNER, content, temperature=0.0)
    except TypeError:
        return agent_runner(AgentType.SCANNER, content)


def _normalize_audit_language(result: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(result)
    normalized["principle"] = _localize_common_text(str(normalized.get("principle", "")))
    normalized["exploit_poc"] = _localize_common_text(str(normalized.get("exploit_poc", "")))
    normalized["fix_suggestion"] = _localize_common_text(str(normalized.get("fix_suggestion", "")))
    normalized["missing_info"] = [
        _localize_common_text(str(item)) for item in normalized.get("missing_info", []) if str(item).strip()
    ]
    normalized["evidence"] = _normalize_evidence_language(normalized.get("evidence", []))
    return normalized


def _normalize_evidence_language(evidence: Any) -> list[Any]:
    if not isinstance(evidence, list):
        return []
    normalized: list[Any] = []
    for item in evidence:
        if isinstance(item, dict):
            updated = dict(item)
            for key in ("description", "reason", "text", "evidence", "detail"):
                if key in updated:
                    updated[key] = _localize_common_text(str(updated[key]))
            normalized.append(updated)
        elif isinstance(item, str):
            normalized.append(_localize_common_text(item))
        else:
            normalized.append(item)
    return normalized


def _localize_common_text(text: str) -> str:
    stripped = text.strip()
    replacements = {
        "The audit task failed before a vulnerability verdict could be established.": "Scanner Agent 未能完成结构化审计，不能给出漏洞结论。",
        "No fix required. The reported sink is a false positive.": "无需修复；该 sink 命中属于误报。",
        "No fix required for this specific chain.": "该调用链无需修复。",
        "No exploit possible.": "无法构造有效利用。",
        "Not applicable.": "不适用。",
        "None required": "无需处理",
        "No PoC was executed.": "未执行任何 PoC。",
        "No fix required": "无需修复",
        "false positive": "误报",
    }
    for source, target in replacements.items():
        stripped = stripped.replace(source, target)
    return stripped


def _build_audit_prompt_payload(
    *,
    root: Path,
    chain: dict[str, Any],
    project_cognition: dict[str, Any],
    allow_active_poc: bool,
) -> dict[str, Any]:
    """Build one Scanner Agent input aligned to prompts/scanner.md."""
    language = str(chain.get("language", "unknown"))
    vulnerability_type = str(chain.get("vulnerability_type", "unknown"))
    skill = load_skill(language, vulnerability_type)
    functions = _list_of_dicts(chain.get("functions"))
    return {
        "role": "DefectMine Scanner Agent",
        "task": "审计一条 source-to-sink 调用链，并返回符合 scanner.md 的严格 JSON。所有解释性字段必须使用中文。",
        "system_rules": [
            audit_system_schema_prompt(),
            "First audit with the provided project_cognition, call_chain_record, functions, and skill. Do not request tools just for optional context.",
            "Request tools only when a key fact is missing: source, sanitizer, caller, route/API entry, or the exact sink argument.",
            "When existing context or tool results already provide enough evidence, stop requesting tools and return the final strict JSON verdict.",
            "只审计当前提供的调用链、项目认知、函数源码和 Skill 知识块。",
            "除 schema 枚举值外，title、principle、data_flow、exploit_poc、fix_suggestion、refuted_by、missing_info、evidence.detail 必须使用中文。",
            "除非能指出明确的 source-to-sink 证据，否则不要给出 vulnerable。",
            "如果缺少 source、sanitizer、鉴权或调用方上下文，返回 uncertain，并在 missing_info 中写清楚缺失项。",
            "最终响应只能是一个 JSON object，不能包含 Markdown、代码围栏、注释或额外解释。",
        ],
        "safety": {
            "active_poc_allowed": bool(allow_active_poc),
            "default_policy": "static_poc_only",
            "forbidden_actions": [
                "Do not execute shell commands as PoC.",
                "Do not send HTTP requests as PoC.",
                "Do not write files, mutate databases, or trigger destructive behavior.",
                "Only describe a static PoC payload and expected reasoning.",
            ],
        },
        "tool_contract": {
            "phase": "phase3_mcp_tool_loop",
            "max_rounds": MAX_AUDIT_TOOL_ROUNDS,
            "available_tools": [
                "ripgrep__search(pattern, path, glob, max_matches)",
                "read_file_window(file_path, center_line, start_line, end_line)",
                "tldr__tldr_extract(file_path, function_name, function_ref, line)",
                "tldr__tldr_impact(file_path, function_name, function_ref, line, max_depth)",
            ],
            "request_format": {
                "tool_calls": [
                    {
                        "tool": "read_file_window",
                        "arguments": {"file_path": "path/to/file.php", "center_line": 120},
                    }
                ]
            },
        },
        "input_schema": {
            "required_context": [
                "project_cognition",
                "call_chain_record",
                "functions",
                "skill",
                "output_schema",
            ],
            "function_source_field": "functions[].source",
        },
        "skill": {
            "language": skill.language,
            "vulnerability_type": skill.vulnerability_type,
            "path": _relative_or_string(Path(__file__).resolve().parents[3], skill.path),
            "fallback_used": skill.fallback_used,
            "content": skill.content,
        },
        "output_schema": AUDIT_RESULT_JSON_SCHEMA,
        "project": {
            "root_path": str(root),
            "root_name": root.name,
        },
        "project_cognition": project_cognition,
        "call_chain_record": {
            "schema_version": chain.get("schema_version", ""),
            "priority_index": chain.get("priority_index", 0),
            "path_id": chain.get("path_id", ""),
            "analysis_id": chain.get("analysis_id", ""),
            "language": language,
            "vulnerability_type": vulnerability_type,
            "rank": _object_or_empty(chain.get("rank")),
            "sink": _object_or_empty(chain.get("sink")),
            "entry": _object_or_empty(chain.get("entry")),
            "chain": _list_of_dicts(chain.get("chain")),
            "call_edges": _list_of_dicts(chain.get("call_edges")),
        },
        "functions": functions,
    }


def _audit_verdict_bucket(value: Any) -> str:
    verdict = str(value or "").strip().lower()
    if verdict in {"vulnerable", "confirmed", "true_positive"}:
        return "vulnerable"
    if verdict in {"safe", "not_vulnerable", "false_positive"}:
        return "safe"
    if verdict in {"uncertain", "needs_review", "inconclusive", "suspicious"}:
        return "uncertain"
    if verdict == "error":
        return "error"
    return "unknown"


def _audit_is_error(raw_item: dict[str, Any], parsed: dict[str, Any]) -> bool:
    meta = parsed.get("meta") if isinstance(parsed.get("meta"), dict) else {}
    return str(raw_item.get("status", "")).lower() == "error" or str(meta.get("status", "")).lower() == "error"


def _build_audit_report(
    *,
    root: Path,
    chains: list[dict[str, Any]],
    audit_tasks: list[dict[str, Any]],
    raw_results: list[dict[str, Any]],
    chain_path: Path,
    profile_path: Path,
    project_cognition: dict[str, Any],
    allow_active_poc: bool,
    enable_llm_audit: bool,
    enable_mcp_tools: bool,
    concurrency: int,
) -> dict[str, Any]:
    audits = [item.get("parsed", {}) for item in raw_results]
    verdict_counts = {key: 0 for key in ("vulnerable", "safe", "uncertain", "error", "unknown")}
    for raw_item, audit in zip(raw_results, audits):
        bucket = "error" if _audit_is_error(raw_item, audit) else _audit_verdict_bucket(audit.get("verdict"))
        verdict_counts[bucket] = verdict_counts.get(bucket, 0) + 1

    severity_counts = {
        severity: sum(1 for item in audits if item.get("severity") == severity)
        for severity in ("critical", "high", "medium", "low", "info", "unknown")
    }
    api_call_counts = [int(item.get("api_calls", 0) or 0) for item in raw_results]
    tool_round_counts = [len(_list_of_dicts(item.get("tool_rounds"))) for item in raw_results]
    summary = {
        "chains": len(chains),
        "audited": len(audits),
        "vulnerable": verdict_counts["vulnerable"],
        "safe": verdict_counts["safe"],
        "uncertain": verdict_counts["uncertain"],
        "errors": verdict_counts["error"],
        "not_vulnerable": verdict_counts["safe"],
        "needs_review": verdict_counts["uncertain"],
        "inconclusive": 0,
        "verdict_counts": verdict_counts,
        "severity_counts": severity_counts,
        "cost": {
            "estimated_api_calls": sum(api_call_counts),
            "max_api_calls_per_chain": max(api_call_counts, default=0),
            "tool_rounds": sum(tool_round_counts),
            "max_tool_rounds_per_chain": max(tool_round_counts, default=0),
            "tool_round_limit": MAX_AUDIT_TOOL_ROUNDS,
        },
        "confirmed_findings": [
            {
                "chain_id": item.get("chain_id", ""),
                "analysis_id": item.get("analysis_id", ""),
                "title": item.get("title", ""),
                "cwe_guess": item.get("cwe_guess", ""),
                "severity": item.get("severity", "unknown"),
                "confidence": item.get("confidence", 0.0),
            }
            for item in audits
            if _audit_verdict_bucket(item.get("verdict")) == "vulnerable"
        ],
    }
    return {
        "schema_version": "defectmine.audit.v1",
        "project": {
            "root_name": root.name,
            "root_path": str(root),
            "project_name": project_cognition.get("project_name", root.name),
            "project_type": project_cognition.get("project_type", "unknown"),
            "technology_stack": project_cognition.get("technology_stack", {}),
            "risk_surfaces": project_cognition.get("risk_surfaces", []),
        },
        "inputs": {
            "priority_chains": _relative_or_string(root, chain_path),
            "treescan_profile": _relative_or_string(root, profile_path),
        },
        "audits": audits,
        "summary": summary,
        "debug": {
            "status": "completed",
            "execution": {
                "phase": "phase3_mcp_audit" if enable_llm_audit else "phase3_audit_input_dry_run",
                "enable_llm_audit": bool(enable_llm_audit),
                "enable_mcp_tools": bool(enable_mcp_tools),
                "concurrency": int(concurrency),
                "sort_order": "rank.priority desc, rank.risk_score desc",
            },
            "project_cognition": project_cognition,
            "safety": {
                "active_poc_allowed": bool(allow_active_poc),
                "policy": "static_poc_only" if not allow_active_poc else "active_poc_explicitly_allowed",
            },
            "audit_tasks": audit_tasks,
            "raw_results": raw_results,
        },
    }


def _render_audit_markdown(report: dict[str, Any]) -> str:
    sections = ["# DefectMine 审计报告", ""]
    summary = _object_or_empty(report.get("summary"))
    sections.append(
        "汇总：调用链={chains}，确认漏洞={vulnerable}，不确定={uncertain}，确认安全={safe}，审计失败={errors}".format(
            chains=summary.get("chains", 0),
            vulnerable=summary.get("vulnerable", 0),
            uncertain=summary.get("uncertain", 0),
            safe=summary.get("safe", 0),
            errors=summary.get("errors", 0),
        )
    )
    sections.append("")
    raw_results = _list_of_dicts(_object_or_empty(report.get("debug")).get("raw_results"))
    total = len(raw_results)
    for index, item in enumerate(raw_results, start=1):
        parsed = _object_or_empty(item.get("parsed"))
        chain = _object_or_empty(item.get("chain"))
        sink = _object_or_empty(chain.get("sink"))
        status_label = _verdict_label(str(parsed.get("verdict", "unknown")))
        vuln = str(parsed.get("cwe_guess") or chain.get("vulnerability_type") or sink.get("vulnerability_type") or sink.get("vulnerability") or "unknown")
        sections.extend(
            [
                f"===== [{index}/{total}] [{status_label}] {vuln} 漏洞 =====",
                "==================================",
                f"严重程度: {parsed.get('severity', 'unknown')}",
                f"漏洞类型: {vuln}",
                f"Verdict: {parsed.get('verdict', 'unknown')}",
                f"Confidence: {parsed.get('confidence', 'unknown')}",
                f"Severity: {parsed.get('severity', 'unknown')}",
                "",
                "### 漏洞原理:",
                str(parsed.get("principle", "")),
                "",
                "### 完整调用链:",
                _format_chain(chain),
                "",
                "### 验证POC与流程:",
                str(parsed.get("exploit_poc", "")) or "未生成 PoC。默认策略只允许静态 PoC 描述，不执行任何真实利用操作。",
                "",
                "### 修复建议:",
                str(parsed.get("fix_suggestion", "")),
                "",
                "### 证据:",
                _format_evidence(parsed.get("evidence", [])),
                "",
                "### 反证:",
                str(parsed.get("refuted_by") or "无。"),
                "",
                "### 缺失信息:",
                _format_list(parsed.get("missing_info", [])),
                "",
            ]
        )
    return "\n".join(sections).rstrip() + "\n"


def _verdict_label(verdict: str) -> str:
    return {
        "vulnerable": "确认漏洞",
        "safe": "确认安全",
        "not_vulnerable": "确认安全",
        "uncertain": "不确定",
        "needs_review": "不确定",
        "inconclusive": "不确定",
        "error": "审计失败",
    }.get(verdict, "未知结论")


def _format_evidence(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "无。"
    lines: list[str] = []
    for item in items:
        if isinstance(item, dict):
            location = item.get("location") or item.get("file") or item.get("path") or ""
            line = item.get("line") or item.get("line_number") or ""
            text = (
                item.get("detail")
                or item.get("description")
                or item.get("text")
                or item.get("evidence")
                or item.get("reason")
                or ""
            )
            if not text:
                text = json.dumps(item, ensure_ascii=False)
            suffix = f":{line}" if line else ""
            lines.append(f"- {location}{suffix} {text}".strip())
        else:
            lines.append(f"- {item}")
    return "\n".join(lines)


def _format_chain(chain: dict[str, Any]) -> str:
    nodes = chain.get("chain", [])
    if not isinstance(nodes, list) or not nodes:
        return "无调用链节点。"
    lines = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        file = node.get("file", "")
        function = node.get("function", node.get("name", ""))
        line = node.get("line") or node.get("start_line") or ""
        location = f"{file}:{line}" if line else str(file)
        lines.append(f"- `{function}` @ `{location}`")
    return "\n".join(lines) if lines else "无调用链节点。"


def _format_list(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "无。"
    return "\n".join(f"- {item}" for item in items)


def _select_scan_targets(root: Path, tree: dict[str, Any]) -> list[dict[str, Any]]:
    focus_paths = tree.get("focus_paths", [])
    seen: set[str] = set()
    targets: list[dict[str, Any]] = []

    for item in focus_paths:
        if item.get("type") != "file":
            continue
        relative_path = item.get("path", "")
        if relative_path in seen:
            continue

        absolute_path = root / relative_path
        if not absolute_path.is_file():
            continue
        if absolute_path.suffix.lower() not in ALLOWED_SOURCE_SUFFIXES:
            continue

        target = {
            "path": relative_path,
            "absolute_path": str(absolute_path),
            "name": absolute_path.name,
            "kind": item.get("kind", "unknown"),
            "priority": item.get("priority", "medium"),
            "reason": item.get("reason", ""),
        }
        targets.append(target)
        seen.add(relative_path)

        if len(targets) >= MAX_SCAN_TARGETS:
            break

    return targets


#----------- Scanner 输入构造：只发送必要画像、目录上下文与目标文件源码 ------------#
def _build_scanner_input(
    *,
    root: Path,
    tree: dict[str, Any],
    profile: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    source_path = root / target["path"]
    source = _read_source_excerpt(source_path)

    return {
        "project": {
            "root_name": tree.get("root", {}).get("name", root.name),
            "root_path": str(root),
            "project_name": profile.get("project_name", "unknown"),
            "project_function": profile.get("project_function", "unknown"),
            "project_type": profile.get("project_type", "unknown"),
            "technology_stack": profile.get("technology_stack", {}),
            "architecture_style": profile.get("architecture_style", []),
        },
        #----------- Scanner 项目认知注入：把 TreeScan 沉淀的项目理解持续带给后续 Agent ------------#
        "project_cognition": {
            "project_name": profile.get("project_name", "unknown"),
            "project_function": profile.get("project_function", "unknown"),
            "project_type": profile.get("project_type", "unknown"),
            "project_summary": profile.get("project_summary", ""),
            "project_understanding": profile.get("project_understanding", {}),
            "scanner_hints": profile.get("scanner_hints", {}),
            "technology_stack": profile.get("technology_stack", {}),
            "architecture_style": profile.get("architecture_style", []),
            "confidence": profile.get("confidence", {}),
        },
        "project_context": {
            "summary": tree.get("summary", {}),
            "metadata": tree.get("metadata", {}),
            "signals": tree.get("signals", {}),
            "focus_paths": tree.get("focus_paths", [])[:60],
            "hot_directories": tree.get("hot_directories", [])[:40],
            "scan_plan": tree.get("scan_plan", {}),
        },
        "directory_context": _directory_context_for_target(tree, target["path"]),
        "target_file": {
            "file_path": target["path"],
            "file_name": target["name"],
            "kind": target.get("kind", "unknown"),
            "priority": target.get("priority", "medium"),
            "reason": target.get("reason", ""),
            "source": source,
        },
    }


#----------- Scanner 目录上下文：给目标文件附上局部树结构，避免只看孤立源码 ------------#
def _directory_context_for_target(tree: dict[str, Any], relative_path: str) -> dict[str, Any]:
    parts = Path(relative_path).parts
    hot_directories = tree.get("hot_directories", [])
    lineage = []

    for index in range(1, len(parts)):
        candidate = Path(*parts[:index]).as_posix()
        lineage.append(
            {
                "path": candidate,
                "signals": _hot_directory_signals(hot_directories, candidate),
            }
        )

    siblings = _sibling_candidates(tree.get("focus_paths", []), relative_path)
    return {
        "ancestors": lineage,
        "sibling_files": siblings,
        "sibling_dirs": [],
    }


def _hot_directory_signals(hot_directories: list[dict[str, Any]], path: str) -> int:
    for item in hot_directories:
        if item.get("path") == path:
            return int(item.get("signals", 0))
    return 0


def _sibling_candidates(focus_paths: list[dict[str, Any]], relative_path: str) -> list[dict[str, Any]]:
    parent = Path(relative_path).parent.as_posix()
    candidates = [
        {
            "path": item.get("path", ""),
            "kind": item.get("kind", "unknown"),
            "priority": item.get("priority", "medium"),
            "reason": item.get("reason", ""),
        }
        for item in focus_paths
        if item.get("type") == "file" and Path(str(item.get("path", ""))).parent.as_posix() == parent
    ]
    return candidates[:20]


#----------- Scanner 输出解析：兼容非严格 JSON，并在失败时保留错误上下文 ------------#
def _parse_scanner_output(raw_output: str, file_path: str) -> dict[str, Any]:
    try:
        parsed = _parse_json_object(raw_output)
    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "findings": [],
            "summary": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "suspicious": 0,
            },
            "status": "invalid_json",
            "file": file_path,
            "error": str(exc),
            "raw_output_preview": raw_output[:2000],
        }

    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    summary = parsed.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}

    return {
        "findings": findings,
        "summary": {
            "total": int(summary.get("total", len(findings))),
            "critical": int(summary.get("critical", 0)),
            "high": int(summary.get("high", 0)),
            "medium": int(summary.get("medium", 0)),
            "low": int(summary.get("low", 0)),
            "suspicious": int(summary.get("suspicious", 0)),
        },
    }


#----------- Scanner 聚合逻辑：把逐文件 findings 合并成一个总报告 ------------#
def _merge_scanner_results(raw_results: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "suspicious": 0,
    }

    for item in raw_results:
        parsed = item.get("parsed", {})
        parsed_findings = parsed.get("findings", [])
        if not isinstance(parsed_findings, list):
            parsed_findings = []

        for finding in parsed_findings:
            if not isinstance(finding, dict):
                continue
            findings.append(finding)
            severity = str(finding.get("severity", "")).lower()
            status = str(finding.get("status", "")).lower()

            summary["total"] += 1
            if severity in {"critical", "high", "medium", "low"}:
                summary[severity] += 1
            elif status == "suspicious":
                summary["suspicious"] += 1

    return {
        "findings": findings,
        "summary": summary,
    }


def _read_source_excerpt(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    return content[:MAX_FILE_BYTES]


def _load_project_cognition(profile_path: Path) -> dict[str, Any]:
    if not profile_path.is_file():
        return {
            "project_name": "unknown",
            "project_type": "unknown",
            "project_function": "unknown",
            "technology_stack": {},
            "risk_surfaces": [],
            "scanner_hints": {},
            "source": "missing_treescan_profile",
        }

    profile = _read_json_object(profile_path)
    understanding = _object_or_empty(profile.get("project_understanding"))
    deterministic = _object_or_empty(profile.get("deterministic"))
    scanner_inferred = _object_or_empty(profile.get("scanner_inferred"))

    return {
        "project_name": profile.get("project_name", "unknown"),
        "project_type": profile.get("project_type", "unknown"),
        "project_function": profile.get("project_function", "unknown"),
        "project_summary": profile.get("project_summary", ""),
        "technology_stack": profile.get("technology_stack", {}),
        "architecture_style": profile.get("architecture_style", []),
        "risk_surfaces": _unique_strings(
            _ensure_list(understanding.get("attack_surfaces"))
            + _ensure_list(profile.get("potential_attack_surfaces"))
            + _ensure_list(deterministic.get("attack_surfaces"))
            + _ensure_list(scanner_inferred.get("attack_surfaces"))
        )[:12],
        "focus_modules": _ensure_list(understanding.get("focus_modules"))[:20],
        "scanner_hints": profile.get("scanner_hints", {}),
        "confidence": profile.get("confidence", {}),
        "source": str(profile_path),
    }


def _resolve_artifacts_dir(root: Path, artifacts_dir: str | Path | None) -> Path:
    if artifacts_dir is None:
        return (root / ARTIFACTS_DIRNAME).resolve()

    path = Path(artifacts_dir).expanduser()
    if not path.is_absolute():
        path = root / path

    return path.resolve()


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        parsed = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _sort_priority_chains(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        chains,
        key=lambda chain: (
            _priority_sort_value(str(_object_or_empty(chain.get("rank")).get("priority", "P9"))),
            -int(_object_or_empty(chain.get("rank")).get("risk_score", 0) or 0),
            int(chain.get("priority_index", 0) or 0),
            str(chain.get("path_id", "")),
        ),
    )


def _priority_sort_value(priority: str) -> int:
    normalized = priority.strip().upper()
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(normalized, 9)


def _resolve_priority_chains_path(
    root: Path,
    output_dir: Path,
    priority_chains_path: str | Path | None,
) -> Path:
    if priority_chains_path is None:
        return output_dir / CALLSCAN_PRIORITY_CHAINS_FILENAME

    path = Path(priority_chains_path).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(text + "\n", encoding="utf-8")


def _report_progress(
    progress_reporter: ProgressReporter | None,
    payload: dict[str, Any],
) -> None:
    if progress_reporter is None:
        return
    progress_reporter(payload)


def _parse_json_object(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = _strip_code_fence(cleaned)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = json.loads(_extract_json_object(cleaned))

    if not isinstance(parsed, dict):
        raise ValueError("Scanner Agent response must be a JSON object.")

    return parsed


def _strip_code_fence(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError("Scanner Agent response does not contain a JSON object.")

    return text[start : end + 1]


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _ensure_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip()
        key = normalized.casefold()
        if not normalized or key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


def _relative_or_string(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)
