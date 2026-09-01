"""Checker Agent: second-pass review for Auditor findings.

The checker is intentionally not part of the scan workflow. Run it manually:

    python -m app.agent checker <project_path> <scan_id> [chain_id]

It reads Auditor output, replays evidence for vulnerable findings, and writes
its own artifacts without mutating audit results or project source code.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.agent.logger import write_event
from app.agent.mcp import MCPToolbox, default_server_specs
from app.agent.prompts import load_prompt
from app.agent.run_scope import RunScope, resolve_run_scope
from app.agent.sub_agent.auditor import (
    _confidence_value,
    _execute_tool,
    _json_object,
    _parse_json_from_text,
    _stable_hash,
    _string_value,
    _text_list,
)
from app.llm.client import chat_completion, response_message_to_dict
from app.ui.console import action, info, print_status

AUDIT_JSON_FILENAME = "audit_agent.json"
CALLSCAN_PRIORITY_JSONL = "callscan_chains.priority.jsonl"
CHECKER_JSON_FILENAME = "checker_agent.json"
CHECKER_MD_FILENAME = "checker_findings.md"
CHECKER_PROGRESS_JSONL = "checker_progress.jsonl"
CHECKER_FAILURES_JSONL = "checker_failures.jsonl"

MAX_TOOL_ROUNDS = 6
TOOL_RESULT_CHAR_LIMIT = 10_000
SNIPPET_CONTEXT_LINES = 18
MAX_SNIPPETS = 12
CHECKER_VERDICTS = {"confirmed", "refuted", "need_context"}
SEVERITIES = {"critical", "high", "medium", "low"}

LLM_TOOL_NAMES = {
    "tldr__tldr_extract",
    "tldr__tldr_impact",
    "tldr__tldr_calls",
    "tldr__tldr_search",
    "ripgrep__search",
    "ripgrep__advanced-search",
}


@dataclass(frozen=True)
class CheckerSpec:
    name: str = "Checker Agent"
    system_message: str = load_prompt("checker.md")
    temperature: float = 0.0
    max_tokens: int = 4000


SPEC = CheckerSpec()


def run(
    project_path: str,
    run_id: str | None = None,
    chain_id: str | None = None,
) -> dict[str, Any]:
    if not run_id:
        raise ValueError("Checker requires <scan_id>; it is not a root workflow agent.")
    return asyncio.run(_run_async(project_path, run_id, chain_id=chain_id))


async def _run_async(
    project_path: str,
    run_id: str,
    *,
    chain_id: str | None = None,
) -> dict[str, Any]:
    started_at = time.perf_counter()
    scope = resolve_run_scope(project_path, run_id)
    project_root = scope.project_root
    base = scope.artifacts_dir

    audit_path = base / AUDIT_JSON_FILENAME
    if not audit_path.is_file():
        raise FileNotFoundError(
            f"{AUDIT_JSON_FILENAME} not found: {audit_path}. Run Auditor first."
        )

    audit = _read_json(audit_path)
    all_findings = [
        item for item in audit.get("findings") or [] if isinstance(item, dict)
    ]
    targets = _select_findings(all_findings, chain_id)
    chains = _load_priority_chains(base / CALLSCAN_PRIORITY_JSONL)

    progress_path = base / CHECKER_PROGRESS_JSONL
    failures_path = base / CHECKER_FAILURES_JSONL
    output_json = base / CHECKER_JSON_FILENAME
    output_md = base / CHECKER_MD_FILENAME

    completed = _load_progress(progress_path)
    target_ids = [_finding_id(finding) for finding in targets]
    results = [
        completed[finding_id]
        for finding_id in target_ids
        if finding_id in completed
    ]
    pending = [
        finding
        for finding in targets
        if _finding_id(finding) not in completed
    ]

    if not targets:
        result = _build_result(
            [],
            project_path,
            project_root,
            scope,
            started_at,
            failed=0,
            total_targets=0,
        )
        _write_outputs(result, output_json, output_md)
        return result

    if not pending:
        info("Checker: all selected finding(s) already reviewed in checkpoint.")
        result = _build_result(
            results,
            project_path,
            project_root,
            scope,
            started_at,
            failed=0,
            total_targets=len(targets),
        )
        _write_outputs(result, output_json, output_md)
        return result

    info(
        f"Checker: {len(pending)} pending finding(s), "
        f"{len(results)} loaded from checkpoint"
    )

    failed = 0
    print_status(
        "checker",
        active=True,
        label=f"checker 进度 {len(results)}/{len(targets)}",
        detail=f"run_id={run_id}",
    )

    toolbox: MCPToolbox | None = None
    stack = contextlib.AsyncExitStack()
    try:
        try:
            specs = default_server_specs(project_root)
            toolbox = await stack.enter_async_context(MCPToolbox(specs, pool_size=1))
            visible = len(set(toolbox.tool_names) & LLM_TOOL_NAMES)
            info(
                f"Checker: MCP tools loaded: {len(toolbox.tool_names)} "
                f"(LLM-visible: {visible})"
            )
        except Exception as exc:  # noqa: BLE001
            info(
                f"Checker: MCP unavailable ({type(exc).__name__}: {exc}); "
                "continuing with embedded code snippets only."
            )
            toolbox = None

        for finding in pending:
            fid = _finding_id(finding)
            chain = chains.get(fid, {})
            write_event("checker_finding_start", finding_id=fid)
            t0 = time.perf_counter()
            try:
                user_message = _build_user_message(
                    scope,
                    project_root,
                    finding,
                    chain,
                )
                raw = await _run_checker_tool_loop(
                    SPEC.system_message,
                    user_message,
                    project_root,
                    toolbox,
                )
                checked = _normalize_checker_result(raw, finding, chain)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                _append_failure(
                    failures_path,
                    finding_id=fid,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                write_event(
                    "checker_finding_error",
                    finding_id=fid,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                info(f"Checker failed for {fid}: {type(exc).__name__}: {exc}")
                continue

            elapsed = time.perf_counter() - t0
            checked["elapsed_seconds"] = round(elapsed, 2)
            results.append(checked)
            _append_progress(progress_path, checked)
            write_event(
                "checker_finding_end",
                finding_id=fid,
                verdict=checked.get("verdict"),
                elapsed=elapsed,
            )
            result = _build_result(
                results,
                project_path,
                project_root,
                scope,
                started_at,
                failed=failed,
                total_targets=len(targets),
                partial=True,
            )
            _write_outputs(result, output_json, output_md)
            print_status(
                "checker",
                active=True,
                label=f"checker 进度 {len(results)}/{len(targets)}",
                detail=f"{fid} -> {checked.get('verdict')}",
            )
    finally:
        await stack.aclose()
        print_status("checker", active=False)

    result = _build_result(
        results,
        project_path,
        project_root,
        scope,
        started_at,
        failed=failed,
        total_targets=len(targets),
    )
    _write_outputs(result, output_json, output_md)
    info(
        "Checker: "
        f"{result['summary']['total_checked']} checked, "
        f"{result['summary']['confirmed']} confirmed, "
        f"{result['summary']['refuted']} refuted, "
        f"{result['summary']['need_context']} need_context, "
        f"{failed} failed"
    )
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return data


def _select_findings(
    findings: list[dict[str, Any]],
    chain_id: str | None,
) -> list[dict[str, Any]]:
    if chain_id:
        selected = [
            finding
            for finding in findings
            if _finding_id(finding) == str(chain_id)
        ]
        if not selected:
            raise ValueError(f"Finding not found in audit_agent.json: {chain_id}")
        return selected
    return [
        finding
        for finding in findings
        if str(finding.get("verdict") or "").lower() == "vulnerable"
    ]


def _finding_id(finding: dict[str, Any]) -> str:
    return str(
        finding.get("chain_id")
        or finding.get("finding_id")
        or finding.get("id")
        or ""
    ).strip()


def _load_priority_chains(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    out: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line_s = line.strip()
            if not line_s:
                continue
            try:
                row = json.loads(line_s)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or row.get("type") != "chain":
                continue
            chain_id = str(row.get("chain_id") or "").strip()
            if chain_id:
                out[chain_id] = row
    return out


def _build_user_message(
    scope: RunScope,
    project_root: Path,
    finding: dict[str, Any],
    chain: dict[str, Any],
) -> str:
    fid = _finding_id(finding)
    payload = {
        "task": "复核 Auditor 提交的单个 finding，并返回 checker.md 要求的 JSON schema。",
        "project_path": scope.project_path,
        "scan_id": scope.run_id,
        "finding_id": fid,
        "language": finding.get("language") or chain.get("language"),
        "vulnerability_type": finding.get("vulnerability_type")
        or chain.get("vulnerability_type"),
        "auditor_finding": finding,
        "callscan_chain": _compact_chain(chain),
        "code_snippets": _collect_code_snippets(project_root, finding, chain),
        "output_contract": (
            "Return exactly one JSON object with finding_id equal to the input "
            "finding_id. Use verdict confirmed/refuted/need_context only."
        ),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _compact_chain(chain: dict[str, Any]) -> dict[str, Any]:
    if not chain:
        return {}
    keep = {
        "chain_id",
        "index",
        "language",
        "vulnerability_type",
        "severity",
        "sink_file",
        "sink_line",
        "sink_function",
        "has_call_chain",
        "call_chains",
        "evidence",
        "limits",
        "audit_pack",
    }
    return {key: chain.get(key) for key in keep if key in chain}


def _collect_code_snippets(
    project_root: Path,
    finding: dict[str, Any],
    chain: dict[str, Any],
) -> list[dict[str, Any]]:
    locations: list[tuple[str, int | None]] = []

    def add(file_value: Any, line_value: Any = None) -> None:
        rel_file = str(file_value or "").strip()
        if not rel_file:
            return
        line: int | None = None
        try:
            if line_value is not None:
                line = int(line_value)
        except (TypeError, ValueError):
            line = None
        item = (rel_file.replace("\\", "/"), line)
        if item not in locations:
            locations.append(item)

    for key in ("source", "sink"):
        obj = finding.get(key)
        if isinstance(obj, dict):
            add(obj.get("file"), obj.get("line"))

    for evidence in finding.get("evidence") or []:
        if isinstance(evidence, dict):
            add(evidence.get("file"), evidence.get("line"))

    add(chain.get("sink_file"), chain.get("sink_line"))
    for call_chain in chain.get("call_chains") or []:
        if not isinstance(call_chain, list):
            continue
        for node in call_chain:
            if isinstance(node, dict):
                add(node.get("file"), node.get("line"))

    return [
        _read_snippet(project_root, rel_file, line)
        for rel_file, line in locations[:MAX_SNIPPETS]
    ]


def _read_snippet(
    project_root: Path,
    rel_file: str,
    line: int | None,
) -> dict[str, Any]:
    item: dict[str, Any] = {"file": rel_file, "line": line}
    try:
        target = (project_root / rel_file).resolve()
        target.relative_to(project_root.resolve())
    except Exception as exc:  # noqa: BLE001
        item["error"] = f"invalid path: {exc}"
        return item
    if not target.is_file():
        item["error"] = "file not found"
        return item
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        item["error"] = str(exc)
        return item

    if not lines:
        item.update({"start_line": 1, "end_line": 1, "code": ""})
        return item
    center = max(1, min(line or 1, len(lines)))
    start = max(1, center - SNIPPET_CONTEXT_LINES)
    end = min(len(lines), center + SNIPPET_CONTEXT_LINES)
    numbered = [
        f"{idx}: {lines[idx - 1]}"
        for idx in range(start, end + 1)
    ]
    item.update(
        {
            "start_line": start,
            "end_line": end,
            "code": "\n".join(numbered),
        }
    )
    return item


async def _run_checker_tool_loop(
    system_message: str,
    user_message: str,
    project_root: Path,
    toolbox: MCPToolbox | None,
) -> dict[str, Any]:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message},
    ]
    tools = toolbox.as_litellm_tools(LLM_TOOL_NAMES) if toolbox else []
    seen_tool_calls: dict[str, int] = {}

    for _round in range(1, MAX_TOOL_ROUNDS + 1):
        response = await asyncio.to_thread(
            functools.partial(
                chat_completion,
                messages,
                tools=tools if tools else None,
                tool_choice="auto" if tools else None,
                response_format={"type": "json_object"},
                temperature=SPEC.temperature,
                max_tokens=SPEC.max_tokens,
            )
        )
        message = response_message_to_dict(response)
        tool_calls = message.get("tool_calls") or []

        if not tool_calls:
            raw = message.get("content") or ""
            parsed = _parse_json_from_text(raw)
            if isinstance(parsed, dict) and parsed.get("verdict"):
                return parsed
            messages.append({"role": "assistant", "content": raw})
            return await _force_final_check(messages)

        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            args_s = fn.get("arguments") or "{}"
            if not tc.get("id"):
                tc["id"] = "checker_" + _stable_hash(f"{name}:{args_s}")[:16]
            tc.setdefault("type", "function")

        messages.append(
            {
                "role": "assistant",
                "content": message.get("content") or "",
                "tool_calls": tool_calls,
            }
        )

        async def dispatch(tc: dict[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
            fn = tc.get("function") or {}
            name = fn.get("name")
            raw_args = fn.get("arguments") or "{}"
            arguments = _json_object(raw_args)
            repeat_key = (
                f"{name}:{json.dumps(arguments, sort_keys=True, ensure_ascii=False)}"
            )
            seen_tool_calls[repeat_key] = seen_tool_calls.get(repeat_key, 0) + 1
            if seen_tool_calls[repeat_key] > 2:
                result = {
                    "tool": name,
                    "is_error": True,
                    "text": "Repeated identical tool call; use existing result.",
                }
            elif toolbox is None:
                result = {
                    "tool": name,
                    "is_error": True,
                    "text": "MCP tools are unavailable in this checker run.",
                }
            else:
                result = await _execute_tool(name, arguments, toolbox, project_root)
            return tc["id"], name, result

        for tc_id, name, tool_result in await asyncio.gather(
            *[dispatch(tc) for tc in tool_calls]
        ):
            text = json.dumps(tool_result, ensure_ascii=False)
            if len(text) > TOOL_RESULT_CHAR_LIMIT:
                tool_result["text"] = text[:TOOL_RESULT_CHAR_LIMIT]
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "name": name,
                    "content": json.dumps(
                        tool_result, ensure_ascii=False
                    )[:TOOL_RESULT_CHAR_LIMIT],
                }
            )

    return await _force_final_check(messages)


async def _force_final_check(messages: list[dict[str, Any]]) -> dict[str, Any]:
    forced = list(messages) + [
        {
            "role": "user",
            "content": (
                "工具预算已用完或上一轮不是合法 JSON。不要再请求工具。"
                "严格按照 checker.md 的 JSON Schema 返回一个 JSON 对象；"
                "证据不足时使用 verdict=\"need_context\"。"
            ),
        }
    ]
    response = await asyncio.to_thread(
        functools.partial(
            chat_completion,
            forced,
            response_format={"type": "json_object"},
            temperature=SPEC.temperature,
            max_tokens=SPEC.max_tokens,
        )
    )
    message = response_message_to_dict(response)
    raw = message.get("content") or ""
    parsed = _parse_json_from_text(raw)
    if isinstance(parsed, dict) and parsed.get("verdict"):
        return parsed
    raise ValueError("Checker returned invalid JSON.")


def _normalize_checker_result(
    raw: Any,
    finding: dict[str, Any],
    chain: dict[str, Any],
) -> dict[str, Any]:
    obj = _json_object(raw)
    if not obj:
        raise ValueError("Checker result is empty or not a JSON object.")

    fid = _finding_id(finding)
    verdict = str(obj.get("verdict") or "need_context").strip().lower()
    if verdict not in CHECKER_VERDICTS:
        verdict = "need_context"
    confidence = _confidence_value(obj.get("confidence"), 0.5)
    concrete_payload = _string_value(obj.get("concrete_payload")).strip() or None
    reasoning = _string_value(obj.get("verdict_reasoning")).strip()

    model_finding_id = str(obj.get("finding_id") or "").strip()
    if model_finding_id and model_finding_id != fid:
        reasoning = (
            f"{reasoning}\n模型返回的 finding_id={model_finding_id} 与输入 "
            f"{fid} 不一致，已按输入值归档。"
        ).strip()

    if verdict == "confirmed" and not concrete_payload:
        verdict = "refuted"
        confidence = min(confidence, 0.7)
        reasoning = (
            f"{reasoning}\nChecker 返回 confirmed 但未提供 concrete_payload；"
            "按复核规则不能确认漏洞。"
        ).strip()

    severity = _string_value(obj.get("severity_revised")).strip().lower() or None
    if severity not in SEVERITIES:
        severity = None

    return {
        "finding_id": fid,
        "chain_id": fid,
        "verdict": verdict,
        "confidence": confidence,
        "concrete_payload": concrete_payload,
        "trigger_steps": _text_list(obj.get("trigger_steps")),
        "blocking_filters": _blocking_filters(obj.get("blocking_filters")),
        "missing_context": _text_list(obj.get("missing_context")),
        "verdict_reasoning": reasoning,
        "severity_revised": severity,
        "auditor_verdict": finding.get("verdict"),
        "auditor_confidence": finding.get("confidence"),
        "auditor_severity": finding.get("severity"),
        "language": finding.get("language") or chain.get("language"),
        "vulnerability_type": finding.get("vulnerability_type")
        or chain.get("vulnerability_type"),
        "title": finding.get("title"),
        "source": finding.get("source"),
        "sink": finding.get("sink"),
    }


def _blocking_filters(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        line = item.get("line")
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        out.append(
            {
                "file": _string_value(item.get("file")).strip(),
                "line": line,
                "why_effective": _string_value(item.get("why_effective")).strip(),
            }
        )
    return out


def _load_progress(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    out: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line_s = line.strip()
            if not line_s:
                continue
            try:
                row = json.loads(line_s)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            result = row.get("result")
            fid = str(row.get("finding_id") or "").strip()
            if (
                fid
                and isinstance(result, dict)
                and result.get("verdict") in CHECKER_VERDICTS
            ):
                out[fid] = result
    return out


def _append_progress(path: Path, result: dict[str, Any]) -> None:
    fid = str(result.get("finding_id") or "").strip()
    if not fid:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"finding_id": fid, "result": result}
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _append_failure(
    path: Path,
    *,
    finding_id: str,
    error_type: str,
    error: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "finding_id": finding_id,
        "error_type": error_type,
        "error": error[:2000],
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _build_result(
    results: list[dict[str, Any]],
    project_path: str,
    project_root: Path,
    scope: RunScope,
    started_at: float,
    *,
    failed: int,
    total_targets: int,
    partial: bool = False,
) -> dict[str, Any]:
    counter = {"confirmed": 0, "refuted": 0, "need_context": 0}
    by_vuln: dict[str, int] = {}
    for item in results:
        verdict = str(item.get("verdict") or "need_context")
        counter[verdict if verdict in counter else "need_context"] += 1
        vuln = str(item.get("vulnerability_type") or "unknown")
        by_vuln[vuln] = by_vuln.get(vuln, 0) + 1

    if total_targets == 0:
        status = "no_vulnerable_findings"
    elif failed and not results:
        status = "error"
    elif partial or failed:
        status = "partial"
    else:
        status = "ok"

    return {
        "status": status,
        "project_path": project_path,
        "project_root": str(project_root),
        "scope": scope.to_dict(),
        "summary": {
            "total_targets": total_targets,
            "total_checked": len(results),
            "confirmed": counter["confirmed"],
            "refuted": counter["refuted"],
            "need_context": counter["need_context"],
            "failed": failed,
            "by_vulnerability": by_vuln,
            "checkpoint": bool(partial),
        },
        "findings": results,
        "elapsed_seconds": round(time.perf_counter() - started_at, 2),
    }


def _write_outputs(result: dict[str, Any], json_path: Path, md_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    action("Write", str(json_path))
    _write_markdown(result, md_path)
    action("Write", str(md_path))


def _write_markdown(result: dict[str, Any], path: Path) -> None:
    summary = result.get("summary") or {}
    findings = [
        item for item in result.get("findings") or [] if isinstance(item, dict)
    ]
    lines: list[str] = [
        "# DefectMine Checker 复核报告",
        "",
        f"**项目**: `{result.get('project_path')}`  ",
        f"**状态**: `{result.get('status')}`  ",
        (
            "**摘要**: "
            f"目标 {summary.get('total_targets', 0)} 条，"
            f"已复核 {summary.get('total_checked', 0)} 条，"
            f"confirmed {summary.get('confirmed', 0)} 条，"
            f"refuted {summary.get('refuted', 0)} 条，"
            f"need_context {summary.get('need_context', 0)} 条，"
            f"failed {summary.get('failed', 0)} 条。"
        ),
        "",
        "---",
        "",
    ]
    if not findings:
        lines.append("暂无 Checker 复核结果。")
    for idx, item in enumerate(findings, 1):
        lines.extend(
            [
                f"## [{idx}/{len(findings)}] {item.get('verdict')} - {item.get('finding_id')}",
                "",
                f"- 漏洞类型：`{item.get('vulnerability_type') or 'unknown'}`",
                f"- Auditor 结论：`{item.get('auditor_verdict')}`",
                f"- Checker 置信度：`{item.get('confidence')}`",
                f"- 修正严重性：`{item.get('severity_revised') or '-'}`",
                "",
                "### 复核理由",
                "",
                str(item.get("verdict_reasoning") or "").strip() or "-",
                "",
            ]
        )
        payload = item.get("concrete_payload")
        if payload:
            lines.extend(["### 具体 Payload", "", "```", str(payload), "```", ""])
        steps = _text_list(item.get("trigger_steps"))
        if steps:
            lines.extend(["### 触发步骤", ""])
            lines.extend([f"- {step}" for step in steps])
            lines.append("")
        filters = item.get("blocking_filters") or []
        if filters:
            lines.extend(["### 有效拦截点", ""])
            for flt in filters:
                if not isinstance(flt, dict):
                    continue
                lines.append(
                    f"- `{flt.get('file')}:{flt.get('line')}` "
                    f"{flt.get('why_effective')}"
                )
            lines.append("")
        missing = _text_list(item.get("missing_context"))
        if missing:
            lines.extend(["### 缺失上下文", ""])
            lines.extend([f"- {text}" for text in missing])
            lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
