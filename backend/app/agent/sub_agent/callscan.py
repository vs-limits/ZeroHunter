"""CallScan Agent: map dangerous-function sink hits to candidate call chains."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import json
import os
import re
import subprocess
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from app.agent.logger import write_event
from app.agent.mcp import MCPToolbox, PROJECT_ROOT, default_server_specs
from app.agent.prompts import load_prompt
from app.agent.run_scope import RunScope, resolve_run_scope
from app.agent.runner import _flatten_exception_group
from app.llm.client import chat_completion, response_message_to_dict
from app.scanner.rules import RG_EXCLUDE_GLOBS, should_skip_for_scan
from app.scanner.sink import SinkRule, iter_sink_rules, line_is_dynamic, matches_extra
from app.scanner.sink.profiles import enrich_sink_profile
from app.scanner.sink.python.sql_semantics import (
    python_graphql_execute_is_relevant,
    python_sql_execute_is_dynamic,
)
from app.scanner.slicer import (
    CodeSlicer,
    FunctionPool,
    build_all_chains,
    collect_local_helper_refs,
    enrich_chains_static_fast,
    enrich_chains_with_pool,
    format_audit_pack,
)
from app.ui.console import (
    action,
    buffer_collapsed_line,
    flush_collapse_block,
    info,
    print_markup,
    print_status,
    reset_collapse_buffer,
)


TREESCAN_FILENAME = "treescan_agent.json"
CALLSCAN_FILENAME = "callscan_agent.json"
# Per-chain persistence — each line is one self-contained chain (newline as
# strict separator), so downstream agents can read N at a time and feed each
# to the LLM without re-parsing the full callscan_agent.json bundle.
CALLSCAN_CHAINS_JSONL = "callscan_chains.jsonl"
# Subset of chains the Auditor agent should consume first: high-signal only
# (has a real reverse caller chain, OR severity >= high). Keeps LLM cost down
# on no-context noise candidates.
CALLSCAN_CHAINS_PRIORITY_JSONL = "callscan_chains.priority.jsonl"
# Markdown sibling: one fenced section per chain with explicit BEGIN/END
# markers so a reader (LLM or human) can split-and-batch by string match.
CALLSCAN_CHAINS_MD = "callscan_chains.md"
# Per-sink checkpoint for resume after process kill (same pattern as audit_progress.jsonl).
CALLSCAN_PROGRESS_JSONL = "callscan_progress.jsonl"
# Hard delimiters used inside callscan_chains.md.
CHAIN_BEGIN_MARK = "=== CHAIN BEGIN"
CHAIN_END_MARK = "=== CHAIN END"
MAX_CONCURRENT_SINK_CHATS = 3
CALLSCAN_HEARTBEAT_SECS = max(1, int(os.environ.get("CALLSCAN_HEARTBEAT_SECS", "5")))
CALLSCAN_COMPACT_FLUSH_EVERY = max(
    5, int(os.environ.get("CALLSCAN_COMPACT_FLUSH_EVERY", "25"))
)
TOOL_RESULT_CHAR_LIMIT = 8_000
EVIDENCE_TLDR_TEXT_CHAR_LIMIT = 6_000
# Hard cap on multi-turn tool calls per sink. Without this the loop is
# unbounded: a model that keeps emitting tool_calls with slightly different
# parameters blows past the per-tool dedupe and stalls the entire scan.
# Override via CALLSCAN_MAX_TOOL_ROUNDS env var.
CALLSCAN_MAX_TOOL_ROUNDS = int(os.environ.get("CALLSCAN_MAX_TOOL_ROUNDS", "10"))
# Per-tool ceiling: even if arguments differ each time, stop calling the same
# tool after this many invocations within one sink conversation.
CALLSCAN_PER_TOOL_CALL_LIMIT = int(
    os.environ.get("CALLSCAN_PER_TOOL_CALL_LIMIT", "6")
)
CALLSCAN_IMPACT_DEPTH = int(os.environ.get("CALLSCAN_IMPACT_DEPTH", "6"))
# 全局默认：环境变量 CALLSCAN_USE_LLM=0 可关闭；单次扫描以 scan.json options 为准。
_callscan_use_llm_override: ContextVar[bool | None] = ContextVar(
    "callscan_use_llm_override", default=None
)
_callscan_concurrency_override: ContextVar[int | None] = ContextVar(
    "callscan_concurrency_override", default=None
)


def _env_callscan_use_llm_default() -> bool:
    return os.getenv("CALLSCAN_USE_LLM", "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def callscan_use_llm_enabled() -> bool:
    override = _callscan_use_llm_override.get()
    if override is not None:
        return override
    return _env_callscan_use_llm_default()


def set_callscan_use_llm(enabled: bool) -> object:
    return _callscan_use_llm_override.set(bool(enabled))


def reset_callscan_use_llm(token: object) -> None:
    _callscan_use_llm_override.reset(token)


def _env_callscan_concurrency_default() -> int:
    return max(1, min(16, int(os.getenv("CALLSCAN_CONCURRENCY", "3"))))


def callscan_concurrency() -> int:
    override = _callscan_concurrency_override.get()
    if override is not None:
        return max(1, min(16, int(override)))
    return _env_callscan_concurrency_default()


def set_callscan_concurrency(value: int) -> object:
    return _callscan_concurrency_override.set(max(1, min(16, int(value))))


def reset_callscan_concurrency(token: object) -> None:
    _callscan_concurrency_override.reset(token)
# Compact log mode: only the first/last few per-hit lines are printed in full;
# the middle is summarised. Set CALLSCAN_VERBOSE=1 to keep the legacy stream.
CALLSCAN_VERBOSE = os.getenv("CALLSCAN_VERBOSE", "").lower() in {"1", "true", "yes", "on"}
COMPACT_HEAD_TAIL = 25  # how many leading/trailing per-hit lines to keep
MODULE_INCLUDER_TIMEOUT = float(os.getenv("CALLSCAN_MODULE_RG_TIMEOUT", "60"))
MODULE_INCLUDER_MAX_CALLERS = max(
    1, int(os.getenv("CALLSCAN_MODULE_INCLUDER_MAX", "12"))
)
STATIC_MODULE_RG_TIMEOUT = float(os.getenv("CALLSCAN_STATIC_MODULE_RG_TIMEOUT", "10"))
STATIC_MODULE_MAX_CALLERS = max(
    1, int(os.getenv("CALLSCAN_STATIC_MODULE_INCLUDER_MAX", "6"))
)
STATIC_CHAIN_MAX = max(1, int(os.getenv("CALLSCAN_STATIC_CHAINS_PER_SINK", "6")))
STATIC_BRANCH_LIMIT = max(1, int(os.getenv("CALLSCAN_STATIC_BRANCH_LIMIT", "6")))
LLM_TOOL_NAMES = {
    "tldr__tldr_extract",
    "tldr__tldr_impact",
    "tldr__tldr_search",
    "ripgrep__search",
    "ripgrep__advanced-search",
    "ripgrep__count-matches",
}


@dataclass(frozen=True)
class AgentSpec:
    name: str
    system_message: str
    temperature: float = 0.1
    max_tokens: int = 3000


@dataclass(frozen=True)
class SinkHit:
    language: str
    vulnerability_type: str
    rule: SinkRule
    file: str
    absolute_file: str
    line: int
    column: int | None
    code: str
    matched_text: str | None


SPEC = AgentSpec(
    name="CallScan Agent",
    system_message=load_prompt("callscan.md"),
    temperature=0.1,
    max_tokens=3000,
)


TECHNOLOGY_LANGUAGE_ALIASES = {
    # PHP
    "php": "php",
    # Python
    "python": "python",
    "python3": "python",
    "django": "python",
    "flask": "python",
    "fastapi": "python",
    # JavaScript / Node
    "javascript": "javascript",
    "js": "javascript",
    "node.js": "javascript",
    "nodejs": "javascript",
    "node": "javascript",
    "express": "javascript",
    "next.js": "javascript",
    "nextjs": "javascript",
    "vue": "javascript",
    "react": "javascript",
    # TypeScript
    "typescript": "typescript",
    "ts": "typescript",
    "angular": "typescript",
    "nestjs": "typescript",
    "deno": "typescript",
    "bun": "typescript",
    # Java / JVM
    "java": "java",
    "kotlin": "java",
    "scala": "java",
    "groovy": "java",
    "spring": "java",
    "spring boot": "java",
    "springboot": "java",
    # Go
    "go": "go",
    "golang": "go",
    # Rust
    "rust": "rust",
    # C
    "c": "c",
    # C++
    "cpp": "cpp",
    "c++": "cpp",
    "cxx": "cpp",
    # HTML / templates
    "html": "html",
    "html5": "html",
    "jinja": "html",
    "jinja2": "html",
    "twig": "html",
    "blade": "html",
    "thymeleaf": "html",
}


def run(project_path: str, run_id: str | None = None) -> dict:
    return asyncio.run(_run_async(project_path, run_id=run_id))


async def _run_async(project_path: str, run_id: str | None = None) -> dict:
    llm_token: object | None = None
    conc_token: object | None = None
    if run_id:
        try:
            from app.server import scans as scans_mod

            meta = scans_mod.get_scan(project_path, run_id)
            opts = meta.get("options") or {}
            llm_token = set_callscan_use_llm(bool(opts.get("callscan_use_llm", True)))
            if "callscan_concurrency" in opts:
                conc_token = set_callscan_concurrency(int(opts["callscan_concurrency"]))
        except FileNotFoundError:
            pass
    info(
        f"CallScan LLM: {'on' if callscan_use_llm_enabled() else 'off (static path only)'}"
    )
    info(f"CallScan concurrency: {callscan_concurrency()} sink(s) in parallel")
    try:
        return await _run_async_body(project_path, run_id=run_id)
    finally:
        if llm_token is not None:
            reset_callscan_use_llm(llm_token)
        if conc_token is not None:
            reset_callscan_concurrency(conc_token)


async def _run_async_body(project_path: str, run_id: str | None = None) -> dict:
    started_at = time.perf_counter()
    scope = resolve_run_scope(project_path, run_id)
    project_root = scope.project_root
    artifacts_dir = scope.artifacts_dir
    profile_path = scope.artifacts_dir / TREESCAN_FILENAME
    if not profile_path.is_file():
        # 兼容旧扫描：treescan 产物可能仍在仓库根 .defectmine/
        profile_path = scope.root_artifacts_dir / TREESCAN_FILENAME
    output_path = scope.artifacts_dir / CALLSCAN_FILENAME
    if scope.mode == "specific":
        info(
            f"Specific CallScan scope: run_id={scope.run_id} "
            f"target={scope.target_rel_dir}"
        )

    if not profile_path.is_file():
        raise FileNotFoundError(
            f"TreeScan profile not found: {profile_path}. Run TreeScan before CallScan."
        )

    action("Read TreeScan profile", str(profile_path))
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    raw_stack = profile.get("technology_stack") or {}
    raw_values = sorted(
        {
            str(value).strip()
            for items in raw_stack.values()
            for value in (items if isinstance(items, list) else [items] if items else [])
            if value
        }
    )
    languages = _languages_from_profile(profile)
    if raw_values:
        info(f"TreeScan tech stack: {', '.join(raw_values)}")
    info(
        f"Detected supported languages for CallScan: "
        f"{', '.join(languages) or 'none'}"
    )
    _print_rule_overview(languages)

    rule_total = sum(
        1 for lang in languages for _v, _r in iter_sink_rules(lang)
    )
    info(
        f"Rg prefilter: scanning {rule_total} rule(s) on repository "
        f"(excludes vendor/node_modules/tests; may take several minutes) …"
    )

    hits, skipped, filter_stats = _collect_sink_hits(project_root, languages, scope)
    hits, dedup_dropped = _dedupe_hits_by_location(hits)
    filter_stats["dedup_dropped"] = dedup_dropped
    info(
        f"Local rg prefilter: {filter_stats['rg_raw']} raw hit(s) -> "
        f"{len(hits)} kept (filtered "
        f"path={filter_stats['filtered_by_path']}, "
        f"scope={filter_stats['filtered_by_scope']}, "
        f"comment={filter_stats['filtered_by_comment']}, "
        f"dynamic={filter_stats['filtered_by_dynamic']}, "
        f"extra={filter_stats['filtered_by_extra']}, "
        f"dedup={filter_stats['dedup_dropped']})"
    )

    progress_path = artifacts_dir / CALLSCAN_PROGRESS_JSONL
    resumed_by_id = _load_callscan_progress(progress_path)
    if not resumed_by_id and output_path.is_file():
        resumed_by_id = _candidates_from_partial_agent(output_path)
        if resumed_by_id:
            _rewrite_callscan_progress(progress_path, resumed_by_id)
            info(
                f"CallScan resume: recovered {len(resumed_by_id)} sink(s) "
                f"from partial {output_path.name}"
            )
    if resumed_by_id:
        info(
            f"CallScan resume: {len(resumed_by_id)} sink(s) already analyzed "
            f"(checkpoint: {progress_path.name})"
        )
    total_hits = len(hits)
    pending_hits = [h for h in hits if _chain_id(h) not in resumed_by_id]
    skipped_resume = total_hits - len(pending_hits)
    if skipped_resume:
        info(f"CallScan resume: skipping {skipped_resume} sink(s) from checkpoint")

    candidate_chains: list[dict[str, Any]] = list(resumed_by_id.values())
    jsonl_path = artifacts_dir / CALLSCAN_CHAINS_JSONL
    md_path = artifacts_dir / CALLSCAN_CHAINS_MD
    priority_path = artifacts_dir / CALLSCAN_CHAINS_PRIORITY_JSONL
    function_pool: FunctionPool | None = None
    candidates_lock = asyncio.Lock()

    if pending_hits:
        # 在分析前按严重度排序，使日志和后续 Auditor 都先看到 critical/high。
        pending_hits.sort(key=_hit_priority, reverse=True)
        concurrency = callscan_concurrency()
        async with MCPToolbox(
            default_server_specs(project_root), pool_size=concurrency
        ) as toolbox:
            visible_tools = len(set(toolbox.tool_names) & LLM_TOOL_NAMES)
            info(
                f"MCP tools loaded: {len(toolbox.tool_names)} "
                f"(LLM-visible: {visible_tools}; pool={toolbox.pool_size}; "
                f"ripgrep calls use local rg.exe -u)"
            )
            slicer = CodeSlicer(toolbox, project_root)
            function_pool = FunctionPool(slicer)
            semaphore = asyncio.Semaphore(concurrency)
            total = len(pending_hits) + len(resumed_by_id)
            counter = {
                "done": len(resumed_by_id),
                "llm_skipped": 0,
                "llm_reused": 0,
                "module_fallback": 0,
                "collapsed_since_flush": 0,
            }
            counter_lock = asyncio.Lock()
            reset_collapse_buffer()
            write_event(
                "callscan_batch_start",
                pending=len(pending_hits),
                total=total,
                concurrency=concurrency,
                llm_enabled=callscan_use_llm_enabled(),
            )
            # Cache expensive per-symbol work across sink hits in the same run.
            llm_cache: dict[str, asyncio.Future[dict[str, Any] | None]] = {}
            impact_cache: dict[str, asyncio.Future[dict[str, Any] | None]] = {}
            module_callers_cache: dict[str, asyncio.Future[dict[str, Any] | None]] = {}
            tasks = [
                asyncio.create_task(
                    _analyze_hit(
                        project_root,
                        hit,
                        toolbox,
                        slicer,
                        function_pool,
                        semaphore,
                        total,
                        counter,
                        counter_lock,
                        llm_cache,
                        impact_cache,
                        module_callers_cache,
                        progress_path=progress_path,
                        candidates_lock=candidates_lock,
                        candidate_chains=candidate_chains,
                    )
                )
                for hit in pending_hits
            ]

            print_status(
                "callscan",
                active=True,
                label=f"callscan 进度 0/{total}",
                detail=f"已运行 0s · 并发 {concurrency}",
            )

            async def _heartbeat() -> None:
                while True:
                    await asyncio.sleep(CALLSCAN_HEARTBEAT_SECS)
                    async with counter_lock:
                        done = counter["done"]
                    elapsed = time.perf_counter() - started_at
                    print_status(
                        "callscan",
                        active=True,
                        label=f"callscan 进度 {done}/{total}",
                        detail=f"已运行 {elapsed:.0f}s · 并发 {concurrency}",
                    )
                    write_event(
                        "callscan_heartbeat",
                        done=done,
                        total=total,
                        elapsed=elapsed,
                        concurrency=concurrency,
                    )

            hb = asyncio.create_task(_heartbeat())
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                first_exc: BaseException | None = None
                for hit, outcome in zip(pending_hits, results):
                    if isinstance(outcome, BaseException):
                        sub_excs = _flatten_exception_group(outcome)
                        write_event(
                            "callscan_sink_error",
                            chain_id=_chain_id(hit),
                            file=hit.file,
                            line=hit.line,
                            function=hit.rule.function,
                            error_type=type(outcome).__name__,
                            error=str(outcome),
                            sub_exceptions=sub_excs,
                        )
                        info(
                            f"sink failed {hit.file}:{hit.line} "
                            f"({type(outcome).__name__}: {outcome}) — "
                            f"sub: {sub_excs[:3]}"
                        )
                        if first_exc is None:
                            first_exc = outcome
                if first_exc is not None:
                    raise first_exc
            finally:
                hb.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await hb
                print_status("callscan", active=False)
                flush_collapse_block("条 sink hit")
            write_event(
                "callscan_batch_end",
                done=counter["done"],
                total=total,
                elapsed=time.perf_counter() - started_at,
            )
            info(
                f"LLM skipped: {counter['llm_skipped']} sink(s); "
                f"reused: {counter['llm_reused']} sink(s); "
                f"module-level fallback chains: {counter['module_fallback']}"
            )
            info(
                f"Function pool: {len(function_pool)} unique function/module slice(s) "
                f"(shared across {len(candidate_chains)} candidate(s))"
            )
    elif resumed_by_id:
        info("CallScan: all sinks already in checkpoint — finalizing artifacts.")

    summary = _build_summary(
        candidate_chains, skipped, filter_stats, total_hits, started_at
    )

    result = {
        "status": _status(candidate_chains, skipped),
        "project_path": project_path,
        "project_root": str(project_root),
        "scope": scope.to_dict(),
        "languages": languages,
        "summary": summary,
        "function_pool": function_pool.to_dict() if function_pool else {},
        "candidate_chains": candidate_chains,
        "skipped": skipped,
    }

    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    action("Write", str(output_path))

    # Per-chain streaming outputs for downstream Auditor / LLM batching.
    written, compat_written = _write_chain_streams(
        candidate_chains, jsonl_path, md_path, priority_path, project_path, scope
    )
    action("Write", f"{jsonl_path} ({written} chain(s))")
    action("Write", f"{md_path} ({written} chain(s))")
    action("Write", f"{priority_path} ({compat_written} compat chain(s))")

    return result


def _languages_from_profile(profile: dict[str, Any]) -> list[str]:
    """Map TreeScan's `technology_stack` dict to CallScan language codes.

    Scans every value in the stack (backend, runtime, frontend, template_engine,
    database, ...) so detected technologies like Twig or a TypeScript frontend
    pull in their corresponding sink rule packs alongside the backend language.
    """
    stack = profile.get("technology_stack") or {}
    values: list[str] = []
    for item in stack.values():
        if isinstance(item, list):
            values.extend(str(value) for value in item)
        elif item:
            values.append(str(item))

    languages: list[str] = []
    for value in values:
        normalized = value.strip().lower()
        language = TECHNOLOGY_LANGUAGE_ALIASES.get(normalized)
        if language and language not in languages:
            languages.append(language)
    return languages


def _collect_sink_hits(
    project_root: Path,
    languages: list[str],
    scope: RunScope,
) -> tuple[list[SinkHit], list[dict[str, Any]], dict[str, int]]:
    """对每条规则跑 ripgrep + 过滤，返回 (hits, skipped_rules, filter_stats)。

    filter_stats 用于 callscan 的 summary，记录被路径过滤、动态信号过滤、
    extra 正则过滤、php 注释过滤分别淘汰了多少条原始 rg 命中。
    """
    hits: list[SinkHit] = []
    skipped_rules: list[dict[str, Any]] = []
    filter_stats: dict[str, int] = {
        "rg_raw": 0,
        "filtered_by_path": 0,
        "filtered_by_scope": 0,
        "filtered_by_comment": 0,
        "filtered_by_dynamic": 0,
        "filtered_by_extra": 0,
        "kept": 0,
    }

    rule_total = sum(1 for lang in languages for _v, _r in iter_sink_rules(lang))
    done_rules = 0
    t0 = time.perf_counter()

    for language in languages:
        lang_rules = list(iter_sink_rules(language))
        if not lang_rules:
            continue
        info(f"  rg [{language}] starting ({len(lang_rules)} rules) …")
        for vulnerability_type, rule in lang_rules:
            rule_hits = _run_rg(
                project_root,
                language,
                vulnerability_type,
                rule,
                filter_stats,
                scope,
            )
            done_rules += 1
            if done_rules == 1 or done_rules % 20 == 0 or done_rules == rule_total:
                elapsed = time.perf_counter() - t0
                info(
                    f"  rg prefilter progress: {done_rules}/{rule_total} rules "
                    f"({elapsed:.0f}s, raw_hits={filter_stats['rg_raw']})"
                )
            if not rule_hits:
                skipped_rules.append(
                    {
                        "language": language,
                        "vulnerability_type": vulnerability_type,
                        "sink_rule": rule.to_dict(),
                        "reason": "no_rg_match",
                    }
                )
                continue
            hits.extend(rule_hits)

    return hits, skipped_rules, filter_stats


def _run_rg(
    project_root: Path,
    language: str,
    vulnerability_type: str,
    rule: SinkRule,
    filter_stats: dict[str, int],
    scope: RunScope,
) -> list[SinkHit]:
    rg_exe = PROJECT_ROOT / "ripgrep" / "rg.exe"
    if not rg_exe.is_file():
        raise FileNotFoundError(f"rg.exe not found: {rg_exe}")

    command = [
        str(rg_exe),
        "-u",
        "--json",
        "-n",
        "-e",
        rule.call_regex,
    ]
    for extension in rule.extensions:
        command.extend(["--glob", f"*{extension}"])
    for exclude in RG_EXCLUDE_GLOBS:
        command.extend(["--glob", exclude])
    command.append(str(project_root))

    completed = subprocess.run(
        command,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(
            f"rg failed for {rule.id}: {completed.stderr.strip() or completed.stdout.strip()}"
        )

    hits: list[SinkHit] = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue

        data = event.get("data") or {}
        raw_path = (data.get("path") or {}).get("text")
        if not raw_path:
            continue
        absolute_path = Path(raw_path)
        if not absolute_path.is_absolute():
            absolute_path = project_root / absolute_path
        try:
            rel_file = absolute_path.resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            rel_file = absolute_path.as_posix()

        filter_stats["rg_raw"] += 1

        # 1) 路径过滤：vendor / tests / 第三方静态资源等。
        skip_path, _ = should_skip_for_scan(rel_file)
        if skip_path:
            filter_stats["filtered_by_path"] += 1
            continue

        if not scope.contains_rel_path(rel_file):
            filter_stats["filtered_by_scope"] += 1
            continue

        submatches = data.get("submatches") or []
        first_match = submatches[0] if submatches else {}
        column = first_match.get("start")
        matched_text = (first_match.get("match") or {}).get("text")
        code = ((data.get("lines") or {}).get("text") or "").rstrip("\r\n")
        column_int = int(column) if isinstance(column, int) else None

        # 2) PHP 注释/字符串过滤。
        if not _is_code_match(language, absolute_path, int(data.get("line_number") or 0), column_int):
            filter_stats["filtered_by_comment"] += 1
            continue

        semantic_dynamic = _semantic_dynamic_override(
            language=language,
            vulnerability_type=vulnerability_type,
            rule=rule,
            absolute_path=absolute_path,
            line_number=int(data.get("line_number") or 0),
        )
        if semantic_dynamic is not None:
            if not semantic_dynamic:
                filter_stats["filtered_by_dynamic"] += 1
                continue
        else:
            # 3) require_dynamic：sink 行必须出现变量/拼接信号。
            if rule.require_dynamic and not line_is_dynamic(code):
                filter_stats["filtered_by_dynamic"] += 1
                continue

            # 4) extra_match_regex：例如 SQL execute 必须出现字符串拼接。
            if not matches_extra(rule, code):
                filter_stats["filtered_by_extra"] += 1
                continue

        filter_stats["kept"] += 1
        hits.append(
            SinkHit(
                language=language,
                vulnerability_type=vulnerability_type,
                rule=rule,
                file=rel_file,
                absolute_file=str(absolute_path),
                line=int(data.get("line_number") or 0),
                column=column_int,
                code=code,
                matched_text=matched_text,
            )
        )

    return hits


def _semantic_dynamic_override(
    *,
    language: str,
    vulnerability_type: str,
    rule: SinkRule,
    absolute_path: Path,
    line_number: int,
) -> bool | None:
    """Rule-specific semantic dynamic checks.

    Current override:
    - Python DB-API SQL execution should inspect the first execute argument,
      not just the matched sink line. This catches:
          sql = f"...{user}..."
          conn.execute(sql)
      and filters out parameterized constant templates that merely contain
      arithmetic like `views = views + 1`.
    """

    if (
        language == "python"
        and vulnerability_type == "sql_injection"
        and rule.id
        in {
            "py-sql-cursor-execute",
            "py-sql-sqlalchemy-raw-execute",
            "py-sql-asyncpg-execute",
        }
    ):
        return python_sql_execute_is_dynamic(absolute_path, line_number)
    if (
        language == "python"
        and vulnerability_type == "graphql_injection"
        and rule.id
        in {
            "py-graphql-graphene-execute",
            "py-graphql-gql-client",
            "py-graphql-strawberry-execute",
        }
    ):
        return python_graphql_execute_is_relevant(absolute_path, line_number)
    return None


def _is_code_match(language: str, file_path: Path, line_number: int, column: int | None) -> bool:
    if language != "php" or line_number <= 0:
        return True
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return True
    if line_number > len(lines):
        return True
    line = lines[line_number - 1]
    char_column = _byte_offset_to_char_index(line, column or 0)
    return _php_offset_is_code(lines, line_number - 1, char_column)


def _byte_offset_to_char_index(text: str, byte_offset: int) -> int:
    if byte_offset <= 0:
        return 0
    return len(text.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore"))


def _php_offset_is_code(lines: list[str], target_line: int, target_column: int) -> bool:
    in_block_comment = False
    quote: str | None = None
    escaped = False

    for line_index, line in enumerate(lines[: target_line + 1]):
        i = 0
        limit = target_column if line_index == target_line else len(line)
        while i <= len(line):
            if line_index == target_line and i >= limit:
                return not in_block_comment and quote is None
            if i >= len(line):
                break

            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if quote is not None:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                i += 1
                continue

            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "/":
                if line_index == target_line:
                    return False
                break
            if ch == "#":
                if line_index == target_line:
                    return False
                break
            if ch in {"'", '"', "`"}:
                quote = ch
            i += 1

    return not in_block_comment and quote is None


async def _analyze_hit(
    project_root: Path,
    hit: SinkHit,
    toolbox: MCPToolbox,
    slicer: CodeSlicer,
    pool: FunctionPool,
    semaphore: asyncio.Semaphore,
    total: int,
    counter: dict[str, int],
    counter_lock: asyncio.Lock,
    llm_cache: dict[str, "asyncio.Future[dict[str, Any] | None]"],
    impact_cache: dict[str, "asyncio.Future[dict[str, Any] | None]"],
    module_callers_cache: dict[str, "asyncio.Future[dict[str, Any] | None]"],
    *,
    progress_path: Path,
    candidates_lock: asyncio.Lock,
    candidate_chains: list[dict[str, Any]],
) -> dict[str, Any]:
    async with semaphore:
        chain_id = _chain_id(hit)
        started_at = time.perf_counter()
        stages: dict[str, float] = {}
        write_event(
            "callscan_sink_start",
            chain_id=chain_id,
            file=hit.file,
            line=hit.line,
            function=hit.rule.function,
            severity=hit.rule.severity,
            language=hit.language,
        )
        info(
            f"分析 sink {hit.file}:{hit.line} "
            f"({hit.rule.function}) …"
        )

        t0 = time.perf_counter()
        symbol, extract_json = await _resolve_sink_symbol(
            project_root, hit, slicer
        )
        stages["resolve_symbol"] = time.perf_counter() - t0
        extract_payload = {
            "tool": "tldr__tldr_extract",
            "is_error": extract_json is None and symbol.get("function") != "<module>",
            "json": extract_json,
        }
        if extract_json is not None:
            slicer.seed_extract(hit.file, extract_json)

        impact_payload: dict[str, Any] | None = None
        calls_payload: dict[str, Any] | None = None
        module_callers_payload: dict[str, Any] | None = None
        if symbol["function"] != "<module>":
            impact_key = (
                f"{hit.language}:{hit.file}:{symbol['function']}:{CALLSCAN_IMPACT_DEPTH}"
            )
            t0 = time.perf_counter()
            impact_payload = await _get_cached_payload(
                impact_cache,
                impact_key,
                lambda: toolbox.call_tool(
                    "tldr__tldr_impact",
                    {
                        "path": str(project_root),
                        "function": symbol["function"],
                        "language": hit.language,
                        "file": hit.file,
                        "depth": CALLSCAN_IMPACT_DEPTH,
                    },
                ),
            )
            stages["tldr_impact"] = time.perf_counter() - t0
        else:
            # 模块级 sink（典型：setup/install.php / handlers/*.php）反向链
            # 不能走 tldr_impact（它只索引函数）。这里用 ripgrep 在仓库里找
            # 谁 include / require 了这个文件，把"被入口文件 include"作为反向
            # 链兜底，给下游 Auditor 一个可解释的入口。
            t0 = time.perf_counter()
            module_callers_payload = await _get_cached_payload(
                module_callers_cache,
                hit.file,
                lambda: _find_module_includers(project_root, hit.file),
            )
            stages["module_includers"] = time.perf_counter() - t0
            if module_callers_payload and module_callers_payload.get("callers"):
                async with counter_lock:
                    counter["module_fallback"] += 1

        evidence = _base_evidence(
            project_root,
            hit,
            symbol,
            extract_payload,
            impact_payload,
            calls_payload,
            module_callers_payload,
        )
        llm_status = _classify_llm_need(evidence)

        llm_candidate: dict[str, Any] | None = None
        if llm_status == "skip":
            async with counter_lock:
                counter["llm_skipped"] += 1
        else:
            cache_key = f"{symbol.get('file')}::{symbol.get('function')}"
            future = llm_cache.get(cache_key)
            if future is None:
                future = asyncio.get_running_loop().create_future()
                llm_cache[cache_key] = future
                try:
                    result = await _run_sink_conversation(toolbox, evidence)
                except Exception as exc:  # noqa: BLE001
                    future.set_exception(exc)
                    raise
                else:
                    future.set_result(result)
                    llm_candidate = result
            else:
                async with counter_lock:
                    counter["llm_reused"] += 1
                llm_candidate = await future

        candidate = _merge_candidate(chain_id, hit, symbol, evidence, llm_candidate)

        # 1) 全枚举所有从 sink 到 entry 的链（广度+深度）
        chain_kw: dict[str, Any] = {}
        if not callscan_use_llm_enabled():
            chain_kw = {
                "max_chains": STATIC_CHAIN_MAX,
                "branch_limit": STATIC_BRANCH_LIMIT,
            }
        all_chains = build_all_chains(
            evidence.get("tldr_impact"),
            evidence.get("module_callers"),
            evidence,
            **chain_kw,
        )
        if not all_chains and candidate.get("call_chains"):
            all_chains = candidate["call_chains"]

        # 2) 把每个节点替换为对全局 FunctionPool 的引用，源码不重复落盘
        static_mode = not callscan_use_llm_enabled()
        t0 = time.perf_counter()
        try:
            if static_mode:
                enriched = await enrich_chains_static_fast(all_chains, pool)
            else:
                enriched = await enrich_chains_with_pool(all_chains, slicer, pool)
        except Exception as exc:  # noqa: BLE001
            info(f"slicer enrichment failed for {hit.file}:{hit.line}: {exc}")
            enriched = all_chains
        stages["enrich_chains"] = time.perf_counter() - t0
        candidate["call_chains"] = enriched
        candidate["call_chain_count"] = len(enriched)
        candidate["helper_function_refs"] = []
        if not static_mode and hit.vulnerability_type == "xss" and enriched:
            try:
                candidate["helper_function_refs"] = await collect_local_helper_refs(
                    enriched,
                    slicer,
                    pool,
                )
            except Exception as exc:  # noqa: BLE001
                info(
                    f"helper discovery failed for {hit.file}:{hit.line}: {exc}"
                )
        # 3) 渲染候选级 audit_pack（静态模式只保留链路径 + sink 行，省略大段函数体）
        fn_line = int(symbol.get("line") or hit.line)
        fn_end = int(symbol.get("line_end") or hit.line)
        win_start = max(1, fn_line - 20)
        win_end = fn_end + 20
        sink_function_window = slicer.slice_lines(hit.file, win_start, win_end)
        candidate["audit_pack"] = format_audit_pack(
            candidate,
            pool,
            max_chains_to_render=STATIC_CHAIN_MAX if static_mode else None,
            include_bodies=not static_mode,
            extract_json=extract_json if isinstance(extract_json, dict) else None,
            enclosing_symbol=symbol,
            sink_function_window=sink_function_window,
        )

        elapsed = time.perf_counter() - started_at
        async with counter_lock:
            counter["done"] += 1
            index = counter["done"]
        write_event(
            "callscan_sink_end",
            chain_id=chain_id,
            file=hit.file,
            line=hit.line,
            function=hit.rule.function,
            elapsed=elapsed,
            chain_count=len(enriched),
            from_llm=llm_status != "skip",
            stages=stages,
        )
        _print_chain_result(
            index=index,
            total=total,
            file=hit.file,
            line=hit.line,
            function_name=hit.rule.function,
            severity=hit.rule.severity,
            chains=candidate.get("call_chains") or [],
            limits=candidate.get("limits") or [],
            elapsed=elapsed,
            from_llm=llm_status != "skip",
            counter=counter,
        )
        async with candidates_lock:
            candidate_chains.append(candidate)
            _append_callscan_progress(progress_path, candidate)
        return candidate


async def _get_cached_payload(
    cache: dict[str, "asyncio.Future[dict[str, Any] | None]"],
    key: str,
    factory: Callable[[], Awaitable[dict[str, Any] | None]],
) -> dict[str, Any] | None:
    future = cache.get(key)
    if future is None:
        future = asyncio.get_running_loop().create_future()
        cache[key] = future
        try:
            result = await factory()
        except Exception as exc:  # noqa: BLE001
            future.set_exception(exc)
            raise
        future.set_result(result)
        return result
    return await future


def _print_chain_result(
    *,
    index: int,
    total: int,
    file: str,
    line: int,
    function_name: str,
    severity: str,
    chains: list[Any],
    limits: list[Any],
    elapsed: float,
    from_llm: bool,
    counter: dict[str, int] | None = None,
) -> None:
    """Render one sink result with its candidate call chains.

    Compact mode (default): one short line per hit, no chain detail; head
    and tail only with a single summary dot in between, so terminal scroll
    buffer survives runs with thousands of hits.

    Verbose mode (CALLSCAN_VERBOSE=1): legacy multi-line style with chains.
    """
    chain_list = [list(nodes) for nodes in chains or []]
    has_chain = any(chain_list)

    marker = "[bold green]OK[/]" if has_chain else "[bold yellow]?[/]"
    src_tag = "[dim](static)[/]" if not from_llm else "[dim](llm)[/]"
    sev_tag = _severity_tag(severity)
    progress = f"[dim]\\[{index}/{total}][/]"
    location = f"[dim]@[/] {file}:{line}"
    head_line = (
        f"  {marker} {progress} [bold]{function_name}[/] {sev_tag} {location} "
        f"[dim]({elapsed:.2f}s)[/] {src_tag}"
    )

    chain_count = len(chain_list)
    tail = f" [dim]({chain_count} chain)[/]" if chain_count else ""
    compact_line = head_line + tail

    if not CALLSCAN_VERBOSE:
        # Compact mode: head/tail printed; middle flushed in batches for UI expand.
        if index <= COMPACT_HEAD_TAIL or index > total - COMPACT_HEAD_TAIL:
            print_markup(compact_line)
        else:
            buffer_collapsed_line(compact_line)
            if counter is not None:
                counter["collapsed_since_flush"] = (
                    counter.get("collapsed_since_flush", 0) + 1
                )
                if counter["collapsed_since_flush"] >= CALLSCAN_COMPACT_FLUSH_EVERY:
                    remaining = max(0, total - index)
                    flush_collapse_block(
                        f"中间 {counter['collapsed_since_flush']} 条 sink hit"
                        f"（剩余约 {remaining}）"
                    )
                    counter["collapsed_since_flush"] = 0
            elif index == COMPACT_HEAD_TAIL + 1:
                remaining = max(0, total - 2 * COMPACT_HEAD_TAIL)
                flush_collapse_block(f"{remaining} 条 sink hit")
        return

    print_markup(head_line)

    if not has_chain:
        reason = ""
        for limit in (limits or []):
            text = str(limit).strip()
            if text:
                reason = text
                break
        if not reason:
            reason = "no caller chain detected"
        print_markup(f"    [dim]-> {reason}[/]")
        return

    display_chains = chain_list[:5]
    hidden_count = len(chain_list) - len(display_chains)
    multiple = len(chain_list) > 1
    for idx, nodes in enumerate(display_chains, 1):
        rendered = [_format_chain_node(node) for node in nodes]
        joined = " [dim]->[/] ".join(rendered)
        prefix = f"    [dim]-> chain {idx}:[/]" if multiple else "    [dim]->[/]"
        print_markup(f"{prefix} {joined}")
    if hidden_count > 0:
        print_markup(f"    [dim]... {hidden_count} more chain(s) in artifact[/]")


def _print_rule_overview(languages: list[str]) -> None:
    """Print a one-time summary of how many sink rules each language contributes."""
    if not languages:
        info("No supported languages — CallScan has nothing to scan.")
        return
    grand_total = 0
    grand_vulns: set[str] = set()
    for language in languages:
        per_vuln: dict[str, int] = {}
        for vulnerability_type, _rule in iter_sink_rules(language):
            per_vuln[vulnerability_type] = per_vuln.get(vulnerability_type, 0) + 1
        total = sum(per_vuln.values())
        if total == 0:
            print_markup(f"  [dim]{language}: 0 rules (skipped)[/]")
            continue
        grand_total += total
        grand_vulns.update(per_vuln.keys())
        # Top 4 most-populated vuln categories for the line, full set saved
        # to the artifact via summary['rule_overview'] below.
        top = sorted(per_vuln.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
        top_str = ", ".join(f"{vuln}:{n}" for vuln, n in top)
        more = len(per_vuln) - len(top)
        if more > 0:
            top_str += f", +{more} more"
        print_markup(
            f"  [cyan]{language}[/]: [bold]{total}[/] rule(s) "
            f"across {len(per_vuln)} vuln categories  [dim]({top_str})[/]"
        )
    info(
        f"Loaded {grand_total} sink rule(s) across {len(languages)} language(s) / "
        f"{len(grand_vulns)} vulnerability categor{'y' if len(grand_vulns) == 1 else 'ies'}"
    )


def _dedupe_hits_by_location(
    hits: list[SinkHit],
) -> tuple[list[SinkHit], int]:
    """Collapse multiple rules firing on the same (file, line) into one hit.

    Same line is the same lexical call; reporting it under N rule names is
    just noise. We keep the highest-severity rule per location.
    """
    if not hits:
        return [], 0
    best: dict[tuple[str, int], SinkHit] = {}
    for hit in hits:
        key = (hit.file, hit.line)
        existing = best.get(key)
        if existing is None or _hit_priority(hit) > _hit_priority(existing):
            best[key] = hit
    dedup_dropped = len(hits) - len(best)
    return list(best.values()), dedup_dropped


def _severity_tag(severity: str) -> str:
    color = {
        "critical": "red",
        "high": "yellow",
        "medium": "cyan",
        "low": "dim",
    }.get(severity, "dim")
    short = {
        "critical": "crit",
        "high": "high",
        "medium": "med",
        "low": "low",
    }.get(severity, severity or "?")
    return f"[{color}][{short}][/]"


def _format_chain_node(node: dict[str, Any]) -> str:
    func = node.get("function") or "?"
    file = node.get("file") or "?"
    line = node.get("line")
    role = (node.get("role") or "").lower()
    location = f"{file}:{line}" if line else file
    color = "magenta" if role == "sink" else "cyan"
    return f"[{color}]{func}[/] [dim]({location})[/]"


def _write_chain_streams(
    candidates: list[dict[str, Any]],
    jsonl_path: Path,
    md_path: Path,
    priority_path: Path,
    project_path: str,
    scope: RunScope,
) -> tuple[int, int]:
    """Persist one self-contained record per candidate call chain.

    Produces three sibling files in .defectmine/:

    - ``callscan_chains.jsonl``: one JSON object per line (strict newline
      separator). Downstream Auditor / batch LLM tooling reads N lines at a
      time and feeds each line's ``audit_pack`` directly to the model.
    - ``callscan_chains.md``: same chains in Markdown with hard delimiters
      ``=== CHAIN BEGIN <id> ...===`` / ``=== CHAIN END <id> ===`` so a
      human or LLM can split the file by string match.
    - ``callscan_chains.priority.jsonl``: deprecated compatibility alias that
      carries the same chain records as ``callscan_chains.jsonl``.

    Candidates already carry a self-contained ``audit_pack`` (chain summary +
    deduped function bodies). We re-export the structured fields too so
    JSON-only consumers don't need to parse the markdown.

    Returns ``(total_written, compat_written)``.
    """
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    # Sort highest-severity first; downstream agents that paginate by N then
    # always start with the most-important chains.
    ordered = sorted(
        candidates,
        key=lambda c: (
            _SINK_LEVEL_PRIORITY.get((c.get("sink_rule") or {}).get("level") or "L0", 0),
            _SEVERITY_PRIORITY.get((c.get("sink_rule") or {}).get("severity") or "", 0),
            1 if c.get("call_chains") else 0,
        ),
        reverse=True,
    )

    written = 0
    compat_written = 0
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as jsonl_fp, \
         md_path.open("w", encoding="utf-8", newline="\n") as md_fp, \
         priority_path.open("w", encoding="utf-8", newline="\n") as priority_fp:
        # JSONL header is the project path on the first non-record comment is
        # not part of the JSONL spec, so we instead emit an index-style line
        # marked with type="meta" that batchers can filter out.
        meta_line = json.dumps(
            {
                "type": "meta",
                "project_path": project_path,
                "mode": scope.mode,
                "run_id": scope.run_id,
                "target_rel_dir": scope.target_rel_dir,
                "scope": {
                    "mode": scope.mode,
                    "run_id": scope.run_id,
                    "target_rel_dir": scope.target_rel_dir,
                },
                "total_chains": len(ordered),
                "schema": [
                    "chain_id",
                    "severity",
                    "vulnerability_type",
                    "language",
                    "sink_file",
                    "sink_line",
                    "sink_function",
                    "sink_level",
                    "semantic_tags",
                    "required_evidence",
                    "repair_hints",
                    "has_call_chain",
                    "call_chains",
                    "audit_pack",
                ],
            },
            ensure_ascii=False,
        )
        jsonl_fp.write(meta_line + "\n")
        priority_meta = json.dumps(
            {
                "type": "meta",
                "project_path": project_path,
                "mode": scope.mode,
                "run_id": scope.run_id,
                "target_rel_dir": scope.target_rel_dir,
                "scope": {
                    "mode": scope.mode,
                    "run_id": scope.run_id,
                    "target_rel_dir": scope.target_rel_dir,
                },
                "filter": "none",
                "deprecated_alias_of": CALLSCAN_CHAINS_JSONL,
                "schema": json.loads(meta_line)["schema"],
            },
            ensure_ascii=False,
        )
        priority_fp.write(priority_meta + "\n")

        scope_suffix = ""
        if scope.mode == "specific":
            scope_suffix = (
                f"\nTarget directory: `{scope.target_rel_dir}`"
                f"\nRun ID: `{scope.run_id}`"
            )
        md_fp.write(
            f"# CallScan candidate chains — {project_path}\n\n"
            f"Total chains: {len(ordered)}. "
            f"Each chain section is bounded by `{CHAIN_BEGIN_MARK}` / "
            f"`{CHAIN_END_MARK}` markers for safe batch splitting."
            f"{scope_suffix}\n\n"
        )

        for index, candidate in enumerate(ordered, 1):
            chain_id = str(candidate.get("id") or f"C-{index:06d}")
            sink_rule = candidate.get("sink_rule") or {}
            sink = candidate.get("sink") or {}
            severity = (sink_rule.get("severity") or "unknown").lower()
            vuln = candidate.get("vulnerability_type") or "unknown"
            language = candidate.get("language") or "unknown"
            sink_file = sink.get("file") or ""
            sink_line = sink.get("line") or 0
            sink_function = sink_rule.get("function") or ""
            chains = candidate.get("call_chains") or []
            audit_pack = candidate.get("audit_pack") or ""

            record = {
                "type": "chain",
                "index": index,
                "chain_id": chain_id,
                "severity": severity,
                "vulnerability_type": vuln,
                "language": language,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "sink_function": sink_function,
                "sink_rule_id": sink_rule.get("id"),
                "sink_level": sink_rule.get("level") or "L0",
                "semantic_tags": sink_rule.get("semantic_tags") or [],
                "required_evidence": sink_rule.get("required_evidence") or [],
                "repair_hints": sink_rule.get("repair_hints") or [],
                "has_call_chain": bool(chains),
                "call_chain_count": len(chains),
                "call_chains": chains,
                "summary": candidate.get("summary") or "",
                "limits": candidate.get("limits") or [],
                "audit_pack": audit_pack,
            }
            line = json.dumps(record, ensure_ascii=False) + "\n"
            jsonl_fp.write(line)
            priority_fp.write(line)
            compat_written += 1

            begin = (
                f"{CHAIN_BEGIN_MARK} {chain_id} | "
                f"index={index}/{len(ordered)} | "
                f"severity={severity} | "
                f"vuln={vuln} | "
                f"lang={language} | "
                f"sink={sink_file}:{sink_line} ===\n"
            )
            end = f"{CHAIN_END_MARK} {chain_id} ===\n\n"
            md_fp.write(begin)
            md_fp.write(audit_pack.rstrip() + "\n" if audit_pack else "(no audit_pack rendered)\n")
            md_fp.write(end)

            written += 1
    return written, compat_written


def _classify_llm_need(evidence: dict[str, Any]) -> str:
    """Decide whether we need to spend an LLM call for this sink.

    Returns one of:
      "skip" - static evidence is already enough; no LLM call.
      "needed" - context is sparse, ask the LLM to reason about callers.
    """
    if not callscan_use_llm_enabled():
        return "skip"

    impact = evidence.get("tldr_impact") or {}
    parsed = impact.get("json") if isinstance(impact, dict) else None
    if isinstance(parsed, dict):
        targets = parsed.get("targets") or {}
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            callers = target.get("callers") or []
            if callers:
                # TLDR already produced reverse callers; static path can build
                # a candidate chain without invoking the model.
                return "skip"
    return "needed"


def _base_evidence(
    project_root: Path,
    hit: SinkHit,
    symbol: dict[str, Any],
    extract_payload: dict[str, Any],
    impact_payload: dict[str, Any] | None,
    calls_payload: dict[str, Any] | None,
    module_callers_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "repository": {
            "root": str(project_root),
            "path_policy": "MCP paths are normalized by CallScan before tool execution; use repository-relative paths in reasoning.",
        },
        "language": hit.language,
        "vulnerability_type": hit.vulnerability_type,
        "sink_rule": enrich_sink_profile(
            hit.rule.to_dict(),
            language=hit.language,
            vulnerability_type=hit.vulnerability_type,
            file=hit.file,
            code=hit.code,
            function=hit.rule.function,
        ),
        "sink": {
            "file": hit.file,
            "absolute_file": hit.absolute_file,
            "line": hit.line,
            "column": hit.column,
            "expr": hit.matched_text,
            "code": hit.code,
        },
        "enclosing_symbol": symbol,
        # tldr_extract 包含整个文件的 AST 摘要，发给 LLM 性价比很差，
        # 这里只保留 enclosing 函数定位需要的局部信号。
        "tldr_extract": _slim_extract_payload(extract_payload, symbol),
        "tldr_impact": _compact_tool_payload(impact_payload) if impact_payload else None,
        "tldr_calls": _compact_tool_payload(calls_payload) if calls_payload else None,
        "module_callers": module_callers_payload,
    }


def _slim_extract_payload(
    payload: dict[str, Any] | None,
    symbol: dict[str, Any],
) -> dict[str, Any] | None:
    if payload is None:
        return None
    return {
        "tool": payload.get("tool"),
        "is_error": payload.get("is_error"),
        "summary": {
            "file": symbol.get("file"),
            "enclosing_function": symbol.get("function"),
            "line": symbol.get("line"),
            "line_end": symbol.get("line_end"),
        },
    }


def _normalize_tool_arguments(
    tool_name: str | None,
    arguments: Any,
    project_root: Path,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    normalized = dict(arguments) if isinstance(arguments, dict) else {}
    sink_file = str((evidence.get("sink") or {}).get("file") or ".")

    if tool_name == "tldr__tldr_extract":
        file_value = normalized.get("file") or sink_file
        normalized["file"] = str(_resolve_repo_path(file_value, project_root, sink_file))
        normalized["base_path"] = str(project_root)
        return normalized

    if tool_name == "tldr__tldr_impact":
        normalized["path"] = str(project_root)
        if normalized.get("file"):
            normalized["file"] = _repo_relative_path(normalized["file"], project_root, sink_file)
        return normalized

    if tool_name and tool_name.startswith("tldr__"):
        if "path" in normalized or tool_name in {"tldr__tldr_search", "tldr__tldr_calls"}:
            path_value = normalized.get("path") or "."
            normalized["path"] = str(_resolve_repo_path(path_value, project_root, "."))
        if "file" in normalized:
            normalized["file"] = str(_resolve_repo_path(normalized["file"], project_root, sink_file))
        if "base_path" in normalized:
            normalized["base_path"] = str(project_root)
        return normalized

    if tool_name and tool_name.startswith("ripgrep__"):
        normalized["path"] = _repo_relative_path(normalized.get("path") or ".", project_root, ".")
        normalized.setdefault("includeHidden", True)
        normalized.setdefault("useColors", False)
        if tool_name in {"ripgrep__search", "ripgrep__advanced-search"}:
            normalized.setdefault("maxResults", 30)
        return normalized

    return normalized


def _resolve_repo_path(raw: Any, project_root: Path, default_relative: str) -> Path:
    root = project_root.resolve()
    raw_text = str(raw or default_relative).strip().strip("'\"")
    if raw_text in {"", ".", "./"}:
        return root

    normalized = raw_text.replace("\\", "/")
    candidate: Path
    root_text = root.as_posix().lower()
    lowered = normalized.lower()

    if lowered.startswith(root_text):
        candidate = Path(normalized)
    elif len(normalized) >= 2 and normalized[1] == ":":
        candidate = Path(normalized)
    elif normalized.startswith("/repo/"):
        candidate = PROJECT_ROOT / normalized.lstrip("/")
    elif normalized.startswith("repo/"):
        candidate = PROJECT_ROOT / normalized
    elif normalized.startswith("/"):
        candidate = root / normalized.lstrip("/")
    else:
        candidate = root / normalized

    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError:
        fallback = (root / default_relative).resolve(strict=False)
        try:
            fallback.relative_to(root)
        except ValueError:
            return root
        return fallback
    return resolved


def _repo_relative_path(raw: Any, project_root: Path, default_relative: str) -> str:
    root = project_root.resolve()
    target = _resolve_repo_path(raw, project_root, default_relative)
    try:
        rel = target.relative_to(root).as_posix()
    except ValueError:
        return default_relative
    return rel or "."


async def _call_repository_tool(
    toolbox: MCPToolbox,
    tool_name: str | None,
    arguments: dict[str, Any],
    project_root: Path,
) -> dict[str, Any]:
    if tool_name and tool_name.startswith("ripgrep__"):
        return await asyncio.to_thread(_run_local_ripgrep_tool, tool_name, arguments, project_root)
    return await toolbox.call_tool(str(tool_name), arguments)


def _run_local_ripgrep_tool(
    tool_name: str,
    arguments: dict[str, Any],
    project_root: Path,
) -> dict[str, Any]:
    pattern = str(arguments.get("pattern") or "")
    if not pattern and tool_name != "ripgrep__list-files":
        return {
            "tool": tool_name,
            "server": "local-ripgrep",
            "is_error": True,
            "text": "Missing required pattern.",
        }

    search_path = _resolve_repo_path(arguments.get("path") or ".", project_root, ".")
    rg_exe = PROJECT_ROOT / "ripgrep" / "rg.exe"
    if not rg_exe.is_file():
        return {
            "tool": tool_name,
            "server": "local-ripgrep",
            "is_error": True,
            "text": f"rg.exe not found: {rg_exe}",
        }

    if tool_name == "ripgrep__count-matches":
        return _run_local_ripgrep_count(rg_exe, pattern, search_path, arguments, tool_name)
    if tool_name == "ripgrep__list-files":
        return _run_local_ripgrep_list_files(rg_exe, search_path, arguments, tool_name)
    return _run_local_ripgrep_search(rg_exe, pattern, search_path, arguments, tool_name)


def _run_local_ripgrep_search(
    rg_exe: Path,
    pattern: str,
    search_path: Path,
    arguments: dict[str, Any],
    tool_name: str,
) -> dict[str, Any]:
    command = _base_ripgrep_command(rg_exe, arguments)
    context = arguments.get("context")
    if isinstance(context, int) and context > 0:
        command.extend(["-C", str(context)])
    command.extend(["-e", pattern, str(search_path)])

    completed = _run_ripgrep_command(command, search_path)
    if completed.returncode not in (0, 1):
        return _ripgrep_error(tool_name, completed)

    max_results = int(arguments.get("maxResults") or 30)
    lines = completed.stdout.splitlines()
    return {
        "tool": tool_name,
        "server": "local-ripgrep",
        "is_error": False,
        "text": "\n".join(lines[:max_results]),
    }


def _run_local_ripgrep_count(
    rg_exe: Path,
    pattern: str,
    search_path: Path,
    arguments: dict[str, Any],
    tool_name: str,
) -> dict[str, Any]:
    command = _base_ripgrep_command(rg_exe, arguments)
    command.extend(["--json", "-e", pattern, str(search_path)])
    completed = _run_ripgrep_command(command, search_path)
    if completed.returncode not in (0, 1):
        return _ripgrep_error(tool_name, completed)

    count = 0
    matched_lines: set[tuple[str, int]] = set()
    for line in completed.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue
        data = event.get("data") or {}
        path = ((data.get("path") or {}).get("text")) or ""
        line_no = int(data.get("line_number") or 0)
        if arguments.get("countLines"):
            matched_lines.add((path, line_no))
        else:
            count += len(data.get("submatches") or [None])
    if arguments.get("countLines"):
        count = len(matched_lines)

    return {
        "tool": tool_name,
        "server": "local-ripgrep",
        "is_error": False,
        "text": str(count),
    }


def _run_local_ripgrep_list_files(
    rg_exe: Path,
    search_path: Path,
    arguments: dict[str, Any],
    tool_name: str,
) -> dict[str, Any]:
    command = [str(rg_exe), "-u", "--files"]
    file_pattern = arguments.get("filePattern")
    if file_pattern:
        command.extend(["--glob", str(file_pattern)])
    file_type = arguments.get("fileType")
    if file_type:
        command.extend(["-t", str(file_type)])
    command.append(str(search_path))

    completed = _run_ripgrep_command(command, search_path)
    if completed.returncode not in (0, 1):
        return _ripgrep_error(tool_name, completed)
    return {
        "tool": tool_name,
        "server": "local-ripgrep",
        "is_error": False,
        "text": "\n".join(completed.stdout.splitlines()[:100]),
    }


def _base_ripgrep_command(rg_exe: Path, arguments: dict[str, Any]) -> list[str]:
    command = [str(rg_exe), "-u", "-n"]
    if arguments.get("fixedStrings"):
        command.append("-F")
    if arguments.get("wordMatch"):
        command.append("-w")
    case_sensitive = arguments.get("caseSensitive")
    if case_sensitive is True:
        command.append("-s")
    elif case_sensitive is False:
        command.append("-i")
    file_pattern = arguments.get("filePattern")
    if file_pattern:
        command.extend(["--glob", str(file_pattern)])
    file_type = arguments.get("fileType")
    if file_type:
        command.extend(["-t", str(file_type)])
    return command


def _run_ripgrep_command(command: list[str], search_path: Path) -> subprocess.CompletedProcess[str]:
    cwd = search_path if search_path.is_dir() else search_path.parent
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _ripgrep_error(tool_name: str, completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "tool": tool_name,
        "server": "local-ripgrep",
        "is_error": True,
        "text": completed.stderr.strip() or completed.stdout.strip(),
    }


async def _run_sink_conversation(toolbox: MCPToolbox, evidence: dict[str, Any]) -> dict[str, Any] | None:
    try:
        text = await _run_native_tool_loop(toolbox, evidence)
    except Exception as native_error:
        info(f"native tool loop failed: {type(native_error).__name__}: {native_error}")
        try:
            text = await _run_json_action_loop(toolbox, evidence, native_error)
        except Exception as fallback_error:
            info(
                f"json action loop also failed: "
                f"{type(fallback_error).__name__}: {fallback_error}"
            )
            return {
                "status": "insufficient_context",
                "candidate_chain": {
                    "summary": "LLM tool loop failed; using static MCP evidence only.",
                    "call_chains": [],
                    "evidence": [
                        {
                            "source": "llm",
                            "detail": f"native_error={native_error}; fallback_error={fallback_error}",
                            "file": None,
                            "line": None,
                            "code": None,
                        }
                    ],
                    "limits": ["LLM conversation did not complete."],
                },
            }

    parsed = _parse_json_from_text(text)
    if _is_valid_llm_result(parsed):
        return parsed
    return {
        "status": "insufficient_context",
        "candidate_chain": {
            "summary": "LLM did not return the required JSON object; using static MCP evidence only.",
            "call_chains": [],
            "evidence": [
                {
                    "source": "llm",
                    "detail": text[:1000],
                    "file": None,
                    "line": None,
                    "code": None,
                }
            ],
            "limits": ["LLM final response was not a valid CallScan JSON object."],
        },
    }


async def _run_native_tool_loop(toolbox: MCPToolbox, evidence: dict[str, Any]) -> str:
    project_root = Path(evidence["repository"]["root"])
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SPEC.system_message},
        {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
    ]
    tools = toolbox.as_litellm_tools(LLM_TOOL_NAMES)
    seen_tool_calls: dict[str, int] = {}
    per_tool_counts: dict[str, int] = {}
    round_count = 0

    while True:
        round_count += 1
        if round_count > CALLSCAN_MAX_TOOL_ROUNDS:
            # Budget exhausted — drop tools and force a final JSON answer so
            # the conversation cannot stall indefinitely.
            return await _force_callscan_final(messages)

        response = await asyncio.to_thread(
            functools.partial(
                chat_completion,
                messages,
                tools=tools,
                tool_choice="auto",
                response_format={"type": "json_object"},
                temperature=SPEC.temperature,
                max_tokens=SPEC.max_tokens,
            )
        )
        message = response_message_to_dict(response)
        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            return str(message.get("content") or "")

        # 确保每个 tool_call.id 非空，并把 fallback id 回写到 tool_call，
        # 否则下一轮拼接的 messages 会触发 DeepSeek/OpenAI 的
        # "tool_calls must be followed by tool messages responding to each tool_call_id" 错误
        for tool_call in tool_calls:
            function = tool_call.get("function") or {}
            name = function.get("name")
            raw_arguments = function.get("arguments") or "{}"
            if not tool_call.get("id"):
                tool_call["id"] = "call_" + _stable_hash(f"{name}:{raw_arguments}")[:16]
            tool_call.setdefault("type", "function")

        assistant_message = {
            "role": "assistant",
            "content": message.get("content") or "",
            "tool_calls": tool_calls,
        }
        if message.get("reasoning_content"):
            # DeepSeek-V4 thinking mode requires the same reasoning_content
            # to be echoed back on the next request, otherwise the API rejects
            # the multi-turn tool call with HTTP 400.
            assistant_message["reasoning_content"] = message["reasoning_content"]
        messages.append(assistant_message)

        for tool_call in tool_calls:
            function = tool_call.get("function") or {}
            name = function.get("name")
            raw_arguments = function.get("arguments") or "{}"
            tool_call_id = tool_call["id"]
            arguments = _json_object(raw_arguments)
            repeat_key = f"{name}:{json.dumps(arguments, sort_keys=True, ensure_ascii=False)}"
            seen_tool_calls[repeat_key] = seen_tool_calls.get(repeat_key, 0) + 1
            per_tool_counts[str(name)] = per_tool_counts.get(str(name), 0) + 1

            if seen_tool_calls[repeat_key] > 2:
                tool_result = {
                    "tool": name,
                    "is_error": True,
                    "text": "Repeated identical tool call suppressed; use existing result and finish.",
                }
            elif per_tool_counts[str(name)] > CALLSCAN_PER_TOOL_CALL_LIMIT:
                # Model is varying parameters but not converging — cut it off.
                tool_result = {
                    "tool": name,
                    "is_error": True,
                    "text": (
                        f"Per-tool call limit reached ({CALLSCAN_PER_TOOL_CALL_LIMIT}); "
                        "stop calling this tool and return the final JSON answer "
                        "using evidence already collected."
                    ),
                }
            else:
                normalized_arguments = _normalize_tool_arguments(
                    name,
                    arguments,
                    project_root,
                    evidence,
                )
                tool_result = await _call_repository_tool(
                    toolbox,
                    name,
                    normalized_arguments,
                    project_root,
                )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "name": name,
                    "content": _truncate_tool_content(tool_result),
                }
            )


async def _run_json_action_loop(
    toolbox: MCPToolbox,
    evidence: dict[str, Any],
    native_error: Exception,
) -> str:
    project_root = Path(evidence["repository"]["root"])
    tool_catalog = toolbox.as_json_tool_catalog(LLM_TOOL_NAMES)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SPEC.system_message},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "fallback_reason": str(native_error),
                    "tool_catalog": tool_catalog,
                    "evidence": evidence,
                },
                ensure_ascii=False,
            ),
        },
    ]
    seen_actions: dict[str, int] = {}
    round_count = 0

    while True:
        round_count += 1
        if round_count > CALLSCAN_MAX_TOOL_ROUNDS:
            return await _force_callscan_final(messages)
        response = await asyncio.to_thread(
            functools.partial(
                chat_completion,
                messages,
                response_format={"type": "json_object"},
                temperature=SPEC.temperature,
                max_tokens=SPEC.max_tokens,
            )
        )
        message = response_message_to_dict(response)
        content = str(message.get("content") or "")
        parsed = _parse_json_from_text(content)
        if not isinstance(parsed, dict):
            return content

        action_payload = parsed.get("action")
        if not isinstance(action_payload, dict):
            return content

        tool_name = action_payload.get("tool")
        arguments = action_payload.get("arguments") or {}
        repeat_key = f"{tool_name}:{json.dumps(arguments, sort_keys=True, ensure_ascii=False)}"
        seen_actions[repeat_key] = seen_actions.get(repeat_key, 0) + 1
        if seen_actions[repeat_key] > 2:
            tool_result = {
                "tool": tool_name,
                "is_error": True,
                "text": "Repeated identical JSON action suppressed; use existing result and finish.",
            }
        else:
            normalized_arguments = _normalize_tool_arguments(
                tool_name,
                arguments,
                project_root,
                evidence,
            )
            tool_result = await _call_repository_tool(
                toolbox,
                tool_name,
                normalized_arguments,
                project_root,
            )

        messages.append({"role": "assistant", "content": content})
        messages.append(
            {
                "role": "user",
                "content": json.dumps(
                    {"tool_result": tool_result},
                    ensure_ascii=False,
                )[:TOOL_RESULT_CHAR_LIMIT],
            }
        )


async def _force_callscan_final(messages: list[dict[str, Any]]) -> str:
    """Tool budget exhausted: ask the model for the final JSON without tools so
    a stalled multi-turn session cannot block the whole scan."""
    forced = list(messages) + [
        {
            "role": "user",
            "content": (
                "Tool budget exhausted for this sink. Do not request any more "
                "tools. Return ONLY the final CallScan JSON object using the "
                "evidence already gathered. If evidence is incomplete, set "
                "\"status\": \"insufficient_context\" and list the gaps under "
                "\"limits\"."
            ),
        }
    ]
    try:
        response = await asyncio.to_thread(
            functools.partial(
                chat_completion,
                forced,
                response_format={"type": "json_object"},
                temperature=SPEC.temperature,
                max_tokens=SPEC.max_tokens,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return json.dumps(
            {
                "status": "insufficient_context",
                "candidate_chain": {
                    "summary": "CallScan tool loop exhausted and final fallback failed.",
                    "call_chains": [],
                    "evidence": [],
                    "limits": [
                        f"tool_loop_exhausted: max_rounds={CALLSCAN_MAX_TOOL_ROUNDS}",
                        f"final_fallback_error: {type(exc).__name__}: {exc}",
                    ],
                },
            },
            ensure_ascii=False,
        )
    message = response_message_to_dict(response)
    return str(message.get("content") or "")


def _merge_candidate(
    chain_id: str,
    hit: SinkHit,
    symbol: dict[str, Any],
    evidence: dict[str, Any],
    llm_candidate: dict[str, Any] | None,
) -> dict[str, Any]:
    llm_chain = {}
    if isinstance(llm_candidate, dict):
        llm_chain = llm_candidate.get("candidate_chain") or {}

    call_chains = llm_chain.get("call_chains") or _chains_from_tool_evidence(evidence)
    evidence_items = _default_evidence_items(hit, symbol)
    evidence_items.extend(llm_chain.get("evidence") or [])
    sink_rule = enrich_sink_profile(
        hit.rule.to_dict(),
        language=hit.language,
        vulnerability_type=hit.vulnerability_type,
        file=hit.file,
        code=hit.code,
        function=hit.rule.function,
    )

    limits = []
    limits.extend(llm_chain.get("limits") or [])
    if not call_chains:
        limits.append("No reverse callers were confirmed by TLDR for this sink function.")

    return {
        "id": chain_id,
        "language": hit.language,
        "vulnerability_type": hit.vulnerability_type,
        "sink_rule": sink_rule,
        "sink": evidence["sink"],
        "enclosing_symbol": symbol,
        "summary": llm_chain.get("summary")
        or f"{hit.rule.function} sink at {hit.file}:{hit.line}",
        "call_chains": call_chains,
        "evidence": evidence_items,
        "limits": _dedupe_strings(limits),
        "raw_tool_evidence": {
            "tldr_extract": evidence.get("tldr_extract"),
            "tldr_impact": evidence.get("tldr_impact"),
            "tldr_calls": evidence.get("tldr_calls"),
        },
    }


def _chains_from_tool_evidence(evidence: dict[str, Any]) -> list[list[dict[str, Any]]]:
    chains: list[list[dict[str, Any]]] = []

    sink_file = evidence["sink"]["file"]
    sink_function = evidence["enclosing_symbol"]["function"]
    sink_node_template = {
        "file": sink_file,
        "function": sink_function,
        "line": evidence["enclosing_symbol"].get("line") or evidence["sink"]["line"],
        "code": evidence["sink"]["code"],
        "role": "sink",
    }

    # 1) tldr_impact 提供的反向调用者（适用于函数级 sink）
    impact = evidence.get("tldr_impact") or {}
    parsed = impact.get("json") if isinstance(impact, dict) else None
    if isinstance(parsed, dict):
        targets = parsed.get("targets") or {}
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            sink_node = dict(sink_node_template)
            sink_node["file"] = target.get("file") or sink_file
            sink_node["function"] = target.get("function") or sink_function
            callers = target.get("callers") or []
            if not callers:
                chains.append([sink_node])
                continue
            for caller in callers:
                if isinstance(caller, dict):
                    chains.append(
                        [
                            {
                                "file": caller.get("file"),
                                "function": caller.get("function"),
                                "line": caller.get("line"),
                                "code": None,
                                "role": "caller",
                            },
                            sink_node,
                        ]
                    )

    # 2) module_callers 提供的反向 include 链（适用于模块级 sink）
    module_callers = evidence.get("module_callers") or {}
    callers = module_callers.get("callers") if isinstance(module_callers, dict) else None
    if callers:
        sink_node = dict(sink_node_template)
        for caller in callers:
            if not isinstance(caller, dict):
                continue
            chains.append(
                [
                    {
                        "file": caller.get("file"),
                        "function": caller.get("function") or "<module>",
                        "line": caller.get("line"),
                        "code": caller.get("code"),
                        "role": "caller",
                    },
                    sink_node,
                ]
            )

    return chains


_PHP_CLASS_RE = re.compile(r"^\s*(?:abstract\s+)?class\s+(\w+)\b", re.IGNORECASE)
_PHP_FUNC_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*"
    r"function\s+(\w+)\s*\(",
    re.IGNORECASE,
)
_JS_FUNC_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(",
)


async def _resolve_sink_symbol(
    project_root: Path,
    hit: SinkHit,
    slicer: CodeSlicer,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """静态模式优先本地解析 enclosing symbol，避免对大文件做 tldr_extract（可达数分钟）。"""
    if not callscan_use_llm_enabled():
        symbol = _find_enclosing_symbol_local(
            project_root, hit.file, hit.line, hit.language
        )
        if symbol["function"] == "<module>":
            return symbol, None
        # 函数级 sink 在静态模式下仍跳过 MCP；链构造依赖 tldr_impact，静态本就不调 LLM。
        return symbol, None

    extract_json = await slicer.get_extract(hit.file)
    symbol = _find_enclosing_symbol(extract_json, hit.line, hit.file)
    return symbol, extract_json


def _find_enclosing_symbol_local(
    project_root: Path,
    rel_file: str,
    line: int,
    language: str,
) -> dict[str, Any]:
    path = project_root / rel_file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return _module_symbol(rel_file)
    if line < 1 or line > len(lines):
        return _module_symbol(rel_file)
    if language == "php":
        return _find_enclosing_symbol_local_php(lines, rel_file, line)
    if language in ("javascript", "typescript"):
        return _find_enclosing_symbol_local_js(lines, rel_file, line)
    return _module_symbol(rel_file)


def _find_enclosing_symbol_local_php(
    lines: list[str], rel_file: str, line: int
) -> dict[str, Any]:
    current_class: str | None = None
    spans: list[tuple[int, int, str, str | None]] = []

    for i, raw in enumerate(lines, start=1):
        if m := _PHP_CLASS_RE.match(raw):
            current_class = m.group(1)
        if m := _PHP_FUNC_RE.match(raw):
            fname = m.group(1)
            qualified = f"{current_class}.{fname}" if current_class else fname
            spans.append((i, len(lines), qualified, current_class))

    for idx, (start, _end, qualified, cls) in enumerate(spans):
        end = (spans[idx + 1][0] - 1) if idx + 1 < len(spans) else len(lines)
        spans[idx] = (start, end, qualified, cls)

    containing = [s for s in spans if s[0] <= line <= s[1]]
    if not containing:
        return _module_symbol(rel_file)
    start, end, qualified, cls = min(containing, key=lambda s: s[1] - s[0])
    return {
        "file": rel_file,
        "function": qualified,
        "name": qualified.split(".")[-1],
        "class": cls,
        "line": start,
        "line_end": end,
    }


def _find_enclosing_symbol_local_js(
    lines: list[str], rel_file: str, line: int
) -> dict[str, Any]:
    spans: list[tuple[int, int, str]] = []
    for i, raw in enumerate(lines, start=1):
        if m := _JS_FUNC_RE.match(raw):
            spans.append((i, len(lines), m.group(1)))
    for idx, (start, _end, name) in enumerate(spans):
        end = (spans[idx + 1][0] - 1) if idx + 1 < len(spans) else len(lines)
        spans[idx] = (start, end, name)
    containing = [s for s in spans if s[0] <= line <= s[1]]
    if not containing:
        return _module_symbol(rel_file)
    start, end, name = min(containing, key=lambda s: s[1] - s[0])
    return {
        "file": rel_file,
        "function": name,
        "name": name,
        "class": None,
        "line": start,
        "line_end": end,
    }


def _find_enclosing_symbol(extract_json: Any, line: int, rel_file: str) -> dict[str, Any]:
    if not isinstance(extract_json, dict):
        return _module_symbol(rel_file)

    candidates: list[dict[str, Any]] = []
    for function in extract_json.get("functions") or []:
        _add_symbol_candidate(candidates, rel_file, function, None)
    for class_info in extract_json.get("classes") or []:
        class_name = class_info.get("name")
        for method in class_info.get("methods") or []:
            _add_symbol_candidate(candidates, rel_file, method, class_name)

    containing = [
        candidate
        for candidate in candidates
        if candidate.get("line") is not None
        and candidate.get("line_end") is not None
        and int(candidate["line"]) <= line <= int(candidate["line_end"])
    ]
    if not containing:
        return _module_symbol(rel_file)

    containing.sort(key=lambda item: (int(item["line_end"]) - int(item["line"]), item["function"]))
    return containing[0]


def _add_symbol_candidate(
    candidates: list[dict[str, Any]],
    rel_file: str,
    symbol: dict[str, Any],
    class_name: str | None,
) -> None:
    name = symbol.get("name")
    if not name:
        return
    qualified_name = f"{class_name}.{name}" if class_name else name
    candidates.append(
        {
            "file": rel_file,
            "function": qualified_name,
            "name": name,
            "class": class_name,
            "line": symbol.get("line"),
            "line_end": symbol.get("line_end"),
        }
    )


def _module_symbol(rel_file: str) -> dict[str, Any]:
    return {
        "file": rel_file,
        "function": "<module>",
        "name": "<module>",
        "class": None,
        "line": None,
        "line_end": None,
    }


def _default_evidence_items(hit: SinkHit, symbol: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "source": "rg",
            "detail": f"Matched sink rule {hit.rule.id} ({hit.rule.function}).",
            "file": hit.file,
            "line": hit.line,
            "code": hit.code,
        },
        {
            "source": "tldr_extract",
            "detail": f"Sink is inside {symbol['function']}.",
            "file": symbol.get("file"),
            "line": symbol.get("line"),
            "code": None,
        },
    ]


def _compact_tool_payload(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    text = payload.get("text") or ""
    parsed = _parse_json_from_text(text)
    return {
        "tool": payload.get("tool"),
        "is_error": payload.get("is_error"),
        "json": parsed,
        # If the payload already parses as JSON we don't need the raw text too;
        # this saves a lot of input tokens for large MCP responses.
        "text": "" if parsed is not None else text[:EVIDENCE_TLDR_TEXT_CHAR_LIMIT],
    }


def _parse_json_from_text(text: str) -> Any:
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].strip()

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _is_valid_llm_result(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("status") not in {"ok", "insufficient_context"}:
        return False
    return isinstance(value.get("candidate_chain"), dict)


def _json_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _truncate_tool_content(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)[:TOOL_RESULT_CHAR_LIMIT]


def _chain_id(hit: SinkHit) -> str:
    return "C-" + _stable_hash(
        f"{hit.language}:{hit.vulnerability_type}:{hit.rule.id}:{hit.file}:{hit.line}:{hit.code}"
    )[:12]


def _stable_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()


def _dedupe_strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value)
        if text and text not in result:
            result.append(text)
    return result


# 严重度 -> 排序权重，高的优先。
_SEVERITY_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SINK_LEVEL_PRIORITY = {"L2": 3, "L1": 2, "L0": 1}


def _hit_priority(hit: SinkHit) -> tuple[int, int, str, int]:
    """命中排序键：严重度高、文件靠前的先处理。"""
    severity_score = _SEVERITY_PRIORITY.get(hit.rule.severity, 0)
    return (severity_score, -len(hit.file.split("/")), hit.file, -hit.line)


_INCLUDE_REGEX = re.compile(
    r"\b(?:include|include_once|require|require_once)\b\s*\(?\s*['\"]([^'\"]+)['\"]"
)


def _module_includer_needles(sink_rel_file: str) -> list[str]:
    """从具体到模糊排列 include 搜索串（固定字符串，避免全库正则灾难）。"""
    rel = sink_rel_file.replace("\\", "/").strip("/")
    needles: list[str] = []
    if rel:
        needles.append(rel)
    parts = rel.split("/")
    if len(parts) >= 2:
        needles.append("/".join(parts[-2:]))
    if len(parts) >= 3:
        needles.append("/".join(parts[-3:]))
    base = Path(rel).name
    if base and base not in needles:
        needles.append(base)
    seen: set[str] = set()
    ordered: list[str] = []
    for n in needles:
        if n and n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


def _rg_timeout_for_needle(needle: str, *, basename: str) -> float:
    if needle == basename:
        return min(MODULE_INCLUDER_TIMEOUT, 20.0)
    return MODULE_INCLUDER_TIMEOUT


def _module_includer_search_paths(
    project_root: Path, sink_rel_file: str, *, static_mode: bool
) -> list[Path]:
    """限制 include 反查的目录范围；静态模式只搜 sink 所在顶层目录（如 src/）。"""
    rel = sink_rel_file.replace("\\", "/")
    paths: list[Path] = []
    parts = rel.split("/")
    if parts:
        top = (project_root / parts[0]).resolve()
        if top.is_dir():
            paths.append(top)
    root = project_root.resolve()
    if not paths:
        paths.append(root)
    elif static_mode:
        return paths[:1]
    if root not in paths:
        paths.append(root)
    return paths


def _run_rg_module_includers(
    project_root: Path,
    *,
    search_path: Path,
    needle: str,
    sink_rel_file: str,
    target_basename: str,
    timeout: float,
    max_callers: int,
) -> tuple[list[dict[str, Any]], str | None]:
    rg_exe = PROJECT_ROOT / "ripgrep" / "rg.exe"
    if not rg_exe.is_file():
        return [], "rg.exe not found"

    command = [
        str(rg_exe),
        "-u",
        "-n",
        "--json",
        "--glob",
        "*.php",
        "-F",
        needle,
    ]
    for exclude in RG_EXCLUDE_GLOBS:
        command.extend(["--glob", exclude])
    command.append(str(search_path))
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [], f"rg timeout after {timeout:.0f}s"

    if completed.returncode not in (0, 1):
        return [], (completed.stderr or "").strip()[:300] or None

    callers: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue
        data = event.get("data") or {}
        raw_path = (data.get("path") or {}).get("text")
        if not raw_path:
            continue
        try:
            rel = Path(raw_path).resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            rel = Path(raw_path).as_posix()

        skip, _ = should_skip_for_scan(rel)
        if skip or rel == sink_rel_file:
            continue

        line_no = int(data.get("line_number") or 0)
        if (rel, line_no) in seen:
            continue
        seen.add((rel, line_no))

        code = ((data.get("lines") or {}).get("text") or "").rstrip("\r\n")
        match = _INCLUDE_REGEX.search(code)
        if not match:
            continue
        included = match.group(1).replace("\\", "/")
        if not included.endswith(target_basename):
            continue
        if (
            included != target_basename
            and not sink_rel_file.endswith(included.lstrip("./"))
            and not included.endswith(sink_rel_file)
        ):
            continue

        callers.append(
            {
                "file": rel,
                "function": "<module>",
                "line": line_no,
                "code": code[:200],
            }
        )
        if len(callers) >= max_callers:
            break

    return callers, None


async def _find_module_includers(
    project_root: Path, sink_rel_file: str
) -> dict[str, Any]:
    """对模块级 sink 用 ripgrep 反查谁 include / require 了它。

    优先用相对路径固定串（如 wp-includes/user.php），最后才退回 basename；
    basename 全库扫描在大仓库上可能耗时数分钟，因此单独缩短超时。
    静态模式：只在 sink 顶层目录（如 src/）内搜索，且不使用 basename 全库扫描。
    """
    static_mode = not callscan_use_llm_enabled()
    target_basename = Path(sink_rel_file).name
    if not target_basename:
        return {"callers": []}

    needles = _module_includer_needles(sink_rel_file)
    if static_mode:
        needles = [n for n in needles if "/" in n][:2]
    search_paths = _module_includer_search_paths(
        project_root, sink_rel_file, static_mode=static_mode
    )
    max_callers = STATIC_MODULE_MAX_CALLERS if static_mode else MODULE_INCLUDER_MAX_CALLERS

    callers: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    notes: list[str] = []

    for search_path in search_paths:
        for needle in needles:
            if len(callers) >= max_callers:
                break
            if static_mode:
                timeout = STATIC_MODULE_RG_TIMEOUT
            else:
                timeout = _rg_timeout_for_needle(needle, basename=target_basename)
            batch, err = await asyncio.to_thread(
                _run_rg_module_includers,
                project_root,
                search_path=search_path,
                needle=needle,
                sink_rel_file=sink_rel_file,
                target_basename=target_basename,
                timeout=timeout,
                max_callers=max_callers,
            )
            if err:
                notes.append(err)
            for c in batch:
                key = (c.get("file"), int(c.get("line") or 0))
                if key in seen:
                    continue
                seen.add(key)
                callers.append(c)
                if len(callers) >= max_callers:
                    break
        if static_mode and callers:
            break

    out: dict[str, Any] = {"callers": callers}
    if static_mode:
        out["limits"] = [
            f"static include search under {search_paths[0].name}/ "
            f"(max {max_callers} callers, {STATIC_MODULE_RG_TIMEOUT:.0f}s/rg)"
        ]
    if notes:
        out.setdefault("limits", [])
        out["limits"].extend(notes[:2])
    return out


# ── checkpoint / progress ───────────────────────────────────────────────────


def _load_callscan_progress(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    done: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line_s = line.strip()
            if not line_s:
                continue
            try:
                row = json.loads(line_s)
            except json.JSONDecodeError:
                continue
            chain_id = str(row.get("chain_id") or "").strip()
            candidate = row.get("candidate")
            if chain_id and isinstance(candidate, dict):
                done[chain_id] = candidate
    return done


def _append_callscan_progress(path: Path, candidate: dict[str, Any]) -> None:
    chain_id = str(candidate.get("id") or "").strip()
    if not chain_id:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"chain_id": chain_id, "candidate": candidate}
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _rewrite_callscan_progress(
    path: Path, candidates_by_id: dict[str, dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"chain_id": chain_id, "candidate": candidate}, ensure_ascii=False)
        for chain_id, candidate in candidates_by_id.items()
    ]
    text = "\n".join(lines)
    path.write_text((text + "\n") if text else "", encoding="utf-8")


def _candidates_from_partial_agent(agent_path: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(agent_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict) or not payload.get("partial"):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for candidate in payload.get("candidate_chains") or []:
        if not isinstance(candidate, dict):
            continue
        chain_id = str(candidate.get("id") or "").strip()
        if chain_id:
            out[chain_id] = candidate
    return out


def _build_summary(
    candidate_chains: list[dict[str, Any]],
    skipped_rules: list[dict[str, Any]],
    filter_stats: dict[str, int],
    sink_hit_total: int,
    started_at: float,
) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_vuln: dict[str, int] = {}
    by_function: dict[str, int] = {}
    with_chain = 0
    for candidate in candidate_chains:
        rule = candidate.get("sink_rule") or {}
        severity = rule.get("severity") or "unknown"
        by_severity[severity] = by_severity.get(severity, 0) + 1
        vuln = candidate.get("vulnerability_type") or "unknown"
        by_vuln[vuln] = by_vuln.get(vuln, 0) + 1
        func = rule.get("function") or "unknown"
        by_function[func] = by_function.get(func, 0) + 1
        if candidate.get("call_chains"):
            with_chain += 1

    top_chains = sorted(
        candidate_chains,
        key=lambda c: (
            _SEVERITY_PRIORITY.get((c.get("sink_rule") or {}).get("severity") or "", 0),
            1 if c.get("call_chains") else 0,
        ),
        reverse=True,
    )[:30]

    return {
        "sink_hits": sink_hit_total,
        "candidate_chains": len(candidate_chains),
        "with_call_chain": with_chain,
        "no_call_chain": len(candidate_chains) - with_chain,
        "skipped_rules": len(skipped_rules),
        "by_severity": by_severity,
        "by_vulnerability": by_vuln,
        "by_function": by_function,
        "filter_stats": filter_stats,
        "top_candidates": [
            {
                "id": c.get("id"),
                "severity": (c.get("sink_rule") or {}).get("severity"),
                "vulnerability_type": c.get("vulnerability_type"),
                "function": (c.get("sink_rule") or {}).get("function"),
                "file": (c.get("sink") or {}).get("file"),
                "line": (c.get("sink") or {}).get("line"),
                "has_call_chain": bool(c.get("call_chains")),
            }
            for c in top_chains
        ],
        "elapsed_seconds": round(time.perf_counter() - started_at, 2),
    }


def _status(candidate_chains: list[dict[str, Any]], skipped: list[dict[str, Any]]) -> str:
    if candidate_chains:
        return "ok"
    if skipped:
        return "no_sinks"
    return "partial"
