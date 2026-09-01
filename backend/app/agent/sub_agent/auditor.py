"""Auditor Agent: per-chain vulnerability assessment with MCP tool-loop.

Reads all CallScan candidate chains, injects Skill knowledge for
the (language, vulnerability_type) pair, and runs a multi-turn LLM session
that may call tldr + ripgrep MCP tools to gather missing context.

Produces two artifacts in .defectmine/:
- ``audit_agent.json`` — full structured verdicts
- ``audit_findings.md`` — human-readable report with POC / fix per finding
"""

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
from typing import Any

from app.agent.logger import write_event
from app.agent.mcp import MCPToolbox, PROJECT_ROOT, default_server_specs
from app.agent.prompts import load_prompt
from app.agent.run_scope import RunScope, resolve_run_scope
from app.llm.client import chat_completion, response_message_to_dict
from app.ui.console import action, console, info, print_status

# ── constants ──────────────────────────────────────────────────────────────
CALLSCAN_CHAINS_JSONL = "callscan_chains.jsonl"
CALLSCAN_PRIORITY_JSONL = "callscan_chains.priority.jsonl"
DATAFLOW_CHAINS_JSONL = "cross_request_chains.jsonl"
AUDIT_JSON_FILENAME = "audit_agent.json"
AUDIT_MD_FILENAME = "audit_findings.md"
AUDIT_PROGRESS_JSONL = "audit_progress.jsonl"
AUDIT_FAILURES_JSONL = "audit_failures.jsonl"
SKILLS_DIR = Path(__file__).resolve().parents[1] / "skills"

MAX_TOOL_ROUNDS = 6                    # per chain
MAX_REPAIR_ROUNDS = 1                  # initial audit + one evidence repair pass
MAX_CONCURRENT_AUDIT_TASKS = 2         # env fallback when scan options unset
MAX_AUDITOR_MCP_POOL = 32              # cap independent tldr-mcp subprocesses
TOOL_RESULT_CHAR_LIMIT = 10_000
AUDITOR_HEARTBEAT_SECS = max(
    1, int(os.environ.get("AUDITOR_HEARTBEAT_SECS", "5"))
)
AUDITOR_CHAIN_TIMEOUT_S = float(os.environ.get("AUDITOR_CHAIN_TIMEOUT", "600"))
RG_SEARCH_TIMEOUT_S = float(os.environ.get("RG_SEARCH_TIMEOUT", "60"))

REPAIR_BREAKPOINTS = {
    "missing_source_entry",
    "missing_permission_check",
    "missing_template_binding",
    "missing_sql_column_mapping",
    "missing_storage_read",
    "missing_file_save_path",
    "missing_sanitizer_state",
    "missing_reachability",
    "missing_runtime_config",
}

REQUIRED_EVIDENCE_TO_BREAKPOINT = {
    "source_control": "missing_source_entry",
    "permission_check": "missing_permission_check",
    "template_binding": "missing_template_binding",
    "storage_identity": "missing_storage_read",
    "storage_read": "missing_storage_read",
    "file_save_path": "missing_file_save_path",
    "sanitizer_state": "missing_sanitizer_state",
    "reachability": "missing_reachability",
}

REPAIR_PATTERNS = {
    "missing_source_entry": [
        r"\b(route|handler|action|performer|controller|request|req\.|request\.|Wikirequest)\b|\$_(?:GET|POST|REQUEST)\b",
    ],
    "missing_permission_check": [
        r"\b(auth|authorize|permission|checkPermission|isAdmin|isAllowed|middleware|login_required|canAccess)\b",
    ],
    "missing_template_binding": [
        r"\b(render|render_template|display|TemplateEngine|assign|include|twig|smarty|blade|props|v-html|innerHTML)\b",
    ],
    "missing_sql_column_mapping": [
        r"\b(select|insert|update|delete|from|where|save\(|objects\.|db\.session|query\()\b",
    ],
    "missing_storage_read": [
        r"\b(config|settings|option|page|comment|content|load|get|read|find|select|query)\b",
    ],
    "missing_file_save_path": [
        r"\b(move_uploaded_file|save\(|writeFile|file_put_contents|open\(|rename|copy|upload|filename|basename)\b",
    ],
    "missing_sanitizer_state": [
        r"\b(escape|htmlspecialchars|htmlentities|sanitize|clean|purify|whitelist|allowed|basename|realpath|autoescape)\b",
    ],
    "missing_reachability": [
        r"\b(route|router|action|performer|controller|dispatch|mount|urlpatterns|app\.|server\.|middleware)\b",
    ],
    "missing_runtime_config": [
        r"\b(config|settings|env|getenv|ini_get|yaml|json|toml|dotenv|constant)\b",
    ],
}

_auditor_concurrency_override: ContextVar[int | None] = ContextVar(
    "auditor_concurrency_override", default=None
)


def _env_auditor_concurrency_default() -> int:
    return max(1, min(2500, int(os.environ.get("AUDITOR_CONCURRENCY", "8"))))


def auditor_concurrency() -> int:
    override = _auditor_concurrency_override.get()
    if override is not None:
        return override
    return _env_auditor_concurrency_default()


def set_auditor_concurrency(value: int) -> object:
    return _auditor_concurrency_override.set(max(1, min(2500, int(value))))


def reset_auditor_concurrency(token: object) -> None:
    _auditor_concurrency_override.reset(token)

LLM_TOOL_NAMES = {
    "tldr__tldr_extract",
    "tldr__tldr_impact",
    "tldr__tldr_calls",
    "tldr__tldr_search",
    "ripgrep__search",
    "ripgrep__advanced-search",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
REVIEW_FIELD_DEFAULTS = {
    "Codex核验": "",
    "Codex-Review": "",
    "Codex核验时间": "",
    "人工核验": "",
    "人工-Review": "",
    "人工核验时间": "",
    "CC核验": "",
    "CC-Review": "",
    "CC核验时间": "",
}

# ── helpers ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuditorSpec:
    name: str = "Auditor Agent"
    system_message: str = load_prompt("auditor.md")
    temperature: float = 0.0
    max_tokens: int = 4000


SPEC = AuditorSpec()


def _load_skill(language: str, vulnerability_type: str) -> str:
    """Try <skills>/<lang>/<vuln>.md, then _default.md. Return markdown."""
    candidates = [
        SKILLS_DIR / language / f"{vulnerability_type}.md",
        SKILLS_DIR / "_default.md",
    ]
    for path in candidates:
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    return ""


def _skill_header(language: str, vulnerability_type: str) -> str:
    return (
        f"\n\n<!-- SKILL: {language} / {vulnerability_type} -->\n"
        "============================================================\n"
        f"# Skill Knowledge Block — {language} / {vulnerability_type}\n"
        "============================================================\n"
    )


def _load_auditor_chains(*paths: Path) -> list[dict[str, Any]]:
    """Load CallScan and DataFlowScan chain JSONL records with de-duplication."""
    chains: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line_s = line.strip()
                if not line_s:
                    continue
                try:
                    obj = json.loads(line_s)
                except json.JSONDecodeError:
                    continue
                if obj.get("type") != "chain":
                    continue
                chain_id = str(obj.get("chain_id") or obj.get("id") or "").strip()
                if not chain_id:
                    continue
                if _skip_dataflow_chain_for_auditor(obj, path):
                    continue
                if chain_id in seen:
                    continue
                seen.add(chain_id)
                chains.append(obj)
    return chains


def _skip_dataflow_chain_for_auditor(obj: dict[str, Any], path: Path) -> bool:
    """Keep weak DataFlow evidence visible in UI but out of default LLM audit."""
    if path.name != DATAFLOW_CHAINS_JSONL:
        return False
    if obj.get("chain_kind") not in {"cross_request", "recovered_partial"}:
        return False
    quality = str(obj.get("evidence_quality") or "").strip().lower()
    if obj.get("suppressed") is True:
        return True
    return quality == "weak"


# ── main entry ─────────────────────────────────────────────────────────────


def run(project_path: str, run_id: str | None = None) -> dict:
    return asyncio.run(_run_async(project_path, run_id=run_id))


async def _run_async(project_path: str, run_id: str | None = None) -> dict:
    conc_token: object | None = None
    if run_id:
        try:
            from app.server import scans as scans_mod

            meta = scans_mod.get_scan(project_path, run_id)
            opts = meta.get("options") or {}
            if "auditor_concurrency" in opts:
                conc_token = set_auditor_concurrency(int(opts["auditor_concurrency"]))
        except FileNotFoundError:
            pass
    concurrency = auditor_concurrency()
    info(f"Auditor concurrency: {concurrency} chain(s) in parallel")
    try:
        return await _run_async_body(project_path, run_id=run_id, concurrency=concurrency)
    finally:
        if conc_token is not None:
            reset_auditor_concurrency(conc_token)


async def _run_async_body(
    project_path: str,
    run_id: str | None = None,
    *,
    concurrency: int,
) -> dict:
    started_at = time.perf_counter()
    scope = resolve_run_scope(project_path, run_id)
    project_root = scope.project_root
    callscan_path = scope.artifacts_dir / CALLSCAN_CHAINS_JSONL
    legacy_priority_path = scope.artifacts_dir / CALLSCAN_PRIORITY_JSONL
    dataflow_path = scope.artifacts_dir / DATAFLOW_CHAINS_JSONL
    output_json = scope.artifacts_dir / AUDIT_JSON_FILENAME
    output_md = scope.artifacts_dir / AUDIT_MD_FILENAME

    if scope.mode == "specific":
        info(
            f"Specific Auditor scope: run_id={scope.run_id} "
            f"target={scope.target_rel_dir}"
        )

    callscan_inputs = [callscan_path] if callscan_path.is_file() else []
    if not callscan_inputs and legacy_priority_path.is_file():
        callscan_inputs = [legacy_priority_path]
        info(
            "Auditor: full CallScan chain file not found; "
            f"falling back to legacy {legacy_priority_path.name}"
        )

    if not callscan_inputs and not dataflow_path.is_file():
        raise FileNotFoundError(
            f"Auditable chain file not found: {callscan_path}, "
            f"{legacy_priority_path}, or {dataflow_path}. "
            "Run CallScan/DataFlowScan first."
        )

    # 1) load all CallScan candidates plus auditable DataFlow chains
    chains = _load_auditor_chains(*callscan_inputs, dataflow_path)
    if not chains:
        info("Auditor: no auditable candidate chains — nothing to audit.")
        result = _empty_result(project_path, project_root, started_at, scope)
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        action("Write", str(output_json))
        _write_findings_md([], output_md, project_path, scope)
        action("Write", str(output_md))
        return result

    progress_path = scope.artifacts_dir / AUDIT_PROGRESS_JSONL
    failures_path = scope.artifacts_dir / AUDIT_FAILURES_JSONL
    resumed_findings = _sanitize_audit_progress_file(progress_path)
    if resumed_findings:
        info(
            f"Auditor resume: {len(resumed_findings)} chain(s) already audited "
            f"(checkpoint: {progress_path.name})"
        )

    # 2) sort highest-severity first
    chains.sort(
        key=lambda c: (
            2 if c.get("chain_kind") == "cross_request" else 1,
            SEVERITY_RANK.get(c.get("severity") or "", 0),
            1 if c.get("has_call_chain") else 0,
        ),
        reverse=True,
    )
    done_ids = set(resumed_findings)
    chains = [c for c in chains if str(c.get("chain_id") or "") not in done_ids]
    if not chains and resumed_findings:
        info("Auditor: all candidate chains already in checkpoint — finalizing artifacts.")
        findings = list(resumed_findings.values())
        counter = _counter_from_findings(findings)
        result = _build_result(
            findings, project_path, project_root, started_at, counter, scope
        )
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        action("Write", str(output_json))
        _write_findings_md(findings, output_md, project_path, scope)
        action("Write", str(output_md))
        return result

    info(f"Auditor: {len(chains)} candidate chain(s) to audit")

    # 3) run audits concurrently (semaphore-gated)
    findings: list[dict[str, Any]] = list(resumed_findings.values())
    findings_lock = asyncio.Lock()
    mcp_pool = min(concurrency, MAX_AUDITOR_MCP_POOL)
    async with MCPToolbox(
        default_server_specs(project_root), pool_size=mcp_pool
    ) as toolbox:
        visible = len(set(toolbox.tool_names) & LLM_TOOL_NAMES)
        info(
            f"Auditor: MCP tools loaded: {len(toolbox.tool_names)} "
            f"(LLM-visible: {visible}, pool={toolbox.pool_size})"
        )

        semaphore = asyncio.Semaphore(concurrency)
        total = len(chains) + len(resumed_findings)
        counter = _counter_from_findings(resumed_findings.values())
        counter.setdefault("failed", 0)
        counter_lock = asyncio.Lock()
        in_flight: dict[str, str] = {}
        in_flight_lock = asyncio.Lock()

        print_status(
            "auditor",
            active=True,
            label=f"auditor 进度 {counter['done']}/{total}",
            detail=f"已运行 0s · 并发 {concurrency}",
        )

        async def _heartbeat() -> None:
            while True:
                await asyncio.sleep(AUDITOR_HEARTBEAT_SECS)
                async with counter_lock:
                    done = counter["done"]
                async with in_flight_lock:
                    flying = len(in_flight)
                    sample = next(iter(in_flight.values()), "")
                elapsed = time.perf_counter() - started_at
                detail = (
                    f"已运行 {elapsed:.0f}s · 并发 {concurrency}"
                    f" · 进行中 {flying}"
                )
                if sample:
                    detail += f" · {sample}"
                print_status(
                    "auditor",
                    active=True,
                    label=f"auditor 进度 {done}/{total}",
                    detail=detail,
                )
                write_event(
                    "auditor_heartbeat",
                    done=done,
                    total=total,
                    elapsed=elapsed,
                    in_flight=flying,
                    sample=sample or None,
                )

        hb = asyncio.create_task(_heartbeat())
        try:
            tasks = [
                asyncio.create_task(
                    _audit_one_chain(
                        idx,
                        chain,
                        toolbox,
                        semaphore,
                        total,
                        counter,
                        counter_lock,
                        in_flight,
                        in_flight_lock,
                        project_root,
                        progress_path,
                        failures_path,
                        findings,
                        findings_lock,
                        output_json,
                        output_md,
                        project_path,
                        scope,
                        started_at,
                    )
                )
                for idx, chain in enumerate(chains, len(resumed_findings) + 1)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            hb.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await hb
            print_status("auditor", active=False)
        for item in results:
            if isinstance(item, BaseException):
                info(
                    f"Auditor task error: {type(item).__name__}: {item}"
                )

    # 4) persist (exclude LLM transport failures — not audit conclusions)
    findings = _publishable_findings([f for f in findings if f is not None])
    result = _build_result(
        findings, project_path, project_root, started_at, counter, scope
    )
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    action("Write", str(output_json))
    _write_findings_md(findings, output_md, project_path, scope)
    action("Write", str(output_md))

    elapsed = time.perf_counter() - started_at
    failed = counter.get("failed", 0)
    tail = f", {failed} LLM failed (not in report)" if failed else ""
    info(
        f"Auditor: {counter['done']} chain(s) done "
        f"({counter['vulnerable']} vulnerable / "
        f"{counter['uncertain']} uncertain / "
        f"{counter['safe']} safe{tail}) "
        f"in {elapsed:.2f}s"
    )
    return result


# ── per-chain audit ────────────────────────────────────────────────────────


async def _audit_one_chain(
    index: int,
    chain: dict[str, Any],
    toolbox: MCPToolbox,
    semaphore: asyncio.Semaphore,
    total: int,
    counter: dict[str, int],
    counter_lock: asyncio.Lock,
    in_flight: dict[str, str],
    in_flight_lock: asyncio.Lock,
    project_root: Path,
    progress_path: Path,
    failures_path: Path,
    findings: list[dict[str, Any]],
    findings_lock: asyncio.Lock,
    output_json: Path,
    output_md: Path,
    project_path: str,
    scope: RunScope,
    started_at: float,
) -> dict[str, Any] | None:
    async with semaphore:
        chain_id = chain.get("chain_id") or f"C-{index:06d}"
        chain_kind = chain.get("chain_kind") or "direct_call"
        language = chain.get("language") or "unknown"
        vuln = chain.get("vulnerability_type") or "unknown"
        sink_file = chain.get("sink_file") or ""
        sink_line = chain.get("sink_line") or 0
        audit_pack = chain.get("audit_pack") or ""
        severity = chain.get("severity") or "medium"
        sink_label = f"{sink_file}:{sink_line}"

        prechecked = _prechecked_dataflow_finding(chain, language, vuln)
        if prechecked:
            async with counter_lock:
                counter["done"] += 1
                idx = counter["done"]
                counter["safe"] = counter.get("safe", 0) + 1
            async with findings_lock:
                findings.append(prechecked)
                _append_audit_progress(progress_path, prechecked)
                _persist_audit_checkpoint(
                    findings,
                    output_json,
                    output_md,
                    project_path,
                    project_root,
                    started_at,
                    counter,
                    scope,
                )
            console.print(
                f"  [bold green]S[/] [dim]\\[{idx}/{total} precheck][/] "
                f"[bold]{prechecked.get('title')}[/] [dim]@ {sink_label}[/]"
            )
            return prechecked

        skill_md = _load_skill(language, vuln)
        system_message = SPEC.system_message
        if skill_md:
            system_message += _skill_header(language, vuln) + "\n" + skill_md

        user_message = (
            f"chain_id: {chain_id}\n"
            f"chain_kind: {chain_kind}\n"
            f"language: {language} / vulnerability_type: {vuln}\n"
            f"severity: {severity}\n"
            f"sink location: {sink_label}\n\n"
            f"{audit_pack}"
        )

        t0 = time.perf_counter()
        async with in_flight_lock:
            in_flight[chain_id] = sink_label
        try:
            finding = await asyncio.wait_for(
                _audit_with_repair_loop(
                    chain=chain,
                    language=language,
                    vulnerability_type=vuln,
                    system_message=system_message,
                    user_message=user_message,
                    project_root=project_root,
                    toolbox=toolbox,
                ),
                timeout=AUDITOR_CHAIN_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            elapsed = time.perf_counter() - t0
            async with counter_lock:
                counter["failed"] = counter.get("failed", 0) + 1
                fail_idx = counter.get("failed", 0)
            _append_audit_failure(
                failures_path,
                chain_id=chain_id,
                chain=chain,
                error_type="TimeoutError",
                error=f"chain audit exceeded {AUDITOR_CHAIN_TIMEOUT_S:.0f}s",
            )
            console.print(
                f"  [bold red]FAIL[/] [dim]\\[{fail_idx} timeout][/] "
                f"[dim]{chain_id} @ {sink_label} "
                f"({elapsed:.1f}s)[/]"
            )
            return None
        except Exception as exc:  # noqa: BLE001
            elapsed = time.perf_counter() - t0
            async with counter_lock:
                counter["failed"] = counter.get("failed", 0) + 1
                fail_idx = counter.get("failed", 0)
            _append_audit_failure(
                failures_path,
                chain_id=chain_id,
                chain=chain,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            console.print(
                f"  [bold red]FAIL[/] [dim]\\[{fail_idx} llm error][/] "
                f"[dim]{chain_id} @ {sink_file}:{sink_line} "
                f"({type(exc).__name__}, {elapsed:.1f}s)[/]"
            )
            info(
                f"Auditor LLM failed for {chain_id}: {type(exc).__name__}: {exc} "
                f"(not written to audit findings; will retry on resume)"
            )
            return None
        finally:
            async with in_flight_lock:
                in_flight.pop(chain_id, None)

        elapsed = time.perf_counter() - t0

        if _is_skipped_audit_finding(finding):
            return None
        verdict = finding.get("verdict") or "uncertain"
        title = finding.get("title") or f"{vuln} @ {sink_file}:{sink_line}"

        async with counter_lock:
            counter["done"] += 1
            idx = counter["done"]
            counter[verdict] = counter.get(verdict, 0) + 1

        v_color = {"vulnerable": "red", "uncertain": "yellow", "safe": "green"}
        console.print(
            f"  [bold {v_color.get(verdict, 'dim')}]{verdict[0].upper()}[/] "
            f"[dim]\\[{idx}/{total}][/] "
            f"[bold]{title}[/] [dim]@ {sink_file}:{sink_line} "
            f"({elapsed:.1f}s)[/]"
        )
        async with findings_lock:
            findings.append(finding)
            _append_audit_progress(progress_path, finding)
            _persist_audit_checkpoint(
                findings,
                output_json,
                output_md,
                project_path,
                project_root,
                started_at,
                counter,
                scope,
            )
        return finding


# ── LLM tool loop ───────────────────────────────────────────────────────────


async def _audit_with_repair_loop(
    *,
    chain: dict[str, Any],
    language: str,
    vulnerability_type: str,
    system_message: str,
    user_message: str,
    project_root: Path,
    toolbox: MCPToolbox,
) -> dict[str, Any]:
    raw_result = await _run_audit_tool_loop(system_message, user_message, project_root, toolbox)
    finding = _parse_finding(raw_result, chain, language, vulnerability_type)
    _ensure_repair_fields(finding, chain, repair_rounds=0)
    if not _finding_needs_repair(finding):
        return finding

    if MAX_REPAIR_ROUNDS <= 0:
        return finding

    missing = _normalized_missing_breakpoints(chain, finding)
    if not missing:
        return finding

    repair_tasks = _build_repair_tasks(chain, missing)
    evidence_patch = _run_repair_tasks(project_root, repair_tasks)
    repaired_chain = _merge_repair_evidence(chain, missing, repair_tasks, evidence_patch)
    repaired_user_message = _append_repair_block_to_user_message(
        user_message,
        missing=missing,
        repair_tasks=repair_tasks,
        evidence_patch=evidence_patch,
    )
    repaired_raw = await _run_audit_tool_loop(
        system_message, repaired_user_message, project_root, toolbox
    )
    repaired_finding = _parse_finding(
        repaired_raw, repaired_chain, language, vulnerability_type
    )
    _ensure_repair_fields(repaired_finding, repaired_chain, repair_rounds=1)
    if repaired_finding.get("verdict") == "uncertain":
        unresolved = repaired_finding.get("unresolved_evidence") or missing
        repaired_finding["blocking_reason"] = _blocking_reason(unresolved)
        repaired_finding["manual_verification_steps"] = _manual_verification_steps(unresolved)
    return repaired_finding


def _finding_needs_repair(finding: dict[str, Any]) -> bool:
    verdict = str(finding.get("verdict") or "uncertain")
    return verdict == "uncertain" or bool(finding.get("missing_info"))


def _ensure_repair_fields(
    finding: dict[str, Any],
    chain: dict[str, Any],
    *,
    repair_rounds: int,
) -> None:
    sink_rule = chain.get("sink_rule") if isinstance(chain.get("sink_rule"), dict) else {}
    finding.setdefault("sink_level", chain.get("sink_level") or sink_rule.get("level") or "L0")
    finding.setdefault("semantic_tags", chain.get("semantic_tags") or sink_rule.get("semantic_tags") or [])
    finding.setdefault("required_evidence", chain.get("required_evidence") or sink_rule.get("required_evidence") or [])
    finding.setdefault("resolved_evidence", chain.get("resolved_evidence") or [])
    finding.setdefault("unresolved_evidence", chain.get("unresolved_evidence") or [])
    finding.setdefault("repair_rounds", repair_rounds)
    finding.setdefault("repair_trace", chain.get("repair_trace") or [])
    finding.setdefault("blocking_reason", "")
    finding.setdefault("manual_verification_steps", [])


def _normalized_missing_breakpoints(chain: dict[str, Any], finding: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    values.extend(chain.get("breakpoints") or [])
    values.extend(chain.get("required_evidence") or [])
    sink_rule = chain.get("sink_rule") if isinstance(chain.get("sink_rule"), dict) else {}
    values.extend(sink_rule.get("required_evidence") or [])
    values.extend(finding.get("missing_info") or [])
    normalized: list[str] = []
    for value in values:
        bp = _normalize_repair_breakpoint(value)
        if bp and bp not in normalized:
            normalized.append(bp)
    return normalized


def _normalize_repair_breakpoint(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in REPAIR_BREAKPOINTS:
        return text
    if text in REQUIRED_EVIDENCE_TO_BREAKPOINT:
        return REQUIRED_EVIDENCE_TO_BREAKPOINT[text]
    if any(token in text for token in ("source", "entry", "入口", "可控")):
        return "missing_source_entry"
    if any(token in text for token in ("permission", "auth", "权限", "登录", "管理员")):
        return "missing_permission_check"
    if any(token in text for token in ("template", "render", "binding", "模板", "渲染")):
        return "missing_template_binding"
    if any(token in text for token in ("sql", "column", "table", "字段", "表")):
        return "missing_sql_column_mapping"
    if any(token in text for token in ("storage", "db", "config", "存储", "读取")):
        return "missing_storage_read"
    if any(token in text for token in ("file", "path", "filename", "文件", "路径")):
        return "missing_file_save_path"
    if any(token in text for token in ("sanitize", "escape", "filter", "过滤", "转义", "校验")):
        return "missing_sanitizer_state"
    if any(token in text for token in ("reach", "route", "可达", "路由", "调用")):
        return "missing_reachability"
    if any(token in text for token in ("runtime", "config", "环境", "配置")):
        return "missing_runtime_config"
    return None


def _build_repair_tasks(chain: dict[str, Any], missing: list[str]) -> list[dict[str, Any]]:
    search_path = _repair_search_path(chain)
    tasks: list[dict[str, Any]] = []
    for kind in missing[:8]:
        for pattern in REPAIR_PATTERNS.get(kind, [])[:2]:
            tasks.append({"kind": kind, "tool": "ripgrep", "pattern": pattern, "path": search_path})
    return tasks


def _repair_search_path(chain: dict[str, Any]) -> str:
    value = str(chain.get("sink_file") or "").strip()
    if value and "/" in value:
        return value.rsplit("/", 1)[0]
    if value and "\\" in value:
        return value.rsplit("\\", 1)[0]
    return "."


def _run_repair_tasks(project_root: Path, tasks: list[dict[str, Any]]) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    resolved: list[str] = []
    for task in tasks[:12]:
        result = _run_local_rg_hot(
            "ripgrep__search",
            {"pattern": task.get("pattern"), "path": task.get("path"), "caseSensitive": False},
            project_root,
        )
        text = str(result.get("text") or "")
        if result.get("is_error") or not text.strip():
            continue
        kind = str(task.get("kind") or "")
        if kind and kind not in resolved:
            resolved.append(kind)
        evidence.append(
            {
                "source": "evidence_repair_rg",
                "missing_kind": kind,
                "pattern": task.get("pattern"),
                "path": task.get("path"),
                "detail": _trim_repair_text(text),
            }
        )
    return {"resolved_evidence": resolved, "evidence": evidence}


def _merge_repair_evidence(
    chain: dict[str, Any],
    missing: list[str],
    repair_tasks: list[dict[str, Any]],
    evidence_patch: dict[str, Any],
) -> dict[str, Any]:
    repaired = dict(chain)
    resolved = _dedupe_texts(
        list(chain.get("resolved_evidence") or [])
        + list(evidence_patch.get("resolved_evidence") or [])
    )
    unresolved = [item for item in missing if item not in resolved]
    repaired["resolved_evidence"] = resolved
    repaired["unresolved_evidence"] = unresolved
    repaired["repair_rounds"] = 1
    repaired["repair_trace"] = list(chain.get("repair_trace") or []) + [
        {
            "round": 1,
            "missing": missing,
            "resolved": resolved,
            "unresolved": unresolved,
            "task_count": len(repair_tasks),
            "evidence_count": len(evidence_patch.get("evidence") or []),
        }
    ]
    repaired["evidence"] = list(chain.get("evidence") or []) + list(evidence_patch.get("evidence") or [])
    repaired["audit_pack"] = (
        str(chain.get("audit_pack") or "")
        + "\n\n## Evidence Repair Patch\n"
        + _repair_patch_markdown(missing, repair_tasks, evidence_patch)
    ).strip() + "\n"
    return repaired


def _append_repair_block_to_user_message(
    user_message: str,
    *,
    missing: list[str],
    repair_tasks: list[dict[str, Any]],
    evidence_patch: dict[str, Any],
) -> str:
    return user_message.rstrip() + "\n\n# Evidence Repair Patch\n" + _repair_patch_markdown(
        missing, repair_tasks, evidence_patch
    )


def _repair_patch_markdown(
    missing: list[str],
    repair_tasks: list[dict[str, Any]],
    evidence_patch: dict[str, Any],
) -> str:
    lines = [
        f"missing_breakpoints: {', '.join(missing) if missing else '(none)'}",
        f"repair_task_count: {len(repair_tasks)}",
    ]
    evidence = evidence_patch.get("evidence") or []
    if evidence:
        lines.append("## Recovered evidence")
        for item in evidence[:10]:
            lines.append(
                f"- {item.get('missing_kind')} via `{item.get('pattern')}` "
                f"in `{item.get('path')}`: {item.get('detail')}"
            )
    else:
        lines.append("No additional code evidence was recovered by repair search.")
    return "\n".join(lines).rstrip() + "\n"


def _blocking_reason(unresolved: list[str]) -> str:
    if not unresolved:
        return ""
    return "自动补证据后仍缺少关键断点：" + "、".join(unresolved)


def _manual_verification_steps(unresolved: list[str]) -> list[str]:
    mapping = {
        "missing_source_entry": "人工确认外部入口和攻击者可控参数。",
        "missing_permission_check": "人工确认入口前是否存在权限/登录/角色校验。",
        "missing_template_binding": "人工追踪 controller/render/assign 到模板变量的绑定。",
        "missing_sql_column_mapping": "人工确认 SQL/ORM 读写是否为同一 table.column。",
        "missing_storage_read": "人工确认持久化写入后是否被后续请求读取。",
        "missing_file_save_path": "人工确认上传/写入文件的保存路径、扩展名和 Web 可达性。",
        "missing_sanitizer_state": "人工确认进入 sink 前是否有强转义、白名单或路径约束。",
        "missing_reachability": "人工确认 sink 所在函数是否可由路由/调度器触发。",
        "missing_runtime_config": "人工确认运行时配置是否开启相关功能或保护。",
    }
    return [mapping.get(item, f"人工验证断点：{item}") for item in unresolved]


def _trim_repair_text(text: str, *, limit: int = 600) -> str:
    return " ".join(str(text or "").split())[:limit]


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _dedupe_texts(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


async def _run_audit_tool_loop(
    system_message: str,
    user_message: str,
    project_root: Path,
    toolbox: MCPToolbox,
) -> dict[str, Any] | None:
    """Multi-turn: feed system+user, handle tool calls, repeat until
    the model emits a JSON object with no tool_calls."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message},
    ]
    tools = toolbox.as_litellm_tools(LLM_TOOL_NAMES)

    round_count = 0
    seen_tool_calls: dict[str, int] = {}

    while True:
        round_count += 1
        if round_count > MAX_TOOL_ROUNDS:
            # One last attempt: drop tools and force a JSON verdict so we don't
            # ship "tool-loop exhausted" placeholders as audit results.
            return await _force_final_verdict(messages)

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
            if isinstance(parsed, dict) and "verdict" in parsed:
                return parsed
            return {"verdict": "uncertain", "confidence": 0.5,
                    "_message_content": raw}

        # ensure IDs
        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            args_s = fn.get("arguments") or "{}"
            if not tc.get("id"):
                tc["id"] = "audit_" + _stable_hash(f"{name}:{args_s}")[:16]
            tc.setdefault("type", "function")

        assistant_msg = {
            "role": "assistant",
            "content": message.get("content") or "",
            "tool_calls": tool_calls,
        }
        if message.get("reasoning_content"):
            assistant_msg["reasoning_content"] = message["reasoning_content"]
        messages.append(assistant_msg)

        async def _dispatch_tool(tc: dict[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
            fn = tc.get("function") or {}
            name = fn.get("name")
            raw_args = fn.get("arguments") or "{}"
            tc_id = tc["id"]
            arguments = _json_object(raw_args)

            repeat_key = (
                f"{name}:{json.dumps(arguments, sort_keys=True, ensure_ascii=False)}"
            )
            seen_tool_calls[repeat_key] = seen_tool_calls.get(repeat_key, 0) + 1
            if seen_tool_calls[repeat_key] > 2:
                tool_result = {
                    "tool": name,
                    "is_error": True,
                    "text": "Repeated identical tool call; use existing result.",
                }
            else:
                tool_result = await _execute_tool(
                    name, arguments, toolbox, project_root
                )
            return tc_id, name, tool_result

        tool_results = await asyncio.gather(
            *[_dispatch_tool(tc) for tc in tool_calls]
        )
        for tc_id, name, tool_result in tool_results:
            text = json.dumps(tool_result, ensure_ascii=False)
            if len(text) > TOOL_RESULT_CHAR_LIMIT:
                tool_result["text"] = text[:TOOL_RESULT_CHAR_LIMIT]

            messages.append({
                "role": "tool", "tool_call_id": tc_id, "name": name,
                "content": json.dumps(tool_result, ensure_ascii=False)[:TOOL_RESULT_CHAR_LIMIT],
            })


async def _force_final_verdict(
    messages: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Tool-loop budget exhausted: ask the model to commit to a JSON verdict
    without any tools so we never persist a 'tool-loop exhausted' placeholder."""
    forced = list(messages) + [
        {
            "role": "user",
            "content": (
                "Tool budget exhausted. Do not request any more tools. "
                "Based strictly on the evidence already gathered, return ONLY "
                "the final audit JSON object. If evidence is insufficient, "
                "use verdict=\"uncertain\" with missing_info and a clear principle."
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
        # Bubble up — the caller already converts this into an audit_failures row.
        raise exc

    message = response_message_to_dict(response)
    raw = message.get("content") or ""
    parsed = _parse_json_from_text(raw)
    if isinstance(parsed, dict) and "verdict" in parsed:
        parsed.setdefault("_tool_stopped", "max_tool_rounds")
        return parsed
    return {
        "verdict": "uncertain",
        "confidence": 0.4,
        "title": "tool-loop exhausted",
        "_tool_stopped": "max_tool_rounds",
        "_message_content": raw,
    }


async def _execute_tool(
    name: str | None,
    arguments: dict[str, Any],
    toolbox: MCPToolbox,
    project_root: Path,
) -> dict[str, Any]:
    if name and name.startswith("ripgrep__"):
        return await asyncio.to_thread(
            _run_local_rg_hot, name, arguments, project_root
        )
    reject = _reject_broad_tldr_path(str(name or ""), arguments)
    if reject:
        return {"tool": name, "is_error": True, "text": reject}
    return await toolbox.call_tool(str(name), arguments)


def _reject_broad_tldr_path(name: str, arguments: dict[str, Any]) -> str | None:
    """Block whole-repo call-graph tools that can stall MCP for minutes."""
    if not name.startswith("tldr__"):
        return None
    if name in {"tldr__tldr_search"}:
        return None
    raw = str(arguments.get("path") or arguments.get("file") or "").strip()
    if raw in {"", "/", ".", "\\", ".."}:
        return (
            "Rejected overly broad path. Pass a specific file path "
            "(e.g. src/Foo.php), not the project root."
        )
    return None


def _run_local_rg_hot(
    tool_name: str,
    arguments: dict[str, Any],
    project_root: Path,
) -> dict[str, Any]:
    """Minimal local ripgrep executor."""
    rg_exe = PROJECT_ROOT / "ripgrep" / "rg.exe"
    if not rg_exe.is_file():
        return {"tool": tool_name, "is_error": True,
                "text": f"rg.exe not found: {rg_exe}"}

    pattern = str(arguments.get("pattern") or "")
    if not pattern:
        return {"tool": tool_name, "is_error": True, "text": "Missing pattern."}

    search_path = project_root
    user_path = arguments.get("path")
    if user_path:
        candidate = (project_root / str(user_path)).resolve()
        if candidate.as_posix().startswith(project_root.resolve().as_posix()):
            search_path = candidate

    cmd = [str(rg_exe), "-u", "-n"]
    if arguments.get("wordMatch"):
        cmd.append("-w")
    if arguments.get("caseSensitive") is True:
        cmd.append("-s")
    elif arguments.get("caseSensitive") is False:
        cmd.append("-i")
    if arguments.get("filePattern"):
        cmd.extend(["--glob", str(arguments["filePattern"])])
    if arguments.get("fileType"):
        cmd.extend(["-t", str(arguments["fileType"])])
    ctx = arguments.get("context")
    if isinstance(ctx, int) and ctx > 0:
        cmd.extend(["-C", str(ctx)])
    max_results = int(arguments.get("maxResults") or 30)
    cmd.extend(["-e", pattern, str(search_path)])

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=RG_SEARCH_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": tool_name,
            "is_error": True,
            "text": f"ripgrep timed out after {RG_SEARCH_TIMEOUT_S:.0f}s",
        }
    if completed.returncode not in (0, 1):
        return {"tool": tool_name, "is_error": True,
                "text": completed.stderr.strip() or completed.stdout.strip()}
    lines = completed.stdout.splitlines()
    return {"tool": tool_name, "server": "local-ripgrep", "is_error": False,
            "text": "\n".join(lines[:max_results])}


# ── parse / build finding ──────────────────────────────────────────────────


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
        s = stripped.find("{")
        e = stripped.rfind("}")
        if s >= 0 and e > s:
            try:
                return json.loads(stripped[s:e + 1])
            except json.JSONDecodeError:
                pass
    return None


def _json_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(str(raw or "{}"))
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


_CONFIDENCE_LABELS = {
    "very_high": 0.95,
    "high": 0.85,
    "medium_high": 0.75,
    "medium": 0.6,
    "medium_low": 0.45,
    "low": 0.35,
    "very_low": 0.2,
    "sure": 0.9,
    "likely": 0.75,
    "possible": 0.55,
    "unlikely": 0.3,
    "uncertain": 0.5,
}


def _string_value(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _mapping_value(value: Any, fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return dict(fallback or {})


def _text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    elif isinstance(value, tuple):
        items = list(value)
    else:
        items = [value]

    clean: list[str] = []
    for item in items:
        text = _string_value(item).strip()
        if text:
            clean.append(text)
    return clean


def _evidence_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    elif isinstance(value, tuple):
        items = list(value)
    else:
        items = [value]

    clean: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            clean.append(item)
            continue
        detail = _string_value(item).strip()
        if detail:
            clean.append({"source": "llm", "detail": detail})
    return clean


def _confidence_value(value: Any, default: float = 0.5) -> float:
    if value is None or isinstance(value, bool):
        confidence = default
    elif isinstance(value, (int, float)):
        confidence = float(value)
    else:
        text = str(value).strip()
        lowered = (
            text.lower()
            .replace("-", "_")
            .replace(" ", "_")
            .replace("/", "_")
        )
        confidence = _CONFIDENCE_LABELS.get(lowered)
        if confidence is None:
            if "高" in text:
                confidence = 0.85
            elif "中" in text:
                confidence = 0.6
            elif "低" in text:
                confidence = 0.35
            elif lowered.endswith("%"):
                try:
                    confidence = float(lowered[:-1]) / 100.0
                except ValueError:
                    confidence = default
            else:
                try:
                    confidence = float(lowered)
                except ValueError:
                    confidence = default

    if confidence > 1.0 and confidence <= 100.0:
        confidence = confidence / 100.0
    if confidence < 0.0 or confidence > 1.0:
        confidence = default
    return max(0.0, min(1.0, confidence))


def _verdict_value(value: Any) -> str:
    text = _string_value(value, "uncertain").strip().lower()
    if not text:
        return "uncertain"
    if text in {"vulnerable", "safe", "uncertain"}:
        return text
    if (
        "not vulnerable" in text
        or "not exploitable" in text
        or "false positive" in text
        or "safe" in text
        or "无漏洞" in text
        or "不存在" in text
        or "安全" in text
    ):
        return "safe"
    if "vulnerable" in text or "exploitable" in text or "存在漏洞" in text or "漏洞" in text:
        return "vulnerable"
    return "uncertain"


def _parse_finding(
    raw: Any,
    chain: dict[str, Any],
    language: str,
    vuln: str,
) -> dict[str, Any]:
    raw = _json_object(raw)
    if not raw:
        return _minimal_finding(chain)
    verdict = _verdict_value(raw.get("verdict"))
    confidence = _confidence_value(raw.get("confidence"), 0.5)
    if confidence < 0.5 and verdict == "vulnerable":
        verdict = "uncertain"
    missing_info = _text_list(raw.get("missing_info"))
    if missing_info and verdict == "vulnerable":
        verdict = "uncertain"
        confidence = min(confidence, 0.6)
    refuted_by = _string_value(raw.get("refuted_by")).strip() or None
    title = _string_value(
        raw.get("title"),
        f"{vuln} 风险点 @ {chain.get('sink_file')}:{chain.get('sink_line')}",
    )
    principle = _string_value(raw.get("principle")).strip()
    xss_refuted = _javascript_xss_refuted(chain, language, vuln, verdict)
    if xss_refuted:
        verdict = "safe"
        confidence = max(confidence, 0.95)
        refuted_by = xss_refuted
        title = "innerHTML 模板插值已被转义或约束，XSS 不成立"
        if not principle:
            principle = xss_refuted
    finding = {
        "chain_id": chain.get("chain_id"),
        "chain_kind": chain.get("chain_kind") or "direct_call",
        "index": chain.get("index"),
        "language": language,
        "vulnerability_type": vuln,
        "verdict": verdict,
        "confidence": confidence,
        "title": title,
        "cwe_guess": _string_value(raw.get("cwe_guess"), _cwe_default(vuln)),
        "severity": _string_value(raw.get("severity"), chain.get("severity") or "medium"),
        "principle": principle,
        "source": _mapping_value(raw.get("source")),
        "sink": _mapping_value(
            raw.get("sink"),
            {
                "file": chain.get("sink_file"),
                "line": chain.get("sink_line"),
                "expr": chain.get("sink_function"),
            },
        ),
        "data_flow": _text_list(raw.get("data_flow")),
        "exploit_poc": _string_value(raw.get("exploit_poc")).strip(),
        "fix_suggestion": _string_value(raw.get("fix_suggestion")).strip(),
        "refuted_by": refuted_by,
        "missing_info": missing_info,
        "evidence": _evidence_list(raw.get("evidence")),
        "sink_level": _string_value(raw.get("sink_level"), _chain_sink_level(chain)),
        "semantic_tags": _text_list(raw.get("semantic_tags")) or _chain_list(chain, "semantic_tags"),
        "required_evidence": _text_list(raw.get("required_evidence")) or _chain_required_evidence(chain),
        "resolved_evidence": _text_list(raw.get("resolved_evidence")) or _chain_list(chain, "resolved_evidence"),
        "unresolved_evidence": _text_list(raw.get("unresolved_evidence")) or _chain_list(chain, "unresolved_evidence"),
        "repair_rounds": _int_value(raw.get("repair_rounds") or chain.get("repair_rounds"), 0),
        "repair_trace": chain.get("repair_trace") if isinstance(chain.get("repair_trace"), list) else [],
        "blocking_reason": _string_value(raw.get("blocking_reason")).strip(),
        "manual_verification_steps": _text_list(raw.get("manual_verification_steps")),
        "storage": chain.get("storage") if isinstance(chain.get("storage"), dict) else None,
        "storage_identity": chain.get("storage_identity") if isinstance(chain.get("storage_identity"), dict) else None,
        "storage_edges": chain.get("storage_edges") if isinstance(chain.get("storage_edges"), list) else [],
        "binding_edges": chain.get("binding_edges") if isinstance(chain.get("binding_edges"), list) else [],
        "sanitizer_trace": chain.get("sanitizer_trace") if isinstance(chain.get("sanitizer_trace"), list) else [],
        "positive_evidence": chain.get("positive_evidence") if isinstance(chain.get("positive_evidence"), list) else [],
        "refuting_evidence": chain.get("refuting_evidence") if isinstance(chain.get("refuting_evidence"), list) else [],
        "weak_sanitizer": chain.get("weak_sanitizer") if isinstance(chain.get("weak_sanitizer"), list) else [],
        "noise_tags": chain.get("noise_tags") if isinstance(chain.get("noise_tags"), list) else [],
        "evidence_quality": chain.get("evidence_quality"),
        "evidence_score": chain.get("evidence_score"),
        "suppressed": chain.get("suppressed") is True,
        "breakpoints": chain.get("breakpoints") if isinstance(chain.get("breakpoints"), list) else [],
        "recovery_trace": chain.get("recovery_trace") if isinstance(chain.get("recovery_trace"), list) else [],
        "_tool_stopped": _string_value(raw.get("_tool_stopped")).strip() or None,
    }
    finding.update(_empty_review_fields())
    return finding


def _prechecked_dataflow_finding(
    chain: dict[str, Any],
    language: str,
    vuln: str,
) -> dict[str, Any] | None:
    if chain.get("chain_kind") not in {"cross_request", "recovered_partial"}:
        return None
    refuting = [
        item
        for item in chain.get("refuting_evidence") or []
        if isinstance(item, dict) and (item.get("evidence") or item.get("kind"))
    ]
    positive = [
        item
        for item in chain.get("positive_evidence") or []
        if isinstance(item, dict) and item.get("kind") != "dangerous_sink"
    ]
    if not refuting or positive:
        return None
    reason = "; ".join(
        str(item.get("kind") or item.get("evidence") or "refuting evidence")
        for item in refuting[:3]
    )
    finding = {
        "chain_id": chain.get("chain_id"),
        "chain_kind": chain.get("chain_kind") or "cross_request",
        "index": chain.get("index"),
        "language": language,
        "vulnerability_type": vuln,
        "verdict": "safe",
        "confidence": 0.95,
        "title": f"DataFlow strong sanitizer/refutation @ {chain.get('sink_file')}:{chain.get('sink_line')}",
        "cwe_guess": _cwe_default(vuln),
        "severity": chain.get("severity") or "medium",
        "principle": "DataFlowScan recovered strong refuting sanitizer evidence before the sink.",
        "source": None,
        "sink": {
            "file": chain.get("sink_file"),
            "line": chain.get("sink_line"),
            "expr": chain.get("sink_function"),
        },
        "data_flow": [],
        "exploit_poc": "",
        "fix_suggestion": "",
        "refuted_by": reason,
        "missing_info": [],
        "evidence": [
            {"source": "DataFlowScan", "detail": str(item.get("evidence") or item.get("kind") or "")}
            for item in refuting[:6]
        ],
        "storage": chain.get("storage") if isinstance(chain.get("storage"), dict) else None,
        "storage_identity": chain.get("storage_identity") if isinstance(chain.get("storage_identity"), dict) else None,
        "storage_edges": chain.get("storage_edges") if isinstance(chain.get("storage_edges"), list) else [],
        "binding_edges": chain.get("binding_edges") if isinstance(chain.get("binding_edges"), list) else [],
        "sanitizer_trace": chain.get("sanitizer_trace") if isinstance(chain.get("sanitizer_trace"), list) else [],
        "positive_evidence": chain.get("positive_evidence") if isinstance(chain.get("positive_evidence"), list) else [],
        "refuting_evidence": refuting,
        "weak_sanitizer": chain.get("weak_sanitizer") if isinstance(chain.get("weak_sanitizer"), list) else [],
        "noise_tags": chain.get("noise_tags") if isinstance(chain.get("noise_tags"), list) else [],
        "sink_level": _chain_sink_level(chain),
        "semantic_tags": _chain_list(chain, "semantic_tags"),
        "required_evidence": _chain_required_evidence(chain),
        "resolved_evidence": _chain_list(chain, "resolved_evidence"),
        "unresolved_evidence": _chain_list(chain, "unresolved_evidence"),
        "repair_rounds": int(chain.get("repair_rounds") or 0),
        "repair_trace": chain.get("repair_trace") if isinstance(chain.get("repair_trace"), list) else [],
        "blocking_reason": "",
        "manual_verification_steps": [],
        "evidence_quality": chain.get("evidence_quality"),
        "evidence_score": chain.get("evidence_score"),
        "suppressed": chain.get("suppressed") is True,
        "breakpoints": chain.get("breakpoints") if isinstance(chain.get("breakpoints"), list) else [],
        "recovery_trace": chain.get("recovery_trace") if isinstance(chain.get("recovery_trace"), list) else [],
    }
    finding.update(_empty_review_fields())
    return finding


def _chain_sink_level(chain: dict[str, Any]) -> str:
    sink_rule = chain.get("sink_rule") if isinstance(chain.get("sink_rule"), dict) else {}
    return str(chain.get("sink_level") or sink_rule.get("level") or "L0")


def _chain_list(chain: dict[str, Any], key: str) -> list[str]:
    values = chain.get(key)
    if not values:
        sink_rule = chain.get("sink_rule") if isinstance(chain.get("sink_rule"), dict) else {}
        values = sink_rule.get(key)
    return [str(item) for item in values or [] if item]


def _chain_required_evidence(chain: dict[str, Any]) -> list[str]:
    values = _chain_list(chain, "required_evidence")
    for value in chain.get("breakpoints") or []:
        text = str(value or "").strip()
        if text and text not in values:
            values.append(text)
    return values


_JS_TEMPLATE_EXPR_RE = re.compile(r"\$\{([^{}]+)\}", re.DOTALL)
_JS_SAFE_TERNARY_RE = re.compile(
    r"""^[^?]+\?\s*(['"]).*?\1\s*:\s*(['"]).*?\2$""",
    re.DOTALL,
)


def _javascript_template_xss_refuted(
    chain: dict[str, Any],
    language: str,
    vuln: str,
    verdict: str,
) -> str | None:
    if language != "javascript" or vuln != "xss" or verdict != "vulnerable":
        return None
    audit_pack = chain.get("audit_pack") or ""
    if "innerHTML" not in audit_pack:
        return None
    sink_function = _sink_function_name(chain)
    if not sink_function:
        return None
    code = _extract_audit_pack_function(audit_pack, sink_function)
    if not code or "innerHTML" not in code or "${" not in code:
        return None
    if "escapeHtml(" not in code:
        return None
    template = _extract_innerhtml_template(code)
    if not template:
        return None

    exprs = [expr.strip() for expr in _JS_TEMPLATE_EXPR_RE.findall(template)]
    if not exprs:
        return None
    for expr in exprs:
        if _js_template_expr_is_safe(expr):
            continue
        return None
    return "审计包中的模板插值均为 escapeHtml(...)、formatDate(...)、数值字段或固定字面量，未发现原始用户输入直接进入 innerHTML。"


def _javascript_helper_xss_refuted(
    chain: dict[str, Any],
    language: str,
    vuln: str,
    verdict: str,
) -> str | None:
    if language != "javascript" or vuln != "xss" or verdict not in {"vulnerable", "uncertain"}:
        return None
    audit_pack = chain.get("audit_pack") or ""
    sink_function = _sink_function_name(chain)
    if not sink_function:
        return None
    sink_code = _extract_audit_pack_function(audit_pack, sink_function)
    if not sink_code or "innerHTML" not in sink_code:
        return None
    helper_names = re.findall(r"map\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", sink_code)
    if not helper_names:
        return None
    seen = set()
    unique_helpers = [name for name in helper_names if not (name in seen or seen.add(name))]
    if not unique_helpers:
        return None
    for helper_name in unique_helpers:
        helper_code = _extract_audit_pack_function(audit_pack, helper_name)
        if not helper_code or "escapeHtml(" not in helper_code:
            return None
        exprs = [expr.strip() for expr in _JS_TEMPLATE_EXPR_RE.findall(helper_code)]
        if not exprs:
            return None
        for expr in exprs:
            if _js_template_expr_is_safe(expr, helper_code):
                continue
            return None
    helpers = ", ".join(unique_helpers)
    return f"审计包中的渲染 helper（{helpers}）对模板中的用户可控字段均使用 escapeHtml 或受限的局部安全片段，未发现原始输入直接进入 innerHTML。"


def _javascript_xss_refuted(
    chain: dict[str, Any],
    language: str,
    vuln: str,
    verdict: str,
) -> str | None:
    return _javascript_template_xss_refuted(chain, language, vuln, verdict) or _javascript_helper_xss_refuted(
        chain,
        language,
        vuln,
        verdict,
    )


def _sink_function_name(chain: dict[str, Any]) -> str | None:
    for call_chain in chain.get("call_chains") or []:
        if not call_chain:
            continue
        node = call_chain[-1]
        function_name = node.get("function")
        if function_name and function_name != "<module>":
            return str(function_name)
    return None


def _extract_audit_pack_function(audit_pack: str, function_name: str) -> str | None:
    pattern = re.compile(
        rf"###\s+{re.escape(function_name)}\s+\([^)]+\)\n```[a-zA-Z0-9_+-]*\n(.*?)\n```",
        re.DOTALL,
    )
    match = pattern.search(audit_pack)
    if match:
        return match.group(1)
    return None


def _extract_innerhtml_template(code: str) -> str | None:
    marker = "innerHTML"
    start = code.find(marker)
    if start < 0:
        return None
    tick_start = code.find("`", start)
    if tick_start < 0:
        return None
    tick_end = code.find("`", tick_start + 1)
    if tick_end < 0:
        return None
    return code[tick_start + 1 : tick_end]


def _js_template_expr_is_safe(expr: str, code: str = "") -> bool:
    compact = " ".join(expr.split())
    if not compact:
        return True
    if "escapeHtml(" in compact or "formatDate(" in compact:
        return True
    if _JS_SAFE_TERNARY_RE.match(compact):
        return True
    if "?? 0" in compact:
        return True
    numeric_hints = (
        ".length",
        ".views",
        ".likes",
        ".like_count",
        ".favorite_count",
        ".comment_count",
        ".article_count",
        ".id",
        "totalArticles",
    )
    if any(hint in compact for hint in numeric_hints):
        return True
    if code and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", compact):
        assigned = _js_local_assignment_rhs(code, compact)
        if assigned and "escapeHtml(" in assigned:
            nested_exprs = [item.strip() for item in _JS_TEMPLATE_EXPR_RE.findall(assigned)]
            if all(_js_template_expr_is_safe(item, code) for item in nested_exprs):
                return True
    return compact.isdigit()


def _js_local_assignment_rhs(code: str, name: str) -> str | None:
    pattern = re.compile(
        rf"(?:const|let|var)\s+{re.escape(name)}\s*=\s*(.*?);",
        re.DOTALL,
    )
    match = pattern.search(code)
    if match:
        return match.group(1)
    return None


_CWE_MAP: dict[str, str] = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_execution": "CWE-78",
    "code_execution": "CWE-94",
    "path_traversal": "CWE-22",
    "file_inclusion": "CWE-98",
    "file_upload": "CWE-434",
    "file_download": "CWE-23",
    "file_path": "CWE-73",
    "deserialization": "CWE-502",
    "ssrf": "CWE-918",
    "csrf": "CWE-352",
    "xxe": "CWE-611",
    "xpath_injection": "CWE-643",
    "ldap_injection": "CWE-90",
    "crlf_injection": "CWE-93",
    "ssti": "CWE-1336",
    "nosql_injection": "CWE-943",
    "graphql_injection": "CWE-89",
    "auth_bypass": "CWE-287",
    "unauthorized_access": "CWE-862",
    "info_disclosure": "CWE-200",
    "weak_credential": "CWE-259",
    "buffer_overflow": "CWE-119",
}


def _cwe_default(vuln: str) -> str:
    return _CWE_MAP.get(vuln, "CWE-unknown")


def _minimal_finding(chain: dict[str, Any]) -> dict[str, Any]:
    finding = {
        "verdict": "uncertain",
        "confidence": 0.5,
        "title": f"{chain.get('vulnerability_type')} 风险点 @ "
        f"{chain.get('sink_file')}:{chain.get('sink_line')}",
        "source": {},
        "sink": {
            "file": chain.get("sink_file"),
            "line": chain.get("sink_line"),
        },
        "missing_info": _chain_required_evidence(chain),
        "evidence": [],
        "sink_level": _chain_sink_level(chain),
        "semantic_tags": _chain_list(chain, "semantic_tags"),
        "required_evidence": _chain_required_evidence(chain),
        "resolved_evidence": _chain_list(chain, "resolved_evidence"),
        "unresolved_evidence": _chain_list(chain, "unresolved_evidence"),
        "repair_rounds": int(chain.get("repair_rounds") or 0),
        "repair_trace": chain.get("repair_trace") if isinstance(chain.get("repair_trace"), list) else [],
        "blocking_reason": "",
        "manual_verification_steps": [],
    }
    finding.update(_empty_review_fields())
    return finding


def _empty_review_fields() -> dict[str, str]:
    return dict(REVIEW_FIELD_DEFAULTS)


# ── checkpoint / progress ───────────────────────────────────────────────────


def _is_skipped_audit_finding(finding: dict[str, Any] | None) -> bool:
    """True for transport/LLM failures or non-conclusive placeholders that
    must not appear as audit verdicts in audit_agent.json / findings.md.

    Real verdicts produced by the forced-final-verdict pass (i.e. tagged with
    ``_tool_stopped="max_tool_rounds"`` but carrying a usable ``principle`` /
    ``evidence``) are kept.
    """
    if not isinstance(finding, dict):
        return True

    stopped = str(finding.get("_tool_stopped") or "").strip()
    title = str(finding.get("title") or "").strip()

    # Transport-level failures (network / 4xx / 5xx) never produce verdicts.
    if stopped == "llm_error" or title.startswith("LLM 调用失败"):
        return True

    # Placeholder rows from the tool-loop dead-end without any reasoning.
    looks_like_placeholder = (
        title == "tool-loop exhausted"
        and not finding.get("principle")
        and not finding.get("evidence")
        and not finding.get("missing_info")
    )
    if looks_like_placeholder:
        return True

    return False


def _publishable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if not _is_skipped_audit_finding(f)]


def _load_audit_progress(path: Path) -> dict[str, dict[str, Any]]:
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
            finding = row.get("finding")
            if (
                chain_id
                and isinstance(finding, dict)
                and not _is_skipped_audit_finding(finding)
            ):
                done[chain_id] = finding
    return done


def _sanitize_audit_progress_file(path: Path) -> dict[str, dict[str, Any]]:
    """Drop legacy LLM-failure rows from checkpoint and rewrite the file if needed."""
    if not path.is_file():
        return {}
    raw_rows = 0
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            if line.strip():
                raw_rows += 1
    good = _load_audit_progress(path)
    if raw_rows != len(good):
        _rewrite_audit_progress(path, good)
        info(
            f"Auditor: removed {raw_rows - len(good)} LLM-failure placeholder(s) "
            f"from {path.name}"
        )
    return good


def _rewrite_audit_progress(path: Path, findings_by_id: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"chain_id": chain_id, "finding": finding}, ensure_ascii=False)
        for chain_id, finding in findings_by_id.items()
    ]
    text = "\n".join(lines)
    path.write_text((text + "\n") if text else "", encoding="utf-8")


def _append_audit_failure(
    path: Path,
    *,
    chain_id: str,
    chain: dict[str, Any],
    error_type: str,
    error: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "chain_id": chain_id,
        "sink_file": chain.get("sink_file"),
        "sink_line": chain.get("sink_line"),
        "error_type": error_type,
        "error": error[:2000],
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _append_audit_progress(path: Path, finding: dict[str, Any]) -> None:
    if _is_skipped_audit_finding(finding):
        return
    chain_id = str(finding.get("chain_id") or "").strip()
    if not chain_id:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"chain_id": chain_id, "finding": finding}
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def _counter_from_findings(findings: Any) -> dict[str, int]:
    counter = {"done": 0, "vulnerable": 0, "uncertain": 0, "safe": 0, "failed": 0}
    for finding in _publishable_findings(
        [f for f in findings if isinstance(f, dict)]
    ):
        if not isinstance(finding, dict):
            continue
        counter["done"] += 1
        verdict = str(finding.get("verdict") or "uncertain")
        if verdict in counter:
            counter[verdict] += 1
        else:
            counter["uncertain"] += 1
    return counter


def _persist_audit_checkpoint(
    findings: list[dict[str, Any]],
    output_json: Path,
    output_md: Path,
    project_path: str,
    project_root: Path,
    started_at: float,
    counter: dict[str, int],
    scope: RunScope,
) -> None:
    clean = _publishable_findings(findings)
    result = _build_result(
        clean,
        project_path,
        project_root,
        started_at,
        counter,
        scope,
        partial=True,
    )
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_findings_md(clean, output_md, project_path, scope)


# ── result builder ─────────────────────────────────────────────────────────


def _build_result(
    findings: list[dict[str, Any]],
    project_path: str,
    project_root: Path,
    started_at: float,
    counter: dict[str, int],
    scope: RunScope,
    *,
    partial: bool = False,
) -> dict[str, Any]:
    findings = _publishable_findings(findings)
    by_severity: dict[str, int] = {}
    by_vuln: dict[str, int] = {}
    for f in findings:
        if f.get("verdict") == "vulnerable":
            sv = f.get("severity") or "unknown"
            by_severity[sv] = by_severity.get(sv, 0) + 1
            vt = f.get("vulnerability_type") or "unknown"
            by_vuln[vt] = by_vuln.get(vt, 0) + 1
    status = "ok" if findings else "no_auditable_chains"
    if partial and findings:
        status = "partial"
    return {
        "status": status,
        "project_path": project_path,
        "project_root": str(project_root),
        "scope": scope.to_dict(),
        "summary": {
            "total_audited": len(findings),
            "vulnerable": counter.get("vulnerable", 0),
            "uncertain": counter.get("uncertain", 0),
            "safe": counter.get("safe", 0),
            "llm_failed": counter.get("failed", 0),
            "by_severity": by_severity,
            "by_vulnerability": by_vuln,
            "checkpoint": partial,
        },
        "findings": findings,
        "elapsed_seconds": round(time.perf_counter() - started_at, 2),
    }


def _empty_result(
    project_path: str,
    project_root: Path,
    started_at: float,
    scope: RunScope,
) -> dict[str, Any]:
    return _build_result(
        [], project_path, project_root, started_at,
        {"done": 0, "vulnerable": 0, "uncertain": 0, "safe": 0},
        scope,
    )


# ── markdown report writer ─────────────────────────────────────────────────


def _write_findings_md(
    findings: list[dict[str, Any]],
    path: Path,
    project_path: str,
    scope: RunScope,
) -> None:
    _write_findings_md_compact(findings, path, project_path, scope)
    return
    path.parent.mkdir(parents=True, exist_ok=True)
    vuln_count = sum(1 for f in findings if f.get("verdict") == "vulnerable")
    unc_count = sum(1 for f in findings if f.get("verdict") == "uncertain")
    safe_count = sum(1 for f in findings if f.get("verdict") == "safe")

    lines: list[str] = []
    lines.append("# DefectMine 审计报告\n")
    lines.append(f"**项目**: `{project_path}`  ")
    if scope.mode == "specific":
        lines.append(f"**目标目录**: `{scope.target_rel_dir}`  ")
        lines.append(f"**运行 ID**: `{scope.run_id}`  ")
    lines.append(f"**生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(
        f"**摘要**: 共审计 {len(findings)} 条调用链，"
        f"确认漏洞 {vuln_count} 条，"
        f"结论不确定 {unc_count} 条，"
        f"确认安全 {safe_count} 条。\n"
    )
    lines.append("---\n")

    for idx, finding in enumerate(findings, 1):
        verdict = finding.get("verdict") or "unknown"
        title = finding.get("title") or "?"
        severity = (finding.get("severity") or "medium").upper()
        cwe = finding.get("cwe_guess") or "?"
        vuln_type = finding.get("vulnerability_type") or "?"
        sink = _mapping_value(finding.get("sink"))
        sink_file = sink.get("file") or "?"
        sink_line = sink.get("line") or 0
        source = _mapping_value(finding.get("source"))
        src_file = source.get("file") or "?"
        src_line = source.get("line") or 0
        principle = finding.get("principle") or ""
        data_flow = _text_list(finding.get("data_flow"))
        poc = finding.get("exploit_poc") or ""
        fix = finding.get("fix_suggestion") or ""
        refuted = finding.get("refuted_by") or ""
        missing = _text_list(finding.get("missing_info"))
        confidence = _confidence_value(finding.get("confidence"), 0.0)

        verdict_label = {
            "vulnerable": "存在漏洞",
            "uncertain": "结论不确定",
            "safe": "确认安全",
        }.get(verdict, "未知")

        lines.append("=" * 70)
        lines.append(
            f"## [{idx}/{len(findings)}] [{verdict_label}] {title}"
        )
        lines.append("=" * 70 + "\n")

        lines.append("| 字段 | 内容 |")
        lines.append("|------|------|")
        lines.append(
            f"| 结论 | **{verdict_label}**（置信度：{confidence:.0%}） |"
        )
        lines.append(f"| CWE | {cwe} |")
        lines.append(f"| 严重程度 | {severity} |")
        lines.append(f"| 漏洞类型 | {vuln_type} |")
        lines.append(f"| 汇聚点位置 | `{sink_file}:{sink_line}` |")
        if src_file and src_file != "?":
            lines.append(f"| 输入源位置 | `{src_file}:{src_line}` |")
        lines.append("")

        if principle:
            lines.append("### 漏洞原理\n")
            lines.append(principle.strip())
            lines.append("")

        if data_flow:
            lines.append("### 完整调用链（输入源 → 汇聚点）\n")
            for step in data_flow:
                lines.append(f"- {step}")
            lines.append("")

        if poc:
            lines.append("### 验证 POC 与流程\n")
            lines.append(poc.strip())
            lines.append("")

        if fix:
            lines.append("### 修复建议\n")
            lines.append(fix.strip())
            lines.append("")

        if refuted:
            lines.append("### 已拦截\n")
            lines.append(f"```\n{refuted}\n```")
            lines.append("")

        if missing:
            lines.append("### 缺失信息（不确定）\n")
            for mi in missing:
                lines.append(f"- `{mi}`")
            lines.append("")

        evidence = _evidence_list(finding.get("evidence"))
        if evidence:
            lines.append("### 证据\n")
            for item in evidence:
                source_name = item.get("source") or "unknown"
                detail = item.get("detail") or ""
                file_name = item.get("file")
                line_no = item.get("line")
                suffix = ""
                if file_name:
                    suffix = f"（{file_name}:{line_no or '?'}）"
                lines.append(f"- [{source_name}] {detail}{suffix}")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def _write_findings_md_compact(
    findings: list[dict[str, Any]],
    path: Path,
    project_path: str,
    scope: RunScope,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    vuln_count = sum(1 for f in findings if f.get("verdict") == "vulnerable")
    unc_count = sum(1 for f in findings if f.get("verdict") == "uncertain")
    safe_count = sum(1 for f in findings if f.get("verdict") == "safe")
    headline_findings = [
        finding
        for finding in findings
        if finding.get("verdict") in {"vulnerable", "uncertain"}
    ]
    safe_findings = [finding for finding in findings if finding.get("verdict") == "safe"]

    lines: list[str] = []
    lines.append("# DefectMine 审计报告\n")
    lines.append(f"**项目**: `{project_path}`  ")
    if scope.mode == "specific":
        lines.append(f"**目标目录**: `{scope.target_rel_dir}`  ")
        lines.append(f"**运行 ID**: `{scope.run_id}`  ")
    lines.append(f"**生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(
        f"**摘要**: 共审计 {len(findings)} 条调用链，"
        f"确认漏洞 {vuln_count} 条，"
        f"结论不确定 {unc_count} 条，"
        f"确认安全 {safe_count} 条。  "
    )
    lines.append(
        "**正文范围**: 正文仅展开 `vulnerable` / `uncertain` 结果，"
        "`safe` 结果收纳到文末摘要。"
    )
    lines.append("")
    lines.append("---\n")

    lines.append("## 重点结论\n")
    if headline_findings:
        for finding in headline_findings:
            verdict = finding.get("verdict") or "unknown"
            verdict_label = {
                "vulnerable": "存在漏洞",
                "uncertain": "结论不确定",
            }.get(verdict, verdict)
            sink = _mapping_value(finding.get("sink"))
            title = finding.get("title") or "?"
            lines.append(
                f"- **{verdict_label}** "
                f"`{sink.get('file') or '?'}:{sink.get('line') or '?'}`: {title}"
            )
    else:
        lines.append("本次未确认可利用漏洞，也没有需要人工补充上下文的 `uncertain` 结果。")
    lines.append("")

    for idx, finding in enumerate(headline_findings, 1):
        verdict = finding.get("verdict") or "unknown"
        title = finding.get("title") or "?"
        severity = (finding.get("severity") or "medium").upper()
        cwe = finding.get("cwe_guess") or "?"
        vuln_type = finding.get("vulnerability_type") or "?"
        sink = _mapping_value(finding.get("sink"))
        sink_file = sink.get("file") or "?"
        sink_line = sink.get("line") or 0
        source = _mapping_value(finding.get("source"))
        src_file = source.get("file") or "?"
        src_line = source.get("line") or 0
        principle = finding.get("principle") or ""
        data_flow = _text_list(finding.get("data_flow"))
        poc = finding.get("exploit_poc") or ""
        fix = finding.get("fix_suggestion") or ""
        refuted = finding.get("refuted_by") or ""
        missing = _text_list(finding.get("missing_info"))
        confidence = _confidence_value(finding.get("confidence"), 0.0)

        verdict_label = {
            "vulnerable": "存在漏洞",
            "uncertain": "结论不确定",
            "safe": "确认安全",
        }.get(verdict, "未知")

        lines.append("=" * 70)
        lines.append(f"## [{idx}/{len(headline_findings)}] [{verdict_label}] {title}")
        lines.append("=" * 70 + "\n")
        lines.append("| 字段 | 内容 |")
        lines.append("|------|------|")
        lines.append(f"| 结论 | **{verdict_label}**（置信度：{confidence:.0%}） |")
        lines.append(f"| CWE | {cwe} |")
        lines.append(f"| 严重程度 | {severity} |")
        lines.append(f"| 漏洞类型 | {vuln_type} |")
        lines.append(f"| 汇聚点位置 | `{sink_file}:{sink_line}` |")
        if src_file and src_file != "?":
            lines.append(f"| 输入源位置 | `{src_file}:{src_line}` |")
        lines.append("")

        if principle:
            lines.append("### 漏洞原理\n")
            lines.append(principle.strip())
            lines.append("")

        if data_flow:
            lines.append("### 完整调用链（输入源 → 汇聚点）\n")
            for step in data_flow:
                lines.append(f"- {step}")
            lines.append("")

        if poc:
            lines.append("### 验证 POC 与流程\n")
            lines.append(poc.strip())
            lines.append("")

        if fix:
            lines.append("### 修复建议\n")
            lines.append(fix.strip())
            lines.append("")

        if refuted:
            lines.append("### 已拦截\n")
            lines.append(f"```\n{refuted}\n```")
            lines.append("")

        if missing:
            lines.append("### 缺失信息（不确定）\n")
            for mi in missing:
                lines.append(f"- `{mi}`")
            lines.append("")

        evidence = _evidence_list(finding.get("evidence"))
        if evidence:
            lines.append("### 证据\n")
            for item in evidence:
                source_name = item.get("source") or "unknown"
                detail = item.get("detail") or ""
                file_name = item.get("file")
                line_no = item.get("line")
                suffix = f"（{file_name}:{line_no or '?'}）" if file_name else ""
                lines.append(f"- [{source_name}] {detail}{suffix}")
            lines.append("")

    if safe_findings:
        lines.append("## 已确认安全摘要\n")
        lines.append(
            f"以下 {len(safe_findings)} 条结果已被判定为 `safe`，"
            "完整结构化证据仍保留在 `audit_agent.json`。"
        )
        lines.append("")
        lines.append("| # | 类型 | 汇聚点 | 标题 | 关键拦截点 |")
        lines.append("|---|---|---|---|---|")
        for idx, finding in enumerate(safe_findings, 1):
            sink = _mapping_value(finding.get("sink"))
            title = str(finding.get("title") or "?").replace("|", "/")
            refuted = " ".join(str(finding.get("refuted_by") or "").split()).replace("|", "/")
            if len(refuted) > 80:
                refuted = refuted[:77] + "..."
            lines.append(
                f"| {idx} | {finding.get('vulnerability_type') or '?'} | "
                f"`{sink.get('file') or '?'}:{sink.get('line') or '?'}` | "
                f"{title} | {refuted} |"
            )
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# ── small utilities ────────────────────────────────────────────────────────


def _stable_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()
