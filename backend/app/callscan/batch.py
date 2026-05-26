from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.callscan.priority_schema import load_priority_chain_jsonl, validate_priority_chain_records


CALLSCAN_ALL_CHAINS_FILENAME = "callscan_chains.all.jsonl"
CALLSCAN_PARTIAL_CHAINS_FILENAME = "callscan_chains.partial.jsonl"
CALLSCAN_COVERAGE_FILENAME = "callscan_coverage.json"
CALLSCAN_DISCOVERY_META_FILENAME = "callscan_discovery.meta.json"
CALLSCAN_PRIORITY_CHAINS_FILENAME = "callscan_chains.priority.jsonl"
AUDIT_COMPLETED_POOL_FILENAME = "audit_completed_pool.jsonl"
AUDIT_BATCHES_DIRNAME = "audit_batches"
BATCH_META_FILENAME = "batch_meta.json"
BATCH_QUEUE_FILENAME = "queue.jsonl"
BATCH_AUDIT_AGENT_FILENAME = "audit_agent.json"
BATCH_AUDIT_FINDINGS_FILENAME = "audit_findings.md"
SCAN_AUDIT_AGENT_FILENAME = "audit_agent.json"
SCAN_AUDIT_FINDINGS_FILENAME = "audit_findings.md"

ProgressReporter = Callable[[dict[str, Any]], None]


@dataclass(frozen=True, slots=True)
class AuditBatchResult:
    """Batch audit result kept separate from the scan-level aggregate."""

    artifacts_dir: Path
    batch_id: str
    batch_dir: Path
    queue_path: Path
    report: dict[str, Any]
    markdown: str
    aggregate_report: dict[str, Any]


def build_callscan_coverage(
    all_chains: list[dict[str, Any]],
    partial_chains: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Summarize the full candidate pool for scheduling and workbench display."""

    partial_chains = partial_chains or []
    coverage = {
        "schema_version": "defectmine.callscan.coverage.v1",
        "generated_at": _now_iso(),
        "total_candidates": len(all_chains) + len(partial_chains),
        "complete_candidates": len(all_chains),
        "partial_candidates": len(partial_chains),
        "by_vulnerability_type": {},
        "by_language": {},
        "by_risk_level": {},
        "by_bucket": {},
    }
    for chain in all_chains:
        vuln = _chain_vulnerability_type(chain)
        language = str(chain.get("language") or _object_or_empty(chain.get("sink")).get("language") or "unknown")
        risk = str(_object_or_empty(chain.get("rank")).get("risk_level") or "unknown")
        _inc(coverage["by_vulnerability_type"], vuln)
        _inc(coverage["by_language"], language)
        _inc(coverage["by_risk_level"], risk)
        _inc(coverage["by_bucket"], f"{language}/{vuln}")
    return coverage


def create_audit_batch(
    artifacts_dir: str | Path,
    *,
    limit: int = 20,
    per_type: int = 1,
    vulnerability_types: list[str] | None = None,
    selected_chain_ids: list[str] | None = None,
    exclude_completed: bool = True,
    name: str | None = None,
    batch_id: str | None = None,
    progress_reporter: ProgressReporter | None = None,
) -> dict[str, Any]:
    """Create a local audit queue from the full pool without invoking the LLM."""

    output_dir = Path(artifacts_dir).expanduser().resolve()
    all_chains, candidate_source = _load_candidate_pool(output_dir)
    selected_ids = [item.strip() for item in (selected_chain_ids or []) if item.strip()]
    allowed_types = {item.strip().lower() for item in (vulnerability_types or []) if item.strip()}
    if selected_ids:
        # Manual selection is explicit user intent: allow re-auditing completed
        # chains and preserve the cross-page selection order from the workbench.
        chains_by_id = {_chain_id(chain): chain for chain in all_chains}
        missing_ids = [chain_id for chain_id in selected_ids if chain_id not in chains_by_id]
        if missing_ids:
            raise ValueError(f"selected chains not found in candidate pool: {', '.join(missing_ids[:5])}")
        selected = [
            _copy_with_selection(chains_by_id[chain_id], "manual", "selected in workbench", index)
            for index, chain_id in enumerate(selected_ids, start=1)
        ]
    else:
        completed = completed_chain_ids(output_dir) if exclude_completed else set()
        candidates = [
            chain
            for chain in all_chains
            if _chain_id(chain) not in completed
            and (not allowed_types or _chain_vulnerability_type(chain).lower() in allowed_types)
        ]
        selected = _select_coverage_then_risk(candidates, limit=max(int(limit or 0), 0), per_type=max(int(per_type or 0), 0))
    queued = [_with_schedule(record, index) for index, record in enumerate(selected, start=1)]
    validate_priority_chain_records(queued)

    batch_id = batch_id or _new_batch_id()
    batch_dir = output_dir / AUDIT_BATCHES_DIRNAME / batch_id
    queue_path = batch_dir / BATCH_QUEUE_FILENAME
    meta_path = batch_dir / BATCH_META_FILENAME
    batch_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(queued, queue_path)

    meta = {
        "schema_version": "defectmine.audit_batch.v1",
        "batch_id": batch_id,
        "name": name or batch_id,
        "status": "pending",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "queue_path": str(queue_path),
        "queue_count": len(queued),
        "limit": max(int(limit or 0), 0),
        "per_type": max(int(per_type or 0), 0),
        "vulnerability_types": sorted(allowed_types),
        "selected_chain_ids": selected_ids,
        "selection_mode": "manual" if selected_ids else "scheduled",
        "candidate_source": candidate_source,
        "exclude_completed": bool(exclude_completed),
        "coverage": _queue_distribution(queued),
    }
    _write_json(meta, meta_path)
    _write_jsonl(queued, output_dir / CALLSCAN_PRIORITY_CHAINS_FILENAME)

    _report_progress(
        progress_reporter,
        {
            "event": "audit_batch_scheduled",
            "batch_id": batch_id,
            "queue_count": len(queued),
            "queue_path": str(queue_path),
        },
    )
    return meta


def run_audit_batch(
    project_path: str | Path,
    artifacts_dir: str | Path,
    batch_id: str,
    *,
    audit_limit: int | None = None,
    concurrency: int = 4,
    allow_active_poc: bool = False,
    enable_llm_audit: bool = True,
    enable_mcp_tools: bool = True,
    rerun_completed: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> AuditBatchResult:
    """Run Scanner on one scheduled queue, then merge its results into scan-level artifacts."""

    output_dir = Path(artifacts_dir).expanduser().resolve()
    batch_dir = output_dir / AUDIT_BATCHES_DIRNAME / batch_id
    queue_path = batch_dir / BATCH_QUEUE_FILENAME
    if not queue_path.is_file():
        raise FileNotFoundError(f"Audit batch queue not found: {queue_path}")

    meta = _read_json(batch_dir / BATCH_META_FILENAME)
    meta.update({"status": "running", "started_at": _now_iso(), "updated_at": _now_iso()})
    _write_json(meta, batch_dir / BATCH_META_FILENAME)
    _report_progress(progress_reporter, {"event": "audit_batch_started", "batch_id": batch_id, "queue_path": str(queue_path)})

    try:
        # Delay Scanner import until a batch actually runs. This keeps CallScan
        # discovery and FastAPI route loading free from Scanner/Agent import cycles.
        from app.scanner import run_audit_scanner

        result = run_audit_scanner(
            project_path,
            artifacts_dir=output_dir,
            priority_chains_path=queue_path,
            audit_limit=audit_limit,
            concurrency=concurrency,
            persist=False,
            allow_active_poc=allow_active_poc,
            enable_llm_audit=enable_llm_audit,
            enable_mcp_tools=enable_mcp_tools,
            progress_reporter=progress_reporter,
        )
        batch_report = _tag_batch_report(result.report, batch_id)
        batch_markdown = result.markdown
        _write_json(batch_report, batch_dir / BATCH_AUDIT_AGENT_FILENAME)
        (batch_dir / BATCH_AUDIT_FINDINGS_FILENAME).write_text(batch_markdown, encoding="utf-8")
        append_completed_pool(output_dir, batch_id, batch_report, queue_path, rerun_completed=rerun_completed)
        aggregate_report = merge_audit_batches(output_dir)

        meta.update(
            {
                "status": "done",
                "finished_at": _now_iso(),
                "updated_at": _now_iso(),
                "audited_count": len(_list_of_dicts(batch_report.get("audits"))),
                "summary": batch_report.get("summary", {}),
            }
        )
        _write_json(meta, batch_dir / BATCH_META_FILENAME)
        _report_progress(
            progress_reporter,
            {
                "event": "audit_batch_completed",
                "batch_id": batch_id,
                "summary": batch_report.get("summary", {}),
            },
        )
        return AuditBatchResult(
            artifacts_dir=output_dir,
            batch_id=batch_id,
            batch_dir=batch_dir,
            queue_path=queue_path,
            report=batch_report,
            markdown=batch_markdown,
            aggregate_report=aggregate_report,
        )
    except Exception as exc:
        meta.update({"status": "error", "finished_at": _now_iso(), "updated_at": _now_iso(), "error_message": str(exc)})
        _write_json(meta, batch_dir / BATCH_META_FILENAME)
        raise


def list_audit_batches(artifacts_dir: str | Path) -> list[dict[str, Any]]:
    output_dir = Path(artifacts_dir).expanduser().resolve()
    batches_dir = output_dir / AUDIT_BATCHES_DIRNAME
    if not batches_dir.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for meta_path in batches_dir.glob(f"*/{BATCH_META_FILENAME}"):
        meta = _read_json(meta_path)
        if meta:
            items.append(meta)
    return sorted(items, key=lambda item: str(item.get("created_at", "")), reverse=True)


def completed_chain_ids(artifacts_dir: str | Path) -> set[str]:
    output_dir = Path(artifacts_dir).expanduser().resolve()
    ids: set[str] = set()
    for item in _read_jsonl(output_dir / AUDIT_COMPLETED_POOL_FILENAME):
        chain_id = str(item.get("chain_id") or "").strip()
        if chain_id:
            ids.add(chain_id)
    return ids


def append_completed_pool(
    artifacts_dir: str | Path,
    batch_id: str,
    batch_report: dict[str, Any],
    queue_path: str | Path,
    *,
    rerun_completed: bool = False,
) -> None:
    """Append a minimal completed index after a batch succeeds."""

    output_dir = Path(artifacts_dir).expanduser().resolve()
    path = output_dir / AUDIT_COMPLETED_POOL_FILENAME
    existing = _read_jsonl(path)
    seen = {str(item.get("chain_id") or "") for item in existing if isinstance(item, dict)}
    queue_index = {_chain_id(item): item for item in _read_jsonl(Path(queue_path))}
    rows = list(existing)
    for audit in _list_of_dicts(batch_report.get("audits")):
        chain_id = str(audit.get("chain_id") or _object_or_empty(audit.get("meta")).get("chain_id") or "").strip()
        if not chain_id or (chain_id in seen and not rerun_completed):
            continue
        chain = queue_index.get(chain_id, {})
        sink = _object_or_empty(chain.get("sink"))
        rows.append(
            {
                "chain_id": chain_id,
                "batch_id": batch_id,
                "verdict": str(audit.get("verdict") or "uncertain"),
                "severity": str(audit.get("severity") or _object_or_empty(chain.get("rank")).get("risk_level") or "unknown"),
                "vulnerability_type": str(
                    audit.get("vulnerability_type")
                    or chain.get("vulnerability_type")
                    or sink.get("vulnerability_type")
                    or audit.get("cwe_guess")
                    or "unknown"
                ),
                "completed_at": _now_iso(),
            }
        )
        seen.add(chain_id)
    _write_jsonl(rows, path)


def merge_audit_batches(artifacts_dir: str | Path) -> dict[str, Any]:
    """Merge all batch audit outputs into the scan-level audit artifacts."""

    output_dir = Path(artifacts_dir).expanduser().resolve()
    audits_by_chain: dict[str, dict[str, Any]] = {}
    project: dict[str, Any] = {}
    inputs: dict[str, Any] = {
        "treescan_profile": "treescan_agent.json",
        "priority_chains": CALLSCAN_PRIORITY_CHAINS_FILENAME,
        "full_candidate_pool": CALLSCAN_ALL_CHAINS_FILENAME,
        "completed_pool": AUDIT_COMPLETED_POOL_FILENAME,
    }
    batch_ids: list[str] = []
    for batch in reversed(list_audit_batches(output_dir)):
        batch_id = str(batch.get("batch_id") or "")
        report = _read_json(output_dir / AUDIT_BATCHES_DIRNAME / batch_id / BATCH_AUDIT_AGENT_FILENAME)
        if not report:
            continue
        if not project:
            project = _object_or_empty(report.get("project"))
        batch_ids.append(batch_id)
        for audit in _list_of_dicts(report.get("audits")):
            chain_id = str(audit.get("chain_id") or _object_or_empty(audit.get("meta")).get("chain_id") or "").strip()
            if not chain_id:
                continue
            audits_by_chain.setdefault(chain_id, audit)

    audits = list(audits_by_chain.values())
    report = {
        "schema_version": "defectmine.audit.v1",
        "project": project,
        "inputs": inputs,
        "audits": audits,
        "summary": _audit_summary(audits, total_chains=_count_jsonl(output_dir / CALLSCAN_ALL_CHAINS_FILENAME)),
        "debug": {"status": "merged_batches", "batch_ids": batch_ids},
    }
    _write_json(report, output_dir / SCAN_AUDIT_AGENT_FILENAME)
    (output_dir / SCAN_AUDIT_FINDINGS_FILENAME).write_text(_render_aggregate_markdown(report), encoding="utf-8")
    return report


def _select_coverage_then_risk(candidates: list[dict[str, Any]], *, limit: int, per_type: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    by_type: dict[str, list[dict[str, Any]]] = {}
    for chain in candidates:
        by_type.setdefault(_chain_vulnerability_type(chain), []).append(chain)

    if per_type > 0:
        for vuln in sorted(by_type):
            for bucket_rank, chain in enumerate(by_type[vuln][:per_type], start=1):
                if len(selected) >= limit:
                    return selected
                chain_id = _chain_id(chain)
                if chain_id in selected_ids:
                    continue
                selected.append(_copy_with_selection(chain, "coverage", f"best candidate for {vuln}", bucket_rank))
                selected_ids.add(chain_id)

    for chain in candidates:
        if len(selected) >= limit:
            break
        chain_id = _chain_id(chain)
        if chain_id in selected_ids:
            continue
        selected.append(_copy_with_selection(chain, "risk", "highest remaining risk score", len(selected) + 1))
        selected_ids.add(chain_id)
    return selected


def _copy_with_selection(chain: dict[str, Any], phase: str, reason: str, bucket_rank: int) -> dict[str, Any]:
    copied = dict(chain)
    language = str(copied.get("language") or _object_or_empty(copied.get("sink")).get("language") or "unknown")
    vuln = _chain_vulnerability_type(copied)
    copied["schedule"] = {
        "phase": phase,
        "selection_reason": reason,
        "bucket": f"{language}/{vuln}",
        "bucket_rank": bucket_rank,
    }
    return copied


def _with_schedule(chain: dict[str, Any], index: int) -> dict[str, Any]:
    copied = dict(chain)
    copied["batch_queue_index"] = index
    copied.setdefault("schedule", {"phase": "risk", "selection_reason": "selected for audit", "bucket": "unknown/unknown", "bucket_rank": index})
    return copied


def _tag_batch_report(report: dict[str, Any], batch_id: str) -> dict[str, Any]:
    tagged = dict(report)
    audits: list[dict[str, Any]] = []
    for audit in _list_of_dicts(report.get("audits")):
        item = dict(audit)
        item["batch_id"] = batch_id
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        item["meta"] = {**meta, "batch_id": batch_id}
        audits.append(item)
    tagged["audits"] = audits
    debug = tagged.get("debug") if isinstance(tagged.get("debug"), dict) else {}
    tagged["debug"] = {**debug, "batch_id": batch_id}
    return tagged


def _audit_summary(audits: list[dict[str, Any]], *, total_chains: int) -> dict[str, Any]:
    summary = {
        "total_chains": total_chains or len(audits),
        "chains": total_chains or len(audits),
        "total_audited": len(audits),
        "audited": len(audits),
        "vulnerable": 0,
        "safe": 0,
        "uncertain": 0,
        "errors": 0,
        "by_vulnerability": {},
        "by_severity": {},
        "verdict_counts": {"vulnerable": 0, "safe": 0, "uncertain": 0, "error": 0, "unknown": 0},
        "severity_counts": {},
    }
    for audit in audits:
        verdict = _verdict_bucket(audit.get("verdict"))
        if str(_object_or_empty(audit.get("meta")).get("status", "")).lower() == "error":
            verdict = "error"
        if verdict == "error":
            summary["errors"] += 1
        elif verdict in {"vulnerable", "safe", "uncertain"}:
            summary[verdict] += 1
        else:
            summary["uncertain"] += 1
        summary["verdict_counts"][verdict] = summary["verdict_counts"].get(verdict, 0) + 1
        severity = str(audit.get("severity") or "unknown")
        vuln = str(audit.get("vulnerability_type") or audit.get("cwe_guess") or "unknown")
        _inc(summary["by_vulnerability"], vuln)
        _inc(summary["by_severity"], severity)
        _inc(summary["severity_counts"], severity)
    summary["not_vulnerable"] = summary["safe"]
    summary["needs_review"] = summary["uncertain"]
    summary["inconclusive"] = 0
    return summary


def _render_aggregate_markdown(report: dict[str, Any]) -> str:
    summary = _object_or_empty(report.get("summary"))
    lines = [
        "# DefectMine 漏洞审计聚合报告",
        "",
        "汇总：调用链 {chains} 条，已审计 {audited} 条，确认漏洞 {vulnerable} 条，不确定 {uncertain} 条，确认安全 {safe} 条，审计失败 {errors} 条。".format(
            chains=summary.get("total_chains", 0),
            audited=summary.get("total_audited", 0),
            vulnerable=summary.get("vulnerable", 0),
            uncertain=summary.get("uncertain", 0),
            safe=summary.get("safe", 0),
            errors=summary.get("errors", 0),
        ),
        "",
    ]
    audits = _list_of_dicts(report.get("audits"))
    for index, audit in enumerate(audits, start=1):
        vuln = str(audit.get("vulnerability_type") or audit.get("cwe_guess") or "unknown")
        lines.extend(
            [
                f"===== [{index}/{len(audits)}] [{_verdict_label(audit.get('verdict'))}] {vuln} 漏洞 =====",
                "==================================",
                f"严重程度: {audit.get('severity', 'unknown')}",
                f"漏洞类型: {vuln}",
                f"Verdict: {audit.get('verdict', 'unknown')}",
                f"Confidence: {audit.get('confidence', 'unknown')}",
                f"Batch: {audit.get('batch_id', '')}",
                "",
                "### 漏洞原理:",
                str(audit.get("principle", "")),
                "",
                "### POC 与验证思路:",
                str(audit.get("exploit_poc", "")),
                "",
                "### 修复建议:",
                str(audit.get("fix_suggestion", "")),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _queue_distribution(chains: list[dict[str, Any]]) -> dict[str, Any]:
    return build_callscan_coverage(chains, [])


def _load_candidate_pool(output_dir: Path) -> tuple[list[dict[str, Any]], str]:
    all_path = output_dir / CALLSCAN_ALL_CHAINS_FILENAME
    priority_path = output_dir / CALLSCAN_PRIORITY_CHAINS_FILENAME
    if all_path.is_file():
        return _sort_priority_chains(load_priority_chain_jsonl(all_path)), CALLSCAN_ALL_CHAINS_FILENAME
    if priority_path.is_file():
        return _sort_priority_chains(load_priority_chain_jsonl(priority_path)), CALLSCAN_PRIORITY_CHAINS_FILENAME
    raise FileNotFoundError(
        f"Candidate pool not found: expected {CALLSCAN_ALL_CHAINS_FILENAME} or {CALLSCAN_PRIORITY_CHAINS_FILENAME}"
    )


def _chain_id(chain: dict[str, Any]) -> str:
    return str(chain.get("path_id") or chain.get("chain_id") or chain.get("analysis_id") or "").strip()


def _chain_vulnerability_type(chain: dict[str, Any]) -> str:
    sink = _object_or_empty(chain.get("sink"))
    return str(chain.get("vulnerability_type") or sink.get("vulnerability_type") or sink.get("vulnerability") or "unknown")


def _sort_priority_chains(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        chains,
        key=lambda chain: (
            _priority_sort_value(str(_object_or_empty(chain.get("rank")).get("priority", "P9"))),
            -int(_object_or_empty(chain.get("rank")).get("risk_score", 0) or 0),
            int(chain.get("priority_index", 0) or 0),
            _chain_id(chain),
        ),
    )


def _priority_sort_value(priority: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(priority.strip().upper(), 9)


def _verdict_bucket(value: Any) -> str:
    verdict = str(value or "").lower()
    if verdict in {"vulnerable", "confirmed", "true_positive"}:
        return "vulnerable"
    if verdict in {"not_vulnerable", "safe", "false_positive"}:
        return "safe"
    if verdict in {"needs_review", "inconclusive", "uncertain", "suspicious"}:
        return "uncertain"
    if verdict == "error":
        return "error"
    return "unknown"


def _verdict_label(value: Any) -> str:
    return {
        "vulnerable": "确认漏洞",
        "safe": "确认安全",
        "uncertain": "不确定",
        "error": "审计失败",
    }.get(_verdict_bucket(value), "不确定")


def _inc(target: dict[str, int], key: str) -> None:
    target[key] = int(target.get(key, 0) or 0) + 1


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _write_jsonl(items: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in items]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _count_jsonl(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()) if path.is_file() else 0


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _new_batch_id() -> str:
    return f"batch-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _report_progress(progress_reporter: ProgressReporter | None, payload: dict[str, Any]) -> None:
    if progress_reporter is not None:
        progress_reporter(payload)
