"""跨 run / 跨 agent 的可观测性数据。

读取项目产物目录里的：
- ``conversations/<agent>/index.jsonl`` 与 ``turn-NNNN.json``
- ``events.jsonl``
聚合出仪表盘、工作流图、对话流所需的数据。
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

from app.server import json_io
from app.server.paths import (
    ARTIFACTS_DIRNAME,
    PROJECT_ROOT_DIR,
    REPO_ROOT,
    SCANS_DIRNAME,
    SPECIFIC_DIRNAME,
    artifacts_dir,
    project_dir,
    repo_root,
)

DASHBOARD_CACHE_PATH = PROJECT_ROOT_DIR / ".defectmine" / "dashboard_cache.json"
_DASHBOARD_BUILD_WORKERS = 8


def _empty_dashboard_overview(*, days: int = 30) -> dict[str, Any]:
    return {
        "projects": [],
        "totals": {
            "projects": 0,
            "scans": 0,
            "audited": 0,
            "vulnerable": 0,
            "uncertain": 0,
            "safe": 0,
            "candidate_chains": 0,
            "tokens": {"prompt": 0, "completion": 0},
        },
        "by_severity": {},
        "by_vulnerability": {},
        "by_language": {},
        "agent_tokens": {},
        "agent_avg_elapsed": {},
        "quality": {
            "total_vulnerable_findings": 0,
            "total_marked_findings": 0,
            "true_positives": 0,
            "false_positives": 0,
            "uncertain": 0,
            "missed": 0,
            "expected_total": 0,
            "precision": None,
            "recall": None,
            "f1": None,
        },
        "series": _build_daily_series(
            days,
            scans=Counter(),
            audited=Counter(),
            vulnerable=Counter(),
            tokens_in=Counter(),
            tokens_out=Counter(),
        ),
    }


def _normalize_dashboard_overview(payload: dict[str, Any], *, days: int = 30) -> dict[str, Any]:
    defaults = _empty_dashboard_overview(days=days)
    normalized = dict(payload)

    projects = normalized.get("projects")
    normalized["projects"] = projects if isinstance(projects, list) else []

    totals = normalized.get("totals")
    totals = dict(totals) if isinstance(totals, dict) else {}
    default_totals = defaults["totals"]
    tokens = totals.get("tokens")
    totals["tokens"] = {
        **default_totals["tokens"],
        **(tokens if isinstance(tokens, dict) else {}),
    }
    normalized["totals"] = {**default_totals, **totals}

    for key in ("by_severity", "by_vulnerability", "by_language", "agent_tokens", "agent_avg_elapsed"):
        value = normalized.get(key)
        normalized[key] = value if isinstance(value, dict) else defaults[key]

    quality = normalized.get("quality")
    normalized["quality"] = {
        **defaults["quality"],
        **(quality if isinstance(quality, dict) else {}),
    }

    series = normalized.get("series")
    normalized["series"] = series if isinstance(series, list) else defaults["series"]
    return normalized


# ---------------------------------------------------------------------------
# 通用：扫描所有 run（root + specific）
# ---------------------------------------------------------------------------


def _walk_artifact_dirs(project_path: str) -> list[tuple[str | None, Path]]:
    """返回 [(run_id, artifacts_dir), ...]。run_id=None 表示 root（全仓库）。"""
    proj = project_dir(project_path)
    base = proj / ARTIFACTS_DIRNAME
    out: list[tuple[str | None, Path]] = []
    if base.is_dir():
        out.append((None, base))
    # 新扫描
    scans_root = base / "scans"
    if scans_root.is_dir():
        for d in sorted(p for p in scans_root.iterdir() if p.is_dir()):
            out.append((d.name, d))
    specific = base / SPECIFIC_DIRNAME
    if specific.is_dir():
        for d in sorted(p for p in specific.iterdir() if p.is_dir()):
            out.append((d.name, d))
    return out


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json_io.loads_line(line))
            except ValueError:
                continue
    return out


def _read_json(path: Path) -> dict[str, Any] | None:
    data = json_io.read_json_cached(path)
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# 事件流：直接读 events.jsonl
# ---------------------------------------------------------------------------


def read_events(
    project_path: str,
    run_id: str | None = None,
    *,
    offset: int = 0,
    limit: int = 500,
) -> dict[str, Any]:
    base = artifacts_dir(project_path, run_id)
    events_path = base / "events.jsonl"
    events: list[dict[str, Any]] = []
    total = 0

    if events_path.is_file():
        with events_path.open("r", encoding="utf-8") as fp:
            for line in fp:
                stripped = line.strip()
                if not stripped:
                    continue
                if total >= offset and (limit <= 0 or len(events) < limit):
                    try:
                        events.append(json_io.loads_line(stripped))
                    except ValueError:
                        continue
                total += 1

    return {
        "path": str(events_path),
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": events,
    }


# ---------------------------------------------------------------------------
# 工作流图：根据事件流 + 产物状态生成节点 + 边
# ---------------------------------------------------------------------------


PIPELINE_AGENTS = ["treescan", "callscan", "dataflowscan", "auditor"]


def build_workflow_graph(project_path: str, run_id: str | None = None) -> dict[str, Any]:
    """生成工作流 DAG。

    节点：pipeline / treescan / callscan / auditor 以及二级 sub-task。
    状态：pending / running / done / error，由事件流推断。
    边：上游 agent → 下游 agent。
    """
    base = artifacts_dir(project_path, run_id)
    events = _read_jsonl(base / "events.jsonl")

    # ---- 推断每个 agent 的当前状态 ----
    statuses: dict[str, str] = {a: "pending" for a in PIPELINE_AGENTS}
    timing: dict[str, dict[str, Any]] = {a: {} for a in PIPELINE_AGENTS}
    last_seen: dict[str, dict[str, Any]] = {}
    turn_counts: dict[str, int] = Counter()
    token_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"prompt": 0, "completion": 0})

    pipeline_status = "pending"
    pipeline_started: str | None = None
    pipeline_ended: str | None = None
    pipeline_elapsed: float | None = None

    for ev in events:
        etype = ev.get("type")
        agent = ev.get("agent")
        ts = ev.get("ts")
        if etype == "pipeline_start":
            pipeline_status = "running"
            pipeline_started = ts
        elif etype == "pipeline_end":
            pipeline_status = "done"
            pipeline_ended = ts
            pipeline_elapsed = ev.get("elapsed")
        elif etype == "agent_start" and agent in statuses:
            statuses[agent] = "running"
            timing[agent]["start_ts"] = ts
        elif etype == "agent_end" and agent in statuses:
            if statuses[agent] != "error":
                statuses[agent] = "done"
            timing[agent]["end_ts"] = ts
            timing[agent]["elapsed"] = ev.get("elapsed")
            timing[agent]["summary"] = ev.get("result_summary")
        elif etype == "agent_error" and agent in statuses:
            statuses[agent] = "error"
            timing[agent]["error"] = ev.get("error")
            timing[agent]["error_type"] = ev.get("error_type")
        elif etype == "llm_request" and agent:
            turn_counts[agent] += 1
            last_seen[agent] = ev
        elif etype == "llm_response" and agent:
            usage = ev.get("usage") or {}
            token_totals[agent]["prompt"] += int(usage.get("prompt_tokens") or 0)
            token_totals[agent]["completion"] += int(usage.get("completion_tokens") or 0)
            last_seen[agent] = ev
        elif etype == "llm_error" and agent:
            last_seen[agent] = ev

    # 即使没有事件流，也按产物文件存在与否推断状态（兼容旧 run）
    artifact_signals = _infer_artifact_signals(base)
    for agent, sig in artifact_signals.items():
        if statuses.get(agent) == "pending" and sig:
            statuses[agent] = "done"

    # ---- 构造节点 ----
    nodes: list[dict[str, Any]] = []
    nodes.append(
        {
            "id": "pipeline",
            "label": "Pipeline",
            "kind": "pipeline",
            "status": pipeline_status,
            "started_at": pipeline_started,
            "ended_at": pipeline_ended,
            "elapsed": pipeline_elapsed,
        }
    )

    agent_meta = {
        "treescan": {
            "label": "目录画像",
            "en": "TreeScan",
            "desc": "扫描仓库目录，输出 Project Profile。",
            "outputs": ["tree.json", "treescan_agent.json"],
        },
        "callscan": {
            "label": "调用扫描",
            "en": "CallScan",
            "desc": "ripgrep 命中危险函数，构造调用链候选。",
            "outputs": [
                "callscan_chains.jsonl",
                "callscan_chains.priority.jsonl",
                "callscan_chains.md",
                "callscan_agent.json",
            ],
        },
        "dataflowscan": {
            "label": "数据流恢复",
            "en": "DataFlowScan",
            "desc": "恢复跨请求数据流与持久化桥。",
            "outputs": [
                "dataflow_graph.json",
                "cross_request_chains.jsonl",
            ],
        },
        "auditor": {
            "label": "漏洞审计",
            "en": "Auditor",
            "desc": "对每条候选链做 LLM 验证，给出 verdict。",
            "outputs": ["audit_agent.json", "audit_findings.md"],
        },
    }

    for agent in PIPELINE_AGENTS:
        meta = agent_meta[agent]
        present_outputs = [
            o for o in meta["outputs"] if (base / o).is_file()
        ]
        nodes.append(
            {
                "id": agent,
                "label": meta["label"],
                "en": meta["en"],
                "desc": meta["desc"],
                "kind": "agent",
                "status": statuses[agent],
                "turns": turn_counts.get(agent, 0),
                "tokens": token_totals.get(agent, {"prompt": 0, "completion": 0}),
                "elapsed": timing[agent].get("elapsed"),
                "started_at": timing[agent].get("start_ts"),
                "ended_at": timing[agent].get("end_ts"),
                "summary": timing[agent].get("summary"),
                "error": timing[agent].get("error"),
                "outputs": meta["outputs"],
                "outputs_present": present_outputs,
            }
        )

    # 输入数据节点：项目仓库
    nodes.append(
        {
            "id": "repo",
            "label": "项目仓库",
            "en": "repository",
            "kind": "input",
            "status": "ready",
            "path": project_path,
        }
    )
    # 终端：findings
    audit_summary = _audit_summary(base / "audit_agent.json")
    nodes.append(
        {
            "id": "findings",
            "label": "漏洞结果",
            "en": "findings",
            "kind": "output",
            "status": "done" if audit_summary else "pending",
            "summary": audit_summary,
        }
    )

    # ---- 边 ----
    edges = [
        {"from": "repo", "to": "treescan", "label": "目录树"},
        {"from": "treescan", "to": "callscan", "label": "Project Profile"},
        {"from": "callscan", "to": "dataflowscan", "label": "候选调用链"},
        {"from": "dataflowscan", "to": "auditor", "label": "跨请求链"},
        {"from": "auditor", "to": "findings", "label": "审计结论"},
    ]

    return {
        "project_path": project_path,
        "run_id": run_id,
        "artifacts_dir": str(base),
        "pipeline_status": pipeline_status,
        "nodes": nodes,
        "edges": edges,
        "agent_meta": agent_meta,
    }


def _infer_artifact_signals(base: Path) -> dict[str, bool]:
    return {
        "treescan": (base / "treescan_agent.json").is_file(),
        "callscan": (base / "callscan_agent.json").is_file(),
        "dataflowscan": (base / "dataflow_graph.json").is_file() or (base / "cross_request_chains.jsonl").is_file(),
        "auditor": (base / "audit_agent.json").is_file(),
    }


def _audit_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not data:
        return None
    s = data.get("summary") or {}
    return {
        "total_audited": s.get("total_audited", 0),
        "vulnerable": s.get("vulnerable", 0),
        "uncertain": s.get("uncertain", 0),
        "safe": s.get("safe", 0),
    }


# ---------------------------------------------------------------------------
# 对话流：扫描 conversations/<agent>/index.jsonl
# ---------------------------------------------------------------------------


def list_conversations(
    project_path: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    """列出该 run 下每个 agent 的对话索引（不返回大文件）。"""
    base = artifacts_dir(project_path, run_id)
    conv_dir = base / "conversations"
    out: list[dict[str, Any]] = []
    if not conv_dir.is_dir():
        return {"artifacts_dir": str(base), "agents": []}

    for agent_dir in sorted(p for p in conv_dir.iterdir() if p.is_dir()):
        agent = agent_dir.name
        index_entries = _read_jsonl(agent_dir / "index.jsonl")
        # index 里同一 turn 可能有 pending+ok 两条记录，做合并
        latest: dict[int, dict[str, Any]] = {}
        for e in index_entries:
            t = e.get("turn")
            if t is None:
                continue
            current = latest.get(t)
            if current is None:
                latest[t] = e
            else:
                # ok / error 覆盖 pending
                if current.get("status") == "pending":
                    latest[t] = e
                elif current.get("status") == e.get("status"):
                    latest[t] = e

        turns = sorted(latest.values(), key=lambda x: x.get("turn", 0))
        prompt_total = sum(int((t.get("usage") or {}).get("prompt_tokens") or 0) for t in turns)
        completion_total = sum(
            int((t.get("usage") or {}).get("completion_tokens") or 0) for t in turns
        )
        out.append(
            {
                "agent": agent,
                "turns_count": len(turns),
                "prompt_tokens": prompt_total,
                "completion_tokens": completion_total,
                "turns": turns,
            }
        )
    return {"artifacts_dir": str(base), "agents": out}


def read_conversation_turn(
    project_path: str,
    run_id: str | None,
    agent: str,
    turn: int,
) -> dict[str, Any]:
    base = artifacts_dir(project_path, run_id)
    conv_dir = base / "conversations" / agent
    target = (conv_dir / f"turn-{int(turn):04d}.json").resolve()
    try:
        target.relative_to(conv_dir.resolve())
    except ValueError as err:
        raise ValueError("非法路径") from err
    if not target.is_file():
        raise FileNotFoundError(f"对话不存在：{target}")
    data = _read_json(target) or {}
    return {
        "path": str(target),
        "agent": agent,
        "turn": turn,
        **data,
    }


_CHAIN_RE = re.compile(r"chain_id\s*:\s*(\S+)", re.IGNORECASE)


def _extract_first_user_chain_id(turn_doc: dict[str, Any]) -> str | None:
    """从 turn 的 request.messages 里取第一条 user 消息的 chain_id（如有）。"""
    req = turn_doc.get("request") or {}
    msgs = req.get("messages") or []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        if m.get("role") != "user":
            continue
        content = m.get("content")
        if not isinstance(content, str):
            return None
        match = _CHAIN_RE.search(content)
        return match.group(1).strip() if match else None
    return None


def find_conversation_by_chain(
    project_path: str,
    run_id: str | None,
    chain_id: str,
    agent: str = "auditor",
) -> dict[str, Any]:
    """查找某 chain_id 对应的对话轮次（默认 auditor）。

    Auditor 多轮工具调用时，每个 turn 的 messages 都包含同一个初始 user 消息
    ``chain_id: <id>``。本函数遍历该 agent 的所有 turn 文件，返回 chain 匹配的
    所有轮次。返回内容与 ``read_conversation_turn`` 一致（含 request/response）。
    """
    base = artifacts_dir(project_path, run_id)
    conv_dir = base / "conversations" / agent
    if not conv_dir.is_dir():
        return {
            "artifacts_dir": str(base),
            "agent": agent,
            "chain_id": chain_id,
            "turns": [],
        }

    matched: list[dict[str, Any]] = []
    for p in sorted(conv_dir.glob("turn-*.json")):
        doc = _read_json(p)
        if not doc:
            continue
        found_chain = _extract_first_user_chain_id(doc)
        if found_chain is None or found_chain != chain_id:
            continue
        turn_no_str = p.stem.removeprefix("turn-")
        try:
            turn_no = int(turn_no_str)
        except ValueError:
            continue
        matched.append(
            {
                "path": str(p),
                "agent": agent,
                "turn": turn_no,
                **doc,
            }
        )

    matched.sort(key=lambda x: x.get("turn", 0))
    return {
        "artifacts_dir": str(base),
        "agent": agent,
        "chain_id": chain_id,
        "turns": matched,
    }


# ---------------------------------------------------------------------------
# 仪表盘：跨项目 / 跨 run 的概览
# ---------------------------------------------------------------------------


_RUN_ID_FMT = re.compile(r"^\d{8}-\d{6}-\d{6}$")


def _scan_repo_fingerprint() -> tuple[int, int]:
    """轻量指纹：scan 目录数 + 最新 scan/verification 产物 mtime_ns。"""
    if not REPO_ROOT.is_dir():
        return 0, 0
    count = 0
    max_mtime_ns = 0
    for source in REPO_ROOT.iterdir():
        if not source.is_dir() or source.name.startswith("."):
            continue
        for owner in source.iterdir():
            if not owner.is_dir() or owner.name.startswith("."):
                continue
            for repo in owner.iterdir():
                if not repo.is_dir() or repo.name.startswith("."):
                    continue
                for version in repo.iterdir():
                    if not version.is_dir() or version.name.startswith("."):
                        continue
                    scans_root = version / ARTIFACTS_DIRNAME / SCANS_DIRNAME
                    if not scans_root.is_dir():
                        continue
                    for scan_dir in scans_root.iterdir():
                        if not scan_dir.is_dir() or scan_dir.name.startswith("."):
                            continue
                        meta_path = scan_dir / "scan.json"
                        if not meta_path.is_file():
                            continue
                        count += 1
                        for tracked_path in (meta_path, scan_dir / "verification.json"):
                            if not tracked_path.is_file():
                                continue
                            try:
                                max_mtime_ns = max(max_mtime_ns, tracked_path.stat().st_mtime_ns)
                            except OSError:
                                pass
    return count, max_mtime_ns


def _load_dashboard_cache(fingerprint: tuple[int, int], *, days: int = 30) -> dict[str, Any] | None:
    cached = json_io.read_json_object(DASHBOARD_CACHE_PATH)
    if not cached:
        return None
    if cached.get("fingerprint") != list(fingerprint):
        return None
    payload = cached.get("payload")
    return _normalize_dashboard_overview(payload, days=days) if isinstance(payload, dict) else None


def _save_dashboard_cache(fingerprint: tuple[int, int], payload: dict[str, Any]) -> None:
    json_io.write_json(
        DASHBOARD_CACHE_PATH,
        {"fingerprint": list(fingerprint), "payload": payload},
        indent=True,
    )


def dashboard_overview(*, days: int = 30, refresh: bool = False) -> dict[str, Any]:
    """聚合 repo/ 下所有项目的总体指标 + 时间序列 + 质量指标。"""
    fingerprint = _scan_repo_fingerprint()
    if not refresh:
        cached = _load_dashboard_cache(fingerprint, days=days)
        if cached is not None:
            return cached

    payload = _normalize_dashboard_overview(_build_dashboard_overview(days=days), days=days)
    try:
        _save_dashboard_cache(fingerprint, payload)
    except OSError:
        pass
    return payload


def _build_dashboard_overview(*, days: int = 30) -> dict[str, Any]:
    """构建仪表盘数据（可并行、结果写入磁盘缓存）。"""
    from app.server import scans as scans_mod

    root = repo_root()
    projects: list[dict[str, Any]] = []
    total_runs = 0
    total_findings_vulnerable = 0
    total_findings_safe = 0
    total_findings_uncertain = 0
    total_audited = 0
    total_chains = 0
    by_severity: Counter = Counter()
    by_vulnerability: Counter = Counter()
    by_language: Counter = Counter()
    token_total = {"prompt": 0, "completion": 0}
    agent_token_total: dict[str, dict[str, int]] = defaultdict(
        lambda: {"prompt": 0, "completion": 0, "turns": 0}
    )
    agent_elapsed: dict[str, list[float]] = defaultdict(list)

    # 时间序列：按日期聚合
    daily_scans: Counter = Counter()
    daily_audited: Counter = Counter()
    daily_vulnerable: Counter = Counter()
    daily_tokens_in: Counter = Counter()
    daily_tokens_out: Counter = Counter()

    # 质量指标
    quality_total_findings = 0  # 模型给出 vulnerable 的总数
    quality_true_positives = 0
    quality_false_positives = 0
    quality_uncertain_marks = 0
    quality_marked_findings = 0
    quality_missed = 0
    quality_expected = 0

    if not root.is_dir():
        return _empty_dashboard_overview(days=days)

    project_index: dict[str, dict[str, Any]] = {}

    all_scans = scans_mod.list_all_scans()

    def _scan_metrics(scan: dict[str, Any]) -> dict[str, Any]:
        project_path = str(scan.get("project_path") or "")
        scan_dir = scans_mod._scan_dir(project_path, scan["scan_id"])
        local_agent_tokens: dict[str, dict[str, int]] = defaultdict(
            lambda: {"prompt": 0, "completion": 0, "turns": 0}
        )
        local_agent_elapsed: dict[str, list[float]] = defaultdict(list)
        p_tokens, c_tokens = _accumulate_tokens(scan_dir, local_agent_tokens, local_agent_elapsed)
        marks = scans_mod.list_marks(project_path, scan["scan_id"])
        audit = _read_json(scan_dir / "audit_agent.json") or {}
        vulnerable_chain_ids = {
            str(finding.get("chain_id"))
            for finding in (audit.get("findings") or [])
            if finding.get("verdict") == "vulnerable" and finding.get("chain_id")
        }
        return {
            "p_tokens": p_tokens,
            "c_tokens": c_tokens,
            "agent_tokens": dict(local_agent_tokens),
            "agent_elapsed": {k: list(v) for k, v in local_agent_elapsed.items()},
            "marks": marks,
            "vulnerable_chain_ids": vulnerable_chain_ids,
        }

    scan_extras: dict[str, dict[str, Any]] = {}
    if all_scans:
        workers = min(_DASHBOARD_BUILD_WORKERS, len(all_scans))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for scan, extra in zip(all_scans, pool.map(_scan_metrics, all_scans), strict=True):
                scan_extras[str(scan.get("scan_id"))] = extra

    for scan in all_scans:
        project_path = str(scan.get("project_path") or "")
        parts = project_path.split("/")
        version = parts[3] if len(parts) == 4 else ""
        project_key = "/".join(parts[:3]) if len(parts) >= 3 else project_path
        proj_info = project_index.setdefault(
            project_path,
            {
                "project_path": project_path,
                "project_key": project_key,
                "version": version,
                "scan_count": 0,
                "vulnerable": 0,
                "uncertain": 0,
                "safe": 0,
                "total_audited": 0,
                "candidate_chains": 0,
            },
        )

        proj_info["scan_count"] += 1
        total_runs += 1
        audit_summary = scan.get("audit_summary") or {}
        proj_info["total_audited"] += int(audit_summary.get("total_audited", 0) or 0)
        proj_info["vulnerable"] += int(audit_summary.get("vulnerable", 0) or 0)
        proj_info["uncertain"] += int(audit_summary.get("uncertain", 0) or 0)
        proj_info["safe"] += int(audit_summary.get("safe", 0) or 0)
        for k, v in (audit_summary.get("by_severity") or {}).items():
            by_severity[k] += int(v)
        for k, v in (audit_summary.get("by_vulnerability") or {}).items():
            by_vulnerability[k] += int(v)

        callscan_summary = scan.get("callscan_summary") or {}
        proj_info["candidate_chains"] += int(callscan_summary.get("candidate_chains", 0) or 0)
        for lang in callscan_summary.get("languages") or []:
            by_language[lang] += 1

        day_key = (scan.get("created_at") or "")[:10] or "unknown"
        daily_scans[day_key] += 1
        daily_audited[day_key] += int(audit_summary.get("total_audited", 0) or 0)
        daily_vulnerable[day_key] += int(audit_summary.get("vulnerable", 0) or 0)

        extra = scan_extras.get(str(scan.get("scan_id"))) or {}
        p_tokens = int(extra.get("p_tokens") or 0)
        c_tokens = int(extra.get("c_tokens") or 0)
        token_total["prompt"] += p_tokens
        token_total["completion"] += c_tokens
        daily_tokens_in[day_key] += p_tokens
        daily_tokens_out[day_key] += c_tokens

        for agent, bucket in (extra.get("agent_tokens") or {}).items():
            target = agent_token_total[agent]
            target["prompt"] += int(bucket.get("prompt") or 0)
            target["completion"] += int(bucket.get("completion") or 0)
            target["turns"] += int(bucket.get("turns") or 0)
        for agent, elapsed_list in (extra.get("agent_elapsed") or {}).items():
            agent_elapsed[agent].extend(elapsed_list)

        quality_total_findings += int(audit_summary.get("vulnerable", 0) or 0)
        marks = extra.get("marks") or {}
        vulnerable_chain_ids = extra.get("vulnerable_chain_ids") or set()
        if not vulnerable_chain_ids:
            continue
        for chain_id, m in marks.items():
            if str(chain_id) not in vulnerable_chain_ids:
                continue
            v = m.get("人工核验") or m.get("user_verdict") or m.get("Codex核验")
            if v == "true_positive":
                quality_true_positives += 1
                quality_marked_findings += 1
            elif v == "false_positive":
                quality_false_positives += 1
                quality_marked_findings += 1
            elif v == "uncertain":
                quality_uncertain_marks += 1
                quality_marked_findings += 1
        gt = scan.get("ground_truth") or {}
        if gt.get("missed") is not None:
            quality_missed += int(gt["missed"])
        if gt.get("expected_total") is not None:
            quality_expected += int(gt["expected_total"])

    for proj_info in project_index.values():
        total_findings_vulnerable += proj_info["vulnerable"]
        total_findings_safe += proj_info["safe"]
        total_findings_uncertain += proj_info["uncertain"]
        total_audited += proj_info["total_audited"]
        total_chains += proj_info["candidate_chains"]
        projects.append(proj_info)

    # Calculate precision / recall.
    tp = quality_true_positives
    fp = quality_false_positives
    fn = quality_missed
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)

    # 时间序列：补齐最近 N 天
    series = _build_daily_series(
        days,
        scans=daily_scans,
        audited=daily_audited,
        vulnerable=daily_vulnerable,
        tokens_in=daily_tokens_in,
        tokens_out=daily_tokens_out,
    )

    # Agent 平均耗时
    agent_avg_elapsed = {
        k: (sum(v) / len(v)) if v else None for k, v in agent_elapsed.items()
    }

    return {
        "projects": projects,
        "totals": {
            "projects": len(projects),
            "scans": total_runs,
            "audited": total_audited,
            "vulnerable": total_findings_vulnerable,
            "uncertain": total_findings_uncertain,
            "safe": total_findings_safe,
            "candidate_chains": total_chains,
            "tokens": token_total,
        },
        "by_severity": dict(by_severity),
        "by_vulnerability": dict(by_vulnerability),
        "by_language": dict(by_language),
        "agent_tokens": {k: v for k, v in agent_token_total.items()},
        "agent_avg_elapsed": agent_avg_elapsed,
        "quality": {
            "total_vulnerable_findings": quality_total_findings,
            "total_marked_findings": quality_marked_findings,
            "true_positives": tp,
            "false_positives": fp,
            "uncertain": quality_uncertain_marks,
            "missed": fn,
            "expected_total": quality_expected,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "series": series,
    }


def _build_daily_series(
    days: int,
    *,
    scans: Counter,
    audited: Counter,
    vulnerable: Counter,
    tokens_in: Counter,
    tokens_out: Counter,
) -> list[dict[str, Any]]:
    from datetime import date, timedelta

    today = date.today()
    series: list[dict[str, Any]] = []
    for i in range(days - 1, -1, -1):
        d = today - timedelta(days=i)
        key = d.isoformat()
        series.append(
            {
                "date": key,
                "scans": scans.get(key, 0),
                "audited": audited.get(key, 0),
                "vulnerable": vulnerable.get(key, 0),
                "tokens_in": tokens_in.get(key, 0),
                "tokens_out": tokens_out.get(key, 0),
            }
        )
    return series


def _accumulate_tokens(
    base: Path,
    agent_token_total: dict[str, dict[str, int]],
    agent_elapsed: dict[str, list[float]],
) -> tuple[int, int]:
    """累计该 scan 目录的 token，返回 (prompt, completion)。"""
    prompt_total = 0
    completion_total = 0
    conv_dir = base / "conversations"
    if conv_dir.is_dir():
        for agent_dir in conv_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            agent = agent_dir.name
            entries = _read_jsonl(agent_dir / "index.jsonl")
            seen: set[int] = set()
            for e in entries:
                t = e.get("turn")
                if t in seen or e.get("status") not in {"ok", "error"}:
                    continue
                seen.add(t)
                usage = e.get("usage") or {}
                p = int(usage.get("prompt_tokens") or 0)
                c = int(usage.get("completion_tokens") or 0)
                prompt_total += p
                completion_total += c
                bucket = agent_token_total[agent]
                bucket["prompt"] += p
                bucket["completion"] += c
                bucket["turns"] += 1

    # 从 events.jsonl 收 agent 耗时
    events = _read_jsonl(base / "events.jsonl")
    for ev in events:
        if ev.get("type") == "agent_end":
            agent = ev.get("agent")
            elapsed = ev.get("elapsed")
            if agent and elapsed is not None:
                try:
                    agent_elapsed[agent].append(float(elapsed))
                except (TypeError, ValueError):
                    pass
    return prompt_total, completion_total


def _accumulate(
    base: Path,
    proj_info: dict[str, Any],
    by_severity: Counter,
    by_vulnerability: Counter,
    by_language: Counter,
    token_total: dict[str, int],
    agent_token_total: dict[str, dict[str, int]],
) -> None:
    """旧实现，保留以防兼容。"""
    audit = _read_json(base / "audit_agent.json")
    if audit:
        s = audit.get("summary") or {}
        proj_info["total_audited"] = proj_info.get("total_audited", 0) + int(
            s.get("total_audited", 0)
        )
        proj_info["vulnerable"] = proj_info.get("vulnerable", 0) + int(s.get("vulnerable", 0))
        proj_info["uncertain"] = proj_info.get("uncertain", 0) + int(s.get("uncertain", 0))
        proj_info["safe"] = proj_info.get("safe", 0) + int(s.get("safe", 0))
        for k, v in (s.get("by_severity") or {}).items():
            by_severity[k] += int(v)
        for k, v in (s.get("by_vulnerability") or {}).items():
            by_vulnerability[k] += int(v)

    callscan = _read_json(base / "callscan_agent.json")
    if callscan:
        s = callscan.get("summary") or {}
        proj_info["candidate_chains"] = proj_info.get("candidate_chains", 0) + int(
            s.get("candidate_chains", 0)
        )
        for lang in callscan.get("languages") or []:
            by_language[lang] += 1
