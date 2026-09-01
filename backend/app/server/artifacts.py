"""产物文件解析：分块读取大文件，避免一次性加载。

策略：
- 小 JSON（tree.json / treescan_agent.json / *_agent.json 摘要）整体返回 dict。
- audit_agent.json：summary/scope 整体返回；findings 按 offset/limit 分页。
- callscan_chains*.jsonl：按行分页（分页前先扫描首行 meta）。
- callscan_chains.md / audit_findings.md：按 ``=== CHAIN BEGIN`` 或 ``## [n/total]`` 分节，按 offset/limit 分页。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.server import json_io
from app.server.paths import artifacts_dir


# ---------- 通用 ----------


def _resolve_artifact(project_path: str, filename: str, run_id: str | None) -> Path:
    base = artifacts_dir(project_path, run_id)
    target = (base / filename).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError as err:
        raise ValueError("非法的产物文件名") from err
    if not target.is_file():
        raise FileNotFoundError(f"产物文件不存在：{target}")
    return target


def _stat(path: Path) -> dict[str, Any]:
    s = path.stat()
    return {"size": s.st_size, "mtime": s.st_mtime}


# ---------- 简单 JSON ----------


def read_full_json(project_path: str, filename: str, run_id: str | None = None) -> dict[str, Any]:
    path = _resolve_artifact(project_path, filename, run_id)
    data = json_io.read_json_cached(path)
    if data is None:
        raise FileNotFoundError(f"产物文件无法解析：{path}")
    return {"path": str(path), **_stat(path), "data": data}


# ---------- audit_agent.json (含大数组 findings) ----------


def read_audit_agent(
    project_path: str,
    run_id: str | None = None,
    *,
    offset: int = 0,
    limit: int = 50,
    severity: str | None = None,
    verdict: str | None = None,
    keyword: str | None = None,
) -> dict[str, Any]:
    path = _resolve_artifact(project_path, "audit_agent.json", run_id)
    raw = json_io.read_json_cached(path)
    if not isinstance(raw, dict):
        raise FileNotFoundError(f"audit_agent.json 无法解析：{path}")

    from app.agent.sub_agent.auditor import _publishable_findings

    findings: list[dict[str, Any]] = _publishable_findings(
        list(raw.get("findings") or [])
    )
    if severity:
        findings = [f for f in findings if str(f.get("severity", "")).lower() == severity.lower()]
    if verdict:
        findings = [f for f in findings if str(f.get("verdict", "")).lower() == verdict.lower()]
    if keyword:
        kw = keyword.lower()
        findings = [
            f
            for f in findings
            if kw in json.dumps(f, ensure_ascii=False).lower()
        ]

    total = len(findings)
    sliced = findings[offset : offset + max(0, limit)] if limit > 0 else findings[offset:]

    head: dict[str, Any] = {k: v for k, v in raw.items() if k != "findings"}
    return {
        "path": str(path),
        **_stat(path),
        "head": head,
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": sliced,
    }


def get_finding(project_path: str, chain_id: str, run_id: str | None = None) -> dict[str, Any]:
    path = _resolve_artifact(project_path, "audit_agent.json", run_id)
    raw = json_io.read_json_cached(path)
    if not isinstance(raw, dict):
        raise FileNotFoundError(f"audit_agent.json 无法解析：{path}")
    for f in raw.get("findings") or []:
        if str(f.get("chain_id")) == str(chain_id):
            return {"path": str(path), "finding": f}
    raise KeyError(chain_id)


# ---------- callscan_chains*.jsonl ----------


def _is_meta_line(line: str) -> bool:
    s = line.strip()
    if not s or s[0] != "{":
        return False
    return '"type"' in s and '"meta"' in s


def read_jsonl(
    project_path: str,
    filename: str,
    run_id: str | None = None,
    *,
    offset: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    if not filename.endswith(".jsonl"):
        raise ValueError("仅支持 .jsonl 文件")

    path = _resolve_artifact(project_path, filename, run_id)

    meta: dict[str, Any] | None = None
    items: list[dict[str, Any]] = []
    chain_index = 0

    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            stripped = line.strip()
            if not stripped:
                continue

            if _is_meta_line(stripped):
                try:
                    obj = json_io.loads_line(stripped)
                except (json.JSONDecodeError, ValueError):
                    continue
                if obj.get("type") == "meta":
                    if meta is None:
                        meta = obj
                    continue

            if chain_index >= offset and (limit <= 0 or len(items) < limit):
                try:
                    items.append(json_io.loads_line(stripped))
                except (json.JSONDecodeError, ValueError):
                    continue
            chain_index += 1

    return {
        "path": str(path),
        **_stat(path),
        "meta": meta,
        "total": chain_index,
        "offset": offset,
        "limit": limit,
        "items": items,
    }


# ---------- markdown 分节 ----------


_SECTION_PATTERNS = {
    # callscan_chains.md：=== CHAIN BEGIN xxx === ... === CHAIN END xxx ===
    "callscan_chains.md": re.compile(r"^=== CHAIN BEGIN ", re.MULTILINE),
    # audit_findings.md：## [n/total] ...
    "audit_findings.md": re.compile(r"^## \[", re.MULTILINE),
}


def _split_markdown_sections(text: str, filename: str) -> tuple[str, list[str]]:
    """根据文件名匹配的分节正则切分。返回（前言, [节, 节, ...]）。"""
    pattern = _SECTION_PATTERNS.get(filename)
    if pattern is None:
        # 默认按 markdown 一级标题切：## 开头
        pattern = re.compile(r"^## ", re.MULTILINE)

    matches = list(pattern.finditer(text))
    if not matches:
        return text, []

    head = text[: matches[0].start()]
    sections: list[str] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections.append(text[start:end].rstrip() + "\n")
    return head, sections


def read_markdown(
    project_path: str,
    filename: str,
    run_id: str | None = None,
    *,
    offset: int = 0,
    limit: int = 30,
    keyword: str | None = None,
) -> dict[str, Any]:
    if not filename.endswith(".md"):
        raise ValueError("仅支持 .md 文件")

    path = _resolve_artifact(project_path, filename, run_id)
    text = path.read_text(encoding="utf-8")
    head, sections = _split_markdown_sections(text, filename)

    if keyword:
        kw = keyword.lower()
        sections = [s for s in sections if kw in s.lower()]

    total = len(sections)
    sliced = sections[offset : offset + max(0, limit)] if limit > 0 else sections[offset:]

    return {
        "path": str(path),
        **_stat(path),
        "head": head,
        "total": total,
        "offset": offset,
        "limit": limit,
        "sections": sliced,
    }


# ---------- LLM 日志按轮次分组 ----------


def list_logs_index() -> list[dict[str, Any]]:
    """枚举 logs/ 下的日志文件。"""
    from app.server.paths import PROJECT_ROOT_DIR

    log_dir = PROJECT_ROOT_DIR / "logs"
    if not log_dir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(log_dir.glob("*.log")):
        out.append({"name": p.name, **_stat(p)})
    out.sort(key=lambda x: x["name"], reverse=True)
    return out


def read_logs_rounds(
    log_name: str,
    *,
    offset: int = 0,
    limit: int = 30,
    agent: str | None = None,
) -> dict[str, Any]:
    """把日志文件按 LLM 调用轮次分组。

    每一轮以一次 ``llm_request`` 起始，遇到下一次 ``llm_request`` 或文件结束时收尾。
    中间穿插的 ``llm_response`` / ``llm_error`` 都归入当前轮。
    """
    from app.server.paths import PROJECT_ROOT_DIR

    log_dir = PROJECT_ROOT_DIR / "logs"
    target = (log_dir / log_name).resolve()
    try:
        target.relative_to(log_dir.resolve())
    except ValueError as err:
        raise ValueError("非法日志文件名") from err
    if not target.is_file():
        raise FileNotFoundError(f"日志不存在：{target}")

    rounds: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    with target.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json_io.loads_line(line)
            except (json.JSONDecodeError, ValueError):
                continue
            etype = entry.get("type")
            if etype == "llm_request":
                if current is not None:
                    rounds.append(current)
                current = {
                    "ts": entry.get("ts"),
                    "agent": entry.get("agent"),
                    "model": entry.get("model"),
                    "request": entry,
                    "response": None,
                    "error": None,
                }
            elif etype == "llm_response":
                if current is None:
                    current = {
                        "ts": entry.get("ts"),
                        "agent": entry.get("agent"),
                        "model": entry.get("model"),
                        "request": None,
                        "response": entry,
                        "error": None,
                    }
                else:
                    current["response"] = entry
            elif etype == "llm_error":
                if current is None:
                    current = {
                        "ts": entry.get("ts"),
                        "agent": entry.get("agent"),
                        "model": entry.get("model"),
                        "request": None,
                        "response": None,
                        "error": entry,
                    }
                else:
                    current["error"] = entry

    if current is not None:
        rounds.append(current)

    if agent:
        rounds = [r for r in rounds if (r.get("agent") or "") == agent]

    total = len(rounds)
    sliced = rounds[offset : offset + max(0, limit)] if limit > 0 else rounds[offset:]
    return {
        "path": str(target),
        **_stat(target),
        "total": total,
        "offset": offset,
        "limit": limit,
        "rounds": sliced,
    }
