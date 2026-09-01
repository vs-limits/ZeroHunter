"""Prompts / Skills / Sink 内容浏览。

提供：
- prompts: 后端 prompts/*.md
- skills: backend/app/agent/skills/<language>/*.md
- sinks: backend/app/scanner/sink/<language>/*.py，按 SinkRule 数组解析为字典

每个文件支持读写 + 自动历史版本归档：
- 历史目录: <file_dir>/.history/<file_stem>/v{N}-<timestamp>.<ext>
- 索引文件: <file_dir>/.history/<file_stem>/index.json
"""

from __future__ import annotations

import importlib
import json
import re
import shutil
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.server.paths import PROJECT_ROOT_DIR


BACKEND_DIR = PROJECT_ROOT_DIR / "backend"
PROMPTS_DIR = BACKEND_DIR / "prompts"
SKILLS_DIR = BACKEND_DIR / "app" / "agent" / "skills"
SINKS_DIR = BACKEND_DIR / "app" / "scanner" / "sink"

HISTORY_DIRNAME = ".history"
HISTORY_INDEX_FILENAME = "index.json"


# ---------- 共用 ----------


def _safe_join(base: Path, name: str) -> Path:
    """阻止 ../ 越界。"""
    target = (base / name).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError as err:
        raise ValueError(f"非法名称：{name}") from err
    return target


def _stat(p: Path) -> dict[str, Any]:
    s = p.stat()
    return {"size": s.st_size, "mtime": s.st_mtime}


# ---------- 版本归档 ----------


def _history_dir_for(target: Path) -> Path:
    """``<file_dir>/.history/<stem>/``"""
    return target.parent / HISTORY_DIRNAME / target.stem


def _history_index_path(target: Path) -> Path:
    return _history_dir_for(target) / HISTORY_INDEX_FILENAME


def _load_history_index(target: Path) -> list[dict[str, Any]]:
    path = _history_index_path(target)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError):
        return []
    return []


def _write_history_index(target: Path, entries: list[dict[str, Any]]) -> None:
    path = _history_index_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _archive_current(target: Path, *, reason: str = "") -> dict[str, Any] | None:
    """归档当前文件为新一版。返回写入的索引条目。"""
    if not target.is_file():
        return None
    history_dir = _history_dir_for(target)
    history_dir.mkdir(parents=True, exist_ok=True)

    entries = _load_history_index(target)
    next_version = (max((e.get("version", 0) for e in entries), default=0) + 1) if entries else 1
    ts = datetime.now().astimezone()
    ts_compact = ts.strftime("%Y%m%d-%H%M%S")
    archived_name = f"v{next_version}-{ts_compact}{target.suffix}"
    archived_path = history_dir / archived_name

    shutil.copy2(target, archived_path)
    stat = archived_path.stat()
    entry = {
        "version": next_version,
        "timestamp": ts.isoformat(timespec="seconds"),
        "filename": archived_name,
        "size": stat.st_size,
        "reason": reason,
    }
    entries.append(entry)
    _write_history_index(target, entries)
    return entry


def list_history(target: Path) -> list[dict[str, Any]]:
    entries = _load_history_index(target)
    # 按版本号倒序
    entries = sorted(entries, key=lambda e: e.get("version", 0), reverse=True)
    return entries


def read_history_version(target: Path, version: int) -> str:
    history_dir = _history_dir_for(target)
    entries = _load_history_index(target)
    match = next((e for e in entries if int(e.get("version", -1)) == version), None)
    if not match:
        raise FileNotFoundError(f"历史版本不存在: v{version}")
    archived = (history_dir / match["filename"]).resolve()
    try:
        archived.relative_to(history_dir.resolve())
    except ValueError as err:
        raise ValueError("非法历史路径") from err
    if not archived.is_file():
        raise FileNotFoundError(f"归档文件丢失: {archived}")
    return archived.read_text(encoding="utf-8")


def _write_with_history(
    target: Path,
    new_content: str,
    *,
    reason: str = "",
) -> dict[str, Any]:
    """先归档当前文件，再覆盖写入新内容。"""
    target.parent.mkdir(parents=True, exist_ok=True)
    archived = _archive_current(target, reason=reason) if target.is_file() else None
    target.write_text(new_content, encoding="utf-8")
    return {
        "path": str(target),
        **_stat(target),
        "archived": archived,
        "history_count": len(_load_history_index(target)),
    }


# ---------- Prompts ----------


def list_prompts() -> list[dict[str, Any]]:
    if not PROMPTS_DIR.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for p in sorted(PROMPTS_DIR.glob("*.md")):
        items.append({"name": p.name, **_stat(p)})
    return items


def read_prompt(name: str) -> dict[str, Any]:
    if not name.endswith(".md"):
        raise ValueError("仅支持 .md 文件")
    target = _safe_join(PROMPTS_DIR, name)
    if not target.is_file():
        raise FileNotFoundError(f"提示词不存在：{target}")
    return {
        "name": name,
        "path": str(target),
        **_stat(target),
        "content": target.read_text(encoding="utf-8"),
        "history_count": len(_load_history_index(target)),
    }


def write_prompt(name: str, content: str, *, reason: str = "") -> dict[str, Any]:
    if not name.endswith(".md"):
        raise ValueError("仅支持 .md 文件")
    target = _safe_join(PROMPTS_DIR, name)
    return _write_with_history(target, content, reason=reason)


def list_prompt_history(name: str) -> list[dict[str, Any]]:
    target = _safe_join(PROMPTS_DIR, name)
    return list_history(target)


def read_prompt_version(name: str, version: int) -> dict[str, Any]:
    target = _safe_join(PROMPTS_DIR, name)
    return {
        "name": name,
        "version": version,
        "content": read_history_version(target, version),
    }


# ---------- Skills ----------


def list_skill_languages() -> list[dict[str, Any]]:
    if not SKILLS_DIR.is_dir():
        return []
    out: list[dict[str, Any]] = []
    # 顶层散落的 md（_default.md 等）作为「通用」组
    top_md = sorted(p for p in SKILLS_DIR.glob("*.md"))
    if top_md:
        out.append(
            {
                "language": "_root",
                "label": "通用",
                "files": [{"name": p.name, **_stat(p)} for p in top_md],
            }
        )
    for d in sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir() and not p.name.startswith("__") and p.name != HISTORY_DIRNAME):
        files = sorted(d.glob("*.md"))
        out.append(
            {
                "language": d.name,
                "label": d.name,
                "files": [{"name": p.name, **_stat(p)} for p in files],
            }
        )
    return out


def read_skill(language: str, name: str) -> dict[str, Any]:
    if not name.endswith(".md"):
        raise ValueError("仅支持 .md 文件")
    target = _resolve_skill(language, name)
    if not target.is_file():
        raise FileNotFoundError(f"技能文件不存在：{target}")
    return {
        "language": language,
        "name": name,
        "path": str(target),
        **_stat(target),
        "content": target.read_text(encoding="utf-8"),
        "history_count": len(_load_history_index(target)),
    }


def write_skill(language: str, name: str, content: str, *, reason: str = "") -> dict[str, Any]:
    if not name.endswith(".md"):
        raise ValueError("仅支持 .md 文件")
    target = _resolve_skill(language, name)
    return _write_with_history(target, content, reason=reason)


def list_skill_history(language: str, name: str) -> list[dict[str, Any]]:
    target = _resolve_skill(language, name)
    return list_history(target)


def read_skill_version(language: str, name: str, version: int) -> dict[str, Any]:
    target = _resolve_skill(language, name)
    return {
        "language": language,
        "name": name,
        "version": version,
        "content": read_history_version(target, version),
    }


def _resolve_skill(language: str, name: str) -> Path:
    if language == "_root":
        return _safe_join(SKILLS_DIR, name)
    lang_dir = _safe_join(SKILLS_DIR, language)
    if not lang_dir.is_dir():
        raise FileNotFoundError(f"语言目录不存在：{language}")
    return _safe_join(lang_dir, name)


# ---------- Sinks ----------


def list_sink_languages() -> list[dict[str, Any]]:
    if not SINKS_DIR.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for d in sorted(p for p in SINKS_DIR.iterdir() if p.is_dir() and not p.name.startswith("__") and p.name != HISTORY_DIRNAME):
        files = sorted(p for p in d.glob("*.py") if p.name != "__init__.py")
        out.append(
            {
                "language": d.name,
                "label": d.name,
                "files": [{"name": p.stem, "filename": p.name, **_stat(p)} for p in files],
            }
        )
    return out


def _resolve_sink(language: str, name: str) -> Path:
    safe_name = name if name.endswith(".py") else f"{name}.py"
    lang_dir = _safe_join(SINKS_DIR, language)
    if not lang_dir.is_dir():
        raise FileNotFoundError(f"语言目录不存在：{language}")
    return _safe_join(lang_dir, safe_name)


# ---------- Sink 标准 read/write ----------


def read_sink(language: str, name: str) -> dict[str, Any]:
    """读取并执行 sink 文件，提取 ``RULES`` 数组。

    这些文件只是数据类定义，不会有副作用。直接 import。
    """
    target = _resolve_sink(language, name)
    if not target.is_file():
        raise FileNotFoundError(f"sink 文件不存在：{target}")

    safe_name = target.name

    # 动态 import 模块名
    module_name = f"app.scanner.sink.{language}.{Path(safe_name).stem}"
    if str(BACKEND_DIR) not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR))

    rules: list[dict[str, Any]] = []
    vulnerability: str | None = None
    parse_error: str | None = None
    try:
        module = importlib.import_module(module_name)
        module = importlib.reload(module)
        rules_raw = getattr(module, "RULES", None) or []
        vulnerability = getattr(module, "VULNERABILITY", None)
        for r in rules_raw:
            if is_dataclass(r):
                d = asdict(r)
            elif isinstance(r, dict):
                d = dict(r)
            else:
                d = {"raw": str(r)}
            rules.append(d)
    except Exception as exc:  # noqa: BLE001
        parse_error = f"{type(exc).__name__}: {exc}"

    return {
        "language": language,
        "name": Path(safe_name).stem,
        "filename": safe_name,
        "path": str(target),
        **_stat(target),
        "vulnerability": vulnerability,
        "rules_count": len(rules),
        "rules": rules,
        "raw_source": target.read_text(encoding="utf-8"),
        "parse_error": parse_error,
        "history_count": len(_load_history_index(target)),
    }


def write_sink(language: str, name: str, content: str, *, reason: str = "") -> dict[str, Any]:
    target = _resolve_sink(language, name)
    return _write_with_history(target, content, reason=reason)


def write_sink_rules(
    language: str,
    name: str,
    *,
    vulnerability: str,
    rules: list[dict[str, Any]],
    reason: str = "",
) -> dict[str, Any]:
    """根据结构化数据重新生成 sink 源码并写盘。

    - 自动归档为历史版本
    - 校验：每条规则的 id/function/call_regex 必填，severity 合法，正则可编译
    - 写之前用 ``compile()`` 校验 Python 语法
    """
    target = _resolve_sink(language, name)

    # ------- 校验 -------
    seen_ids: set[str] = set()
    for r in rules:
        rid = (r.get("id") or "").strip()
        if not rid:
            raise ValueError("每条规则必须包含 id")
        if rid in seen_ids:
            raise ValueError(f"规则 id 重复: {rid}")
        seen_ids.add(rid)
        if not (r.get("function") or "").strip():
            raise ValueError(f"规则 {rid} 缺少 function")
        if not (r.get("call_regex") or "").strip():
            raise ValueError(f"规则 {rid} 缺少 call_regex")
        sev = (r.get("severity") or "medium").strip()
        if sev not in ("low", "medium", "high", "critical"):
            raise ValueError(f"规则 {rid} 的 severity 非法: {sev}")
        try:
            re.compile(r["call_regex"])
        except re.error as err:
            raise ValueError(f"规则 {rid} 的 call_regex 无法编译: {err}") from err
        for extra in r.get("extra_match_regex") or []:
            try:
                re.compile(extra)
            except re.error as err:
                raise ValueError(f"规则 {rid} 的 extra_match_regex 无法编译: {err}") from err

    source = _serialize_sink_module(language, vulnerability, rules)
    try:
        compile(source, str(target), "exec")
    except SyntaxError as err:
        raise ValueError(f"生成的 Python 代码无法编译: {err}") from err
    return _write_with_history(target, source, reason=reason or "结构化编辑规则")


# ------- Sink 源码序列化 -------


_LANG_DOCSTRING_LABEL: dict[str, str] = {
    "c": "C",
    "cpp": "C++",
    "go": "Go",
    "html": "HTML",
    "java": "Java",
    "javascript": "JavaScript",
    "php": "PHP",
    "python": "Python",
    "rust": "Rust",
    "typescript": "TypeScript",
}


def _serialize_sink_module(
    language: str,
    vulnerability: str,
    rules: list[dict[str, Any]],
) -> str:
    """生成形如:

        \"\"\"C — Authentication Bypass sinks.\"\"\"

        from app.scanner.sink.types import SinkRule

        VULNERABILITY = "auth_bypass"

        RULES = [
            SinkRule(...),
            ...
        ]
    """
    lang_label = _LANG_DOCSTRING_LABEL.get(language, language)
    vuln_label = (vulnerability or "").replace("_", " ").strip()
    if vuln_label:
        vuln_label = vuln_label[:1].upper() + vuln_label[1:]
    docstring = f'"""{lang_label} — {vuln_label} sinks."""'

    lines: list[str] = [
        docstring,
        "",
        "from app.scanner.sink.types import SinkRule",
        "",
        f"VULNERABILITY = {_py_str(vulnerability)}",
        "",
        "RULES = [",
    ]

    for r in rules:
        lines.extend(_serialize_rule(r))

    lines.append("]")
    lines.append("")  # trailing newline
    return "\n".join(lines)


def _serialize_rule(r: dict[str, Any]) -> list[str]:
    out: list[str] = ["    SinkRule("]
    rid = str(r.get("id") or "").strip()
    func = str(r.get("function") or "").strip()
    regex = str(r.get("call_regex") or "")
    desc = str(r.get("description") or "")
    severity = str(r.get("severity") or "low").strip().lower() or "low"
    argument_roles = list(r.get("argument_roles") or [])
    extensions = list(r.get("extensions") or [])
    extra_regex = list(r.get("extra_match_regex") or [])
    require_dynamic = bool(r.get("require_dynamic"))

    out.append(f"        id={_py_str(rid)},")
    out.append(f"        function={_py_str(func)},")
    out.append(f"        call_regex={_py_regex(regex)},")
    out.append(f"        description={_py_str(desc)},")
    out.append(f"        argument_roles={_py_str_list(argument_roles)},")
    out.append(f"        extensions={_py_str_list(extensions)},")
    out.append(f"        severity={_py_str(severity)},")
    if require_dynamic:
        out.append("        require_dynamic=True,")
    if extra_regex:
        out.append("        extra_match_regex=[")
        for re_str in extra_regex:
            out.append(f"            {_py_regex(re_str)},")
        out.append("        ],")
    out.append("    ),")
    return out


def _py_str(s: str) -> str:
    """普通字符串：用 repr，但偏向双引号便于阅读。"""
    s = s if isinstance(s, str) else str(s)
    if "'" in s and '"' not in s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return repr(s)


def _py_regex(s: str) -> str:
    """正则字符串：能用 raw string 就用 r""，否则 repr。"""
    if not isinstance(s, str):
        s = str(s)
    if not s:
        return '""'
    if (
        "\\" in s
        and '"' not in s
        and not s.endswith("\\")
    ):
        return f'r"{s}"'
    return repr(s)


def _py_str_list(items: list[Any]) -> str:
    parts = [_py_str(str(x)) for x in items]
    return "[" + ", ".join(parts) + "]"


def list_sink_history(language: str, name: str) -> list[dict[str, Any]]:
    target = _resolve_sink(language, name)
    return list_history(target)


def read_sink_version(language: str, name: str, version: int) -> dict[str, Any]:
    target = _resolve_sink(language, name)
    return {
        "language": language,
        "name": Path(target).stem,
        "version": version,
        "content": read_history_version(target, version),
    }
