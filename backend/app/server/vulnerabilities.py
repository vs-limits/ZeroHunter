"""Project-level vulnerability collection storage and helpers."""

from __future__ import annotations

import mimetypes
import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from app.agent.prompts import load_prompt
from app.llm.client import chat_completion, response_message_to_dict
from app.server import artifacts, json_io, scans as scans_mod
from app.server.paths import (
    PROJECT_ROOT_DIR,
    normalize_segment,
    parse_project_key,
    project_dir,
    project_container_dir,
)


VULNERABILITY_DIRNAME = "vulnerability"
META_FILENAME = "meta.json"
ENVIRONMENT_DIRNAME = "environment"
POC_DIRNAME = "poc"
FILES_DIRNAME = "files"
COMMANDS_DIRNAME = "commands"
ASSETS_DIRNAME = "assets"
REPRODUCTION_FILENAME = "reproduction.md"
POC_COMMANDS_FILENAME = "commands.json"
SETTINGS_PATH = PROJECT_ROOT_DIR / ".defectmine" / "settings.json"

SEVERITIES = {"critical", "high", "medium", "low"}
STATUSES = {"draft", "confirmed", "reproducing", "reproduced", "archived"}
SOURCES = {"manual", "scan", "import"}
FILE_SECTIONS = {"environment", "poc"}
AI_SECTIONS = {"info", "environment", "reproduction", "poc"}
AI_PROMPT_FILENAME = "vulnerability_ai.md"

DEFAULT_SETTINGS: dict[str, Any] = {
    "vulnerability_tags": [
        "SQL注入",
        "XSS",
        "命令执行",
        "路径穿越",
        "反序列化",
        "SSRF",
        "Java",
        "Python",
        "JavaScript",
        "PHP",
        "Go",
    ],
    "environment_file_presets": [
        "Dockerfile",
        "docker-compose.yml",
        "app.js",
        "app.py",
        "README.md",
    ],
    "poc_file_presets": [
        "exploit.py",
        "poc.py",
        "exp.py",
        "main.go",
        "index.js",
        "exploit.sh",
    ],
    "poc_parameter_presets": [
        {"name": "rhost", "type": "string", "default": "", "required": True},
        {"name": "rport", "type": "number", "default": "", "required": False},
        {"name": "lhost", "type": "string", "default": "", "required": False},
        {"name": "lport", "type": "number", "default": "", "required": False},
        {"name": "url", "type": "string", "default": "", "required": False},
        {"name": "token", "type": "string", "default": "", "required": False},
        {"name": "username", "type": "string", "default": "", "required": False},
        {"name": "password", "type": "string", "default": "", "required": False},
        {"name": "proxy", "type": "string", "default": "", "required": False},
    ],
}


def list_vulnerabilities(source: str, owner: str, repo: str) -> list[dict[str, Any]]:
    root = _vulnerabilities_root(source, owner, repo)
    if not root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for item_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        meta = _read_meta(item_dir)
        if meta:
            items.append(_summary(meta, item_dir))
    items.sort(key=lambda item: item.get("updated_at") or "", reverse=True)
    return items


def create_vulnerability(
    source: str,
    owner: str,
    repo: str,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    root = _vulnerabilities_root(key.source, key.owner, key.repo)
    root.mkdir(parents=True, exist_ok=True)
    vuln_id = _new_vulnerability_id()
    vuln_dir = root / vuln_id
    vuln_dir.mkdir(parents=True, exist_ok=False)
    meta = _meta_defaults(key.source, key.owner, key.repo, vuln_id)
    meta = _apply_meta_fields(meta, fields or {})
    _write_meta(vuln_dir, meta)
    _ensure_vulnerability_layout(vuln_dir)
    return get_vulnerability(key.source, key.owner, key.repo, vuln_id)


def get_vulnerability(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    meta = _read_meta(vuln_dir)
    if not meta:
        raise FileNotFoundError(f"vulnerability does not exist: {vulnerability_id}")
    return _detail(meta, vuln_dir)


def update_vulnerability(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    meta = _read_meta(vuln_dir)
    if not meta:
        raise FileNotFoundError(f"vulnerability does not exist: {vulnerability_id}")

    meta_fields = {k: v for k, v in fields.items() if k not in _DETAIL_FIELD_NAMES}
    meta = _apply_meta_fields(meta, meta_fields)
    meta["updated_at"] = _now_iso()
    _write_meta(vuln_dir, meta)

    if "environment_commands" in fields:
        _write_environment_commands(vuln_dir, fields.get("environment_commands") or {})
    if "reproduction" in fields:
        _write_reproduction(vuln_dir, str(fields.get("reproduction") or ""))
    if "poc_commands" in fields:
        _write_poc_commands(vuln_dir, fields.get("poc_commands") or {})

    return get_vulnerability(source, owner, repo, vulnerability_id)


def delete_vulnerability(source: str, owner: str, repo: str, vulnerability_id: str) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    meta = _read_meta(vuln_dir) or {}
    shutil.rmtree(vuln_dir)
    return meta


def convert_finding_to_vulnerability(
    source: str,
    owner: str,
    repo: str,
    *,
    project_path: str,
    scan_id: str,
    chain_id: str,
    duplicate: bool = False,
) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    existing = _find_by_source_finding(key.source, key.owner, key.repo, project_path, scan_id, chain_id)
    if existing and not duplicate:
        return {"duplicate": True, "item": existing}

    found = artifacts.get_finding(project_path, chain_id, scan_id)
    finding = found.get("finding") or {}
    fields = _fields_from_finding(project_path, scan_id, chain_id, finding)
    created = create_vulnerability(key.source, key.owner, key.repo, fields)
    return {"duplicate": False, "item": created}


def analyze_vulnerability(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
) -> dict[str, Any]:
    section = str(section or "").strip()
    if section not in AI_SECTIONS:
        raise ValueError("section must be info, environment, reproduction, or poc")

    detail = get_vulnerability(source, owner, repo, vulnerability_id)
    system_prompt = load_prompt(AI_PROMPT_FILENAME)
    user_payload = {
        "task": "analyze_vulnerability_section",
        "section": section,
        "project": {
            "source": source,
            "owner": owner,
            "repo": repo,
            "project_key": f"{source}/{owner}/{repo}",
        },
        "current_vulnerability": _ai_context(detail, section),
        "output_contract": "Return one strict JSON object that follows backend/prompts/vulnerability_ai.md.",
    }
    response = chat_completion(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
        max_tokens=5000,
        thinking=False,
    )
    message = response_message_to_dict(response)
    parsed = _parse_ai_json(message.get("content"))
    return _normalize_ai_result(parsed, section)


def link_targets(source: str, owner: str, repo: str) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    container = project_container_dir(key.source, key.owner, key.repo)
    if not container.is_dir():
        raise FileNotFoundError(f"project does not exist: {key.project_key}")

    versions: list[dict[str, Any]] = []
    scan_items: list[dict[str, Any]] = []
    for version_dir in sorted(p for p in container.iterdir() if p.is_dir()):
        if _is_reserved_project_child(version_dir.name):
            continue
        project_path = f"{key.source}/{key.owner}/{key.repo}/{version_dir.name}"
        versions.append(
            {
                "project_path": project_path,
                "version": version_dir.name,
                "name": version_dir.name,
            }
        )
        try:
            for scan in scans_mod.list_scans(project_path):
                scan_items.append(
                    {
                        "project_path": project_path,
                        "version": version_dir.name,
                        "scan_id": scan.get("scan_id"),
                        "name": scan.get("name") or scan.get("scan_id"),
                        "status": scan.get("status"),
                    }
                )
        except (FileNotFoundError, ValueError):
            continue
    return {"versions": versions, "scans": scan_items}


def list_files(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    file_dir = _section_files_dir(vuln_dir, section)
    return {"items": _list_text_files(file_dir)}


def write_file(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
    filename: str,
    content: str,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    target = _safe_text_file(_section_files_dir(vuln_dir, section), filename)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _touch_meta(vuln_dir)
    return _file_entry(target)


def rename_file(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
    filename: str,
    new_filename: str,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    file_dir = _section_files_dir(vuln_dir, section)
    old = _safe_text_file(file_dir, filename)
    new = _safe_text_file(file_dir, new_filename)
    if not old.is_file():
        raise FileNotFoundError(f"file does not exist: {filename}")
    if new.exists():
        raise FileExistsError(f"file already exists: {new_filename}")
    new.parent.mkdir(parents=True, exist_ok=True)
    old.rename(new)
    _touch_meta(vuln_dir)
    return _file_entry(new)


def delete_file(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
    filename: str,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    target = _safe_text_file(_section_files_dir(vuln_dir, section), filename)
    if not target.is_file():
        raise FileNotFoundError(f"file does not exist: {filename}")
    target.unlink()
    _touch_meta(vuln_dir)
    return {"ok": True, "filename": filename}


def save_asset(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    *,
    filename: str,
    content_type: str | None,
    data: bytes,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    if not data:
        raise ValueError("asset cannot be empty")
    ext = _asset_extension(filename, content_type)
    asset_name = f"asset-{datetime.now().astimezone().strftime('%Y%m%d-%H%M%S-%f')}{ext}"
    target = _safe_asset_file(vuln_dir, asset_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    _touch_meta(vuln_dir)
    return {
        "filename": asset_name,
        "size": len(data),
        "content_type": content_type or mimetypes.guess_type(asset_name)[0] or "application/octet-stream",
        "markdown": f"![{Path(filename).stem or 'image'}](assets/{asset_name})",
    }


def asset_path(source: str, owner: str, repo: str, vulnerability_id: str, filename: str) -> Path:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    target = _safe_asset_file(vuln_dir, filename)
    if not target.is_file():
        raise FileNotFoundError(f"asset does not exist: {filename}")
    return target


def read_settings() -> dict[str, Any]:
    raw = json_io.read_json_object(SETTINGS_PATH) or {}
    return _normalize_settings(raw)


def update_settings(fields: dict[str, Any]) -> dict[str, Any]:
    current = read_settings()
    merged = dict(current)
    for key in DEFAULT_SETTINGS:
        if key in fields:
            merged[key] = fields[key]
    settings = _normalize_settings(merged)
    json_io.write_json(SETTINGS_PATH, settings, indent=True)
    return settings


def export_vulnerability(
    source: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    export_format: str,
    sections: list[str] | None = None,
) -> dict[str, Any]:
    vuln_dir = _existing_vulnerability_dir(source, owner, repo, vulnerability_id)
    meta = _read_meta(vuln_dir)
    if not meta:
        raise FileNotFoundError(f"vulnerability does not exist: {vulnerability_id}")
    from app.server.vulnerability_export import build_vulnerability_export

    return build_vulnerability_export(
        _detail(meta, vuln_dir),
        vuln_dir,
        export_format,
        sections=sections,
    )


_DETAIL_FIELD_NAMES = {"environment_commands", "reproduction", "poc_commands"}


def _vulnerabilities_root(source: str, owner: str, repo: str) -> Path:
    key = parse_project_key(source, owner, repo)
    container = project_container_dir(key.source, key.owner, key.repo)
    if not container.is_dir():
        raise FileNotFoundError(f"project does not exist: {key.project_key}")
    return container / VULNERABILITY_DIRNAME


def _vulnerability_dir(source: str, owner: str, repo: str, vulnerability_id: str) -> Path:
    root = _vulnerabilities_root(source, owner, repo)
    vid = normalize_segment(vulnerability_id, field="vulnerability_id")
    target = (root / vid).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as err:
        raise ValueError("vulnerability_id must stay under vulnerability/") from err
    return target


def _existing_vulnerability_dir(source: str, owner: str, repo: str, vulnerability_id: str) -> Path:
    target = _vulnerability_dir(source, owner, repo, vulnerability_id)
    if not target.is_dir():
        raise FileNotFoundError(f"vulnerability does not exist: {vulnerability_id}")
    return target


def _new_vulnerability_id() -> str:
    return f"vuln-{datetime.now().astimezone().strftime('%Y%m%d-%H%M%S-%f')}"


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _meta_defaults(source: str, owner: str, repo: str, vulnerability_id: str) -> dict[str, Any]:
    now = _now_iso()
    return {
        "vulnerability_id": vulnerability_id,
        "project_key": f"{source}/{owner}/{repo}",
        "source_root": source,
        "owner": owner,
        "repo": repo,
        "name": "未命名漏洞",
        "details": "",
        "tags": [],
        "location": "",
        "affected_version": "",
        "severity": "medium",
        "status": "draft",
        "cve": "",
        "references": [],
        "source": "manual",
        "links": {"version_project_paths": [], "scans": [], "external": []},
        "source_finding": None,
        "created_at": now,
        "updated_at": now,
    }


def _read_meta(vuln_dir: Path) -> dict[str, Any] | None:
    data = json_io.read_json_object(vuln_dir / META_FILENAME)
    return _normalize_meta(data, vuln_dir.name) if data else None


def _write_meta(vuln_dir: Path, meta: dict[str, Any]) -> None:
    json_io.write_json(vuln_dir / META_FILENAME, _normalize_meta(meta, vuln_dir.name), indent=True)


def _touch_meta(vuln_dir: Path) -> None:
    meta = _read_meta(vuln_dir)
    if not meta:
        return
    meta["updated_at"] = _now_iso()
    _write_meta(vuln_dir, meta)


def _normalize_meta(meta: dict[str, Any], vulnerability_id: str) -> dict[str, Any]:
    normalized = dict(meta)
    normalized["vulnerability_id"] = vulnerability_id
    normalized["name"] = str(normalized.get("name") or "未命名漏洞")
    normalized["details"] = str(normalized.get("details") or "")
    normalized["tags"] = _string_list(normalized.get("tags"))
    normalized["location"] = str(normalized.get("location") or "")
    normalized["affected_version"] = str(normalized.get("affected_version") or "")
    severity = str(normalized.get("severity") or "medium").lower()
    normalized["severity"] = severity if severity in SEVERITIES else "medium"
    status = str(normalized.get("status") or "draft")
    normalized["status"] = status if status in STATUSES else "draft"
    normalized["cve"] = str(normalized.get("cve") or "")
    normalized["references"] = _string_list(normalized.get("references"))
    source = str(normalized.get("source") or "manual")
    normalized["source"] = source if source in SOURCES else "manual"
    normalized["links"] = _normalize_links(normalized.get("links"))
    normalized["created_at"] = normalized.get("created_at") or _now_iso()
    normalized["updated_at"] = normalized.get("updated_at") or normalized["created_at"]
    return normalized


def _apply_meta_fields(meta: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
    out = dict(meta)
    for key in (
        "name",
        "details",
        "tags",
        "location",
        "affected_version",
        "severity",
        "status",
        "cve",
        "references",
        "source",
        "links",
        "source_finding",
    ):
        if key in fields:
            out[key] = fields[key]
    return _normalize_meta(out, str(out.get("vulnerability_id") or ""))


def _normalize_links(raw: Any) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    scans: list[dict[str, str]] = []
    for item in data.get("scans") or []:
        if not isinstance(item, dict):
            continue
        project_path = str(item.get("project_path") or "").strip()
        scan_id = str(item.get("scan_id") or "").strip()
        if not project_path or not scan_id:
            continue
        scans.append(
            {
                "project_path": project_path,
                "scan_id": scan_id,
                "name": str(item.get("name") or scan_id),
            }
        )
    external: list[dict[str, str]] = []
    for item in data.get("external") or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        external.append({"name": str(item.get("name") or url).strip(), "url": url})
    return {
        "version_project_paths": _string_list(data.get("version_project_paths")),
        "scans": scans,
        "external": external,
    }


def _summary(meta: dict[str, Any], vuln_dir: Path) -> dict[str, Any]:
    return {
        "vulnerability_id": meta["vulnerability_id"],
        "project_key": meta.get("project_key"),
        "name": meta.get("name") or meta["vulnerability_id"],
        "severity": meta.get("severity"),
        "status": meta.get("status"),
        "source": meta.get("source"),
        "tags": meta.get("tags") or [],
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "path": str(vuln_dir),
        "links": meta.get("links") or _normalize_links(None),
    }


def _detail(meta: dict[str, Any], vuln_dir: Path) -> dict[str, Any]:
    item = _summary(meta, vuln_dir)
    item.update(
        {
            "details": meta.get("details") or "",
            "location": meta.get("location") or "",
            "affected_version": meta.get("affected_version") or "",
            "cve": meta.get("cve") or "",
            "references": meta.get("references") or [],
            "source_finding": meta.get("source_finding"),
            "code_regions": _code_regions(meta),
            "meta": meta,
            "environment": {
                "files": _list_text_files(vuln_dir / ENVIRONMENT_DIRNAME / FILES_DIRNAME),
                "commands": _read_environment_commands(vuln_dir),
            },
            "reproduction": _read_reproduction(vuln_dir),
            "poc": {
                "files": _list_text_files(vuln_dir / POC_DIRNAME / FILES_DIRNAME),
                "commands": _read_poc_commands(vuln_dir),
            },
        }
    )
    return item


def _code_regions(meta: dict[str, Any]) -> list[dict[str, Any]]:
    source_finding = meta.get("source_finding") if isinstance(meta.get("source_finding"), dict) else {}
    finding = source_finding.get("finding") if isinstance(source_finding.get("finding"), dict) else {}
    project_path = str(source_finding.get("project_path") or "").strip()
    if not project_path:
        links = meta.get("links") if isinstance(meta.get("links"), dict) else {}
        versions = links.get("version_project_paths") if isinstance(links.get("version_project_paths"), list) else []
        project_path = str(versions[0] if versions else "").strip()
    if not project_path:
        return []
    try:
        root = project_dir(project_path)
    except (FileNotFoundError, ValueError):
        return []

    language = str(finding.get("language") or "").strip()
    candidates: list[dict[str, Any]] = []
    for role, label in (("source", "Source 输入点"), ("sink", "Sink 汇聚点")):
        node = finding.get(role) if isinstance(finding.get(role), dict) else {}
        if node:
            candidates.append(
                {
                    "role": role,
                    "title": label,
                    "file": node.get("file"),
                    "line": node.get("line"),
                    "description": node.get("expr") or node.get("detail") or "",
                }
            )
    for idx, item in enumerate(finding.get("evidence") or [], start=1):
        if not isinstance(item, dict):
            continue
        candidates.append(
            {
                "role": "evidence",
                "title": f"证据区域 {idx}",
                "file": item.get("file"),
                "line": item.get("line"),
                "description": item.get("detail") or item.get("expr") or item.get("source") or "",
            }
        )
    location_file, location_line = _parse_location(meta.get("location"))
    if location_file:
        candidates.append(
            {
                "role": "location",
                "title": "漏洞位置",
                "file": location_file,
                "line": location_line,
                "description": str(meta.get("location") or ""),
            }
        )

    regions: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None, str]] = set()
    for candidate in candidates:
        rel_file = str(candidate.get("file") or "").replace("\\", "/").strip().strip("/")
        if not rel_file or rel_file in {".", ".."} or ".." in rel_file.split("/"):
            continue
        line = _safe_int(candidate.get("line"))
        key = (rel_file, line)
        if key in seen:
            continue
        seen.add(key)
        snippet = _read_code_snippet(root, rel_file, line)
        if not snippet:
            continue
        regions.append(
            {
                "id": f"{len(regions) + 1}:{candidate.get('role') or 'code'}:{rel_file}:{line or 0}",
                "title": candidate.get("title") or "代码区域",
                "role": candidate.get("role") or "code",
                "file": rel_file,
                "line": line,
                "line_start": snippet["line_start"],
                "line_end": snippet["line_end"],
                "language": language or _language_from_path(rel_file),
                "description": str(candidate.get("description") or "").strip(),
                "code": snippet["code"],
            }
        )
    return regions


def _read_code_snippet(root: Path, rel_file: str, line: int | None) -> dict[str, Any] | None:
    target = (root / rel_file).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    if not target.is_file():
        return None
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return None
    focus = line if line and line > 0 else 1
    start = max(1, focus - 8)
    end = min(len(lines), focus + 10)
    if not line:
        start = 1
        end = min(len(lines), 80)
    return {
        "line_start": start,
        "line_end": end,
        "code": "\n".join(lines[start - 1 : end]),
    }


def _parse_location(value: Any) -> tuple[str | None, int | None]:
    text = str(value or "").strip()
    match = re.match(r"([^:\s]+):(\d+)", text)
    if not match:
        return None, None
    return match.group(1), _safe_int(match.group(2))


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _language_from_path(path: str) -> str:
    suffix = Path(path).suffix.lower().lstrip(".")
    return {
        "js": "javascript",
        "jsx": "javascript",
        "ts": "typescript",
        "tsx": "typescript",
        "py": "python",
        "php": "php",
        "java": "java",
        "go": "go",
        "rb": "ruby",
        "rs": "rust",
        "c": "c",
        "h": "c",
        "cpp": "cpp",
        "cc": "cpp",
        "hpp": "cpp",
        "html": "html",
        "vue": "vue",
        "sql": "sql",
    }.get(suffix, suffix or "text")


def _ensure_vulnerability_layout(vuln_dir: Path) -> None:
    (vuln_dir / ENVIRONMENT_DIRNAME / FILES_DIRNAME).mkdir(parents=True, exist_ok=True)
    (vuln_dir / ENVIRONMENT_DIRNAME / COMMANDS_DIRNAME).mkdir(parents=True, exist_ok=True)
    (vuln_dir / POC_DIRNAME / FILES_DIRNAME).mkdir(parents=True, exist_ok=True)
    (vuln_dir / ASSETS_DIRNAME).mkdir(parents=True, exist_ok=True)
    if not (vuln_dir / REPRODUCTION_FILENAME).exists():
        (vuln_dir / REPRODUCTION_FILENAME).write_text("", encoding="utf-8")
    if not (vuln_dir / POC_DIRNAME / POC_COMMANDS_FILENAME).exists():
        _write_poc_commands(vuln_dir, {"template": "", "parameters": []})


def _read_environment_commands(vuln_dir: Path) -> dict[str, str]:
    cmd_dir = vuln_dir / ENVIRONMENT_DIRNAME / COMMANDS_DIRNAME
    return {
        "windows": _read_text(cmd_dir / "windows.bat"),
        "linux": _read_text(cmd_dir / "linux.sh"),
    }


def _write_environment_commands(vuln_dir: Path, commands: dict[str, Any]) -> None:
    cmd_dir = vuln_dir / ENVIRONMENT_DIRNAME / COMMANDS_DIRNAME
    cmd_dir.mkdir(parents=True, exist_ok=True)
    (cmd_dir / "windows.bat").write_text(str(commands.get("windows") or ""), encoding="utf-8")
    (cmd_dir / "linux.sh").write_text(str(commands.get("linux") or ""), encoding="utf-8")


def _read_reproduction(vuln_dir: Path) -> str:
    return _read_text(vuln_dir / REPRODUCTION_FILENAME)


def _write_reproduction(vuln_dir: Path, content: str) -> None:
    (vuln_dir / REPRODUCTION_FILENAME).write_text(content, encoding="utf-8")


def _read_poc_commands(vuln_dir: Path) -> dict[str, Any]:
    data = json_io.read_json_object(vuln_dir / POC_DIRNAME / POC_COMMANDS_FILENAME) or {}
    return {
        "template": str(data.get("template") or ""),
        "parameters": _normalize_poc_parameters(data.get("parameters")),
    }


def _write_poc_commands(vuln_dir: Path, commands: dict[str, Any]) -> None:
    target = vuln_dir / POC_DIRNAME / POC_COMMANDS_FILENAME
    json_io.write_json(
        target,
        {
            "template": str(commands.get("template") or ""),
            "parameters": _normalize_poc_parameters(commands.get("parameters")),
        },
        indent=True,
    )


def _normalize_poc_parameters(raw: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        out.append(
            {
                "name": name,
                "type": str(item.get("type") or "string"),
                "default": str(item.get("default") or ""),
                "required": bool(item.get("required")),
            }
        )
    return out


def _section_files_dir(vuln_dir: Path, section: str) -> Path:
    if section not in FILE_SECTIONS:
        raise ValueError("section must be environment or poc")
    if section == "environment":
        return vuln_dir / ENVIRONMENT_DIRNAME / FILES_DIRNAME
    return vuln_dir / POC_DIRNAME / FILES_DIRNAME


def _list_text_files(file_dir: Path) -> list[dict[str, Any]]:
    if not file_dir.is_dir():
        return []
    return [_file_entry(p) for p in sorted(file_dir.iterdir()) if p.is_file()]


def _file_entry(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "filename": path.name,
        "content": path.read_text(encoding="utf-8", errors="replace"),
        "size": st.st_size,
        "mtime": st.st_mtime,
    }


def _safe_filename(filename: str, *, field: str = "filename") -> str:
    text = str(filename or "").strip()
    if not text:
        raise ValueError(f"{field} cannot be empty")
    if text in {".", ".."} or "/" in text or "\\" in text:
        raise ValueError(f"{field} cannot contain path separators or dot segments")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{field} cannot contain control characters")
    return text


def _safe_text_file(base: Path, filename: str) -> Path:
    safe = _safe_filename(filename)
    target = (base / safe).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError as err:
        raise ValueError("file must stay under section files directory") from err
    return target


def _safe_asset_file(vuln_dir: Path, filename: str) -> Path:
    safe = _safe_filename(filename, field="asset filename")
    base = vuln_dir / ASSETS_DIRNAME
    target = (base / safe).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError as err:
        raise ValueError("asset must stay under assets directory") from err
    return target


def _asset_extension(filename: str, content_type: str | None) -> str:
    suffix = Path(_safe_filename(filename or "asset", field="asset filename")).suffix.lower()
    allowed = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}
    if suffix in allowed:
        return suffix
    guessed = mimetypes.guess_extension(content_type or "")
    if guessed and guessed.lower() in allowed:
        return guessed.lower()
    return ".bin"


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _fields_from_finding(
    project_path: str,
    scan_id: str,
    chain_id: str,
    finding: dict[str, Any],
) -> dict[str, Any]:
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    location = ""
    if sink:
        location = f"{sink.get('file') or ''}:{sink.get('line') or ''} {sink.get('expr') or ''}".strip()
    vuln_type = str(finding.get("vulnerability_type") or "").strip()
    language = str(finding.get("language") or "").strip()
    title = str(finding.get("title") or "").strip()
    name = title if title and title != "unit-test" else f"{vuln_type or '漏洞'} @ {location or chain_id}"
    details_parts = []
    for label, key in (
        ("原理", "principle"),
        ("利用示例", "exploit_poc"),
        ("修复建议", "fix_suggestion"),
        ("已拦截/反证", "refuted_by"),
    ):
        value = finding.get(key)
        if value:
            details_parts.append(f"## {label}\n{value}")
    tags = [item for item in [vuln_type, language, finding.get("cwe_guess")] if item]
    return {
        "name": name,
        "details": "\n\n".join(details_parts),
        "tags": tags,
        "location": location,
        "affected_version": project_path,
        "severity": str(finding.get("severity") or "medium").lower(),
        "status": "confirmed" if finding.get("verdict") == "vulnerable" else "draft",
        "cve": "",
        "references": [],
        "source": "scan",
        "links": {
            "version_project_paths": [project_path],
            "scans": [{"project_path": project_path, "scan_id": scan_id, "name": scan_id}],
            "external": [],
        },
        "source_finding": {
            "project_path": project_path,
            "scan_id": scan_id,
            "chain_id": chain_id,
            "finding": finding,
        },
    }


def _find_by_source_finding(
    source: str,
    owner: str,
    repo: str,
    project_path: str,
    scan_id: str,
    chain_id: str,
) -> dict[str, Any] | None:
    for item in list_vulnerabilities(source, owner, repo):
        detail = get_vulnerability(source, owner, repo, item["vulnerability_id"])
        source_finding = detail.get("source_finding") or {}
        if (
            source_finding.get("project_path") == project_path
            and source_finding.get("scan_id") == scan_id
            and source_finding.get("chain_id") == chain_id
        ):
            return detail
    return None


def _ai_context(detail: dict[str, Any], section: str) -> dict[str, Any]:
    base = {
        "vulnerability_id": detail.get("vulnerability_id"),
        "name": detail.get("name"),
        "details": detail.get("details"),
        "tags": detail.get("tags") or [],
        "location": detail.get("location"),
        "affected_version": detail.get("affected_version"),
        "severity": detail.get("severity"),
        "status": detail.get("status"),
        "cve": detail.get("cve"),
        "references": detail.get("references") or [],
        "source": detail.get("source"),
        "links": detail.get("links") or {},
        "source_finding": detail.get("source_finding"),
    }
    if section == "info":
        return base
    if section == "environment":
        return {
            **base,
            "environment": detail.get("environment") or {},
        }
    if section == "reproduction":
        return {
            **base,
            "reproduction": detail.get("reproduction") or "",
        }
    return {
        **base,
        "poc": detail.get("poc") or {},
    }


def _parse_ai_json(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    text = str(content or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].lstrip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as err:
        raise ValueError("LLM did not return a valid JSON object") from err
    if not isinstance(parsed, dict):
        raise ValueError("LLM response must be a JSON object")
    return parsed


def _normalize_ai_result(raw: dict[str, Any], section: str) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    result: dict[str, Any] = {
        "section": section,
        "web_search_used": bool(data.get("web_search_used")),
        "confidence": _coerce_confidence(data.get("confidence")),
        "summary": str(data.get("summary") or ""),
        "suggestions": _string_list(data.get("suggestions")),
        "warnings": _string_list(data.get("warnings")),
    }
    if section == "info":
        result["info"] = _normalize_ai_info(data.get("info") or data)
    elif section == "environment":
        result["environment"] = _normalize_ai_environment(data.get("environment") or data)
    elif section == "reproduction":
        repro = data.get("reproduction") if isinstance(data.get("reproduction"), dict) else data
        result["reproduction"] = {"markdown": str((repro or {}).get("markdown") or data.get("markdown") or "")}
    elif section == "poc":
        result["poc"] = _normalize_ai_poc(data.get("poc") or data)
    return result


def _normalize_ai_info(raw: Any) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    out = {
        "name": str(data.get("name") or ""),
        "details": str(data.get("details") or ""),
        "tags": _string_list(data.get("tags")),
        "location": str(data.get("location") or ""),
        "affected_version": str(data.get("affected_version") or ""),
        "severity": str(data.get("severity") or "").lower(),
        "status": str(data.get("status") or ""),
        "cve": str(data.get("cve") or ""),
        "references": _string_list(data.get("references")),
        "source": str(data.get("source") or ""),
    }
    if out["severity"] not in SEVERITIES:
        out["severity"] = ""
    if out["status"] not in STATUSES:
        out["status"] = ""
    if out["source"] not in SOURCES:
        out["source"] = ""
    return out


def _normalize_ai_environment(raw: Any) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    commands = data.get("commands") if isinstance(data.get("commands"), dict) else {}
    return {
        "files": _normalize_ai_files(data.get("files")),
        "commands": {
            "windows": str(commands.get("windows") or ""),
            "linux": str(commands.get("linux") or ""),
        },
    }


def _normalize_ai_poc(raw: Any) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    commands = data.get("commands") if isinstance(data.get("commands"), dict) else {}
    return {
        "files": _normalize_ai_files(data.get("files")),
        "commands": {
            "template": str(commands.get("template") or ""),
            "parameters": _normalize_poc_parameters(commands.get("parameters")),
        },
    }


def _normalize_ai_files(raw: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        try:
            filename = _safe_filename(str(item.get("filename") or ""))
        except ValueError:
            continue
        out.append({"filename": filename, "content": str(item.get("content") or "")})
    return out


def _coerce_confidence(raw: Any) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def _is_reserved_project_child(name: str) -> bool:
    return name.startswith(".") or name == VULNERABILITY_DIRNAME


def _string_list(raw: Any) -> list[str]:
    out: list[str] = []
    for item in raw or []:
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _normalize_settings(raw: dict[str, Any]) -> dict[str, Any]:
    settings = dict(DEFAULT_SETTINGS)
    settings.update(raw)
    settings["vulnerability_tags"] = _unique_strings(settings.get("vulnerability_tags"))
    settings["environment_file_presets"] = _unique_strings(settings.get("environment_file_presets"))
    settings["poc_file_presets"] = _unique_strings(settings.get("poc_file_presets"))
    settings["poc_parameter_presets"] = _normalize_poc_parameters(
        settings.get("poc_parameter_presets")
    )
    return settings


def _unique_strings(raw: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in raw or []:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
