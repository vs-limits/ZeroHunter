"""TreeScan Agent：扫描项目树并生成仓库画像。

对外入口: run(project_path) -> dict

内部固定工作流：
    1. 调 scanner.tree.scan_project_tree 得到项目目录结构树
    2. 把项目目录结构树 JSON 喂给 LLM，得到严格 JSON 格式的项目画像
    3. 画像渲染为表格打印到思维流，返回解析后的 dict
"""

import json
import os
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich import box
from rich.table import Table

from app.agent.prompts import load_prompt
from app.core.labels import (
    TREESCAN_CONFIDENCE_LABELS,
    TREESCAN_LABELS,
    TREESCAN_STACK_LABELS,
)
from app.llm.client import chat_completion, response_message_to_dict
from app.scanner.tree import scan_project_tree, resolve_scan_root
from app.ui.console import action, console, info, status_scope


# ============================================================
# Agent 定义
# ============================================================
@dataclass(frozen=True)
class AgentSpec:
    name: str
    system_message: str
    temperature: float = 0.2
    max_tokens: int = 3000


SPEC = AgentSpec(
    name="项目目录结构树扫描智能体",
    system_message=load_prompt("treescan.md"),
    temperature=0.1,
    max_tokens=int(os.environ.get("TREESCAN_MAX_TOKENS", "4096") or "4096"),
)
TREESCAN_MAX_TOKENS_RETRY = int(
    os.environ.get("TREESCAN_MAX_TOKENS_RETRY", "8192") or "8192"
)

# 产物落盘
ARTIFACTS_DIRNAME = ".defectmine"
TREE_FILENAME = "tree.json"
TREESCAN_FILENAME = "treescan_agent.json"
TREESCAN_LLM_TREE_CHAR_BUDGET = int(
    os.environ.get("TREESCAN_LLM_TREE_CHAR_BUDGET", "240000") or "240000"
)
_COMPACTION_PROFILES = [
    (7, 36, 28),
    (6, 28, 20),
    (5, 20, 14),
    (4, 14, 8),
    (4, 10, 4),
    (3, 8, 2),
    (3, 5, 1),
    (2, 5, 1),
    (2, 3, 0),
]
_SIGNAL_FILES = {
    ".env.example",
    "application.properties",
    "application.yml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "docker-compose.yml",
    "dockerfile",
    "go.mod",
    "gradle.properties",
    "manage.py",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "settings.gradle",
    "settings.gradle.kts",
    "setup.py",
    "tsconfig.json",
}
_SIGNAL_DIRS = {
    "api",
    "app",
    "apps",
    "bin",
    "cmd",
    "config",
    "controllers",
    "db",
    "deploy",
    "docker",
    "extension",
    "extensions",
    "frontend",
    "handlers",
    "java",
    "jobs",
    "k8s",
    "main",
    "migrations",
    "modules",
    "plugins",
    "resources",
    "routes",
    "scripts",
    "security",
    "server",
    "src",
    "templates",
    "terraform",
    "web",
    "webapp",
    "workers",
}


# ============================================================
# 对外入口
# ============================================================
def run(project_path: str, run_id: str | None = None) -> dict:
    """扫描目录树 + 生成项目画像，返回画像 dict。

    参数:
        project_path: 相对于 repo/ 的项目路径，
            例如 github/yeswiki/yeswiki。
        run_id: 可选的扫描 ID，若提供则产物落到对应 scan 目录，
            否则落到仓库根 .defectmine/。
    """
    from app.agent.run_scope import resolve_run_scope

    scope = resolve_run_scope(project_path, run_id)
    project_root = scope.project_root
    artifacts_dir = scope.artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # 1. 扫描项目目录树
    action("扫描", str(project_root))
    t0 = time.perf_counter()
    tree = scan_project_tree(project_path)["tree"]
    file_count, dir_count = _count_tree(tree)
    info(f"共 {dir_count} 个目录 / {file_count} 个文件（{time.perf_counter() - t0:.2f}s）")

    tree_path = artifacts_dir / TREE_FILENAME
    _write_json(tree, tree_path)
    action("写入", str(tree_path))

    # 2. 调用 LLM 生成项目画像
    tree_json, compacted = _tree_json_for_llm(tree)
    if compacted:
        full_chars = len(json.dumps(tree, ensure_ascii=False))
        info(f"目录树过大，LLM 输入已压缩：{full_chars:,} -> {len(tree_json):,} 字符")
    else:
        info(f"向 LLM 提交 {len(tree_json):,} 字符的项目目录结构树")

    t0 = time.perf_counter()
    with status_scope("treescan_llm", label="调用 TreeScan Agent..."):
        profile = _request_profile(tree_json)
    info(f"LLM 推理耗时 {time.perf_counter() - t0:.2f}s")

    _render_profile(profile)

    profile_path = artifacts_dir / TREESCAN_FILENAME
    _write_json(profile, profile_path)
    action("写入", str(profile_path))

    return profile


# ============================================================
# 内部工具
# ============================================================
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
                pass
    return None


def _request_profile(tree_json: str) -> dict[str, Any]:
    """调用 LLM 生成仓库画像；输出被截断时自动提高 max_tokens 重试一次。"""
    max_tokens = SPEC.max_tokens
    last_raw = ""
    finish_reason: str | None = None

    for attempt in range(2):
        response = chat_completion(
            messages=[
                {"role": "system", "content": SPEC.system_message},
                {"role": "user", "content": tree_json},
            ],
            temperature=SPEC.temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        # Different providers return different response shapes: LiteLLM usually
        # returns an object with `.choices`, while the MiMo direct adapter returns
        # an OpenAI-compatible dict. Read the finish reason defensively and keep
        # content extraction centralized in response_message_to_dict().
        if isinstance(response, dict):
            choices = response.get("choices")
            choice = choices[0] if isinstance(choices, list) and choices else {}
            finish_reason = (
                choice.get("finish_reason") if isinstance(choice, dict) else None
            )
        else:
            choice = response.choices[0]
            finish_reason = getattr(choice, "finish_reason", None)
        message = response_message_to_dict(response)
        last_raw = str(message.get("content") or "")
        profile = _parse_json_from_text(last_raw)
        if isinstance(profile, dict):
            return profile
        if finish_reason == "length" and attempt == 0:
            next_tokens = max(max_tokens * 2, TREESCAN_MAX_TOKENS_RETRY)
            info(
                f"TreeScan 输出在 {max_tokens} tokens 处被截断，"
                f"提高至 {next_tokens} 后重试"
            )
            max_tokens = next_tokens
            continue
        break

    hint = "（LLM 输出可能被截断）" if finish_reason == "length" else ""
    preview = last_raw[:240].replace("\n", "\\n")
    raise ValueError(f"TreeScan Agent 返回无效 JSON{hint}: {preview}")


def _write_json(payload, path: Path):
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    path.write_text(text + "\n", encoding="utf-8")


def _count_tree(node):
    files = len(node.get("files", []))
    files += node.get("binary", {}).get("total", 0)
    dirs = 0
    for child in node.get("dirs", {}).values():
        dirs += 1
        sub_files, sub_dirs = _count_tree(child)
        files += sub_files
        dirs += sub_dirs
    return files, dirs


def _tree_json_for_llm(tree: dict) -> tuple[str, bool]:
    full = json.dumps(tree, ensure_ascii=False)
    if len(full) <= TREESCAN_LLM_TREE_CHAR_BUDGET:
        return full, False

    file_count, dir_count = _count_tree(tree)
    ext_counts = _extension_counts(tree)
    for max_depth, dirs_per_dir, files_per_dir in _COMPACTION_PROFILES:
        compacted = {
            "_defectmine_tree_compaction": {
                "compacted": True,
                "reason": "full tree exceeded LLM context budget",
                "original_chars": len(full),
                "original_files": file_count,
                "original_dirs": dir_count,
                "policy": {
                    "max_depth": max_depth,
                    "dirs_per_dir": dirs_per_dir,
                    "files_per_dir": files_per_dir,
                },
                "extension_summary": dict(ext_counts.most_common(30)),
            },
            "tree": _compact_node(
                tree,
                depth=0,
                max_depth=max_depth,
                dirs_per_dir=dirs_per_dir,
                files_per_dir=files_per_dir,
            ),
        }
        text = json.dumps(compacted, ensure_ascii=False)
        if len(text) <= TREESCAN_LLM_TREE_CHAR_BUDGET:
            return text, True

    fallback = {
        "_defectmine_tree_compaction": {
            "compacted": True,
            "reason": "full tree exceeded LLM context budget; summary fallback used",
            "original_chars": len(full),
            "original_files": file_count,
            "original_dirs": dir_count,
            "extension_summary": dict(ext_counts.most_common(50)),
        },
        "tree": _compact_node(
            tree,
            depth=0,
            max_depth=1,
            dirs_per_dir=80,
            files_per_dir=20,
        ),
    }
    text = json.dumps(fallback, ensure_ascii=False)
    if len(text) > TREESCAN_LLM_TREE_CHAR_BUDGET:
        fallback["tree"] = _compact_node(
            tree,
            depth=0,
            max_depth=1,
            dirs_per_dir=30,
            files_per_dir=5,
        )
        text = json.dumps(fallback, ensure_ascii=False)
    return text, True


def _compact_node(
    node: dict,
    *,
    depth: int,
    max_depth: int,
    dirs_per_dir: int,
    files_per_dir: int,
) -> dict:
    result: dict = {}
    files = sorted(node.get("files", []), key=str.lower)
    selected_files = _select_files(files, files_per_dir)
    if selected_files:
        result["files"] = selected_files
    omitted_files = max(0, len(files) - len(selected_files))
    if omitted_files:
        result["_omitted_files"] = omitted_files
        ext_counts = Counter(_file_ext(name) for name in files)
        result["_file_ext_counts"] = dict(ext_counts.most_common(10))

    binary = node.get("binary") or {}
    if binary.get("total", 0) > 0:
        result["binary"] = binary

    dirs = dict(sorted((node.get("dirs") or {}).items(), key=lambda item: item[0].lower()))
    if not dirs:
        return result

    if depth >= max_depth:
        omitted_files_total = 0
        omitted_dirs_total = 0
        for child in dirs.values():
            child_files, child_dirs = _count_tree(child)
            omitted_files_total += child_files
            omitted_dirs_total += child_dirs + 1
        result["_omitted_dirs"] = omitted_dirs_total
        result["_omitted_descendant_files"] = omitted_files_total
        return result

    selected_names = _select_dir_names(list(dirs), dirs_per_dir)
    if selected_names:
        result["dirs"] = {
            name: _compact_node(
                dirs[name],
                depth=depth + 1,
                max_depth=max_depth,
                dirs_per_dir=dirs_per_dir,
                files_per_dir=files_per_dir,
            )
            for name in selected_names
        }

    selected_set = set(selected_names)
    omitted_names = [name for name in dirs if name not in selected_set]
    if omitted_names:
        omitted_files_total = 0
        omitted_dirs_total = 0
        for name in omitted_names:
            child_files, child_dirs = _count_tree(dirs[name])
            omitted_files_total += child_files
            omitted_dirs_total += child_dirs + 1
        result["_omitted_dirs"] = len(omitted_names)
        result["_omitted_descendant_dirs"] = omitted_dirs_total
        result["_omitted_descendant_files"] = omitted_files_total
    return result


def _select_files(files: list[str], limit: int) -> list[str]:
    signal = [name for name in files if _is_signal_file(name)]
    signal_set = set(signal)
    rest = [name for name in files if name not in signal_set]
    selected = signal + rest[: max(0, limit)]
    return _dedupe(selected)


def _select_dir_names(names: list[str], limit: int) -> list[str]:
    signal = [name for name in names if name.lower() in _SIGNAL_DIRS]
    signal_set = set(signal)
    rest = [name for name in names if name not in signal_set]
    selected = signal + rest[: max(0, limit)]
    return _dedupe(selected)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _is_signal_file(name: str) -> bool:
    lower = name.lower()
    return (
        lower in _SIGNAL_FILES
        or lower.endswith((".gradle", ".properties", ".yml", ".yaml", ".toml"))
        or lower.startswith("dockerfile")
    )


def _extension_counts(node: dict) -> Counter[str]:
    counts: Counter[str] = Counter()
    for name in node.get("files", []):
        counts[_file_ext(name)] += 1
    binary = node.get("binary") or {}
    for ext, count in (binary.get("by_ext") or {}).items():
        counts[str(ext)] += int(count or 0)
    for child in (node.get("dirs") or {}).values():
        counts.update(_extension_counts(child))
    return counts


def _file_ext(name: str) -> str:
    return Path(name).suffix.lower() or "<no_ext>"


# ============================================================
# 画像展示
# ============================================================
_DISPLAY_ORDER = [
    "project_name",
    "project_function",
    "project_type",
    "architecture_style",
    "repository_shape",
    "summary",
    "interface_shape",
    "execution_model",
    "technology_stack",
    "engineering_context",
    "confidence",
    "limits",
]


def _render_profile(profile: dict):
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        show_lines=True,
        header_style="bold cyan",
        expand=False,
        pad_edge=False,
    )
    table.add_column("字段", style="bold", no_wrap=True)
    table.add_column("值", style="cyan", overflow="fold")

    for key in _DISPLAY_ORDER:
        if key not in profile:
            continue
        label = TREESCAN_LABELS.get(key, key)
        value = profile[key]

        if key == "technology_stack":
            rendered = _format_stack(value)
        elif key == "confidence":
            rendered = _format_confidence(value)
        else:
            rendered = _format_value(value)

        if rendered is None:
            continue
        table.add_row(label, rendered)

    console.print(table)


def _format_value(value):
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return "、".join(str(item) for item in value)
    return str(value)


def _format_stack(stack: dict):
    lines = []
    for sub_key, sub_label in TREESCAN_STACK_LABELS.items():
        rendered = _format_value(stack.get(sub_key))
        if rendered is None:
            continue
        lines.append(f"[bold]{sub_label}[/]: {rendered}")
    return "\n".join(lines) if lines else None


def _format_confidence(confidence: dict):
    lines = []
    overall = confidence.get("overall")
    if overall:
        lines.append(f"[bold]{TREESCAN_CONFIDENCE_LABELS['overall']}[/]: {overall}")
    notes = confidence.get("notes") or []
    if notes:
        lines.append(f"[bold]{TREESCAN_CONFIDENCE_LABELS['notes']}[/]:")
        for note in notes:
            lines.append(f"  - {note}")
    return "\n".join(lines) if lines else None
