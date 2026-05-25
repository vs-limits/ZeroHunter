"""扫描器目录/文件过滤与压缩规则。

两条用途：
1. TreeScan：构建项目目录结构树时跳过噪声目录、聚合二进制文件。
2. CallScan：在 ripgrep 全仓搜 sink 后，用正则二次过滤低价值命中。

`DIR_DENY` / `FILE_DENY` 仍保留为 TreeScan 的轻量黑名单；
CallScan 的路径判断统一走正则，避免 glob 在 Windows/Unix 路径上表现不一致。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


DIR_DENY = {
    ".defectmine",
    ".git",
    ".hg",
    ".idea",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".turbo",
    ".venv",
    ".vscode",
    "__pycache__",
    "bower_components",
    "build",
    "coverage",
    "dist",
    "env",
    "node_modules",
    "target",
    "tmp",
    "venv",
    "vendor",
}

FILE_DENY = {
    ".DS_Store",
    "Thumbs.db",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}

BINARY_SUFFIXES = {
    ".7z",
    ".avi",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".exe",
    ".gif",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".lock",
    ".min.js.map",
    ".mov",
    ".mp3",
    ".mp4",
    ".o",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".sqlite",
    ".tar",
    ".wasm",
    ".webp",
    ".zip",
}

RG_EXCLUDE_GLOBS = tuple(
    f"!{name}/**"
    for name in sorted(DIR_DENY)
) + tuple(
    f"!**/{name}/**"
    for name in sorted(DIR_DENY)
) + tuple(
    f"!**/{name}"
    for name in sorted(FILE_DENY)
)

# CallScan 在 ripgrep 命中后做二次过滤，剔除以下路径段：
# - 任意层级的 vendor / node_modules（很多 PHP 项目把 vendor 嵌在 tools/ 下）
# - 测试目录（tests/、Tests/、__tests__、_test.go）
# - 第三方静态资源（libs/vendor 这类）
# - 备份/脏代码目录（backup/、_old/、deprecated/）
SCAN_SKIP_PATTERNS = [
    r"(^|/)vendor(/|$)",
    r"(^|/)node_modules(/|$)",
    r"(^|/)\.defectmine(/|$)",
    r"(^|/)\.git(/|$)",
    r"(^|/)__pycache__(/|$)",
    r"(^|/)\.venv(/|$)",
    r"(^|/)venv(/|$)",
    r"(^|/)dist(/|$)",
    r"(^|/)build(/|$)",
    r"(^|/)coverage(/|$)",
    r"(^|/)target(/|$)",
    r"(^|/)tmp(/|$)",
    r"(^|/)tests?(/|$)",
    r"(^|/)__tests?__(/|$)",
    r"(^|/)test_fixtures?(/|$)",
    r"(^|/)fixtures?(/|$)",
    r"(^|/)mocks?(/|$)",
    r"(^|/)specs?(/|$)",
    r"(^|/)libs/vendor(/|$)",
    r"(^|/)third[_-]?party(/|$)",
    r"(^|/)backup(/|$)",
    r"(^|/)_old(/|$)",
    r"(^|/)deprecated(/|$)",
    r"(^|/)demos?(/|$)",
    r"(^|/)examples?(/|$)",
    r"(^|/)samples?(/|$)",
    r"(^|/)docs?(/|$)",
    r".*_test\.go$",
    r".*\.min\.js$",
    r".*\.bundle\.js$",
    r".*\.map$",
    r".*\.lock$",
    r".*\.spec\.[a-z]+$",
    r".*\.test\.[a-z]+$",
    r".*Test\.php$",
]


# 技术栈识别只负责决定加载哪种语言的 sink 规则。
# 命中某个语言正则后，会加载该语言全部 sink 规则；这里不做漏洞类型判断。
TECH_STACK_LANGUAGE_PATTERNS = {
    "php": [
        r"\bphp\b",
        r"\bcomposer\b",
        r"\blaravel\b",
        r"\bsymfony\b",
        r"\bthinkphp\b",
        r"\byii\b",
        r"\bwordpress\b",
        r"\bdrupal\b",
        r"\btwig\b",
    ],
    "python": [
        r"\bpython\b",
        r"\bpy\b",
        r"\bdjango\b",
        r"\bflask\b",
        r"\bfastapi\b",
        r"\btornado\b",
        r"\bcelery\b",
    ],
    "javascript": [
        r"\bjavascript\b",
        r"\bjs\b",
        r"\bnode(?:\.js|js)?\b",
        r"\bexpress\b",
        r"\bkoa\b",
        r"\bnext\.?js\b",
        r"\bnuxt\b",
        r"\breact\b",
        r"\bvue\b",
    ],
    "typescript": [
        r"\btypescript\b",
        r"\bts\b",
        r"\btsx\b",
        r"\bnest(?:\.js|js)?\b",
        r"\bangular\b",
    ],
    "java": [
        r"\bjava\b",
        r"\bspring\b",
        r"\bspringboot\b",
        r"\bstruts\b",
        r"\bservlet\b",
        r"\bjsp\b",
        r"\bmaven\b",
        r"\bgradle\b",
    ],
    "go": [
        r"\bgo\b",
        r"\bgolang\b",
        r"\bgin\b",
        r"\becho\b",
        r"\bfiber\b",
    ],
    "rust": [
        r"\brust\b",
        r"\bcargo\b",
        r"\bactix\b",
        r"\brocket\b",
        r"\btokio\b",
    ],
    "c": [
        r"\bc\b",
        r"\bcmake\b",
        r"\bmakefile\b",
    ],
    "cpp": [
        r"\bc\+\+",
        r"\bcpp\b",
        r"\bcxx\b",
        r"\bqt\b",
        r"\bboost\b",
    ],
    "html": [
        r"\bhtml\b",
        r"\bhtm\b",
        r"\btemplate\b",
        r"\bblade\b",
        r"\bsvelte\b",
    ],
}

_SCAN_SKIP_RE = tuple(re.compile(pattern, re.IGNORECASE) for pattern in SCAN_SKIP_PATTERNS)
_BINARY_SUFFIX_RE = tuple(
    re.compile(rf".*{re.escape(suffix)}$", re.IGNORECASE)
    for suffix in sorted(BINARY_SUFFIXES, key=len, reverse=True)
)
_FILE_DENY_RE = tuple(
    re.compile(rf"(^|/){re.escape(name)}$", re.IGNORECASE)
    for name in sorted(FILE_DENY)
)
_TECH_STACK_LANGUAGE_RE = {
    language: tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)
    for language, patterns in TECH_STACK_LANGUAGE_PATTERNS.items()
}


def normalize_scan_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def should_skip_scan_path(path: str) -> bool:
    normalized = normalize_scan_path(path)
    return (
        any(pattern.search(normalized) for pattern in _FILE_DENY_RE)
        or any(pattern.search(normalized) for pattern in _BINARY_SUFFIX_RE)
        or any(pattern.search(normalized) for pattern in _SCAN_SKIP_RE)
    )


def infer_languages_from_technology_stack(values: Iterable[Any] | Mapping[str, Any] | Any) -> list[str]:
    """根据 TreeScan 的技术栈文本正则命中语言，并加载对应语言的完整 sink 集。"""
    text = " ".join(_iter_stack_text(values))
    if not text:
        return []

    languages: list[str] = []
    for language, patterns in _TECH_STACK_LANGUAGE_RE.items():
        if any(pattern.search(text) for pattern in patterns):
            languages.append(language)
    return languages


def _iter_stack_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            yield cleaned
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_stack_text(item)
        return
    if isinstance(value, Iterable):
        for item in value:
            yield from _iter_stack_text(item)
