"""扫描器目录/文件过滤与压缩规则。

两条用途：
1. TreeScan：构建项目目录结构树时跳过噪声目录、聚合二进制文件。
2. CallScan：在 ripgrep 全仓搜 sink 时排除 vendor/tests 等无审计价值路径。

`DIR_DENY` / `FILE_DENY` 是 TreeScan 用的目录/文件黑名单，
`SCAN_SKIP_PATTERNS` 是 CallScan 在 sink 命中后再次过滤的更严格清单。
"""

import re
from pathlib import Path

# 目录黑名单（TreeScan 与 CallScan 都会跳过）
DIR_DENY = [
    r"(^|/)\.git($|/)",
    r"(^|/)node_modules($|/)",
    r"(^|/)vendor($|/)",
    r"(^|/)__pycache__($|/)",
    r"(^|/)dist($|/)",
    r"(^|/)build($|/)",
    r"(^|/)\.idea($|/)",
    r"(^|/)\.vscode($|/)",
]

# 目录白名单
DIR_ALLOW = []

# 文件黑名单
FILE_DENY = [
    r"(^|/)\.DS_Store$",
    r".*\.pyc$",
    r".*\.pyo$",
    r".*\.log$",
]

# 文件白名单
FILE_ALLOW = []

# 需要摘要压缩的文件类型
COMPRESS_FILE = [
    r".*\.(png|jpg|jpeg|gif|webp|ico)$",
    r".*\.(mp4|mov|avi|mkv|webm)$",
    r".*\.(mp3|wav|ogg)$",
    r".*\.(ttf|otf|woff|woff2)$",
    r".*\.(zip|tar|gz|rar|7z)$",
    r".*\.(exe|dll|so|dylib|bin)$",
    r".*\.(pt|onnx|pkl|npy|parquet)$",
]

# CallScan 在 ripgrep 命中后做二次过滤，剔除以下路径段：
# - 任意层级的 vendor / node_modules（很多 PHP 项目把 vendor 嵌在 tools/ 下）
# - 测试目录（tests/、Tests/、__tests__、_test.go）
# - 第三方静态资源（libs/vendor 这类）
# - 备份/脏代码目录（backup/、_old/、deprecated/）
SCAN_SKIP_PATTERNS = [
    r"(^|/)vendor(/|$)",
    r"(^|/)node_modules(/|$)",
    r"(^|/)\.git(/|$)",
    r"(^|/)tests?(/|$)",
    r"(^|/)__tests?__(/|$)",
    r"(^|/)test_fixtures?(/|$)",
    r"(^|/)spec(/|$)",
    r"(^|/)libs/vendor(/|$)",
    r"(^|/)third[_-]?party(/|$)",
    r"(^|/)backup(/|$)",
    r"(^|/)_old(/|$)",
    r"(^|/)deprecated(/|$)",
    r"(^|/)examples?(/|$)",
    r"(^|/)samples?(/|$)",
    r"(^|/)docs?(/|$)",
    r".*\.min\.js$",
    r".*\.bundle\.js$",
    r".*\.spec\.[a-z]+$",
    r".*\.test\.[a-z]+$",
    r".*Test\.php$",
]


def _match_any(patterns: list[str], rel_path: str, name: str) -> bool:
    return any(
        re.search(pattern, rel_path, re.IGNORECASE)
        or re.search(pattern, name, re.IGNORECASE)
        for pattern in patterns
    )


def should_skip_dir(rel_path: str, name: str) -> bool:
    if _match_any(DIR_DENY, rel_path, name):
        return True

    if DIR_ALLOW and not _match_any(DIR_ALLOW, rel_path, name):
        return True

    return False


def should_include_file(rel_path: str, name: str) -> bool:
    if _match_any(FILE_DENY, rel_path, name):
        return False

    if FILE_ALLOW and not _match_any(FILE_ALLOW, rel_path, name):
        return False

    return True


def should_compress_file(rel_path: str, name: str) -> bool:
    return _match_any(COMPRESS_FILE, rel_path, name)


def get_file_ext(name: str) -> str:
    return Path(name).suffix.lower() or "<no_ext>"


# CallScan 在 ripgrep 命令行层排除（比命中后再过滤快得多）。
RG_EXCLUDE_GLOBS: list[str] = [
    "!**/.git/**",
    "!**/node_modules/**",
    "!**/vendor/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/__pycache__/**",
    "!**/tests/**",
    "!**/test/**",
    "!**/__tests__/**",
    "!**/test_fixtures/**",
    "!**/spec/**",
    "!**/third_party/**",
    "!**/third-party/**",
    "!**/backup/**",
    "!**/_old/**",
    "!**/deprecated/**",
    "!**/examples/**",
    "!**/samples/**",
    "!**/*.min.js",
    "!**/*.bundle.js",
    "!**/*.min.css",
]


def should_skip_for_scan(rel_path: str) -> tuple[bool, str | None]:
    """CallScan 是否应该把这个文件路径丢弃。

    返回 (是否跳过, 命中原因)。原因被记录在 callscan 的 skipped 列表里，
    方便事后核对噪声过滤是不是过激。
    """
    normalized = rel_path.replace("\\", "/")
    for pattern in SCAN_SKIP_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True, pattern
    return False, None
