"""Sink rule data types and shared helpers."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Iterable


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class SinkRule:
    """A single dangerous-call pattern for one language.

    Fields
    ------
    id:
        Globally unique short identifier, e.g. ``php-sql-mysqli-query``.
    function:
        Display name of the dangerous function. May contain ``::`` or ``.``
        for class-qualified calls. Used by Auditor and artifact views.
    call_regex:
        Rust regex passed to ripgrep.  KEEP IT SIMPLE: avoid lookaround;
        use word boundaries and small character classes.
    description:
        Short English description shown in reports.
    argument_roles:
        Role hint per positional argument (best-effort).
    extensions:
        File extensions that we run rg with ``--glob *<ext>``.
    severity:
        ``low``/``medium``/``high``/``critical``.
    require_dynamic:
        When True, CallScan only keeps the hit if the matched line shows a
        dynamic input signal (``$``, ``%s``, ``f"..."``, ``+ ``, etc).
        Cuts down on static literal noise (``require __DIR__ . '/foo.php'``).
    extra_match_regex:
        Optional list of regexes that the matched line must satisfy
        (any-match). Used for narrow rules like cursor.execute when the
        SQL is composed via string formatting.
    """

    id: str
    function: str
    call_regex: str
    description: str
    argument_roles: list[str]
    extensions: list[str]
    severity: str = "medium"
    require_dynamic: bool = False
    extra_match_regex: list[str] = field(default_factory=list)
    level: str = "L0"
    semantic_tags: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    repair_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        # extra_match_regex is internal; downstream consumers don't need it.
        data.pop("extra_match_regex", None)
        data["level"] = _normalize_level(data.get("level"))
        data["semantic_tags"] = _dedupe_strings(data.get("semantic_tags") or [])
        data["required_evidence"] = _dedupe_strings(data.get("required_evidence") or [])
        data["repair_hints"] = _dedupe_strings(data.get("repair_hints") or [])
        return data

    def severity_score(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


# 用于 require_dynamic：匹配行里出现 $var / 拼接 / sprintf / format 等动态信号
_DYNAMIC_HINTS = [
    r"\$\w",                     # PHP / shell variable
    r"%[sdif]",                   # printf-style placeholder
    r"f['\"]",                    # Python f-string
    r"\.format\s*\(",             # Python str.format
    r"`[^`]*\$\{",                # JS/TS template literal with var
    r"\{\{",                      # template / Jinja / JSX
    r"\+\s*(?:['\"$]|[A-Za-z_])",  # explicit string concat with var / literal
    r"\bsprintf\s*\(",
    r"\bvsprintf\s*\(",
    r"\bstr_replace\s*\(",
    r"\bstrtr\s*\(",
    r"\bgetenv\s*\(",             # env-derived inputs
]
_DYNAMIC_REGEX = re.compile("|".join(_DYNAMIC_HINTS), re.IGNORECASE)


def line_is_dynamic(line: str) -> bool:
    """sink 行是否包含变量/拼接/格式化等动态信号。"""
    if not line:
        return False
    return bool(_DYNAMIC_REGEX.search(line))


def matches_extra(rule: SinkRule, line: str) -> bool:
    """rule.extra_match_regex 任一匹配则视为符合。无则总是 True。"""
    if not rule.extra_match_regex:
        return True
    if not line:
        return False
    return any(re.search(pattern, line) for pattern in rule.extra_match_regex)


def _normalize_level(value: str | None) -> str:
    text = str(value or "L0").upper()
    return text if text in {"L0", "L1", "L2"} else "L0"


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _extensions_for(*exts: str) -> list[str]:
    """Tiny helper to keep extension lists readable in rule files."""
    return list(exts)


__all__ = [
    "SEVERITY_RANK",
    "SinkRule",
    "line_is_dynamic",
    "matches_extra",
]
