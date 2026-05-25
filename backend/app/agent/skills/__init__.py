from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SKILLS_DIR = Path(__file__).resolve().parent
DEFAULT_SKILL_FILE = "_default.md"

LANGUAGE_ALIASES = {
    "js": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "ts": "typescript",
    "py": "python",
    "c++": "cpp",
}

VULNERABILITY_ALIASES = {
    "file_path": "path_traversal",
    "file_download": "path_traversal",
    "file_upload": "path_traversal",
    "file-read-write": "path_traversal",
    "command-execution": "command_execution",
    "code-execution": "code_execution",
    "sql-query": "sql_injection",
    "xss": "xss",
}

LANGUAGE_FALLBACKS = {
    "typescript": ("javascript",),
    "html": ("javascript",),
    "cpp": ("c",),
}


@dataclass(frozen=True, slots=True)
class SkillBlock:
    language: str
    vulnerability_type: str
    path: Path
    content: str
    fallback_used: bool = False


def load_skill(language: str, vulnerability_type: str) -> SkillBlock:
    """Load a language/vulnerability skill block for Scanner Agent prompts."""
    normalized_language = normalize_language(language)
    normalized_vulnerability = normalize_vulnerability(vulnerability_type)

    candidates = [SKILLS_DIR / normalized_language / f"{normalized_vulnerability}.md"]
    for fallback_language in LANGUAGE_FALLBACKS.get(normalized_language, ()):
        candidates.append(SKILLS_DIR / fallback_language / f"{normalized_vulnerability}.md")
    candidates.append(SKILLS_DIR / DEFAULT_SKILL_FILE)
    for index, path in enumerate(candidates):
        if path.is_file():
            return SkillBlock(
                language=normalized_language,
                vulnerability_type=normalized_vulnerability,
                path=path,
                content=path.read_text(encoding="utf-8").strip(),
                fallback_used=index > 0,
            )

    raise FileNotFoundError(f"Default skill file does not exist: {SKILLS_DIR / DEFAULT_SKILL_FILE}")


def list_skills() -> dict[str, list[str]]:
    """Return available skills as {language: [vulnerability_type, ...]}."""
    coverage: dict[str, list[str]] = {}
    for language_dir in sorted(path for path in SKILLS_DIR.iterdir() if path.is_dir()):
        skills = sorted(path.stem for path in language_dir.glob("*.md"))
        if skills:
            coverage[language_dir.name] = skills
    return coverage


def missing_skills(required_pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Find requested language/vulnerability pairs that would fall back to default."""
    missing: list[tuple[str, str]] = []
    for language, vulnerability_type in required_pairs:
        skill = load_skill(language, vulnerability_type)
        if skill.fallback_used:
            missing.append((normalize_language(language), normalize_vulnerability(vulnerability_type)))
    return sorted(set(missing))


def normalize_language(language: str) -> str:
    value = str(language or "unknown").strip().casefold()
    return LANGUAGE_ALIASES.get(value, value)


def normalize_vulnerability(vulnerability_type: str) -> str:
    value = str(vulnerability_type or "unknown").strip().casefold().replace("-", "_")
    return VULNERABILITY_ALIASES.get(value, value)


__all__ = [
    "SkillBlock",
    "load_skill",
    "list_skills",
    "missing_skills",
    "normalize_language",
    "normalize_vulnerability",
]
