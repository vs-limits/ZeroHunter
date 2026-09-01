"""Generate a file-name tree of the yeswiki repository.

Walks ``repo/github/yeswiki`` (resolved relative to the project root) and
writes a tree of file/directory names to stdout and to
``docs/yeswiki_tree.txt``.

Usage:
    python backend/scripts/gen_yeswiki_tree.py [--root PATH] [--out PATH]
                                               [--no-ignore]

By default it skips noisy directories such as ``.git``, ``node_modules``,
``vendor``, ``__pycache__``, ``.idea`` and ``.vscode``. Pass ``--no-ignore``
to include everything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

DEFAULT_IGNORES = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    "node_modules",
    "vendor",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
}


def iter_tree(
    root: Path,
    ignore: set[str],
    prefix: str = "",
) -> Iterable[str]:
    """Yield lines of a tree-style listing rooted at ``root``."""
    try:
        entries = sorted(
            root.iterdir(),
            key=lambda p: (p.is_file(), p.name.lower()),
        )
    except PermissionError:
        return

    entries = [e for e in entries if e.name not in ignore]
    last_idx = len(entries) - 1

    for idx, entry in enumerate(entries):
        connector = "└── " if idx == last_idx else "├── "
        yield f"{prefix}{connector}{entry.name}"
        if entry.is_dir():
            extension = "    " if idx == last_idx else "│   "
            yield from iter_tree(entry, ignore, prefix + extension)


def build_tree(root: Path, ignore: set[str]) -> str:
    if not root.exists():
        raise FileNotFoundError(f"Root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Root is not a directory: {root}")

    lines = [root.name + "/"]
    lines.extend(iter_tree(root, ignore))
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[2]
    default_root = project_root / "repo" / "github" / "yeswiki"
    default_out = project_root / "docs" / "yeswiki_tree.txt"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=default_root,
        help=f"Directory to scan (default: {default_root})",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=default_out,
        help=f"File to write the tree into (default: {default_out})",
    )
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        help="Do not skip the default ignore list (.git, node_modules, ...).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ignore: set[str] = set() if args.no_ignore else set(DEFAULT_IGNORES)

    tree = build_tree(args.root, ignore)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(tree, encoding="utf-8")

    sys.stdout.write(tree)
    sys.stdout.write(f"\n[Saved to {args.out}]\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
