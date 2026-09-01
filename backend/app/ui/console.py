"""Shared CLI console helpers with ANSI color and UI-expandable collapse blocks."""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from io import StringIO
from typing import Iterator

from rich.console import Console

# Frontend ScanConsole parses this prefix into a clickable expand block.
COLLAPSE_PREFIX = "@@DM_COLLAPSE@@"
# Frontend renders one animated status row per id; inactive clears the row.
STATUS_PREFIX = "@@DM_STATUS@@"

console = Console(force_terminal=True, color_system="truecolor")

_collapse_buffer: list[str] = []


def render_markup(markup: str) -> str:
    """Render Rich markup to an ANSI string for the web console."""
    buffer = StringIO()
    Console(
        file=buffer,
        force_terminal=True,
        color_system="truecolor",
        width=200,
    ).print(markup, highlight=False, overflow="ignore", crop=False, end="")
    return buffer.getvalue()


def print_markup(markup: str) -> None:
    import sys

    console.print(markup, highlight=False, overflow="ignore", crop=False)
    # Rich 在管道/tee 下可能块缓冲；显式 flush 以便 SSE 终端实时更新。
    try:
        sys.stdout.flush()
    except Exception:  # pragma: no cover
        pass


def reset_collapse_buffer() -> None:
    global _collapse_buffer
    _collapse_buffer = []


def buffer_collapsed_line(markup: str) -> None:
    # Keep Rich markup so the web console can colorize even when stdout is piped.
    _collapse_buffer.append(markup)


def _emit_machine_line(prefix: str, payload: str) -> None:
    """Write one logical line without Rich wrapping (frontend parses by prefix)."""
    sys.stdout.write(f"{prefix}{payload}\n")
    try:
        sys.stdout.flush()
    except Exception:  # pragma: no cover
        pass


def flush_collapse_block(label: str | None = None) -> None:
    global _collapse_buffer
    if not _collapse_buffer:
        return
    count = len(_collapse_buffer)
    text_label = label or f"{count} 条已折叠输出"
    payload = json.dumps(
        {"count": count, "label": text_label, "lines": _collapse_buffer},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    _emit_machine_line(COLLAPSE_PREFIX, payload)
    _collapse_buffer = []


def step(index: int, total: int, name: str):
    console.print(f"\n[bold cyan]Step {index}/{total}[/] [bold]{name}[/]")


def action(verb: str, target: str):
    console.print(f"  [dim]*[/] [green]{verb}[/] {target}")


def info(message: str):
    console.print(f"  [dim]-> {message}[/]")


def done(message: str):
    console.print(f"  [bold green]OK[/] {message}")


def print_status(
    status_id: str,
    *,
    active: bool,
    label: str = "",
    detail: str = "",
) -> None:
    """Emit a machine-readable status line for the web console.

    Each update is appended to console.log; the frontend keeps only the latest
    active row per ``status_id`` and removes it when ``active`` is false.
    """
    payload = json.dumps(
        {
            "id": status_id,
            "active": active,
            "label": label,
            "detail": detail,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    _emit_machine_line(STATUS_PREFIX, payload)


@contextmanager
def status_scope(
    status_id: str,
    label: str,
    detail: str = "",
) -> Iterator[None]:
    """Show one in-place loading row in the web console (Rich-style spinner)."""
    print_status(status_id, active=True, label=label, detail=detail)
    try:
        yield
    finally:
        print_status(status_id, active=False)
