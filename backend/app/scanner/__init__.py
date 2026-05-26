from __future__ import annotations

from typing import Any

__all__ = [
    "AuditScannerResult",
    "ScannerResult",
    "run_audit_scanner",
    "run_scanner",
]


def __getattr__(name: str) -> Any:
    """Lazy-load Scanner entrypoints so importing app.scanner.sink stays cheap."""

    if name in __all__:
        from app.scanner import scanner

        return getattr(scanner, name)
    raise AttributeError(name)
