"""JSON 读写：优先 orjson，带基于 mtime 的进程内缓存。"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import orjson

    def loads_bytes(data: bytes) -> Any:
        return orjson.loads(data)

    def dumps_bytes(obj: Any, *, indent: bool = False) -> bytes:
        option = orjson.OPT_INDENT_2 if indent else 0
        return orjson.dumps(obj, option=option)

    USING_ORJSON = True
except ImportError:  # pragma: no cover
    USING_ORJSON = False

    def loads_bytes(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))

    def dumps_bytes(obj: Any, *, indent: bool = False) -> bytes:
        text = json.dumps(obj, ensure_ascii=False, indent=2 if indent else None)
        if indent and not text.endswith("\n"):
            text += "\n"
        return text.encode("utf-8")


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def read_json(path: Path) -> Any | None:
    """读取 JSON 文件（dict / list）；不存在或解析失败返回 None。"""
    if not path.is_file():
        return None
    try:
        return loads_bytes(read_bytes(path))
    except (ValueError, OSError):
        return None


def read_json_object(path: Path) -> dict[str, Any] | None:
    data = read_json(path)
    return data if isinstance(data, dict) else None


def write_json(path: Path, data: Any, *, indent: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dumps_bytes(data, indent=indent))


def file_fingerprint(path: Path) -> tuple[str, int, int] | None:
    if not path.is_file():
        return None
    st = path.stat()
    return (str(path.resolve()), st.st_mtime_ns, st.st_size)


@lru_cache(maxsize=512)
def _read_json_cached(key: tuple[str, int, int]) -> Any:
    return loads_bytes(Path(key[0]).read_bytes())


def read_json_cached(path: Path) -> Any | None:
    """按 (path, mtime_ns, size) 缓存解析结果；文件不存在返回 None。"""
    fp = file_fingerprint(path)
    if fp is None:
        return None
    try:
        return _read_json_cached(fp)
    except (json.JSONDecodeError, ValueError, OSError):
        _read_json_cached.cache_clear()
        return None


def invalidate_json_cache(path: Path | None = None) -> None:
    if path is None:
        _read_json_cached.cache_clear()
        return
    fp = file_fingerprint(path)
    if fp is not None:
        _read_json_cached.cache_pop(fp, None)


def loads_line(line: str) -> Any:
    return loads_bytes(line.encode("utf-8"))
