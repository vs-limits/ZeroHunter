from pathlib import Path

from app.scanner import rules
from app.server.paths import project_dir


def resolve_scan_root(root_path: str) -> Path:
    root = project_dir(root_path)
    if not root.exists():
        raise FileNotFoundError(f"path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"path is not a directory: {root}")
    return root


def scan_project_tree(root_path: str) -> dict:
    root = resolve_scan_root(root_path)
    tree = _scan_dir(root, root)
    return {"tree": _clean_node(tree)}


def _scan_dir(current_dir: Path, scan_root: Path) -> dict:
    node = {
        "files": [],
        "dirs": {},
        "binary": {
            "total": 0,
            "by_ext": {},
        },
    }

    try:
        entries = sorted(
            current_dir.iterdir(),
            key=lambda item: (not item.is_dir(), item.name.lower()),
        )
    except PermissionError:
        return node

    for entry in entries:
        if entry.is_symlink():
            continue

        rel_path = entry.relative_to(scan_root).as_posix()
        name = entry.name

        if entry.is_dir():
            if rules.should_skip_dir(rel_path, name):
                continue

            child = _scan_dir(entry, scan_root)
            cleaned_child = _clean_node(child)

            if cleaned_child:
                node["dirs"][name] = cleaned_child

            continue

        if not entry.is_file():
            continue

        if not rules.should_include_file(rel_path, name):
            continue

        if rules.should_compress_file(rel_path, name):
            ext = rules.get_file_ext(name)
            node["binary"]["total"] += 1
            node["binary"]["by_ext"][ext] = node["binary"]["by_ext"].get(ext, 0) + 1
            continue

        node["files"].append(name)

    return node


def _clean_node(node: dict) -> dict:
    result = {}

    files = sorted(node.get("files", []), key=str.lower)
    dirs = node.get("dirs", {})
    binary = node.get("binary", {})

    if files:
        result["files"] = files

    if dirs:
        result["dirs"] = dict(sorted(dirs.items(), key=lambda item: item[0].lower()))

    if binary.get("total", 0) > 0:
        result["binary"] = {
            "total": binary["total"],
            "by_ext": dict(sorted(binary["by_ext"].items())),
        }

    return result
