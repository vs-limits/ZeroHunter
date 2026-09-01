"""手测后端 server 模块的若干读取函数。"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.server import artifacts as art  # noqa: E402
from app.server import projects as proj  # noqa: E402


def main() -> None:
    items = proj.list_projects()
    print("projects:", json.dumps(items, ensure_ascii=False))

    if not items:
        return

    pp = "github/yeswiki/yeswiki"
    runs = proj.list_specific_runs(pp)
    print("runs count:", len(runs), "first:", runs[0]["run_id"] if runs else None)

    summary = proj.project_summary(pp)
    print("summary keys:", list(summary["artifacts"].keys()))

    audit = art.read_audit_agent(pp, offset=0, limit=2)
    print(
        "audit total:",
        audit["total"],
        "first chain:",
        audit["findings"][0]["chain_id"] if audit["findings"] else None,
    )

    jl = art.read_jsonl(pp, "callscan_chains.priority.jsonl", offset=0, limit=2)
    print("jsonl total:", jl["total"], "items:", len(jl["items"]))

    md = art.read_markdown(pp, "callscan_chains.md", offset=0, limit=2)
    print("md total sections:", md["total"], "first head 30 chars:", md["sections"][0][:30] if md["sections"] else None)

    md2 = art.read_markdown(pp, "audit_findings.md", offset=0, limit=2)
    print("audit md total sections:", md2["total"])

    logs = art.list_logs_index()
    print("logs:", logs)
    if logs:
        rounds = art.read_logs_rounds(logs[0]["name"], offset=0, limit=2)
        print("rounds total:", rounds["total"], "first agent:", rounds["rounds"][0]["agent"] if rounds["rounds"] else None)


if __name__ == "__main__":
    main()
