"""命令行入口：用于本地手测各 Agent 与 specific scoped run。"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from app.agent.run_scope import create_specific_run, resolve_run_scope
from app.agent.runner import run_agent
from app.agent.types import AgentRole


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.agent",
        description="运行单个 Agent，或初始化特定目录的 scoped run。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    specific = subparsers.add_parser(
        "specific",
        help="为项目内某个相对目录创建 scoped run 上下文。",
    )
    specific.add_argument(
        "project_path",
        help="相对于 repo/ 的项目路径，例如 github/yeswiki/yeswiki",
    )
    specific.add_argument(
        "target_rel_dir",
        help="相对于 project_path 的目标目录，例如 pages",
    )

    for role in AgentRole:
        role_parser = subparsers.add_parser(role.value, help=f"运行 {role.value} Agent")
        role_parser.add_argument(
            "project_path",
            help="相对于 repo/ 的项目路径，例如 github/yeswiki/yeswiki",
        )
        role_parser.add_argument(
            "extra_args",
            nargs="*",
            help=argparse.SUPPRESS,
        )

    return parser


def _print_lines(lines: list[str]) -> None:
    if not lines:
        return
    print("summary:")
    for line in lines:
        print(line)


def _summarize_specific(scope: Any) -> list[str]:
    return [
        f"run_id={scope.run_id}",
        f"target_rel_dir={scope.target_rel_dir}",
        f"artifacts_dir={scope.artifacts_dir}",
    ]


def _summarize_result(
    role: AgentRole,
    result: Any,
    project_path: str,
    extra_args: list[str],
) -> list[str]:
    if not isinstance(result, dict):
        return [f"{role.value} 已完成。"]

    if role == AgentRole.TREESCAN:
        scope = resolve_run_scope(project_path)
        project_name = result.get("project_name") or "unknown"
        project_type = result.get("project_type") or "unknown"
        architecture = result.get("architecture_style") or "unknown"
        return [
            f"project={project_name}",
            f"project_type={project_type}, architecture={architecture}",
            f"artifacts_dir={scope.artifacts_dir}",
        ]

    if role == AgentRole.CALLSCAN:
        summary = result.get("summary") or {}
        scope = result.get("scope") or {}
        lines = [
            f"status={result.get('status', 'unknown')}",
            "sink_hits="
            f"{summary.get('sink_hits', 0)}, candidate_chains="
            f"{summary.get('candidate_chains', 0)}, with_call_chain="
            f"{summary.get('with_call_chain', 0)}",
            f"artifacts_dir={scope.get('artifacts_dir') or resolve_run_scope(project_path, extra_args[0] if extra_args else None).artifacts_dir}",
        ]
        target_rel_dir = scope.get("target_rel_dir")
        run_id = scope.get("run_id")
        if run_id:
            lines.insert(1, f"run_id={run_id}, target_rel_dir={target_rel_dir}")
        return lines

    if role == AgentRole.DATAFLOWSCAN:
        summary = result.get("summary") or {}
        scope = result.get("scope") or {}
        lines = [
            f"status={result.get('status', 'unknown')}",
            "cross_request_chains="
            f"{summary.get('cross_request_chains', 0)}, recovered_partial="
            f"{summary.get('recovered_partial', 0)}, storage_nodes="
            f"{summary.get('storage_nodes', 0)}, sink_nodes={summary.get('sink_nodes', 0)}",
            f"artifacts_dir={scope.get('artifacts_dir') or resolve_run_scope(project_path, extra_args[0] if extra_args else None).artifacts_dir}",
        ]
        target_rel_dir = scope.get("target_rel_dir")
        run_id = scope.get("run_id")
        if run_id:
            lines.insert(1, f"run_id={run_id}, target_rel_dir={target_rel_dir}")
        return lines

    if role == AgentRole.AUDITOR:
        summary = result.get("summary") or {}
        scope = result.get("scope") or {}
        lines = [
            f"status={result.get('status', 'unknown')}",
            "audited="
            f"{summary.get('total_audited', 0)}, vulnerable="
            f"{summary.get('vulnerable', 0)}, uncertain="
            f"{summary.get('uncertain', 0)}, safe="
            f"{summary.get('safe', 0)}",
            f"artifacts_dir={scope.get('artifacts_dir') or resolve_run_scope(project_path, extra_args[0] if extra_args else None).artifacts_dir}",
        ]
        target_rel_dir = scope.get("target_rel_dir")
        run_id = scope.get("run_id")
        if run_id:
            lines.insert(1, f"run_id={run_id}, target_rel_dir={target_rel_dir}")
        return lines

    if role == AgentRole.CHECKER:
        summary = result.get("summary") or {}
        scope = result.get("scope") or {}
        lines = [
            f"status={result.get('status', 'unknown')}",
            "checked="
            f"{summary.get('total_checked', 0)}, confirmed="
            f"{summary.get('confirmed', 0)}, refuted="
            f"{summary.get('refuted', 0)}, need_context="
            f"{summary.get('need_context', 0)}, failed="
            f"{summary.get('failed', 0)}",
            f"artifacts_dir={scope.get('artifacts_dir') or resolve_run_scope(project_path, extra_args[0] if extra_args else None).artifacts_dir}",
        ]
        run_id = scope.get("run_id")
        target_rel_dir = scope.get("target_rel_dir")
        if run_id:
            lines.insert(1, f"run_id={run_id}, target_rel_dir={target_rel_dir}")
        return lines

    status = result.get("status")
    if status:
        return [f"{role.value} finished, status={status}."]
    return [f"{role.value} finished."]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "specific":
            scope = create_specific_run(args.project_path, args.target_rel_dir)
            _print_lines(_summarize_specific(scope))
            return 0

        role = AgentRole(args.command)
        extra_args = list(args.extra_args)
        if role in {AgentRole.CALLSCAN, AgentRole.DATAFLOWSCAN, AgentRole.AUDITOR} and len(extra_args) > 1:
            parser.error(f"{role.value} 只接受 <project_path> [run_id]")
        if role == AgentRole.CHECKER and len(extra_args) not in {1, 2}:
            parser.error("checker 只接受 <project_path> <scan_id> [chain_id]")

        print(f"=== 路由到 {role.value} ===\n")
        result = run_agent(role, args.project_path, *extra_args)
        _print_lines(_summarize_result(role, result, args.project_path, extra_args))
        return 0
    except (FileNotFoundError, NotADirectoryError, ValueError) as err:
        print(f"错误: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
