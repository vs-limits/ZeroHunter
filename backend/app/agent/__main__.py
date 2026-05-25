from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from app.agent.registry import get_agent_spec, list_agent_specs, normalize_agent_type
from app.agent.runner import run_agent


#----------- Agent CLI 入口：封装 agent 包能力，便于单独查看 prompt 或调试某个 Agent ------------#
def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        return _list_agents()
    if args.command == "prompt":
        return _show_prompt(args)
    if args.command == "run":
        return _run_agent_command(args)

    parser.print_help()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.agent",
        description="DefectMine Agent package entrypoint.",
    )
    subparsers = parser.add_subparsers(dest="command")

    list_parser = subparsers.add_parser("list", help="List registered agents.")
    list_parser.set_defaults(command="list")

    prompt_parser = subparsers.add_parser("prompt", help="Print an agent system prompt.")
    prompt_parser.add_argument("agent", help="Agent role, such as treescan, callscan, scanner.")
    prompt_parser.set_defaults(command="prompt")

    run_parser = subparsers.add_parser("run", help="Run an agent with text input.")
    run_parser.add_argument("agent", help="Agent role, such as treescan, callscan, scanner.")
    run_parser.add_argument("--input", "-i", default="", help="Inline input text.")
    run_parser.add_argument("--input-file", help="Read input text from a file.")
    run_parser.add_argument("--output-file", help="Write agent output to a file.")
    run_parser.add_argument("--temperature", type=float, default=None, help="Override agent temperature.")
    run_parser.add_argument("--max-tokens", type=int, default=None, help="Override agent max tokens.")
    run_parser.set_defaults(command="run")

    return parser


#----------- Agent 注册表展示：快速确认当前项目已经封装了哪些 Agent 角色 ------------#
def _list_agents() -> int:
    for spec in list_agent_specs():
        print(
            f"{spec.role.value}\t{spec.name}\t"
            f"prompt={spec.prompt_file}\t"
            f"temperature={spec.temperature}\t"
            f"max_tokens={spec.max_tokens}"
        )
    return 0


def _show_prompt(args: argparse.Namespace) -> int:
    role = normalize_agent_type(args.agent)
    spec = get_agent_spec(role)
    print(spec.system_prompt)
    return 0


#----------- Agent 调试运行：统一从 inline、文件或 stdin 读取输入，再调用 run_agent ------------#
def _run_agent_command(args: argparse.Namespace) -> int:
    content = _read_agent_input(args)
    output = run_agent(
        args.agent,
        content,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )

    if args.output_file:
        output_path = Path(args.output_file).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def _read_agent_input(args: argparse.Namespace) -> str:
    if args.input_file:
        return Path(args.input_file).expanduser().read_text(encoding="utf-8")
    if args.input:
        return str(args.input)
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
