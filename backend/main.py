from __future__ import annotations

import argparse
import os
from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from app.callscan import create_audit_batch, run_audit_batch, run_callscan
from app.core.config import LLM_BASEURL, LLM_MODEL, LLM_PROVIDER
from app.scanner import run_audit_scanner
from app.treescan import run_treescan
from app.workflow import run_workflow


console = Console()

ASCII_BANNER = r"""
██████╗ ███████╗███████╗███████╗ ██████╗████████╗███╗   ███╗██╗███╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝████╗ ████║██║████╗  ██║██╔════╝
██║  ██║█████╗  █████╗  █████╗  ██║        ██║   ██╔████╔██║██║██╔██╗ ██║█████╗
██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║        ██║   ██║╚██╔╝██║██║██║╚██╗██║██╔══╝
██████╔╝███████╗██║     ██║     ╚██████╗   ██║   ██║ ╚═╝ ██║██║██║ ╚████║███████╗
╚═════╝ ╚══════╝╚═╝     ╚═╝      ╚═════╝   ╚═╝   ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
"""

#----------- CLI 参数解析：读取项目路径与中间产物持久化选项 ------------#
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defectmine",
        description="DefectMine CLI: TreeScan and Scanner workflow runner.",
    )
    parser.add_argument(
        "project_path",
        help="项目路径；相对路径默认解析到 repo_code/<project_path>。",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=None,
        help="中间产物目录；默认写入 <project>/.defectmine。",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="仅运行流程，不写入中间产物文件。",
    )
    parser.add_argument(
        "--callscan",
        action="store_true",
        help="Only run CallScan sink preselection and local trace analysis.",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run Scanner audit on .defectmine/callscan_chains.priority.jsonl.",
    )
    parser.add_argument(
        "--audit-dry-run",
        action="store_true",
        help="Prepare audit tasks only, without running the LLM audit loop.",
    )
    parser.add_argument(
        "--audit-no-tools",
        action="store_true",
        help="Run Scanner audit without the MCP-style local tool loop.",
    )
    parser.add_argument(
        "--audit-limit",
        type=int,
        default=None,
        metavar="N",
        help="When --audit is enabled, audit only the top N priority chains.",
    )
    parser.add_argument(
        "--show-sink-hits",
        type=int,
        default=10,
        metavar="N",
        help="When --callscan is enabled, show the first N sink_hits in CLI.",
    )
    parser.add_argument(
        "--priority-chain-limit",
        type=int,
        default=20,
        metavar="N",
        help="When --callscan is enabled, write the top N ranked chains to callscan_chains.priority.jsonl.",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Run TreeScan if needed, then build or reuse the full CallScan candidate pool.",
    )
    parser.add_argument(
        "--force-discover",
        action="store_true",
        help="Ignore existing CallScan discovery cache and rebuild the full candidate pool.",
    )
    parser.add_argument(
        "--schedule",
        action="store_true",
        help="Create an audit batch queue from callscan_chains.all.jsonl without running Scanner.",
    )
    parser.add_argument(
        "--batch-audit",
        action="store_true",
        help="Discover if needed, schedule a batch, then audit that batch.",
    )
    parser.add_argument(
        "--audit-batch",
        metavar="BATCH_ID",
        default=None,
        help="Run Scanner against an existing audit_batches/<batch_id>/queue.jsonl.",
    )
    parser.add_argument(
        "--audit-per-type",
        type=int,
        default=1,
        metavar="N",
        help="When scheduling a batch, select at least N chains per vulnerability type before risk fill.",
    )
    parser.add_argument(
        "--audit-vuln-types",
        default="",
        help="Comma-separated vulnerability types to schedule, e.g. xss,ssrf,path_traversal.",
    )
    parser.add_argument(
        "--batch-name",
        default=None,
        help="Optional human-readable audit batch name.",
    )
    parser.add_argument(
        "--include-completed",
        action="store_true",
        help="Allow scheduler to include chains already present in audit_completed_pool.jsonl.",
    )
    return parser


#----------- CLI 标题展示：输出 DEFECTMINE 标题与当前模型元信息 ------------#
def render_banner() -> None:
    console.print(Text(ASCII_BANNER.strip("\n"), style="bold cyan"))

    meta = Text()
    meta.append("v1.0", style="bright_black")
    meta.append("  model ", style="bright_black")
    meta.append(_model_label(), style="bold green")
    meta.append("  endpoint ", style="bright_black")
    meta.append(LLM_BASEURL or "unknown", style="bold blue")
    console.print(meta)


def render_header(project_path: str) -> None:
    console.print(Rule(style="cyan"))
    console.print(Rule(f"DefectMine {project_path}", style="white"))
    console.print()


def render_effective_limits(args: argparse.Namespace) -> None:
    """在 CLI 输出中打印本次真正生效的扫描数量，方便排查工作台参数是否传递成功。"""
    audit_limit = "全部" if args.audit_limit is None else str(args.audit_limit)
    console.print(
        f"[bright_black]limits[/bright_black] callscan priority_top={max(args.priority_chain_limit, 0)} "
        f"audit_top={audit_limit} tools={'off' if args.audit_no_tools else 'on'}"
    )
    console.print()


#----------- CLI 进度渲染：把 workflow 事件翻译成实时流式输出与进度条 ------------#
class CliReporter:
    def __init__(self) -> None:
        self.progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=32, complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        self.workflow_task_id: int | None = None
        self.scanner_task_id: int | None = None
        self.total_steps = 0
        self.scanner_total = 0
        self.callscan_total_hits = 0
        self.callscan_rules_with_hits = 0
        self.callscan_pipeline_seen_ellipsis = False

    def __enter__(self) -> "CliReporter":
        self.progress.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.progress.stop()

    def __call__(self, event: dict[str, Any]) -> None:
        event_name = event.get("event")

        if event_name == "workflow_started":
            self.total_steps = max(int(event.get("total_steps", 1)), 1)
            self.workflow_task_id = self.progress.add_task("[cyan]Workflow[/cyan]", total=self.total_steps)
            return

        if event_name == "stage_started":
            self._render_stage_started(event)
            return

        if event_name == "treescan_scan_started":
            console.print(f"- 扫描 [white]{event.get('root')}[/white]")
            return

        if event_name == "treescan_tree_ready":
            console.print(
                "  └ 共 [cyan]{dirs}[/cyan] 个目录 / [cyan]{files}[/cyan] 个文件".format(
                    dirs=event.get("total_dirs", 0),
                    files=event.get("total_files", 0),
                )
            )
            return

        if event_name == "treescan_tree_written":
            console.print(f"  └ 写入 [green]{event.get('path')}[/green]")
            return

        if event_name == "treescan_agent_submitted":
            console.print(f"- 向 Agent 提交 [cyan]{event.get('input_chars', 0):,}[/cyan] 字符的项目地图")
            return

        if event_name == "treescan_raw_written":
            console.print(f"  └ 写入 [green]{event.get('path')}[/green]")
            return

        if event_name == "treescan_profile_written":
            self._render_project_understanding(event.get("profile_summary", {}))
            console.print(f"  └ 写入 [green]{event.get('path')}[/green]")
            return

        if event_name == "callscan_started":
            console.print("[bold cyan]CallScan[/bold cyan] rg sink preselection and local trace analysis")
            console.print(f"- Project root [white]{event.get('project_root')}[/white]")
            return

        if event_name == "callscan_rg_rule_started":
            console.print(
                "- rg [cyan]{rule}[/cyan] ([white]{language}[/white] / [white]{category}[/white])".format(
                    rule=event.get("sink_rule", ""),
                    language=event.get("language", "unknown"),
                    category=event.get("category", "unknown"),
                )
            )
            return

        if event_name == "callscan_rg_rule_completed":
            matches = int(event.get("matches", 0) or 0)
            self.callscan_total_hits += matches
            if matches > 0:
                self.callscan_rules_with_hits += 1
                console.print(
                    "  - hits [yellow]{matches}[/yellow] | total [cyan]{total}[/cyan]".format(
                        matches=matches,
                        total=self.callscan_total_hits,
                    )
                )
            return

        if event_name == "callscan_sink_analyses_progress":
            # 中间 sink 分析进度会产生大量噪声；CLI 只保留首尾样例和 omitted 汇总。
            return

        if event_name == "callscan_sink_pipeline_item":
            index = int(event.get("index", 0) or 0)
            total = int(event.get("total", 0) or 0)
            if index == 1:
                console.print()
                console.print("[bold cyan]Sink-driven call-chain pipeline[/bold cyan]")
            console.print(
                "[{index}/{total}] [yellow]{sink}[/yellow] @ [white]{location}[/white]{scope}".format(
                    index=index,
                    total=total,
                    sink=event.get("sink", "sink"),
                    location=f"{event.get('file', '')}:{event.get('line', 0)}",
                    scope=f" -> {event.get('scope')}" if event.get("scope") else "",
                )
            )
            return

        if event_name == "callscan_sink_pipeline_omitted":
            if not self.callscan_pipeline_seen_ellipsis:
                self.callscan_pipeline_seen_ellipsis = True
                console.print(
                    "... omitted [cyan]{omitted}[/cyan] sink-driven analysis items ...".format(
                        omitted=event.get("omitted", 0),
                    )
                )
            return

        if event_name == "callscan_sink_pipeline_completed":
            console.print(
                "[bold cyan]Sink pipeline complete[/bold cyan] | total [cyan]{total}[/cyan]".format(
                    total=event.get("total", 0),
                )
            )
            return

        if event_name == "callscan_completed":
            summary = event.get("summary", {})
            console.print(
                "[bold green]CallScan done[/bold green] | sink_hits [cyan]{hits}[/cyan] | analyses [cyan]{analyses}[/cyan] | priority_chains [cyan]{chains}[/cyan] | mcp_tasks [cyan]{tasks}[/cyan]".format(
                    hits=summary.get("sink_hits", 0),
                    analyses=summary.get("sink_analyses", 0),
                    chains=summary.get("priority_chains", 0),
                    tasks=summary.get("mcp_tasks", 0),
                )
            )
            console.print(f"  - artifact [green]{event.get('artifact')}[/green]")
            if event.get("priority_chains_artifact"):
                console.print(f"  - priority chains [green]{event.get('priority_chains_artifact')}[/green]")
            return

        if event_name == "audit_scanner_started":
            mode = "LLM audit" if event.get("enable_llm_audit") else "audit input dry-run"
            console.print(f"[bold cyan]Scanner Audit[/bold cyan] {mode}")
            console.print(f"- Project root [white]{event.get('project_root')}[/white]")
            console.print(f"- Priority chains [green]{event.get('priority_chains')}[/green]")
            console.print(
                "- Tasks [cyan]{total}[/cyan] | concurrency [cyan]{concurrency}[/cyan] | active PoC [cyan]{poc}[/cyan]".format(
                    total=event.get("total", 0),
                    concurrency=event.get("concurrency", 4),
                    poc=event.get("allow_active_poc", False),
                )
            )
            return

        if event_name == "audit_chain_started":
            console.print(
                "AUDIT [{current}/{total}] [yellow]{sink}[/yellow] chain [white]{chain_id}[/white]".format(
                    current=event.get("current", 0),
                    total=event.get("total", 0),
                    sink=event.get("sink", "sink"),
                    chain_id=event.get("chain_id", ""),
                )
            )
            return

        if event_name == "audit_chain_completed":
            console.print(
                "  -> {status} verdict=[cyan]{verdict}[/cyan]".format(
                    status=event.get("status", "completed"),
                    verdict=event.get("verdict", "unknown"),
                )
            )
            return

        if event_name == "audit_tool_round_completed":
            console.print(
                "  tool round {round}: [cyan]{tool_calls}[/cyan] call(s)".format(
                    round=event.get("round", 0),
                    tool_calls=event.get("tool_calls", 0),
                )
            )
            return

        if event_name == "audit_task_prepared":
            console.print(
                "TASK [{current}/{total}] [yellow]{sink}[/yellow] -> [white]{task_id}[/white]".format(
                    current=event.get("current", 0),
                    total=event.get("total", 0),
                    sink=event.get("sink", "sink"),
                    task_id=event.get("task_id", ""),
                )
            )
            return

        if event_name == "audit_scanner_completed":
            summary = event.get("summary", {})
            console.print(
                "[bold green]Scanner audit done[/bold green] | chains [cyan]{chains}[/cyan] | audited [cyan]{audited}[/cyan] | errors [cyan]{errors}[/cyan]".format(
                    chains=summary.get("chains", 0),
                    audited=summary.get("audited", 0),
                    errors=summary.get("errors", 0),
                )
            )
            console.print(f"  - artifact [green]{event.get('artifact')}[/green]")
            console.print(f"  - findings [green]{event.get('markdown')}[/green]")
            return

        if event_name == "scanner_file_started":
            self._render_scanner_progress(event)
            return

        if event_name == "scanner_file_completed":
            console.print(
                f"  └ 完成 [white]{event.get('path')}[/white] · findings=[yellow]{event.get('findings', 0)}[/yellow]"
            )
            if self.scanner_task_id is not None:
                self.progress.update(
                    self.scanner_task_id,
                    total=max(self.scanner_total, 1),
                    completed=int(event.get("current", 1)),
                    description=f"[magenta]Scanner[/magenta] {event.get('path')}",
                )
            return

        if event_name == "stage_completed":
            self._render_stage_completed(event)
            return

        if event_name == "workflow_completed":
            elapsed = float(event.get("elapsed_seconds", 0))
            console.print()
            console.print(Rule(f"[bold green]完成   总耗时 {elapsed:.2f}s[/bold green]", style="cyan"))

    def _render_stage_started(self, event: dict[str, Any]) -> None:
        step_index = int(event.get("step_index", 0))
        total_steps = int(event.get("total_steps", self.total_steps or 1))
        title = event.get("title", event.get("stage", "stage"))
        message = event.get("message", "")
        console.print(f"[bold cyan]步骤 {step_index}/{total_steps} {title}[/bold cyan] {message}")

        if event.get("stage") == "scanner" and self.scanner_task_id is None:
            self.scanner_task_id = self.progress.add_task("[magenta]Scanner[/magenta]", total=1)

    def _render_scanner_progress(self, event: dict[str, Any]) -> None:
        total = max(int(event.get("total", 1)), 1)
        current = max(int(event.get("current", 1)) - 1, 0)
        self.scanner_total = total

        if self.scanner_task_id is None:
            self.scanner_task_id = self.progress.add_task("[magenta]Scanner[/magenta]", total=total)

        self.progress.update(
            self.scanner_task_id,
            total=total,
            completed=current,
            description=f"[magenta]Scanner[/magenta] {event.get('path')} ({event.get('kind', 'unknown')})",
        )
        console.print(f"- 扫描文件 [white]{event.get('path')}[/white] ({event.get('current')}/{total})")

    #----------- TreeScan 项目理解展示：在目录树扫描后直接输出项目认知，供人工快速校验 ------------#
    def _render_project_understanding(self, profile_summary: dict[str, Any]) -> None:
        understanding = profile_summary.get("project_understanding", {})

        console.print(
            "  └ 项目: [white]{name}[/white] · 类型: [white]{ptype}[/white]".format(
                name=profile_summary.get("project_name", "unknown"),
                ptype=profile_summary.get("project_type", "unknown"),
            )
        )
        console.print(
            "  └ 功能: [white]{function}[/white]".format(
                function=profile_summary.get("project_function", "unknown"),
            )
        )
        console.print(
            "  └ 后端: [white]{backend}[/white] · 前端: [white]{frontend}[/white]".format(
                backend=_join_or_unknown(profile_summary.get("backend")),
                frontend=_join_or_unknown(profile_summary.get("frontend")),
            )
        )
        attack_surfaces = understanding.get("attack_surfaces", [])
        if attack_surfaces:
            console.print(f"  └ 风险面: [white]{_join_or_unknown(attack_surfaces)}[/white]")

    def _render_stage_completed(self, event: dict[str, Any]) -> None:
        stage = event.get("stage", "stage")
        elapsed = float(event.get("elapsed_seconds", 0))
        summary = event.get("summary", {})

        if self.workflow_task_id is not None:
            self.progress.advance(self.workflow_task_id, 1)

        if stage == "treescan":
            console.print(f"[bold green]√ 完成[/bold green] ([white]{elapsed:.2f}s[/white])")
            console.print()
            return

        if stage == "callscan":
            console.print(
                "  └ sink hits [cyan]{hits}[/cyan] · analyses [cyan]{analyses}[/cyan] · priority chains [cyan]{chains}[/cyan]".format(
                    hits=summary.get("sink_hits", 0),
                    analyses=summary.get("sink_analyses", 0),
                    chains=summary.get("priority_chains", 0),
                )
            )
            console.print(f"[bold green]√ 完成[/bold green] ([white]{elapsed:.2f}s[/white])")
            console.print()
            return

        if stage == "audit":
            console.print(
                "  └ 审计链 [cyan]{chains}[/cyan] 条 · 确认漏洞 [cyan]{vulnerable}[/cyan] · 需复核 [cyan]{review}[/cyan] · 失败 [cyan]{errors}[/cyan]".format(
                    chains=summary.get("chains", 0),
                    vulnerable=summary.get("vulnerable", 0),
                    review=summary.get("needs_review", 0),
                    errors=summary.get("errors", 0),
                )
            )
            console.print(f"[bold green]√ 完成[/bold green] ([white]{elapsed:.2f}s[/white])")
            console.print()
            return

        if stage == "scanner":
            console.print(
                "  └ 扫描文件 [cyan]{scanned}[/cyan] 个 · findings [cyan]{findings}[/cyan] · high [cyan]{high}[/cyan] · medium [cyan]{medium}[/cyan] · suspicious [cyan]{suspicious}[/cyan]".format(
                    scanned=summary.get("scanned_files", 0),
                    findings=summary.get("findings", 0),
                    high=summary.get("high", 0),
                    medium=summary.get("medium", 0),
                    suspicious=summary.get("suspicious", 0),
                )
            )
            console.print(f"[bold green]√ 完成[/bold green] ([white]{elapsed:.2f}s[/white])")
            console.print()


def _join_or_unknown(values: Any) -> str:
    if not values:
        return "unknown"
    if isinstance(values, list):
        cleaned = [str(item) for item in values if str(item).strip()]
        return ", ".join(cleaned) if cleaned else "unknown"
    return str(values)


def _model_label() -> str:
    provider = (LLM_PROVIDER or "").strip()
    model = (LLM_MODEL or "").strip()
    if provider and model:
        return f"{provider}/{model}"
    return model or provider or "unknown"


#----------- CLI 主函数：串联标题、workflow 执行与 rich 实时输出 ------------#
def _resolve_callscan_project_path(project_path: str) -> str:
    # CallScan receives a concrete repository path; CLI keeps the same repo_code/<project_path> convention as workflow.py.
    raw_path = Path(project_path).expanduser()
    if raw_path.is_absolute() or raw_path.exists():
        return str(raw_path)

    repo_candidate = Path("repo_code") / raw_path
    if repo_candidate.exists():
        return str(repo_candidate)
    return project_path


def _resolve_artifacts_dir(project_root: str, artifacts_dir: str | None) -> Path:
    root = Path(project_root).expanduser().resolve()
    if artifacts_dir:
        path = Path(artifacts_dir).expanduser()
        if not path.is_absolute():
            path = root / path
        return path.resolve()
    return root / ".defectmine"


def _ensure_treescan_profile(project_root: str, artifacts_dir: Path, reporter: Any, *, force: bool, persist: bool) -> None:
    profile_path = artifacts_dir / "treescan_agent.json"
    if profile_path.is_file() and not force:
        return
    run_treescan(
        project_root,
        artifacts_dir=artifacts_dir,
        persist=persist,
        progress_reporter=reporter,
    )


def _csv_values(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def render_sink_hits_report(report: dict[str, Any], limit: int) -> None:
    # sink_hits can be large, so the CLI shows statistics plus the first N rows while the full JSON remains persisted.
    sink_hits = report.get("sink_hits", [])
    if not isinstance(sink_hits, list):
        sink_hits = []

    summary = report.get("summary", {})
    console.print()
    console.print(Rule("[bold cyan]Sink Hits[/bold cyan]", style="cyan"))
    console.print(
        "rules [cyan]{rules}[/cyan] | hits [cyan]{hits}[/cyan] | analyses [cyan]{analyses}[/cyan] | local_edges [cyan]{edges}[/cyan] | mcp_tasks [cyan]{tasks}[/cyan]".format(
            rules=summary.get("sink_rules", 0),
            hits=summary.get("sink_hits", len(sink_hits)),
            analyses=summary.get("sink_analyses", 0),
            edges=summary.get("local_call_edges", 0),
            tasks=summary.get("mcp_tasks", 0),
        )
    )

    categories = Counter(str(hit.get("category", "unknown")) for hit in sink_hits if isinstance(hit, dict))
    if categories:
        console.print(
            "categories "
            + " | ".join(f"[white]{name}[/white]=[cyan]{count}[/cyan]" for name, count in categories.most_common(8))
        )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("sink_id", overflow="fold")
    table.add_column("category", overflow="fold")
    table.add_column("location", overflow="fold")
    table.add_column("match", overflow="fold")
    table.add_column("evidence", overflow="fold")

    for index, hit in enumerate(sink_hits[: max(limit, 0)], start=1):
        if not isinstance(hit, dict):
            continue
        location = f"{hit.get('file', '')}:{hit.get('line', 0)}:{hit.get('column', 0)}"
        table.add_row(
            str(index),
            str(hit.get("sink_id", "")),
            str(hit.get("category", "")),
            location,
            str(hit.get("match", "")),
            _shorten(str(hit.get("evidence", "")), 100),
        )

    if limit > 0 and sink_hits:
        console.print(table)


def render_ranked_impact_paths_report(report: dict[str, Any]) -> None:
    # ranked_impact_paths 是 Scanner 的优先审计队列来源；默认只展示首尾，避免 CLI 被大量链路淹没。
    ranked_paths = report.get("ranked_impact_paths", [])
    if not isinstance(ranked_paths, list) or not ranked_paths:
        return

    console.print()
    console.print(Rule("[bold cyan]Ranked Impact Paths[/bold cyan]", style="cyan"))

    total = len(ranked_paths)
    chain_counts = Counter(str(item.get("analysis_id", "")) for item in ranked_paths if isinstance(item, dict))
    verbose = os.environ.get("CALLSCAN_VERBOSE", "").strip() == "1"
    display_items = _ranked_display_items(ranked_paths, verbose=verbose)
    omitted_printed = False

    for index, item in display_items:
        if item is None:
            omitted = max(total - 30, 0)
            if omitted > 0 and not omitted_printed:
                console.print(
                    "... [cyan]{omitted}[/cyan] more ranked impact path(s); set [white]CALLSCAN_VERBOSE=1[/white] for the full stream ...".format(
                        omitted=omitted,
                    )
                )
                omitted_printed = True
            continue

        console.print(_format_ranked_impact_path_line(index, total, item, chain_counts))


def render_audit_preparation_report(report: dict[str, Any]) -> None:
    debug = report.get("debug", {}) if isinstance(report.get("debug"), dict) else {}
    audit_tasks = debug.get("audit_tasks", [])
    if not isinstance(audit_tasks, list):
        audit_tasks = []

    summary = report.get("summary", {})
    execution = debug.get("execution", {})
    console.print()
    console.print(Rule("[bold cyan]Audit Tasks[/bold cyan]", style="cyan"))
    console.print(
        "phase [cyan]{phase}[/cyan] | chains [cyan]{chains}[/cyan] | prepared [cyan]{prepared}[/cyan] | concurrency [cyan]{concurrency}[/cyan]".format(
            phase=execution.get("phase", "phase1_task_preparation") if isinstance(execution, dict) else "phase1_task_preparation",
            chains=summary.get("chains", len(audit_tasks)) if isinstance(summary, dict) else len(audit_tasks),
            prepared=summary.get("audited", len(audit_tasks)) if isinstance(summary, dict) else len(audit_tasks),
            concurrency=execution.get("concurrency", 4) if isinstance(execution, dict) else 4,
        )
    )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("task_id", overflow="fold")
    table.add_column("priority", overflow="fold")
    table.add_column("language", overflow="fold")
    table.add_column("vulnerability", overflow="fold")
    table.add_column("sink", overflow="fold")
    table.add_column("location", overflow="fold")

    for index, task in enumerate(audit_tasks[:20], start=1):
        if not isinstance(task, dict):
            continue
        rank = task.get("rank", {}) if isinstance(task.get("rank"), dict) else {}
        sink = task.get("sink", {}) if isinstance(task.get("sink"), dict) else {}
        table.add_row(
            str(index),
            str(task.get("task_id", "")),
            f"{rank.get('priority', '')} {rank.get('risk_level', '')}",
            str(task.get("language", "")),
            str(task.get("vulnerability_type", "")),
            str(sink.get("sink_id", "")),
            f"{sink.get('file', '')}:{sink.get('line', 0)}",
        )

    if audit_tasks:
        console.print(table)
        if len(audit_tasks) > 20:
            console.print(f"... [cyan]{len(audit_tasks) - 20}[/cyan] more audit task(s) in audit_agent.json ...")


def render_audit_result_report(report: dict[str, Any]) -> None:
    debug = report.get("debug", {}) if isinstance(report.get("debug"), dict) else {}
    raw_results = debug.get("raw_results", [])
    if not isinstance(raw_results, list):
        raw_results = []

    summary = report.get("summary", {})
    execution = debug.get("execution", {})
    console.print()
    console.print(Rule("[bold cyan]Scanner Audit[/bold cyan]", style="cyan"))
    console.print(
        "phase [cyan]{phase}[/cyan] | chains [cyan]{chains}[/cyan] | vulnerable [cyan]{vulnerable}[/cyan] | needs_review [cyan]{needs_review}[/cyan] | errors [cyan]{errors}[/cyan]".format(
            phase=execution.get("phase", "phase3_mcp_audit") if isinstance(execution, dict) else "phase3_mcp_audit",
            chains=summary.get("chains", len(raw_results)) if isinstance(summary, dict) else len(raw_results),
            vulnerable=summary.get("vulnerable", 0) if isinstance(summary, dict) else 0,
            needs_review=summary.get("needs_review", 0) if isinstance(summary, dict) else 0,
            errors=summary.get("errors", 0) if isinstance(summary, dict) else 0,
        )
    )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("verdict", overflow="fold")
    table.add_column("confidence", overflow="fold")
    table.add_column("severity", overflow="fold")
    table.add_column("sink", overflow="fold")
    table.add_column("location", overflow="fold")

    for index, item in enumerate(raw_results[:20], start=1):
        if not isinstance(item, dict):
            continue
        parsed = item.get("parsed", {}) if isinstance(item.get("parsed"), dict) else {}
        chain = item.get("chain", {}) if isinstance(item.get("chain"), dict) else {}
        sink = chain.get("sink", {}) if isinstance(chain.get("sink"), dict) else {}
        table.add_row(
            str(index),
            str(parsed.get("verdict", "unknown")),
            str(parsed.get("confidence", "unknown")),
            str(parsed.get("severity", "unknown")),
            str(sink.get("sink_id", "")),
            f"{sink.get('file', '')}:{sink.get('line', 0)}",
        )

    if raw_results:
        console.print(table)
        if len(raw_results) > 20:
            console.print(f"... [cyan]{len(raw_results) - 20}[/cyan] more audit result(s) in audit_agent.json ...")


def _ranked_display_items(
    ranked_paths: list[Any],
    *,
    verbose: bool,
) -> list[tuple[int, dict[str, Any] | None]]:
    if verbose or len(ranked_paths) <= 30:
        return [(index, item) for index, item in enumerate(ranked_paths, start=1) if isinstance(item, dict)]

    head = [(index, item) for index, item in enumerate(ranked_paths[:15], start=1) if isinstance(item, dict)]
    tail_start = len(ranked_paths) - 15 + 1
    tail = [
        (tail_start + offset, item)
        for offset, item in enumerate(ranked_paths[-15:])
        if isinstance(item, dict)
    ]
    return [*head, (0, None), *tail]


def _format_ranked_impact_path_line(
    index: int,
    total: int,
    item: dict[str, Any],
    chain_counts: Counter[str],
) -> str:
    path = item.get("path", {}) if isinstance(item.get("path"), dict) else {}
    complete = bool(path.get("complete")) and path.get("status") == "entry_reached"
    status = "[bold green]OK[/bold green]" if complete else "[bold yellow]?[/bold yellow]"

    sink = item.get("sink", {}) if isinstance(item.get("sink"), dict) else {}
    entry = item.get("entry", {}) if isinstance(item.get("entry"), dict) else {}
    rank_level = str(item.get("risk_level", "unknown"))
    priority = str(item.get("priority", "P?"))
    score = int(item.get("risk_score", 0) or 0)
    sink_label = _ranked_sink_label(sink)
    location = _ranked_location(sink)
    mode = _ranked_chain_mode(path)
    chain_count = max(chain_counts.get(str(item.get("analysis_id", "")), 1), 1)
    entry_label = str(entry.get("function", "") or entry.get("kind", "") or "entry")

    return (
        "{status} [{index}/{total}] [yellow]{sink}[/yellow] @ [white]{location}[/white] "
        "([cyan]{priority}[/cyan] {level} score {score}) ({mode}) ({chains} chain{plural}) -> [white]{entry}[/white]"
    ).format(
        status=status,
        index=index,
        total=total,
        sink=sink_label,
        location=location,
        priority=priority,
        level=rank_level,
        score=score,
        mode=mode,
        chains=chain_count,
        plural="" if chain_count == 1 else "s",
        entry=entry_label,
    )


def _ranked_sink_label(sink: dict[str, Any]) -> str:
    function = str(sink.get("function", "")).strip()
    vulnerability = str(sink.get("vulnerability", "")).replace("_", "-")
    category = str(sink.get("category", "")).strip()
    label = function or vulnerability or category or str(sink.get("sink_id", "sink"))
    if vulnerability and vulnerability not in label:
        return f"{label} -> {vulnerability}"
    return label


def _ranked_location(sink: dict[str, Any]) -> str:
    file = str(sink.get("file", ""))
    line = int(sink.get("line", 0) or 0)
    return f"{file}:{line}" if line else file


def _ranked_chain_mode(path: dict[str, Any]) -> str:
    edges = path.get("edges", [])
    if isinstance(edges, list) and any("tldr" in str(edge.get("kind", "")).casefold() for edge in edges if isinstance(edge, dict)):
        return "static"
    if isinstance(edges, list) and edges:
        return "local"
    return "unknown"


def _shorten(value: str, limit: int) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(limit - 3, 0)] + "..."


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    render_banner()
    render_header(args.project_path)
    render_effective_limits(args)

    try:
        with CliReporter() as reporter:
            project_root = _resolve_callscan_project_path(args.project_path)
            artifacts_dir = _resolve_artifacts_dir(project_root, args.artifacts_dir)
            if args.discover:
                _ensure_treescan_profile(project_root, artifacts_dir, reporter, force=args.force_discover, persist=not args.no_persist)
                result = run_callscan(
                    project_root,
                    artifacts_dir=artifacts_dir,
                    persist=not args.no_persist,
                    progress_reporter=reporter,
                    priority_chain_limit=max(args.priority_chain_limit, 0),
                    reuse_discovery=True,
                    force_discover=args.force_discover,
                )
                render_ranked_impact_paths_report(result.report)
            elif args.schedule:
                batch = create_audit_batch(
                    artifacts_dir,
                    limit=args.audit_limit or max(args.priority_chain_limit, 0),
                    per_type=args.audit_per_type,
                    vulnerability_types=_csv_values(args.audit_vuln_types),
                    exclude_completed=not args.include_completed,
                    name=args.batch_name,
                    progress_reporter=reporter,
                )
                console.print(
                    "[bold green]Audit batch scheduled[/bold green] "
                    f"{batch.get('batch_id')} | queue [cyan]{batch.get('queue_count', 0)}[/cyan]"
                )
            elif args.audit_batch:
                result = run_audit_batch(
                    project_root,
                    artifacts_dir,
                    args.audit_batch,
                    audit_limit=args.audit_limit,
                    enable_llm_audit=not args.audit_dry_run,
                    enable_mcp_tools=not args.audit_no_tools,
                    progress_reporter=reporter,
                )
                render_audit_result_report(result.report)
            elif args.batch_audit:
                _ensure_treescan_profile(project_root, artifacts_dir, reporter, force=args.force_discover, persist=not args.no_persist)
                all_pool = artifacts_dir / "callscan_chains.all.jsonl"
                if args.force_discover or not all_pool.is_file():
                    run_callscan(
                        project_root,
                        artifacts_dir=artifacts_dir,
                        persist=not args.no_persist,
                        progress_reporter=reporter,
                        priority_chain_limit=max(args.priority_chain_limit, 0),
                        reuse_discovery=True,
                        force_discover=args.force_discover,
                    )
                batch = create_audit_batch(
                    artifacts_dir,
                    limit=args.audit_limit or max(args.priority_chain_limit, 0),
                    per_type=args.audit_per_type,
                    vulnerability_types=_csv_values(args.audit_vuln_types),
                    exclude_completed=not args.include_completed,
                    name=args.batch_name,
                    progress_reporter=reporter,
                )
                result = run_audit_batch(
                    project_root,
                    artifacts_dir,
                    str(batch.get("batch_id")),
                    audit_limit=args.audit_limit,
                    enable_llm_audit=not args.audit_dry_run,
                    enable_mcp_tools=not args.audit_no_tools,
                    progress_reporter=reporter,
                )
                render_audit_result_report(result.report)
            elif args.callscan:
                result = run_callscan(
                    project_root,
                    artifacts_dir=artifacts_dir,
                    persist=not args.no_persist,
                    progress_reporter=reporter,
                    priority_chain_limit=max(args.priority_chain_limit, 0),
                )
                render_ranked_impact_paths_report(result.report)
                render_sink_hits_report(result.report, args.show_sink_hits)
            elif args.audit:
                result = run_audit_scanner(
                    project_root,
                    artifacts_dir=artifacts_dir,
                    audit_limit=args.audit_limit,
                    enable_llm_audit=not args.audit_dry_run,
                    enable_mcp_tools=not args.audit_no_tools,
                    persist=not args.no_persist,
                    progress_reporter=reporter,
                )
                if args.audit_dry_run:
                    render_audit_preparation_report(result.report)
                else:
                    render_audit_result_report(result.report)
            else:
                run_workflow(
                    args.project_path,
                    artifacts_dir=args.artifacts_dir,
                    persist=not args.no_persist,
                    priority_chain_limit=max(args.priority_chain_limit, 0),
                    audit_limit=args.audit_limit,
                    enable_llm_audit=not args.audit_dry_run,
                    enable_mcp_tools=not args.audit_no_tools,
                    progress_reporter=reporter,
                )
    except Exception as exc:
        console.print()
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
