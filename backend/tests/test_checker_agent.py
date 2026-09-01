from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.agent.prompts import load_prompt
from app.agent.sub_agent import checker
from app.server import paths, scans, scan_runner_cli
from app.server import app as app_mod


def _llm_response(content: str):
    return SimpleNamespace(
        choices=[SimpleNamespace(message={"role": "assistant", "content": content})]
    )


class CheckerAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.tmp.name) / "repo"
        self.repo_root.mkdir()
        self.orig_repo_root = paths.REPO_ROOT
        paths.REPO_ROOT = self.repo_root

        self.project_path = "dataset/defectmine/checker/default__manual"
        self.project_root = self.repo_root / "dataset" / "defectmine" / "checker" / "default__manual"
        self.project_root.mkdir(parents=True)
        (self.project_root / "app.py").write_text(
            "\n".join(
                [
                    "def handler(request):",
                    "    cmd = request.args['cmd']",
                    "    os.system(cmd)",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        meta = scans.create_scan(
            self.project_path,
            name="checker-unit",
            agents=["treescan", "callscan", "auditor"],
        )
        self.scan_id = meta["scan_id"]
        self.scan_dir = (
            self.project_root / ".defectmine" / "scans" / self.scan_id
        )

    def tearDown(self) -> None:
        paths.REPO_ROOT = self.orig_repo_root
        self.tmp.cleanup()

    def test_loads_checker_prompt_with_shared_rules(self) -> None:
        prompt = load_prompt("checker.md")
        self.assertIn("输出 JSON Schema", prompt)
        self.assertNotIn("{{SHARED_OUTPUT_RULES}}", prompt)

    def test_checker_reviews_vulnerable_finding_and_writes_artifacts(self) -> None:
        self._write_audit_and_chains(["C-1"])
        result_json = json.dumps(
            {
                "finding_id": "C-1",
                "verdict": "confirmed",
                "confidence": 0.91,
                "concrete_payload": "cmd=id",
                "trigger_steps": ["请求 /run?cmd=id"],
                "blocking_filters": [],
                "missing_context": [],
                "verdict_reasoning": "独立追踪到 request.args['cmd'] 直接进入 os.system。",
                "severity_revised": "high",
            },
            ensure_ascii=False,
        )

        with patch(
            "app.agent.sub_agent.checker.default_server_specs",
            side_effect=FileNotFoundError("no mcp"),
        ), patch(
            "app.agent.sub_agent.checker.chat_completion",
            return_value=_llm_response(result_json),
        ):
            result = checker.run(self.project_path, self.scan_id)

        self.assertEqual(result["summary"]["total_targets"], 1)
        self.assertEqual(result["summary"]["confirmed"], 1)
        self.assertTrue((self.scan_dir / "checker_agent.json").is_file())
        self.assertTrue((self.scan_dir / "checker_findings.md").is_file())
        saved = json.loads((self.scan_dir / "checker_agent.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["findings"][0]["finding_id"], "C-1")
        self.assertEqual(saved["findings"][0]["chain_id"], "C-1")

    def test_checker_chain_id_limits_review_to_one_finding(self) -> None:
        self._write_audit_and_chains(["C-1", "C-2"])
        result_json = json.dumps(
            {
                "finding_id": "C-2",
                "verdict": "refuted",
                "confidence": 0.8,
                "concrete_payload": None,
                "trigger_steps": [],
                "blocking_filters": [
                    {
                        "file": "app.py",
                        "line": 3,
                        "why_effective": "测试里模拟存在有效拦截。",
                    }
                ],
                "missing_context": [],
                "verdict_reasoning": "只复核指定的 C-2。",
                "severity_revised": None,
            },
            ensure_ascii=False,
        )

        with patch(
            "app.agent.sub_agent.checker.default_server_specs",
            side_effect=FileNotFoundError("no mcp"),
        ), patch(
            "app.agent.sub_agent.checker.chat_completion",
            return_value=_llm_response(result_json),
        ):
            result = checker.run(self.project_path, self.scan_id, "C-2")

        self.assertEqual(result["summary"]["total_targets"], 1)
        self.assertEqual(result["findings"][0]["finding_id"], "C-2")
        self.assertEqual(result["summary"]["refuted"], 1)

    def test_checker_requires_auditor_artifact(self) -> None:
        with self.assertRaises(FileNotFoundError):
            checker.run(self.project_path, self.scan_id)

    def test_invalid_checker_json_is_recorded_as_failure(self) -> None:
        self._write_audit_and_chains(["C-1"])
        with patch(
            "app.agent.sub_agent.checker.default_server_specs",
            side_effect=FileNotFoundError("no mcp"),
        ), patch(
            "app.agent.sub_agent.checker.chat_completion",
            side_effect=[
                _llm_response("not json"),
                _llm_response("still not json"),
            ],
        ):
            result = checker.run(self.project_path, self.scan_id)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertEqual(result["findings"], [])
        self.assertTrue((self.scan_dir / "checker_failures.jsonl").is_file())

    def test_checker_is_not_a_scan_workflow_agent(self) -> None:
        self.assertEqual(scans.ALL_AGENTS, ["treescan", "callscan", "dataflowscan", "auditor"])
        self.assertEqual(
            scan_runner_cli._run_pipeline(
                self.project_path,
                self.scan_id,
                ["checker"],
                resume=False,
            ),
            2,
        )
        with self.assertRaises(ValueError):
            app_mod._launch_scan_run(
                self.project_path,
                self.scan_id,
                ["checker"],
                resume=False,
            )

    def _write_audit_and_chains(self, chain_ids: list[str]) -> None:
        findings = []
        chains = []
        for idx, chain_id in enumerate(chain_ids, 1):
            finding = {
                "chain_id": chain_id,
                "index": idx,
                "language": "python",
                "vulnerability_type": "command_execution",
                "verdict": "vulnerable",
                "confidence": 0.9,
                "title": f"命令执行候选 {chain_id}",
                "severity": "high",
                "source": {"file": "app.py", "line": 2, "expr": "request.args['cmd']"},
                "sink": {"file": "app.py", "line": 3, "expr": "os.system(cmd)"},
                "data_flow": ["request.args['cmd'] -> os.system(cmd)"],
                "exploit_poc": "cmd=id",
                "fix_suggestion": "使用白名单命令。",
                "evidence": [
                    {
                        "source": "audit_pack",
                        "detail": "sink found",
                        "file": "app.py",
                        "line": 3,
                    }
                ],
            }
            chain = {
                "type": "chain",
                "chain_id": chain_id,
                "index": idx,
                "language": "python",
                "vulnerability_type": "command_execution",
                "severity": "high",
                "sink_file": "app.py",
                "sink_line": 3,
                "sink_function": "os.system",
                "has_call_chain": True,
                "call_chains": [
                    [
                        {
                            "file": "app.py",
                            "function": "handler",
                            "line": 1,
                            "role": "caller",
                        },
                        {
                            "file": "app.py",
                            "function": "os.system",
                            "line": 3,
                            "role": "sink",
                        },
                    ]
                ],
                "audit_pack": "handler reads request.args['cmd'] then calls os.system(cmd).",
            }
            findings.append(finding)
            chains.append(chain)

        (self.scan_dir / "audit_agent.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "summary": {"total_audited": len(findings), "vulnerable": len(findings)},
                    "findings": findings,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        with (self.scan_dir / "callscan_chains.priority.jsonl").open(
            "w", encoding="utf-8"
        ) as fp:
            for chain in chains:
                fp.write(json.dumps(chain, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    unittest.main()
