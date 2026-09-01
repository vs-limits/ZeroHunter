"""验证 logger / runner 的项目级落盘与事件流（不调用真实 LLM）。"""

from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.agent import logger  # noqa: E402


def main() -> None:
    workspace = ROOT.parent / "tmp" / "smoke_obs"
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    artifacts_dir = workspace / ".defectmine"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    scope = logger.ObsScope(
        project_path="tmp/smoke/obs",
        project_root=workspace,
        artifacts_dir=artifacts_dir,
    )

    obs_token = logger.set_obs_scope(scope)
    role_token = logger.set_agent_role("treescan")
    try:
        logger.write_event("agent_start", agent="treescan", args=["tmp/smoke/obs"])

        logger.log_request(
            model="openai/test-model",
            messages=[
                {"role": "system", "content": "你是测试助手"},
                {"role": "user", "content": "请输出 ok"},
            ],
            tools=None,
            tool_choice=None,
            temperature=0.1,
            max_tokens=100,
        )

        # 模拟一个 LiteLLM ModelResponse 风格的 dict
        fake_response = {
            "id": "test-1",
            "model": "openai/test-model",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "ok"},
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 1,
                "total_tokens": 13,
            },
        }
        logger.log_response(model="openai/test-model", response=fake_response)
        logger.write_event("agent_end", agent="treescan", elapsed=0.42)
    finally:
        logger.reset_agent_role(role_token)
        logger.reset_obs_scope(obs_token)

    # 检查产物
    print("conversations dir:")
    for p in sorted((artifacts_dir / "conversations").rglob("*")):
        print("  ", p.relative_to(artifacts_dir))

    events_path = artifacts_dir / "events.jsonl"
    print("\nevents.jsonl:")
    print(events_path.read_text(encoding="utf-8"))

    turn_path = artifacts_dir / "conversations" / "treescan" / "turn-0001.json"
    print("turn-0001.json keys:", list(json.loads(turn_path.read_text(encoding="utf-8")).keys()))


if __name__ == "__main__":
    main()
