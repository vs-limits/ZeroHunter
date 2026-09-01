from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.llm_settings import profile_from_test_payload
from app.llm.client import build_litellm_extra_body, chat_completion
from app.server.llms import run_llm_concurrent_test


class _FakeMessage:
    role = "assistant"
    content = "ok"


class _FakeChoice:
    message = _FakeMessage()


class _FakeResponse:
    choices = [_FakeChoice()]


class MiniCustomConfigTests(unittest.TestCase):
    def test_profile_payload_preserves_mini_custom_config(self) -> None:
        profile = profile_from_test_payload(
            {
                "name": "Mini自定义配置",
                "base_url": "https://apiai.sztu.edu.cn/v1",
                "api_key": "sk-test",
                "model_name": "deepseek-v4-pro",
                "protocol": "openai",
                "config_type": "mini_custom",
                "mini_config": {
                    "thinking": True,
                    "reasoning_effort": "max",
                    "top_k": 40,
                    "min_p": 0.05,
                    "repetition_penalty": 1.1,
                },
            }
        )

        self.assertEqual(profile["config_type"], "mini_custom")
        self.assertEqual(
            profile["mini_config"],
            {
                "thinking": True,
                "reasoning_effort": "max",
                "top_k": 40,
                "min_p": 0.05,
                "repetition_penalty": 1.1,
            },
        )

    def test_mini_custom_extra_body_matches_api_document(self) -> None:
        profile = {
            "base_url": "https://apiai.sztu.edu.cn/v1",
            "api_key": "sk-test",
            "model_name": "deepseek-v4-pro",
            "protocol": "openai",
            "config_type": "mini_custom",
            "mini_config": {
                "thinking": True,
                "reasoning_effort": "max",
                "top_k": 40,
                "min_p": 0.05,
                "repetition_penalty": 1.1,
            },
        }

        self.assertEqual(
            build_litellm_extra_body(profile),
            {
                "chat_template_kwargs": {
                    "thinking": True,
                    "reasoning_effort": "max",
                },
                "top_k": 40,
                "min_p": 0.05,
                "repetition_penalty": 1.1,
            },
        )

    def test_mini_custom_exit_sanitizes_reasoning_and_tool_name(self) -> None:
        profile = {
            "base_url": "https://apiai.sztu.edu.cn/v1",
            "api_key": "sk-test",
            "model_name": "deepseek-v4-pro",
            "protocol": "openai",
            "config_type": "mini_custom",
            "mini_config": {
                "thinking": True,
                "reasoning_effort": "high",
                "top_k": -1,
                "min_p": 0.0,
                "repetition_penalty": 1.0,
            },
        }

        with (
            patch("app.llm.client.get_active_llm_config", return_value=profile),
            patch("app.llm.client.completion", return_value=_FakeResponse()) as mocked,
        ):
            chat_completion(
                [
                    {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": "drop me",
                        "tool_calls": [],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_1",
                        "name": "lookup",
                        "content": "{}",
                    },
                ],
                max_tokens=64,
            )

        kwargs = mocked.call_args.kwargs
        self.assertEqual(
            kwargs["extra_body"]["chat_template_kwargs"],
            {"thinking": True, "reasoning_effort": "high"},
        )
        self.assertNotIn("reasoning_content", kwargs["messages"][0])
        self.assertNotIn("name", kwargs["messages"][1])

    def test_global_context_preflight_blocks_oversized_deepseek_prompt(self) -> None:
        profile = {
            "base_url": "https://apiai.sztu.edu.cn/v1",
            "api_key": "sk-test",
            "model_name": "deepseek-v4-pro",
            "protocol": "openai",
            "config_type": "mini_custom",
            "mini_config": {
                "thinking": False,
                "reasoning_effort": "high",
                "top_k": -1,
                "min_p": 0.0,
                "repetition_penalty": 1.0,
            },
        }

        with (
            patch("app.llm.client.get_active_llm_config", return_value=profile),
            patch("app.llm.client.completion", return_value=_FakeResponse()) as mocked,
        ):
            with self.assertRaisesRegex(ValueError, "context budget"):
                chat_completion(
                    [{"role": "user", "content": "x" * 450_000}],
                    max_tokens=2_000,
                )

        mocked.assert_not_called()

    def test_standard_deepseek_keeps_legacy_extra_body(self) -> None:
        profile = {
            "base_url": "https://api.deepseek.com/v1",
            "model_name": "deepseek-v4-flash",
            "protocol": "openai",
            "config_type": "standard",
        }

        self.assertEqual(
            build_litellm_extra_body(profile),
            {"thinking": {"type": "disabled"}},
        )

    def test_concurrent_llm_test_counts_successes_against_threshold(self) -> None:
        responses = iter(
            [
                _FakeResponse(),
                RuntimeError("rate limited"),
                _FakeResponse(),
                _FakeResponse(),
            ]
        )

        def fake_completion(**_kwargs):
            item = next(responses)
            if isinstance(item, BaseException):
                raise item
            return item

        with patch("app.server.llms.completion", side_effect=fake_completion):
            result = run_llm_concurrent_test(
                {
                    "name": "mini",
                    "base_url": "https://apiai.sztu.edu.cn/v1",
                    "api_key": "sk-test",
                    "model_name": "deepseek-v4-pro",
                    "protocol": "openai",
                    "config_type": "mini_custom",
                    "mini_config": {
                        "thinking": False,
                        "reasoning_effort": "high",
                        "top_k": -1,
                        "min_p": 0.0,
                        "repetition_penalty": 1.0,
                    },
                    "count": 4,
                    "success_threshold": 3,
                }
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["total"], 4)
        self.assertEqual(result["success_threshold"], 3)
        self.assertEqual(result["success_count"], 3)
        self.assertEqual(result["failure_count"], 1)


if __name__ == "__main__":
    unittest.main()
