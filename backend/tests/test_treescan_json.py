from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.agent.sub_agent import treescan


class TreeScanJsonTests(unittest.TestCase):
    def test_parse_json_from_markdown_fence(self) -> None:
        raw = '```json\n{"project_name": "demo"}\n```'
        parsed = treescan._parse_json_from_text(raw)
        self.assertEqual(parsed, {"project_name": "demo"})

    def test_parse_json_embedded_in_text(self) -> None:
        raw = '说明如下：{"project_name": "demo", "summary": "x"} 结束'
        parsed = treescan._parse_json_from_text(raw)
        self.assertEqual(parsed["project_name"], "demo")

    def test_parse_json_returns_none_for_truncated_payload(self) -> None:
        raw = '{"project_name": "Django", "technology_stack": {"database": ['
        self.assertIsNone(treescan._parse_json_from_text(raw))


if __name__ == "__main__":
    unittest.main()
