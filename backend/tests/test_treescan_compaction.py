from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.agent.sub_agent import treescan


class TreeScanCompactionTests(unittest.TestCase):
    def test_tree_payload_is_compacted_under_llm_budget(self) -> None:
        tree = {
            "files": [f"Root{i}.java" for i in range(120)] + ["pom.xml"],
            "dirs": {
                f"module-{i:03d}": {
                    "files": [f"Class{j}.java" for j in range(80)]
                    + ["pom.xml", "application.yml"],
                    "dirs": {
                        "src": {
                            "dirs": {
                                "main": {
                                    "dirs": {
                                        "java": {
                                            "files": [
                                                f"Service{j}.java" for j in range(60)
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
                for i in range(80)
            },
        }
        original_budget = treescan.TREESCAN_LLM_TREE_CHAR_BUDGET
        treescan.TREESCAN_LLM_TREE_CHAR_BUDGET = 12_000
        try:
            text, compacted = treescan._tree_json_for_llm(tree)
        finally:
            treescan.TREESCAN_LLM_TREE_CHAR_BUDGET = original_budget

        payload = json.loads(text)
        self.assertTrue(compacted)
        self.assertLessEqual(len(text), 12_000)
        self.assertTrue(payload["_defectmine_tree_compaction"]["compacted"])
        self.assertIn("tree", payload)
        self.assertIn("pom.xml", payload["tree"]["files"])


if __name__ == "__main__":
    unittest.main()
