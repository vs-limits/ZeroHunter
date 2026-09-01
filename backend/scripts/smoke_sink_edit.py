"""验证 sink rules 结构化保存能正确写回并被 import。"""

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.server import content as cnt  # noqa: E402

LANG = "c"
NAME = "auth_bypass"


def main() -> None:
    target = cnt._resolve_sink(LANG, NAME)
    backup = target.with_suffix(target.suffix + ".bak-smoke")
    shutil.copy2(target, backup)
    history_dir = target.parent / ".history" / target.stem
    pre_history_files = set(history_dir.iterdir()) if history_dir.is_dir() else set()

    try:
        original = cnt.read_sink(LANG, NAME)
        rules = original["rules"]
        assert rules, "没有任何规则可改"
        rules[0]["description"] = "smoke: 双击编辑测试"
        rules.append(
            {
                "id": "c-smoke-new-rule",
                "function": "smoke()",
                "call_regex": r"\bsmoke\s*\(",
                "description": "smoke 新增规则",
                "argument_roles": ["x"],
                "extensions": [".c"],
                "severity": "low",
            }
        )

        cnt.write_sink_rules(LANG, NAME, rules, reason="smoke 双击编辑")

        # 校验写入后的源码可以重新被 import
        again = cnt.read_sink(LANG, NAME)
        if again.get("parse_error"):
            raise SystemExit(f"重新解析失败: {again['parse_error']}")
        assert any(r["id"] == "c-smoke-new-rule" for r in again["rules"]), "新规则丢失"
        assert again["rules"][0]["description"] == "smoke: 双击编辑测试"
        print("ok rules_count=", again["rules_count"])

        # 还原
        target.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
    finally:
        if backup.is_file():
            backup.unlink()
        # 清掉 smoke 创建的历史归档（仅清理新增部分）
        if history_dir.is_dir():
            for p in history_dir.iterdir():
                if p not in pre_history_files:
                    p.unlink(missing_ok=True)
            # 如果原来就没历史目录，整个 .history 也回收
            if not pre_history_files:
                shutil.rmtree(history_dir.parent, ignore_errors=True)


if __name__ == "__main__":
    main()
