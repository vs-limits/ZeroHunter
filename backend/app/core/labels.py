"""Agent JSON 字段英文 → 中文标签映射。

统一收纳各 Agent 输出 Schema 的中文标签，用于 CLI 思维流展示。
schema 本身保持英文 key（对 LLM 稳定、对下游友好），只在展示层
通过这里的映射翻译成中文。

维护约定：
- 新增 Agent 时在下方追加一个 *_LABELS 字典。
- 任何字段新增/改名，先改对应 prompt，再同步这里。
- 只放"长期稳定"的字段；临时调试字段不要进。
"""

# TreeScan Agent: 项目画像
TREESCAN_LABELS = {
    "project_name": "项目名称",
    "project_function": "功能定位",
    "summary": "摘要",
    "project_type": "项目类型",
    "architecture_style": "架构风格",
    "repository_shape": "仓库形态",
    "interface_shape": "对外形态",
    "execution_model": "执行模型",
    "technology_stack": "技术栈",
    "engineering_context": "工程背景",
    "confidence": "置信度",
    "limits": "边界说明",
}

# TreeScan Agent: technology_stack 内部子字段
TREESCAN_STACK_LABELS = {
    "frontend": "前端",
    "backend": "后端",
    "database": "数据库",
    "template_engine": "模板引擎",
    "runtime": "运行环境",
    "deployment": "部署形态",
}

# TreeScan Agent: confidence 内部子字段
TREESCAN_CONFIDENCE_LABELS = {
    "overall": "总体",
    "notes": "证据边界",
}
