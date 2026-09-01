"""DefectMine 管理平台后端 API。

通过 FastAPI 暴露：
- 仓库扫描（/api/projects）
- specific run 列表（/api/projects/{...}/runs）
- 产物文件解析与分块读取（/api/artifacts/...）
- 流水线/Agent 命令的 SSE 流式执行（/api/run/...）
"""
