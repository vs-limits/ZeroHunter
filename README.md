# 使用
## 基本命令
```
python main.py <项目路径>
```
## 参数说明
```
--output 输出格式
--indent JSON缩进
```
## 示例
```
python main.py github/yeswiki/yeswiki
python main.py github/yeswiki/yeswiki/ --output tree.json --indent 2
```
<项目路径> 相对于仓库根目录下的 ``repo/`` 目录进行解析
(例如 ``github/yeswiki/yeswiki`` 指向 ``repo/github/yeswiki/yeswiki``)。

# 功能
输入`` python main.py <项目路径> ``后，DefectMine会开始对目标代码仓库进行代码审计，漏洞挖掘。
首先，DefectMine会提取项目目录树，调用一次LLM，从宏观上分析本项目的功能、技术栈


---

# 管理平台（前端 + API）

提供一个本地管理控制台，可视化查看每次扫描产物、跑命令、看 LLM 对话。

## 后端 API

```
cd backend
pip install -r requirements.txt
uvicorn app.server.app:app --port 8765 --reload
```

主要接口：

- `GET  /api/projects` — 列出 `repo/<source>/<owner>/<repo>`。
- `GET  /api/projects/{src}/{owner}/{repo}/runs` — 项目 + specific 运行列表。
- `GET  /api/artifacts/json` — 读取 `tree.json` / `treescan_agent.json` / `callscan_agent.json`。
- `GET  /api/artifacts/audit` — 分页读取 `audit_agent.json` 的 findings（支持 severity/verdict/keyword 过滤）。
- `GET  /api/artifacts/jsonl` — 分页读取 `callscan_chains*.jsonl`。
- `GET  /api/artifacts/markdown` — 按章节分页读取 `callscan_chains.md` / `audit_findings.md`。
- `GET  /api/logs`, `GET /api/logs/{name}` — 按 LLM 对话轮次解析 `logs/YY-MM-DD.log`。
- `GET  /api/run/{run_id}/stream` — SSE 流式获取一次执行的标准输出。

## 前端

```
cd frontend
npm install
npm run dev   # http://localhost:5173
```

- 左侧栏：扫描 `repo/` 下的所有项目，按 `<source>/<owner>/<repo>` 一行展示，点 ▸ 展开后显示「a. 全仓库」+ 各 `specific/<run_id>` 节点。
- 右侧顶部：`a.控制面板  b.目录树  c.TreeScan  d.CallScan  e.Audit` 五个 tab。
- 控制面板：一键运行各步流程 / 创建 specific / 跑 specific 内的某个 agent，输出实时流向控制台。
- CallScan、Audit、Markdown、日志等大文件页面均按页加载，配合 IntersectionObserver 滚动到底自动续读，避免一次性把数百 MB 的产物吃进内存。
