"""子 Agent 模块集合。

每个子 Agent 在独立文件内实现一个 run(...) 函数，由 app.agent.runner
通过 AgentRole.value 反射定位。新增 Agent 时：
    1. 在 app.agent.types.AgentRole 里加一个成员
    2. 在本目录下新建 <role_value>.py，实现 run(...)
runner.py 本身无需修改。
"""
