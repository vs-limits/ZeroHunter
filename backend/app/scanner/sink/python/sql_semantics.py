"""Semantic helpers for Python SQL sink filtering."""

from __future__ import annotations

import ast
import functools
from pathlib import Path


_EXECUTE_NAMES = {"execute", "executemany", "fetch", "fetchrow", "fetchval"}
_USER_INPUT_ATTRS = {"args", "form", "values", "json"}
_USER_INPUT_CALLS = {"get_json", "input"}
_SAFE = "safe"
_UNSAFE = "unsafe"
_UNKNOWN = "unknown"


@functools.lru_cache(maxsize=128)
def _load_analyzer(file_path: str) -> "_Analyzer | None":
    path = Path(file_path)
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return None
    return _Analyzer(tree)


def python_sql_execute_is_dynamic(file_path: str | Path, line_number: int) -> bool | None:
    """Return whether the SQL passed to execute-like calls should reach Auditor.

    True:
        Semantically dynamic with attacker-influenced SQL construction.
    False:
        Dynamically assembled but still constrained to safe SQL fragments.
    None:
        Could not classify; caller should fall back to regex heuristics.
    """

    analyzer = _load_analyzer(str(file_path))
    if analyzer is None:
        return None
    return analyzer.execute_requires_review(line_number)


def python_graphql_execute_is_relevant(file_path: str | Path, line_number: int) -> bool | None:
    """Return whether an execute-like call looks like GraphQL execution."""

    analyzer = _load_analyzer(str(file_path))
    if analyzer is None:
        return None
    return analyzer.graphql_execute_is_relevant(line_number)


class _Analyzer:
    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.parents: dict[ast.AST, ast.AST] = {}
        self.function_defs: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.function_defs.setdefault(parent.name, []).append(parent)

    def execute_requires_review(self, line_number: int) -> bool | None:
        scope = self._find_enclosing_scope(line_number)
        call = self._find_execute_call(scope, line_number)
        if call is None:
            return None
        sql_expr = call.args[0] if call.args else None
        verdict = self._classify_expr(sql_expr, scope=scope, before_line=line_number)
        if verdict == _SAFE:
            return False
        if verdict == _UNSAFE:
            return True
        return None

    def graphql_execute_is_relevant(self, line_number: int) -> bool | None:
        scope = self._find_enclosing_scope(line_number)
        call = self._find_execute_call(scope, line_number)
        if call is None:
            return None
        receiver = None
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            receiver = call.func.value.id.lower()
        if receiver and any(token in receiver for token in {"conn", "cursor", "engine", "session", "db"}):
            return False
        string_hint = self._string_hint(call.args[0] if call.args else None, scope=scope, before_line=line_number)
        if string_hint:
            lowered = string_hint.lower()
            if any(keyword in lowered for keyword in {"select ", "update ", "insert ", "delete ", " from ", " where "}):
                return False
            if (
                any(keyword in lowered for keyword in {"query ", "mutation ", "subscription ", "fragment "})
                or "{" in lowered
            ):
                return True
        if receiver and any(token in receiver for token in {"schema", "graphql", "gql", "strawberry"}):
            return True
        return None

    def _find_enclosing_scope(self, line_number: int) -> ast.AST:
        best: ast.AST = self.tree
        best_span: int | None = None
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start is None or end is None:
                continue
            if start <= line_number <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best = node
                    best_span = span
        return best

    def _find_execute_call(self, scope: ast.AST, line_number: int) -> ast.Call | None:
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node, "lineno", None) != line_number:
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _EXECUTE_NAMES:
                return node
        return None

    def _classify_expr(
        self,
        expr: ast.AST | None,
        *,
        scope: ast.AST,
        before_line: int,
        seen: frozenset[str] = frozenset(),
    ) -> str:
        if expr is None:
            return _UNKNOWN
        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, str):
                return _SAFE
            return _UNKNOWN
        if isinstance(expr, ast.JoinedStr):
            statuses = [
                self._classify_expr(
                    value.value,
                    scope=scope,
                    before_line=getattr(value, "lineno", before_line),
                    seen=seen,
                )
                for value in expr.values
                if isinstance(value, ast.FormattedValue)
            ]
            return _merge(statuses, default=_SAFE)
        if isinstance(expr, ast.BinOp):
            if isinstance(expr.op, (ast.Add, ast.Mod)):
                left = self._classify_expr(
                    expr.left,
                    scope=scope,
                    before_line=getattr(expr.left, "lineno", before_line),
                    seen=seen,
                )
                right = self._classify_expr(
                    expr.right,
                    scope=scope,
                    before_line=getattr(expr.right, "lineno", before_line),
                    seen=seen,
                )
                return _merge([left, right])
            return _UNKNOWN
        if isinstance(expr, ast.IfExp):
            return _merge(
                [
                    self._classify_expr(expr.body, scope=scope, before_line=before_line, seen=seen),
                    self._classify_expr(expr.orelse, scope=scope, before_line=before_line, seen=seen),
                ]
            )
        if isinstance(expr, ast.Call):
            user_input = self._classify_user_input_call(expr)
            if user_input != _UNKNOWN:
                return user_input
            join_verdict = self._classify_join_call(expr, scope=scope, before_line=before_line, seen=seen)
            if join_verdict != _UNKNOWN:
                return join_verdict
            dict_get_verdict = self._classify_dict_get(expr, scope=scope, before_line=before_line, seen=seen)
            if dict_get_verdict != _UNKNOWN:
                return dict_get_verdict
            format_verdict = self._classify_format_call(expr, scope=scope, before_line=before_line, seen=seen)
            if format_verdict != _UNKNOWN:
                return format_verdict
            return _UNKNOWN
        if isinstance(expr, ast.Name):
            if expr.id in seen:
                return _UNKNOWN
            assignment = self._latest_name_assignment(scope, expr.id, before_line)
            if assignment is not None:
                return self._classify_expr(
                    assignment,
                    scope=scope,
                    before_line=getattr(assignment, "lineno", before_line),
                    seen=seen | {expr.id},
                )
            loop_verdict = self._classify_loop_target(expr.id, scope=scope, before_line=before_line, seen=seen)
            if loop_verdict != _UNKNOWN:
                return loop_verdict
            param_verdict = self._classify_parameter_across_calls(expr.id, scope=scope, seen=seen)
            if param_verdict != _UNKNOWN:
                return param_verdict
            return _UNKNOWN
        if isinstance(expr, ast.List):
            return _merge(
                [
                    self._classify_expr(item, scope=scope, before_line=getattr(item, "lineno", before_line), seen=seen)
                    for item in expr.elts
                ],
                default=_SAFE,
            )
        if isinstance(expr, ast.Tuple):
            return _merge(
                [
                    self._classify_expr(item, scope=scope, before_line=getattr(item, "lineno", before_line), seen=seen)
                    for item in expr.elts
                ],
                default=_SAFE,
            )
        if isinstance(expr, ast.Attribute):
            if self._is_user_input_attr(expr):
                return _UNSAFE
            return _UNKNOWN
        return _UNKNOWN

    def _classify_format_call(
        self,
        expr: ast.Call,
        *,
        scope: ast.AST,
        before_line: int,
        seen: frozenset[str],
    ) -> str:
        func = expr.func
        if not isinstance(func, ast.Attribute) or func.attr != "format":
            return _UNKNOWN
        parts = [
            self._classify_expr(func.value, scope=scope, before_line=before_line, seen=seen),
            *[
                self._classify_expr(arg, scope=scope, before_line=before_line, seen=seen)
                for arg in expr.args
            ],
        ]
        return _merge(parts)

    def _classify_join_call(
        self,
        expr: ast.Call,
        *,
        scope: ast.AST,
        before_line: int,
        seen: frozenset[str],
    ) -> str:
        func = expr.func
        if not isinstance(func, ast.Attribute) or func.attr != "join" or not expr.args:
            return _UNKNOWN
        delimiter = func.value
        if not (isinstance(delimiter, ast.Constant) and isinstance(delimiter.value, str)):
            return _UNKNOWN
        return self._classify_expr(expr.args[0], scope=scope, before_line=before_line, seen=seen)

    def _classify_dict_get(
        self,
        expr: ast.Call,
        *,
        scope: ast.AST,
        before_line: int,
        seen: frozenset[str],
    ) -> str:
        func = expr.func
        if not isinstance(func, ast.Attribute) or func.attr != "get":
            return _UNKNOWN
        base = func.value
        if not isinstance(base, ast.Name):
            return _UNKNOWN
        mapping = self._latest_name_assignment(scope, base.id, before_line)
        if not isinstance(mapping, ast.Dict):
            return _UNKNOWN
        value_statuses = [
            self._classify_expr(value, scope=scope, before_line=getattr(value, "lineno", before_line), seen=seen)
            for value in mapping.values
        ]
        if expr.args[1:]:
            value_statuses.append(
                self._classify_expr(expr.args[1], scope=scope, before_line=before_line, seen=seen)
            )
        elif expr.keywords:
            for keyword in expr.keywords:
                if keyword.arg == "default":
                    value_statuses.append(
                        self._classify_expr(keyword.value, scope=scope, before_line=before_line, seen=seen)
                    )
        return _merge(value_statuses, default=_SAFE)

    def _classify_user_input_call(self, expr: ast.Call) -> str:
        func = expr.func
        if isinstance(func, ast.Name) and func.id in _USER_INPUT_CALLS:
            return _UNSAFE
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "__getitem__"} and self._is_user_input_attr(func.value):
                return _UNSAFE
            if func.attr in _USER_INPUT_CALLS:
                return _UNSAFE
        return _UNKNOWN

    def _classify_parameter_across_calls(
        self,
        name: str,
        *,
        scope: ast.AST,
        seen: frozenset[str],
    ) -> str:
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return _UNKNOWN
        parameter_names = [arg.arg for arg in scope.args.args]
        if name not in parameter_names:
            return _UNKNOWN
        param_index = parameter_names.index(name)
        verdicts: list[str] = []
        for call in self._find_calls(scope.name):
            actual = self._resolve_call_argument(call, parameter_names, param_index)
            if actual is None:
                continue
            caller_scope = self._find_enclosing_node(call)
            verdicts.append(
                self._classify_expr(
                    actual,
                    scope=caller_scope,
                    before_line=getattr(call, "lineno", 0),
                    seen=seen | {name},
                )
            )
        return _merge(verdicts)

    def _classify_loop_target(
        self,
        name: str,
        *,
        scope: ast.AST,
        before_line: int,
        seen: frozenset[str],
    ) -> str:
        for node in ast.walk(scope):
            if not isinstance(node, ast.For):
                continue
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start is None or end is None or not (start <= before_line <= end):
                continue
            if isinstance(node.target, ast.Name) and node.target.id == name:
                return self._classify_expr(
                    node.iter,
                    scope=scope,
                    before_line=start,
                    seen=seen | {name},
                )
        return _UNKNOWN

    def _string_hint(self, expr: ast.AST | None, *, scope: ast.AST, before_line: int) -> str | None:
        if expr is None:
            return None
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        if isinstance(expr, ast.JoinedStr):
            parts: list[str] = []
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    parts.append("{expr}")
            return "".join(parts)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self._string_hint(expr.left, scope=scope, before_line=before_line)
            right = self._string_hint(expr.right, scope=scope, before_line=before_line)
            if left is not None and right is not None:
                return left + right
            return None
        if isinstance(expr, ast.Name):
            assignment = self._latest_name_assignment(scope, expr.id, before_line)
            if assignment is None:
                return None
            return self._string_hint(
                assignment,
                scope=scope,
                before_line=getattr(assignment, "lineno", before_line),
            )
        return None

    def _latest_name_assignment(self, scope: ast.AST, name: str, before_line: int) -> ast.AST | None:
        best_value: ast.AST | None = None
        best_line = -1
        for node in ast.walk(scope):
            if not _node_is_before_line(node, before_line):
                continue
            value = _assignment_value_for_name(node, name)
            if value is None:
                continue
            lineno = getattr(node, "lineno", -1)
            if lineno > best_line:
                best_line = lineno
                best_value = value
        if isinstance(best_value, (ast.List, ast.Tuple)):
            reconstructed = self._reconstruct_list_expression(scope, name, before_line)
            if reconstructed is not None:
                return reconstructed
        if best_value is not None:
            return best_value
        for node in ast.walk(self.tree):
            if not _node_is_before_line(node, before_line):
                continue
            value = _assignment_value_for_name(node, name)
            if value is None:
                continue
            lineno = getattr(node, "lineno", -1)
            if lineno > best_line:
                best_line = lineno
                best_value = value
        if best_value is not None:
            return best_value
        return self._reconstruct_list_expression(scope, name, before_line)

    def _reconstruct_list_expression(self, scope: ast.AST, name: str, before_line: int) -> ast.List | None:
        initial: ast.List | None = None
        elements: list[ast.AST] = []
        init_line = -1
        for node in ast.walk(scope):
            if not _node_is_before_line(node, before_line):
                continue
            if isinstance(node, ast.Assign):
                if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                    if isinstance(node.value, ast.List):
                        initial = node.value
                        elements = list(node.value.elts)
                        init_line = getattr(node, "lineno", -1)
                    elif isinstance(node.value, ast.Tuple):
                        initial = ast.List(elts=list(node.value.elts), ctx=ast.Load())
                        elements = list(node.value.elts)
                        init_line = getattr(node, "lineno", -1)
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "append"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == name
                    and node.args
                ):
                    append_line = getattr(node, "lineno", -1)
                    if append_line > init_line >= 0:
                        elements.append(node.args[0])
        if initial is None:
            return None
        return ast.List(elts=elements, ctx=ast.Load())

    def _find_calls(self, function_name: str) -> list[ast.Call]:
        calls: list[ast.Call] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == function_name:
                calls.append(node)
        return calls

    def _resolve_call_argument(
        self,
        call: ast.Call,
        parameter_names: list[str],
        parameter_index: int,
    ) -> ast.AST | None:
        if parameter_index < len(call.args):
            return call.args[parameter_index]
        parameter_name = parameter_names[parameter_index]
        for keyword in call.keywords:
            if keyword.arg == parameter_name:
                return keyword.value
        return None

    def _find_enclosing_node(self, node: ast.AST) -> ast.AST:
        current = node
        while current in self.parents:
            current = self.parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
        return self.tree

    def _is_user_input_attr(self, expr: ast.AST) -> bool:
        return (
            isinstance(expr, ast.Attribute)
            and isinstance(expr.value, ast.Name)
            and expr.value.id == "request"
            and expr.attr in _USER_INPUT_ATTRS
        )


def _merge(statuses: list[str], default: str = _UNKNOWN) -> str:
    filtered = [status for status in statuses if status != _UNKNOWN]
    if not filtered:
        return default
    if any(status == _UNSAFE for status in filtered):
        return _UNSAFE
    if all(status == _SAFE for status in filtered):
        return _SAFE
    return _UNKNOWN


def _node_is_before_line(node: ast.AST, before_line: int) -> bool:
    lineno = getattr(node, "lineno", None)
    return isinstance(lineno, int) and lineno < before_line


def _assignment_value_for_name(node: ast.AST, name: str) -> ast.AST | None:
    if isinstance(node, ast.Assign):
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return node.value
    if isinstance(node, ast.AnnAssign):
        if isinstance(node.target, ast.Name) and node.target.id == name:
            return node.value
    if isinstance(node, ast.AugAssign):
        if isinstance(node.target, ast.Name) and node.target.id == name:
            return node.value
    return None


__all__ = ["python_graphql_execute_is_relevant", "python_sql_execute_is_dynamic"]
