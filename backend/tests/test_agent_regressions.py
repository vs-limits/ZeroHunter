from __future__ import annotations

import sys
import unittest
import json
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.scanner.sink.python.sql_semantics import (
    python_graphql_execute_is_relevant,
    python_sql_execute_is_dynamic,
)
from app.scanner.sink.profiles import enrich_sink_profile
from app.scanner.sink.types import SinkRule
from app.agent.sub_agent.auditor import (
    _build_repair_tasks,
    _javascript_helper_xss_refuted,
    _javascript_template_xss_refuted,
    _load_auditor_chains,
    _merge_repair_evidence,
    _normalize_repair_breakpoint,
    _parse_finding,
    _prechecked_dataflow_finding,
)
from app.agent.sub_agent import callscan, dataflowscan
from app.agent.run_scope import RunScope
from app.scanner.slicer import FunctionPool, collect_local_helper_refs


TESTSQL_APP = (
    REPO_ROOT
    / "repo"
    / "test"
    / "testsql"
    / "testsql"
    / "default__manual"
    / "backend"
    / "app.py"
)


@unittest.skipUnless(TESTSQL_APP.is_file(), "repo/test/testsql fixture is not present")
class PythonSqlSemanticsTests(unittest.TestCase):
    def test_detects_variable_backed_fstring_execute(self) -> None:
        self.assertTrue(python_sql_execute_is_dynamic(TESTSQL_APP, 728))

    def test_drops_parameterized_sql_even_with_arithmetic(self) -> None:
        self.assertFalse(python_sql_execute_is_dynamic(TESTSQL_APP, 88))
        self.assertFalse(python_sql_execute_is_dynamic(TESTSQL_APP, 140))
        self.assertFalse(python_sql_execute_is_dynamic(TESTSQL_APP, 156))
        self.assertFalse(python_sql_execute_is_dynamic(TESTSQL_APP, 355))

    def test_drops_whitelisted_update_field_join(self) -> None:
        self.assertFalse(python_sql_execute_is_dynamic(TESTSQL_APP, 595))

    def test_rejects_sql_execute_as_graphql_false_positive(self) -> None:
        self.assertFalse(python_graphql_execute_is_relevant(TESTSQL_APP, 595))


class LocalHelperDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_recursively_discovers_escape_helpers(self) -> None:
        rel_file = "backend/static/js/app.js"
        extracts = {
            rel_file: {
                "functions": [
                    {"name": "loadHome"},
                    {"name": "articleCard"},
                    {"name": "escapeHtml"},
                    {"name": "openArticle"},
                    {"name": "renderMarkdown"},
                    {"name": "inlineMarkdown"},
                ]
            }
        }
        code_by_name = {
            (rel_file, "loadHome"): 'function loadHome() { $("#articleGrid").innerHTML = latest.items.map(articleCard).join(""); }',
            (rel_file, "articleCard"): "function articleCard(article) { return `<h2>${escapeHtml(article.title)}</h2>`; }",
            (rel_file, "escapeHtml"): "function escapeHtml(value) { return String(value).replaceAll('<', '&lt;'); }",
            (rel_file, "openArticle"): 'function openArticle(article) { return renderMarkdown(article.content); }',
            (rel_file, "renderMarkdown"): "function renderMarkdown(markdown) { return inlineMarkdown(markdown); }",
            (rel_file, "inlineMarkdown"): "function inlineMarkdown(text) { return escapeHtml(text); }",
        }
        slicer = _HelperDiscoverySlicer(extracts, code_by_name)
        pool = FunctionPool(slicer)
        load_home_ref = await pool.register_function(rel_file, "loadHome")
        open_article_ref = await pool.register_function(rel_file, "openArticle")
        chains = [
            [{"role": "sink", "function_ref": load_home_ref, "function": "loadHome", "file": rel_file}],
            [{"role": "sink", "function_ref": open_article_ref, "function": "openArticle", "file": rel_file}],
        ]

        helper_refs = await collect_local_helper_refs(chains, slicer, pool, max_depth=3, max_helpers=8)

        helper_entries = {pool.get(ref)["function"] for ref in helper_refs if pool.get(ref)}
        self.assertIn("articleCard", helper_entries)
        self.assertIn("escapeHtml", helper_entries)
        self.assertIn("renderMarkdown", helper_entries)
        self.assertIn("inlineMarkdown", helper_entries)


class DataFlowScanRecoveryTests(unittest.TestCase):
    def test_recovers_python_local_taint_between_request_and_template_sink(self) -> None:
        py_lines = [
            "def create_post():",
            "    title = request.form['title']",
            "    post.title = title",
            "    return render_template('post.html', title=post.title)",
        ]
        py_items = dataflowscan._extract_python_file(
            "app/views.py",
            "\n".join(py_lines),
            py_lines,
        )
        tpl_items = dataflowscan._extract_template_file(
            "templates/post.html",
            ["<h1>{{ title|safe }}</h1>"],
        )
        graph = {
            "nodes": py_items["nodes"] + tpl_items["nodes"],
            "edges": py_items["edges"] + tpl_items["edges"],
            "writes": py_items["writes"] + tpl_items["writes"],
            "reads": py_items["reads"] + tpl_items["reads"],
            "sinks": py_items["sinks"] + tpl_items["sinks"],
            "breakpoints": [],
        }

        self.assertTrue(
            any((w.get("storage") or {}).get("field") == "title" for w in graph["writes"])
        )
        chains = dataflowscan._build_cross_request_chains(graph, [])
        cross_request = [c for c in chains if c.get("chain_kind") == "cross_request"]

        self.assertEqual(len(cross_request), 1)
        self.assertEqual(cross_request[0]["storage"]["field"], "title")
        self.assertEqual(cross_request[0]["breakpoints"], [])
        self.assertIn(cross_request[0]["evidence_quality"], {"confirmed", "probable"})
        self.assertGreaterEqual(cross_request[0]["evidence_score"], 50)
        self.assertFalse(cross_request[0]["suppressed"])
        self.assertIsInstance(cross_request[0]["storage_identity"], dict)
        self.assertTrue(cross_request[0]["binding_edges"])
        self.assertIn("local_taint", cross_request[0]["audit_pack"])

        summary = dataflowscan._build_summary(graph, chains, started_at=0.0)
        self.assertEqual(summary["total_chains"], 1)
        self.assertEqual(summary["cross_request_chains"], 1)
        self.assertEqual(summary["recovered_partial"], 0)
        self.assertGreaterEqual(summary["confirmed_chains"] + summary["probable_chains"], 1)

    def test_recovered_partial_is_weak_and_suppressed(self) -> None:
        chain = dataflowscan._recovered_partial_chain(
            {
                "chain_id": "C-x",
                "severity": "high",
                "vulnerability_type": "xss",
                "language": "python",
                "sink_function": "raw output",
                "audit_pack": "raw output",
            },
            chain_id="DF-R-x",
            sink_file="app.py",
            sink_line=42,
        )

        self.assertEqual(chain["evidence_quality"], "weak")
        self.assertTrue(chain["suppressed"])
        self.assertIn("missing_storage_bridge", chain["breakpoints"])

    def test_recovers_javascript_storage_to_innerhtml_chain(self) -> None:
        js_lines = [
            "const title = new URLSearchParams(location.search).get('title');",
            "localStorage.setItem('title', title);",
            "const cachedTitle = localStorage.getItem('title');",
            "document.querySelector('#post').innerHTML = cachedTitle;",
        ]
        graph = dataflowscan._extract_javascript_file(
            "static/app.js",
            "\n".join(js_lines),
            js_lines,
        )

        chains = dataflowscan._build_cross_request_chains(graph, [])
        cross_request = [c for c in chains if c.get("chain_kind") == "cross_request"]
        auditable = [c for c in cross_request if not c.get("suppressed")]

        self.assertGreaterEqual(len(cross_request), 1)
        self.assertEqual(len(auditable), 1)
        self.assertEqual(auditable[0]["storage_identity"]["kind"], "cache_key")
        self.assertIn(auditable[0]["evidence_quality"], {"confirmed", "probable"})


class SinkProfileTests(unittest.TestCase):
    def test_sink_rule_defaults_old_rules_to_l0_metadata(self) -> None:
        rule = SinkRule(
            id="unit-echo",
            function="echo",
            call_regex=r"\becho\b",
            description="unit sink",
            argument_roles=["value"],
            extensions=[".php"],
        )

        data = rule.to_dict()

        self.assertEqual(data["level"], "L0")
        self.assertEqual(data["semantic_tags"], [])
        self.assertEqual(data["required_evidence"], [])
        self.assertEqual(data["repair_hints"], [])
        self.assertNotIn("extra_match_regex", data)

    def test_yeswiki_context_upgrades_generic_sink_to_l1(self) -> None:
        enriched = enrich_sink_profile(
            {
                "id": "php-echo",
                "function": "echo",
                "severity": "high",
                "semantic_tags": [],
                "required_evidence": [],
                "repair_hints": [],
            },
            language="php",
            vulnerability_type="xss",
            file="tools/actions/ConfigAction.php",
            code="$this->wiki->render('@template.html.twig', ['config' => $config]);",
            function="TemplateEngine::render",
        )

        self.assertEqual(enriched["level"], "L1")
        self.assertIn("framework_yeswiki", enriched["semantic_tags"])
        self.assertIn("permission_check", enriched["required_evidence"])
        self.assertIn("find_yeswiki_permission", enriched["repair_hints"])

    def test_l2_shape_profile_keeps_issue_family_without_issue_id(self) -> None:
        enriched = enrich_sink_profile(
            {"id": "template-raw", "function": "|raw", "severity": "high"},
            language="php",
            vulnerability_type="xss",
            file="templates/settings.html.twig",
            code='<input value="{{ config.site_name|raw }}" onmouseover="x">',
            function="render",
        )

        self.assertEqual(enriched["level"], "L2")
        self.assertIn("shape_config_to_raw_html_attr", enriched["semantic_tags"])
        self.assertIn("sanitizer_state", enriched["required_evidence"])

    def test_callscan_candidate_propagates_sink_profile_metadata(self) -> None:
        hit = callscan.SinkHit(
            language="php",
            vulnerability_type="xss",
            rule=SinkRule(
                id="php-echo",
                function="echo",
                call_regex=r"\becho\b",
                description="unit sink",
                argument_roles=["value"],
                extensions=[".php"],
                severity="high",
            ),
            file="tools/actions/ConfigAction.php",
            absolute_file="C:/repo/tools/actions/ConfigAction.php",
            line=12,
            column=1,
            code='<a href="{{ config.url|raw }}">',
            matched_text="echo",
        )
        candidate = callscan._merge_candidate(
            "C-unit",
            hit,
            {"function": "render", "line": 10, "line_end": 20, "file": hit.file},
            {
                "sink": {"file": hit.file, "line": hit.line, "code": hit.code},
                "enclosing_symbol": {"function": "render", "line": 10},
            },
            None,
        )

        sink_rule = candidate["sink_rule"]
        self.assertIn(sink_rule["level"], {"L1", "L2"})
        self.assertIn("template_binding", sink_rule["required_evidence"])
        self.assertTrue(sink_rule["repair_hints"])

    def test_callscan_priority_file_is_full_compat_alias(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = RunScope(
                project_path="unit",
                project_root=root,
                artifacts_dir=root,
            )
            candidates = [
                {
                    "id": "C-low",
                    "language": "python",
                    "vulnerability_type": "xss",
                    "sink_rule": {"severity": "low", "function": "render", "level": "L0"},
                    "sink": {"file": "a.py", "line": 1},
                    "call_chains": [],
                    "audit_pack": "low",
                },
                {
                    "id": "C-medium",
                    "language": "python",
                    "vulnerability_type": "xss",
                    "sink_rule": {"severity": "medium", "function": "render", "level": "L0"},
                    "sink": {"file": "b.py", "line": 2},
                    "call_chains": [],
                    "audit_pack": "medium",
                },
                {
                    "id": "C-high",
                    "language": "python",
                    "vulnerability_type": "xss",
                    "sink_rule": {"severity": "high", "function": "render", "level": "L0"},
                    "sink": {"file": "c.py", "line": 3},
                    "call_chains": [[{"role": "sink", "function": "render"}]],
                    "audit_pack": "high",
                },
            ]

            written, compat_written = callscan._write_chain_streams(
                candidates,
                root / "callscan_chains.jsonl",
                root / "callscan_chains.md",
                root / "callscan_chains.priority.jsonl",
                "unit",
                scope,
            )

            full = _jsonl_chain_ids(root / "callscan_chains.jsonl")
            compat = _jsonl_chain_ids(root / "callscan_chains.priority.jsonl")
            priority_meta = _first_jsonl_object(root / "callscan_chains.priority.jsonl")

        self.assertEqual(written, 3)
        self.assertEqual(compat_written, 3)
        self.assertEqual(full, compat)
        self.assertEqual(set(full), {"C-low", "C-medium", "C-high"})
        self.assertEqual(priority_meta.get("filter"), "none")
        self.assertEqual(priority_meta.get("deprecated_alias_of"), "callscan_chains.jsonl")


class AuditorGuardrailTests(unittest.TestCase):
    def test_parse_finding_adds_review_channels(self) -> None:
        finding = _parse_finding(
            {"verdict": "safe", "confidence": 0.9, "title": "unit-test"},
            {
                "chain_id": "C-test",
                "index": 1,
                "sink_file": "app.py",
                "sink_line": 10,
                "sink_function": "eval",
            },
            "python",
            "code_execution",
        )

        self.assertEqual(finding["Codex核验"], "")
        self.assertEqual(finding["Codex-Review"], "")
        self.assertEqual(finding["人工核验"], "")
        self.assertEqual(finding["人工-Review"], "")
        self.assertEqual(finding["CC核验"], "")
        self.assertEqual(finding["CC-Review"], "")

        self.assertEqual(finding["sink_level"], "L0")
        self.assertEqual(finding["repair_rounds"], 0)

    def test_auditor_loader_uses_full_callscan_candidates_and_skips_weak_dataflow(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            full = root / "callscan_chains.jsonl"
            dataflow = root / "cross_request_chains.jsonl"
            full.write_text(
                "\n".join(
                    [
                        '{"type":"chain","chain_id":"C-low","severity":"low","has_call_chain":false}',
                        '{"type":"chain","chain_id":"C-medium","severity":"medium","has_call_chain":false}',
                        '{"type":"chain","chain_id":"C-high","severity":"high","has_call_chain":true}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            dataflow.write_text(
                "\n".join(
                    [
                        '{"type":"chain","chain_id":"DF-weak","chain_kind":"cross_request","evidence_quality":"weak"}',
                        '{"type":"chain","chain_id":"DF-suppressed","chain_kind":"cross_request","evidence_quality":"probable","suppressed":true}',
                        '{"type":"chain","chain_id":"DF-probable","chain_kind":"cross_request","evidence_quality":"probable"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            chains = _load_auditor_chains(full, dataflow)

        self.assertEqual(
            [chain["chain_id"] for chain in chains],
            ["C-low", "C-medium", "C-high", "DF-probable"],
        )

    def test_dataflowscan_loads_full_callscan_records_before_legacy_priority(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "callscan_chains.jsonl").write_text(
                '{"type":"chain","chain_id":"C-full","severity":"low"}\n',
                encoding="utf-8",
            )
            (root / "callscan_chains.priority.jsonl").write_text(
                '{"type":"chain","chain_id":"C-priority","severity":"high"}\n',
                encoding="utf-8",
            )

            records = dataflowscan._load_callscan_records(root)

        self.assertEqual([item["chain_id"] for item in records], ["C-full"])

    def test_dataflowscan_falls_back_to_legacy_priority_records(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "callscan_chains.priority.jsonl").write_text(
                '{"type":"chain","chain_id":"C-priority","severity":"high"}\n',
                encoding="utf-8",
            )

            records = dataflowscan._load_callscan_records(root)

        self.assertEqual([item["chain_id"] for item in records], ["C-priority"])

    def test_dataflow_refuting_evidence_precheck_returns_safe(self) -> None:
        finding = _prechecked_dataflow_finding(
            {
                "chain_id": "DF-safe",
                "chain_kind": "cross_request",
                "sink_file": "templates/post.html",
                "sink_line": 7,
                "sink_function": "template output",
                "severity": "high",
                "refuting_evidence": [
                    {"kind": "html_escape", "evidence": "htmlspecialchars($title)"}
                ],
                "positive_evidence": [],
            },
            "php",
            "xss",
        )

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding["verdict"], "safe")
        self.assertEqual(finding["confidence"], 0.95)

    def test_parse_finding_accepts_json_string_result(self) -> None:
        finding = _parse_finding(
            '{"verdict": "safe", "confidence": "90%", "title": "json-string"}',
            {
                "chain_id": "C-json",
                "index": 1,
                "sink_file": "app.py",
                "sink_line": 11,
                "sink_function": "eval",
            },
            "python",
            "code_execution",
        )

        self.assertEqual(finding["verdict"], "safe")
        self.assertAlmostEqual(finding["confidence"], 0.9)

    def test_parse_finding_normalizes_loose_llm_fields(self) -> None:
        finding = _parse_finding(
            {
                "verdict": "vulnerable",
                "confidence": "high",
                "title": "loose-fields",
                "sink": "app.py:12",
                "source": "request",
                "data_flow": {"step": "request to sink"},
                "missing_info": "runtime config",
                "evidence": ["matched sink", {"source": "rg", "detail": "found"}],
                "repair_rounds": "not-a-number",
            },
            {
                "chain_id": "C-loose",
                "index": 1,
                "sink_file": "app.py",
                "sink_line": 12,
                "sink_function": "eval",
            },
            "python",
            "code_execution",
        )

        self.assertEqual(finding["verdict"], "uncertain")
        self.assertAlmostEqual(finding["confidence"], 0.6)
        self.assertEqual(finding["missing_info"], ["runtime config"])
        self.assertEqual(finding["sink"]["file"], "app.py")
        self.assertEqual(finding["evidence"][0]["detail"], "matched sink")
        self.assertEqual(finding["repair_rounds"], 0)

    def test_repair_breakpoint_normalization_and_tasks(self) -> None:
        self.assertEqual(
            _normalize_repair_breakpoint("template variable binding is missing"),
            "missing_template_binding",
        )
        self.assertEqual(
            _normalize_repair_breakpoint("permission guard is unclear"),
            "missing_permission_check",
        )

        tasks = _build_repair_tasks(
            {"sink_file": "app/templates/post.html", "required_evidence": ["template_binding"]},
            ["missing_template_binding", "missing_sanitizer_state"],
        )

        kinds = {task["kind"] for task in tasks}
        self.assertIn("missing_template_binding", kinds)
        self.assertIn("missing_sanitizer_state", kinds)
        self.assertTrue(all(task["tool"] == "ripgrep" for task in tasks))
        self.assertTrue(all(task["path"] == "app/templates" for task in tasks))

    def test_merge_repair_evidence_records_resolved_and_unresolved_breakpoints(self) -> None:
        repaired = _merge_repair_evidence(
            {
                "chain_id": "C-repair",
                "audit_pack": "# Sink\n",
                "resolved_evidence": ["missing_source_entry"],
            },
            ["missing_source_entry", "missing_sanitizer_state"],
            [{"kind": "missing_sanitizer_state", "pattern": "escape", "path": "."}],
            {
                "resolved_evidence": ["missing_sanitizer_state"],
                "evidence": [
                    {
                        "source": "evidence_repair_rg",
                        "missing_kind": "missing_sanitizer_state",
                        "pattern": "escape",
                        "path": ".",
                        "detail": "escape(value)",
                    }
                ],
            },
        )

        self.assertEqual(
            repaired["resolved_evidence"],
            ["missing_source_entry", "missing_sanitizer_state"],
        )
        self.assertEqual(repaired["unresolved_evidence"], [])
        self.assertEqual(repaired["repair_rounds"], 1)
        self.assertIn("Evidence Repair Patch", repaired["audit_pack"])
        self.assertEqual(repaired["repair_trace"][0]["evidence_count"], 1)

    def test_javascript_template_escape_guard_refutes_false_positive(self) -> None:
        chain = {
            "call_chains": [[{"function": "loadComments"}]],
            "audit_pack": """# Sink: element.innerHTML = value @ backend/static/js/app.js:187

## Function bodies (deduped within candidate)
### loadComments  (backend/static/js/app.js:184-194)
```javascript
async function loadComments(articleId) {
  const data = await api(`/api/articles/${articleId}/comments`);
  $("#commentList").innerHTML = data.items.map((comment) => `
    <article class="comment ${comment.parent_id ? "reply" : ""}">
      <header><strong>${escapeHtml(comment.user_name)}</strong><span>${formatDate(comment.created_at)} · ${comment.likes} 赞</span></header>
      <p>${escapeHtml(comment.content)}</p>
      <button type="button" data-like-comment="${comment.id}">点赞评论</button>
    </article>
  `).join("");
}
```
""",
        }

        reason = _javascript_template_xss_refuted(chain, "javascript", "xss", "vulnerable")

        self.assertIsNotNone(reason)

    def test_helper_render_guard_refutes_uncertain_article_card_path(self) -> None:
        chain = {
            "call_chains": [[{"function": "runSearch"}]],
            "audit_pack": """# Sink: element.innerHTML = value @ backend/static/js/app.js:216

## Function bodies (deduped within candidate)
### runSearch  (backend/static/js/app.js:210-221)
```javascript
async function runSearch(event) {
  event?.preventDefault();
  const data = await api(`/api/search?q=${encodeURIComponent(q)}&scope=${encodeURIComponent(scope)}`);
  $("#searchResults").innerHTML = data.items.length ? data.items.map(articleCard).join("") : '<p class="notice">没有匹配结果。</p>';
}
```

## Local helper bodies
### articleCard  (backend/static/js/app.js:107-121)
```javascript
function articleCard(article) {
  const tagHtml = (article.tags || []).slice(0, 3).map((tag) => `<span class="pill">${escapeHtml(tag)}</span>`).join("");
  return `
    <article class="article-card">
      <div class="cover-strip" style="background:${escapeHtml(article.cover_gradient)}"></div>
      <div class="meta"><span class="pill">${escapeHtml(article.category)}</span>${tagHtml}</div>
      <h2>${escapeHtml(article.title)}</h2>
      <p>${escapeHtml(article.excerpt)}</p>
      <footer>
        <span>${escapeHtml(article.author)} · ${formatDate(article.published_at)}</span>
        <button type="button" data-open-article="${escapeHtml(article.slug)}">阅读</button>
      </footer>
    </article>
  `;
}
```
""",
        }

        reason = _javascript_helper_xss_refuted(chain, "javascript", "xss", "uncertain")

        self.assertIsNotNone(reason)


class _HelperDiscoverySlicer:
    def __init__(self, extracts: dict[str, dict], code_by_name: dict[tuple[str, str], str]) -> None:
        self._extracts = extracts
        self._code_by_name = code_by_name
        self._line_map: dict[tuple[str, str], tuple[int, int]] = {}
        current_line = 1
        for key, code in self._code_by_name.items():
            line_count = max(1, len(code.splitlines()))
            self._line_map[key] = (current_line, current_line + line_count - 1)
            current_line += line_count + 1

    async def get_extract(self, rel_file: str) -> dict | None:
        return self._extracts.get(rel_file)

    async def get_function_info(self, rel_file: str, qualified_name: str) -> dict | None:
        code = self._code_by_name.get((rel_file, qualified_name))
        if code is None:
            return None
        line, line_end = self._line_map[(rel_file, qualified_name)]
        return {
            "file": rel_file,
            "function": qualified_name,
            "line": line,
            "line_end": line_end,
            "class": None,
        }

    def slice_lines(
        self,
        rel_file: str,
        start: int | None,
        end: int | None,
        max_lines: int = 120,
    ) -> str | None:
        for (candidate_file, function_name), code in self._code_by_name.items():
            line, _line_end = self._line_map[(candidate_file, function_name)]
            if candidate_file == rel_file and start == line:
                return code
        return None


def _first_jsonl_object(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            if line.strip():
                return json.loads(line)
    return {}


def _jsonl_chain_ids(path: Path) -> list[str]:
    ids: list[str] = []
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("type") == "chain":
                ids.append(str(item.get("chain_id")))
    return ids


if __name__ == "__main__":
    unittest.main()
