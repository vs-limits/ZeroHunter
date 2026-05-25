"""TypeScript — XSS sinks specific to Angular/NestJS/Deno.

Most JavaScript rules already cover .ts/.tsx files via shared regex+extensions.
This module holds rules that are *only* meaningful in TS frameworks.
"""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_TS = [".ts", ".tsx"]
_ANGULAR = [".ts", ".html"]

RULES = [
    SinkRule(
        id="ts-xss-angular-bypass-html",
        function="DomSanitizer.bypassSecurityTrustHtml",
        call_regex=r"\bbypassSecurityTrustHtml\s*\(",
        description="Angular bypassSecurityTrustHtml disables HTML escaping.",
        argument_roles=["value"],
        extensions=_TS,
        severity="critical",
    ),
    SinkRule(
        id="ts-xss-angular-bypass-resource-url",
        function="DomSanitizer.bypassSecurityTrustResourceUrl",
        call_regex=r"\bbypassSecurityTrust(?:Url|ResourceUrl|Style|Script)\s*\(",
        description="Other Angular bypassSecurityTrust* variants.",
        argument_roles=["value"],
        extensions=_TS,
        severity="critical",
    ),
    SinkRule(
        id="ts-xss-angular-inner-html",
        function="[innerHTML]=\"userValue\" binding",
        call_regex=r"\[\s*innerHTML\s*\]\s*=",
        description="Angular template binds [innerHTML] — bypass sanitizer when SafeHtml is used.",
        argument_roles=[],
        extensions=_ANGULAR,
        severity="high",
    ),
    SinkRule(
        id="ts-xss-nestjs-render-template",
        function="@Render() with dynamic template name",
        call_regex=r"@Render\s*\(",
        description="NestJS @Render with non-literal template name.",
        argument_roles=["template"],
        extensions=_TS,
        severity="medium",
    ),
    SinkRule(
        id="ts-xss-deno-html-response",
        function="new Response(html, {headers: {'content-type':'text/html'}})",
        call_regex=r"\bnew\s+Response\s*\(",
        description="Deno/Bun raw HTML response from concatenated string.",
        argument_roles=["body"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
]
