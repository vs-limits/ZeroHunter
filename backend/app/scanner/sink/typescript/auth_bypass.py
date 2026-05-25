"""TypeScript — Auth bypass sinks unique to NestJS/Angular."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_TS = [".ts", ".tsx"]

RULES = [
    SinkRule(
        id="ts-auth-nestjs-public-decorator",
        function="@Public() route decorator",
        call_regex=r"@Public\s*\(\s*\)",
        description="Skips the global AuthGuard / JwtGuard.",
        argument_roles=[],
        extensions=_TS,
        severity="medium",
    ),
    SinkRule(
        id="ts-auth-nestjs-skipauth",
        function="@SkipAuth() / @AllowAnonymous()",
        call_regex=r"@(?:SkipAuth|AllowAnonymous|NoAuth)\s*\(\s*\)",
        description="Custom auth-skip decorators bypass guards.",
        argument_roles=[],
        extensions=_TS,
        severity="medium",
    ),
    SinkRule(
        id="ts-auth-angular-canactivate-true",
        function="canActivate returns true always",
        call_regex=r"canActivate\s*\([^)]*\)\s*\{\s*return\s+true",
        description="Angular guard always returning true — effectively disabled.",
        argument_roles=[],
        extensions=_TS,
        severity="high",
    ),
    SinkRule(
        id="ts-auth-roles-guard-disabled",
        function="@Roles() empty",
        call_regex=r"@Roles\s*\(\s*\)",
        description="Empty @Roles() decorator — no role gating.",
        argument_roles=[],
        extensions=_TS,
        severity="medium",
    ),
]
