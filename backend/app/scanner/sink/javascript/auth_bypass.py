"""JavaScript / Node.js — Authentication Bypass sinks (CWE-287, CWE-305)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-auth-jwt-verify-noalg",
        function="jwt.verify(... algorithms not pinned)",
        call_regex=r"\bjwt\s*\.\s*verify\s*\(",
        description="jwt.verify without algorithms option lets attacker pick `none`.",
        argument_roles=["token", "secret", "options"],
        extensions=_JS,
        severity="critical",
        extra_match_regex=[r"algorithms?\s*:\s*\[?\s*['\"]none['\"]", r"verify\s*\([^)]*\)\s*"],
    ),
    SinkRule(
        id="js-auth-jwt-decode",
        function="jwt.decode (no verify)",
        call_regex=r"\bjwt\s*\.\s*decode\s*\(",
        description="jwt.decode does not verify signature — trusting its claims is auth bypass.",
        argument_roles=["token"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-auth-bcrypt-compare-naive",
        function="user-password compared with == / ===",
        call_regex=r"\b(?:password|pwd|passwd)\s*={2,3}",
        description="Plain == comparison of password instead of bcrypt.compare.",
        argument_roles=[],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-auth-session-secret-hardcoded",
        function="session secret literal",
        call_regex=r"\bsession\s*\(\s*\{[^}]*secret\s*:\s*['\"][^'\"]+['\"]",
        description="express-session secret hard-coded in source.",
        argument_roles=[],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-auth-passport-strategy-bypass",
        function="passport authenticate session:false on critical route",
        call_regex=r"\bpassport\s*\.\s*authenticate\s*\(",
        description="passport.authenticate — verify failureRedirect/session settings.",
        argument_roles=["strategy", "options"],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-auth-electron-nodeintegration",
        function="webPreferences nodeIntegration:true",
        call_regex=r"nodeIntegration\s*:\s*true",
        description="Electron renderer with full Node API — auth/UI bypass risk.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-auth-jsonwebtoken-sign-noalg",
        function="jwt.sign with weak algorithm",
        call_regex=r"\bjwt\s*\.\s*sign\s*\([^)]*algorithm\s*:\s*['\"](?:none|HS256)['\"]",
        description="Signing JWT with `none` or HS256 + low-entropy key.",
        argument_roles=["payload", "secret", "options"],
        extensions=_JS,
        severity="high",
    ),
]
