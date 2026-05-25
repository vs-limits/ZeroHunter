"""Python — Deserialization sinks (CWE-502)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-deser-pickle-loads",
        function="pickle.loads / load / Unpickler.load",
        call_regex=r"\b(?:pickle|cPickle|_pickle)\.(?:loads?|load_with|Unpickler\s*\([^)]*\)\.load)\s*\(",
        description="pickle.loads decodes arbitrary objects; trivial RCE on untrusted input.",
        argument_roles=["data"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-deser-shelve-open",
        function="shelve.open",
        call_regex=r"\bshelve\.open\s*\(",
        description="shelve uses pickle internally for keys/values.",
        argument_roles=["filename"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-deser-yaml-load-unsafe",
        function="yaml.load (without SafeLoader)",
        call_regex=r"\byaml\.(?:load|full_load|unsafe_load)\s*\(",
        description="yaml.load without SafeLoader instantiates arbitrary Python objects.",
        argument_roles=["stream", "Loader"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-deser-jsonpickle-decode",
        function="jsonpickle.decode",
        call_regex=r"\bjsonpickle\.decode\s*\(",
        description="jsonpickle.decode reconstructs Python objects from JSON.",
        argument_roles=["data"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-deser-marshal-loads",
        function="marshal.loads (deserialization)",
        call_regex=r"\bmarshal\.loads?\s*\(",
        description="marshal can be used as serializer too; arbitrary bytecode is RCE.",
        argument_roles=["data"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-deser-django-signing-loads",
        function="django.core.signing.loads (without signing key rotation)",
        call_regex=r"\bsigning\.loads\s*\(",
        description="Signing.loads on attacker-controlled input with weak key may be forged.",
        argument_roles=["s"],
        extensions=_PY,
        severity="medium",
    ),
]
