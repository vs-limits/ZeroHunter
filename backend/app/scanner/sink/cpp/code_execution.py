"""C++ — Code Execution / Dynamic Library load sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-code-dlopen",
        function="dlopen(filename, flags)",
        call_regex=r"\bdlopen\s*\(",
        description="Loading shared library by caller-controlled path.",
        argument_roles=["filename", "flags"],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-code-loadlibrary",
        function="LoadLibrary / LoadLibraryEx (Windows)",
        call_regex=r"\bLoadLibrary(?:Ex)?(?:A|W)?\s*\(",
        description="Win32 LoadLibrary with dynamic path.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-code-qlibrary-load",
        function="QLibrary::load",
        call_regex=r"\bQLibrary\b[\s\S]{0,40}\.\s*(?:load|setFileName)\s*\(",
        description="Qt QLibrary loading attacker-controlled plugin.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-code-qpluginloader",
        function="QPluginLoader / QFactoryLoader",
        call_regex=r"\bQ(?:Plugin|Factory)Loader\b[\s\S]{0,40}\.\s*(?:setFileName|load)\s*\(",
        description="Qt plugin loader path from user input.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-code-v8-runscript",
        function="v8::Script::Compile/Run",
        call_regex=r"\bv8\s*::\s*Script\b[\s\S]{0,40}::\s*(?:Compile|Run)\s*\(",
        description="Embedding V8 to run attacker JS — RCE.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-code-lua-dostring",
        function="luaL_dostring / lua_load",
        call_regex=r"\b(?:luaL_dostring|lua_load|luaL_loadstring|luaL_loadfile)\s*\(",
        description="Lua source loaded from user input — RCE.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-code-pybind-exec",
        function="py::exec / py::eval (pybind11)",
        call_regex=r"\bpy\s*::\s*(?:exec|eval)\s*\(",
        description="pybind11 exec/eval of Python source from C++.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
]
