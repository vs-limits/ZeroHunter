"""C++ — Insecure Deserialization sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-deser-boost-archive",
        function="boost::archive::*_iarchive >> obj",
        call_regex=r"\bboost\s*::\s*archive\s*::\s*\w+_iarchive\b",
        description="Boost.Serialization input archive on untrusted bytes — can pivot to RCE.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-deser-cereal-load",
        function="cereal::*Archive(stream); ar(obj)",
        call_regex=r"\bcereal\s*::\s*\w+InputArchive\b",
        description="cereal binary/JSON input archive on untrusted data.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
    SinkRule(
        id="cpp-deser-qdata-stream",
        function="QDataStream >> obj",
        call_regex=r"\bQDataStream\b[\s\S]{0,40}>>",
        description="QDataStream deserialise on caller-supplied buffer.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-deser-protobuf-parsefromstring",
        function="proto::ParseFromString / ParseFromArray",
        call_regex=r"\.\s*ParseFrom(?:String|Array|IstreamInputStream|ZeroCopyStream|FileDescriptor|CodedStream)\s*\(",
        description="protobuf parse without size limits / strict typing.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-deser-msgpack-cpp",
        function="msgpack::unpack",
        call_regex=r"\bmsgpack\s*::\s*(?:unpack|unpacker)\s*\(",
        description="msgpack-c++ unpack of untrusted bytes.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
]
