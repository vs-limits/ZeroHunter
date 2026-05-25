"""C — Insecure Deserialization sinks (protobuf, msgpack, cbor)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-deser-protobuf-c-unpack",
        function="protobuf_c_message_unpack",
        call_regex=r"\bprotobuf_c_message_unpack\s*\(|\b\w+__unpack\s*\(",
        description="protobuf-c unpack on untrusted bytes — verify max-size.",
        argument_roles=["allocator", "len", "data"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-deser-msgpack-unpack",
        function="msgpack_unpack / msgpack_unpacker",
        call_regex=r"\bmsgpack_(?:unpack(?:_next)?|unpacker_next)\s*\(",
        description="msgpack unpack of untrusted bytes.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-deser-cbor-load",
        function="cbor_load",
        call_regex=r"\bcbor_load\s*\(",
        description="libcbor cbor_load — verify size limits.",
        argument_roles=["source", "source_size", "result"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-deser-asn1-decode",
        function="d2i_X509 / d2i_ASN1_* family",
        call_regex=r"\bd2i_(?:X509|ASN1_[A-Z_]+|RSAPrivateKey|EC_KEY|PKCS7|PKCS12|SSL_SESSION)\s*\(",
        description="OpenSSL d2i_* decoders historically have parser bugs.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
]
