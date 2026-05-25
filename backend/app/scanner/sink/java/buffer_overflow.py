"""Java — Memory/Buffer mishandling sinks (JNI / NIO ByteBuffer)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "buffer_overflow"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-buf-bytebuffer-allocatedirect",
        function="ByteBuffer.allocateDirect(size)",
        call_regex=r"\bByteBuffer\s*\.\s*allocateDirect\s*\(",
        description="Direct buffer allocation with dynamic size — DoS/memory exhaustion if uncapped.",
        argument_roles=["capacity"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-buf-unsafe-allocate",
        function="sun.misc.Unsafe / jdk.internal.misc.Unsafe",
        call_regex=r"\bUnsafe\b[\s\S]{0,40}\.\s*(?:allocateMemory|copyMemory|setMemory|putByte|putInt|putLong)\s*\(",
        description="Unsafe direct memory manipulation can corrupt JVM state.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-buf-arraycopy-dynamic",
        function="System.arraycopy(src,...,len)",
        call_regex=r"\bSystem\s*\.\s*arraycopy\s*\(",
        description="arraycopy with attacker-controlled length/offset — OOB write.",
        argument_roles=["src", "srcPos", "dst", "dstPos", "length"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-buf-jni-call",
        function="native method declared",
        call_regex=r"\bnative\s+\w+\s+\w+\s*\(",
        description="JNI native method — verify input bounds on the C side.",
        argument_roles=[],
        extensions=_JAVA,
        severity="low",
    ),
]
