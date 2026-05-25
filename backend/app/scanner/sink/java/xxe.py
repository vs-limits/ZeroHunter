"""Java — XXE sinks (CWE-611)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-xxe-documentbuilder-parse",
        function="DocumentBuilder.parse",
        call_regex=r"\.\s*parse\s*\(",
        description="javax.xml DocumentBuilder.parse — verify FEATURE_SECURE_PROCESSING.",
        argument_roles=["src"],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-xxe-saxparser-parse",
        function="SAXParser.parse / XMLReader.parse",
        call_regex=r"\bSAXParser\b[\s\S]{0,40}\.\s*parse\s*\(|\bXMLReader\b[\s\S]{0,40}\.\s*parse\s*\(",
        description="SAX parser without disallow-doctype-decl.",
        argument_roles=["src"],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-xxe-xmlinputfactory-no-secure",
        function="XMLInputFactory without IS_SUPPORTING_EXTERNAL_ENTITIES off",
        call_regex=r"\bXMLInputFactory\b[\s\S]{0,40}\.\s*newInstance\s*\(",
        description="XMLInputFactory created without explicit secure settings.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-xxe-transformerfactory",
        function="TransformerFactory.newTransformer",
        call_regex=r"\bTransformerFactory\b[\s\S]{0,40}\.\s*newTransformer\s*\(",
        description="TransformerFactory without ACCESS_EXTERNAL_DTD set to empty.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-xxe-schemafactory",
        function="SchemaFactory.newSchema",
        call_regex=r"\bSchemaFactory\b[\s\S]{0,40}\.\s*newSchema\s*\(",
        description="SchemaFactory may fetch external schemas (XXE / SSRF).",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-xxe-validator-validate",
        function="Validator.validate",
        call_regex=r"\bValidator\b[\s\S]{0,40}\.\s*validate\s*\(",
        description="Validator may pull DTD/Schema from XML source.",
        argument_roles=["source"],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-xxe-jaxb-unmarshal",
        function="Unmarshaller.unmarshal",
        call_regex=r"\.\s*unmarshal\s*\(",
        description="JAXB unmarshal — XXE if backing parser not hardened.",
        argument_roles=["source"],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-xxe-dom4j-saxreader",
        function="new SAXReader().read",
        call_regex=r"\bSAXReader\b[\s\S]{0,40}\.\s*read\s*\(",
        description="dom4j SAXReader.read without features hardened.",
        argument_roles=["source"],
        extensions=_JAVA,
        severity="high",
    ),
]
