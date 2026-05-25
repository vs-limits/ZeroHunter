# Java — XXE Audit Skill (CWE-611)

## Sink inventory
- `DocumentBuilderFactory` → `DocumentBuilder.parse`.
- `SAXParserFactory` → `SAXParser.parse` / `XMLReader.parse`.
- `XMLInputFactory.createXMLStreamReader / createXMLEventReader`.
- `TransformerFactory.newTransformer` (for XSLT).
- `SchemaFactory.newSchema` (loads external schemas).
- `Unmarshaller.unmarshal` (JAXB).
- dom4j `SAXReader.read`.

## Hardening properties to verify

Hit is **safe** when at least the following are set on the factory:
- `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  OR equivalent
- `setFeature("http://xml.org/sax/features/external-general-entities", false)`
- `setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
- `setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)`
- `setXIncludeAware(false)` and `setExpandEntityReferences(false)`

For `XMLInputFactory`:
- `setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
- `setProperty(XMLInputFactory.SUPPORT_DTD, false)`

For `TransformerFactory` / `SchemaFactory`:
- `setAttribute(ACCESS_EXTERNAL_DTD, "")` and `ACCESS_EXTERNAL_SCHEMA = ""`.

## Decision flow

1. Locate factory construction. Trace property/feature calls.
2. If any of the hardening properties above is missing, mark
   **vulnerable** (or **uncertain** if hardening is set in a
   shared util elsewhere).

## POC template
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

## Fix recommendations
1. Centralize XML parsing in a hardened factory builder.
2. Reject DTDs entirely when you don't need them
   (`disallow-doctype-decl`).
3. For JAXB, wrap `Unmarshaller` over a hardened
   `XMLStreamReader`.
