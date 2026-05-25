# JavaScript / Node — Deserialization Audit Skill (CWE-502)

## Sink inventory
- `node-serialize.unserialize($x)` — known RCE.
- `funcster.deepDeserialize` — function revival.
- `js-yaml` `yaml.load($x)` (pre v4) — `!!js/function` tag.
- `JSON.parse($x, reviver)` with reviver calling eval / require.
- `bson.deserialize` — type-confusion possible on legacy versions.

## Decision flow

1. Input bytes attacker-controlled?
2. Library exposes function-revival hooks? Then RCE class.
3. JSON.parse with no reviver is safe; verify the reviver.

## Tool hints

- `ripgrep__search "node-serialize"` / `"funcster"`.
- For yaml.load: check argument to `safeLoad` or `load` and library
  version in package.json.

## POC template

For `node-serialize`:
```javascript
let serialize = require('node-serialize');
let payload = '{"rce":"_$$ND_FUNC$$_function(){require(\\"child_process\\").execSync(\\"id\\")}"}';
serialize.unserialize(payload);
```

## Fix recommendations

1. Use `JSON.parse` without reviver and validate the schema with
   `ajv`/`zod`.
2. Upgrade js-yaml to ≥ 4 which removed the JS function tag.
3. Sign payloads if you absolutely need a binary format.
