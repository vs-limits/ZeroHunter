# Python — Deserialization Audit Skill (CWE-502)

## Sink inventory (ordered by severity)

- `pickle.loads`, `pickle.load`, `cPickle.loads` — arbitrary RCE
  via `__reduce__` on attacker-built classes.
- `dill.loads`, `cloudpickle.loads` — same as pickle.
- `pyyaml.load(stream)` without `Loader=yaml.SafeLoader` — RCE via
  `!!python/object/apply:os.system`.
- `marshal.loads` — code-object loading, RCE on matching Python
  versions.
- `shelve` / `joblib.load` — pickle-backed.
- `xmlrpc.client.loads` — historically buggy.

## Decision flow

1. Reach the sink with attacker-controlled bytes (HTTP body, file
   upload, message queue body)? If yes, **vulnerable**.
2. Reading from a local file that *was* attacker-written (upload
   feature, log poisoning) — still vulnerable.
3. yaml.load with `SafeLoader` argument — safe.

## Sanitizers and gotchas

- `hmac` signing the payload before `pickle.loads` is the only
  effective gate. Verify with `hmac.compare_digest` *before*
  deserializing.
- `pickletools.optimize` is not a security filter.
- Restricted unpickler subclassing `pickle.Unpickler` overriding
  `find_class` to allow only safe types is acceptable; review the
  allowlist.

## Tool hints

- `ripgrep__search "hmac.compare_digest"` to see if signature is
  validated.
- `tldr__tldr_extract` on the load wrapper to verify SafeLoader is
  passed.

## POC template

```python
import os, pickle, base64
class P:
    def __reduce__(self):
        return (os.system, ('id',))
payload = base64.b64encode(pickle.dumps(P())).decode()
# send payload to the endpoint
```

## Fix recommendations

1. Never `pickle.loads` untrusted bytes; switch to JSON / msgpack
   with strict schema.
2. If pickle is required, sign with HMAC, verify first.
3. For yaml, always pass `Loader=yaml.SafeLoader` or use
   `yaml.safe_load`.
