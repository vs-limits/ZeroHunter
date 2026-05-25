# PHP — SSRF Audit Skill (CWE-918)

## Sink inventory
- `curl_init` / `curl_setopt(CURLOPT_URL, $x)` / `curl_exec`
- `file_get_contents($url)`, `fopen($url, "r")` when
  `allow_url_fopen=On` and `$url` starts with `http(s)://`
- `fsockopen`, `pfsockopen`, `stream_socket_client`
- Guzzle `$client->request(...)`, `$client->get($url)`
- Symfony HttpClient `HttpClient::create()->request(...)`

## What makes a hit exploitable

1. The URL scheme is not constrained — attacker may pivot to
   `file://`, `gopher://`, `dict://`, `phar://` (the latter chains
   into deserialization), or hit internal-only services.
2. The host is not validated against an allowlist *after DNS
   resolution* (otherwise DNS rebinding bypasses).
3. The response is reflected to the attacker (full SSRF) or only
   error messages leak (blind SSRF).

## Decision flow

- If only the path portion of an HTTPS URL is user-controlled and
  scheme+host are static, mark **safe** (use `parse_url` to confirm).
- If the URL is fully attacker-controlled, look for:
  - Scheme allowlist (`['http', 'https']`)
  - Host allowlist or denylist of RFC1918 / link-local
  - `CURLOPT_FOLLOWLOCATION = false` (otherwise redirects can
    rebind to internal IPs)
  - DNS resolution + IP allowlist + `CURLOPT_RESOLVE`

## Tool hints

- `tldr__tldr_extract` on the wrapper function to see if URL
  validation runs before the sink.
- `ripgrep__search "gethostbyname"` / `"filter_var.*FILTER_VALIDATE_IP"`.

## POC templates

Internal probe: `?url=http://127.0.0.1:8080/admin`
Cloud metadata: `?url=http://169.254.169.254/latest/meta-data/`
File read: `?url=file:///etc/passwd` (requires `allow_url_fopen=On`).
Phar gadget: `?url=phar://uploads/poly.jpg/x`.

## Fix recommendations

1. Allowlist schemes via `parse_url($url, PHP_URL_SCHEME)`.
2. Resolve host → IP, reject RFC1918 / loopback / link-local /
   metadata addresses, then connect via the resolved IP.
3. Disable redirects or follow them through the same validator.
4. For Guzzle: pass `allow_redirects => false` and a custom
   `RequestMiddleware` that re-validates each hop.
