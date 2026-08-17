## Userinfo@Host Trick

URLs support an optional `userinfo@` component before the host (`scheme://userinfo@host/path`). Naive host-validation logic (string matching, regex) often gets fooled by a trusted-looking domain placed before the `@`, 
while a standards-compliant parser (`requests`, `curl`, etc.) correctly connects to whatever comes *after* the `@`.
```
http://trusted-domain.com@127.0.0.1/admin
```
If the validator also splits on `:` to strip a port, include a colon before the `@` too, 
so both checks are satisfied at once:
```
http://trusted-domain.com:1@127.0.0.1/admin
```
**Mitigation:** parse with `urllib.parse.urlparse()` and reuse `.hostname` for the actual request, 
instead of re-parsing the raw URL string.

## Double URL Encoding Filter Bypass

### What it is
A bypass technique where a value is percent-encoded *twice* instead of once. 
The filter, which only sees the value after a single decoding pass, doesn't 
recognize the blacklisted string — but the final consumer of the value performs 
an additional decoding pass, revealing the real value at the point of use.

### Why it works
Trace how many times a value gets decoded between the point where it's 
**validated** (the filter) and the point where it's **consumed** (the actual 
processing function). If consumption happens after N decoding passes but 
validation happens after fewer than N, encoding the value N times (once more 
than the validator expects) lets it slip through while still resolving correctly 
at the consumption point.

### Known decoding counts (accumulated from past challenges)
- Flask `request.args.get()` / `request.form.get()`: 1 automatic decode

## scheme-colon-slash-count-leniency

Some URL parsers handle special schemes such as `http` and `https` leniently,
allowing different numbers of slashes after the scheme colon:

```text
http://host/path
http:/host/path
http:host/path
```
## url-fragment-invisible-to-server

URL fragments are the part after `#`:

```text
https://example.com/path?query=value#fragment
```
Fragments are handled by the client are not included in the http request sent to the server.
This can cause an SSRF filter bypass when a filter scans the raw URL string instead of parsing it. The filter may inspect content inside the fragment even though that content will never be sent to the server.
For example:
```text
https://example.com/#http://127.0.0.1
```
A naive string-based filter may detect http://127.0.0.1, while the actual request only targets https://example.com/.


## fetch-rejects-userinfo-urls

URLs can contain userinfo before the hostname:

```text
https://username:password@example.com/path
```
Some HTTP clients accept URLs containing userinfo and use the hostname after
@ as the actual destination. This can create a discrepancy between what a
naive SSRF filter sees and where the request is actually sent.

However, JavaScript's standard fetch() API rejects URLs containing
userinfo/credentials.

Therefore, the applicability of userinfo-based SSRF bypasses depends on the
HTTP client used by the application. A bypass that works with one client may
not work with another.

Key point: Always consider how the actual HTTP client parses and handles the URL, rather than assuming all clients behave the same way.

## octal-ip-cve-2025-59436

IPv4 addresses can have non-standard representations. For example, some URL
parsers interpret `017700000001` as the loopback address `127.0.0.1`.

CVE-2025-59436 affects versions of the npm `ip` package up to 2.0.1.
Its `isPublic()` and `isPrivate()` functions can incorrectly classify
certain non-standard IPv4 representations, such as `017700000001`, as
public addresses.

This can lead to an SSRF bypass when an application relies on the library
to block requests to private or loopback addresses.

The important lesson is that SSRF protection also depends on the correctness
of its dependencies. Always keep security-sensitive libraries up to date and
check their known vulnerabilities.
