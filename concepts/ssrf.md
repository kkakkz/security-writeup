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
- Python `urllib.request.urlopen()` on a `file://` URL: 1 additional internal decode
- (add more here as discovered in future challenges)

### Seen in
- Dream Gallery (Dreamhack) — bypassing `"flag" in url` filter via urlopen's internal decode
- admin only (Dreamhack) — possible variant via form-data decode vs raw-body filter check
- old-26 (Webhacking.kr) — PHP auto-decode + explicit urldecode() double-decode
