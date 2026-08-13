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
