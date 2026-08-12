# [DreamHack Silver] Broken is SSRF possible?

## Challenge Info
- Platform: DreamHack
- Difficulty: Silver 3
- Category: Web / SSRF / Filter Bypass


## Summary
This challenge provides no visible fronted - the root page simply returns "Not Found", and the entire attack surface must be discovered by analyzing the server source code.
Internally, the `/check-url` endpoint validates a user-supplied URL and then makes a server-side request to it - a classic SSRF setup.
The goal is to abuse this SSRF to overwrite a global `flag` varible with a value of the attacker's choosing (via a hidden `/admin` endpoint), then retrieve it through a separate endpoint.

## Analysis
1. Recon (white-box)
   - The `/check-url` endpoint accepts a user-supplied URL and issues a server-side request to it. The `/admin` endpoint is only accessible from the localhost loopback address and allows overwriting the global `flag` variable.
     The `/flag` endpoint returns the flag if the SHA-256 hash of the user's input matches the stored `flag` value.
   
2. Locating the vulnerability
   - The key vulnerability lies in the host validation logic (`host == "www.google.com"`) within `/check-url`. THe regex pattern used to extract the host does not account for the `@` character, which the actual `requests` library interprets as a userinfo separator.
3. Trial and error
   - Initially, I assumed that a simple `userinfo@host` payload would fail, because both `check-url` and `check_ssrf` split the extracted host string on the colon (`:`) character - and this splitting logic only accounts for a `host:port` pattern, not a `userinfo@host` pattern.
   Later, I realized that injecting a `userinfo:port@host` structure would satisfy both conditions simultaneously: the colon-split logic would still correctly exstract `www.google.com` (since colon appears before `@`), while the actual host used by the `requests` library would be everything after the `@`.

## Final Exploit
- I sent the following JSON payload via a POST request to `/check-url` and received a `200` status code, confirming the SSRF filter was bypassed:
```json
{"url": "http://www.google.com:111@127.0.0.1/admin?nickname=sex"}
```
This payload passes the `check-url` host validation becuase, after splitting the extracted string on the colon (`:`), `host[0]` evaluates to `www.google.com` - satisfying the `host == "www.google.com"` check. However, the `requests` library interprets `@` as the uerinfo separator per URL standars, 
so the acutal request is sent to `127.0.0.1`, not `www.google.com`. This caused the internal server to reach its own `/admin` endpoint (accessible only from localhost) and overwrite the global `flag` variable with `sha256("sex")`.
I then retrieved the flag with:
```
POST /flag?nickname=sex
```
Since `sha256("sex")` matched the overwritten `flag` value, the server returned the real flag.

## Root Cause
- There are two root causes behind this vulnerability. First, the devleoper implicitly assumed that the value used during validation would always match the value used when the actual request is made. Passing the `host == "www.google.com"` check in `/check-url` provided no real guarantee that the subsequent `requests.get(url)` call would actually connect to `www.google.com`,
since the two operations are handled by entirely different code paths - a custome regex pattern versus the standards - compliant `requests` library.
Second, the regex (`(<=//)[^/]+`) and the suvsequent `split(":")` logic used to extract the host do not corretly implement URL parsing per `RFC 3986`. This logic never accounts for the `@` character (the userinfo separator) and simply assumes everything before the first colon is the host. As a result, an attacker-controlled string like `www.google.com:111@127.0.0.1` is parsed completely differently by the two components:
the validation logic sees `www.google.com`, while the `requests` library corrently identifies `127.0.0.1` as the actual host.
- Related CWE: CWE-918 : Server-Side Request Forgery
               CWE-1286 : Improper Validation of Synactic Correctness fo Input

## What I Learned
- I reinforced my understading of the `userinfo@host` SSRF bypass technique, which I had previously used in a different challenge (`curling`). What made this instance different was aht a naive `userinfo@host` payload alone was insufficient - the validation logic here additionally split the extraced string on `:`,
assuming it always separates `host` from `port`. This meant the payload had to explicitly include a colon before the `@`(`userinfo:port@host`) to satisfy both the colon-split logic and the suerinfo-separator behavior of the acutal URL parser simultaneously.
  The `userinfo@host` URL structure and how naice host-validation logic an be tricked into exdtracting the wrong component
    -> see [conecpts/ssrf.md](../../../concepts/ssrf.md#Host-Trick)
   
## Mitigation
- 1. Blacklist filter limitation.
      THe `includes('admin')` blacklist approach is inherently fragile - if an attacker finds any bypass techique (e.g. `\t`,`\n`, URL encoding), the entire filter fails. A whitelist approach is recommended instead:
```javascript
// Vulnerable: blacklist
if (msg.includes('admin')) return error;

// Safer: whitelist (only allow expected characters)
if (!/^[a-zA-Z0-9 ]+$/.test(msg)) return error;
```

- 2. URL-encode user input before inserting into URL
      User input should be encoded with `encodeURIComponent()` before being interpolated into a URL. This converts sepcial characters like `&` and `=` into `%26` and `%3D`, preventing paramter injection:
```javascript
// Vulnerable
axios.get(`http://localhost:3000/api?msg=${msg}&admin=0`);

// Safe
axios.get(`http://localhost:3000/api?msg=${encodeURIComponent(msg)}&admin=0`);
```
- 3. Strict type check vefore `Number()` conversion
      Before calling `Number()`, validate that the innput a single string, not an array:
```javascript
// Vulnerable
const isAdmin = Number(req.query.admin);
if (isAdmin !== 0) return FLAG;

// Safe
if (typeof req.query.admin !== 'string') return res.send('No');
const isAdmin = Number(req.query.admin);
if (isAdmin !== 0) return FLAG;
```
## Flag
`null{D0_u_kn0w_expre3S_qu3ry_1i2it?}`
