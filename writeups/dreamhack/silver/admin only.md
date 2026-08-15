# [DreamHack Silver] Test site

## Challenge Info
- Platform: DreamHack
- Difficulty: Silver 1
- Category: Web / SQL Injection / SSRF / Filter Bypass

## Summary
I discovered a SQL injection vulnerability in the user search feature.
Using UNION-based injection, I enumerated te column count, database type(SQLite), table names, andcolmn names, and used this information to log in as admin.
I then found that the `/profile` page's image URL input always returned "nope" regardless of the value submitted.
Through `robots.txt` (HTML comment hint), I discovered a `/getflag` route that appeared to be restricted to localhost-only requests.
By submitting the `/getflag` URL into the image field, I abused this SSRF vector to make the server send a request to itself, ultimately retrieving the flag.

## Analysis
1. Recon (black-box)
   - Based on the challenge title, I inferred that the goal was to log in as admin.
   While exploring the site, I identified the following features:
     - `/search?q=`: allows checking whether a givenn username exists
     - `/profile` : accepts an image URL and updates the profile picture by fetching it (inferred from the UI, not yet confirmed)
   I also found an HTML comment hinting at `robots.txt`.
2. Locating the vulnerability
   - I found that submitting ` ' or 1=1 --` into the `/search?q=` parameter returned every user's information (role, id, username), confirming a SQL injection vulnerability at this endpoint.
   The image URL input `/profile` was visible from the start, but submitting a valid external image URL consistently returned "nope". This led me to suspect that the endpoint only allows internal (local) requests and blocks external ones.
    
   
3. Trial and error
   -Through `robots.txt` HTML comment, i discovered `/getflag` route. However, directly accessing it in the browser returned `nope`, suggesting the route was restrictedto loachost-only requests.
   1. Using the imgae URL input on `profile`, i tried `http://127.0.0.1/getflag` (without a port), which returned `nope`.
   2. Suspecting a port mismatch, I tried `http://127.0.0.2:19974/getflag` which also failed. This was likely because 19974 was the external port used to access the container from outside,
not the actual port the application was listening on internally — the same internal-vs-external port distinction encountered in the `web-ssrf` challenge.
## Final Exploit
```
GET /request?url=file:/%2566%256c%2561%2567.txt&title=test HTTP/1.1
```

- The file: scheme treats file:// (double slash) and file:/ (single slash) as equivalent, which allowed me to bypass the `startswith("file://")` check. To bypass the "flag" substring filter, i exploited the gap between when the filter checks the value (agter one decoding pass) and
when `urlopen()` actually opens the file (after two decoding passes) by double-URL-encoding each cahracter of "flag".

## Root Cause
- The root cuase is that the data validated by the filter differs from the data actually used at access time. This stems from two independent sub-cuases:
(1) Incomlete Graamar Coverage (Scheme Bypass)
The filter only checked for the literal string `file://`, but per RFC 3986, the `file:` scheme treats `file://` and `file:/` as equivalent forms. The filter failed to account for the full grammar of the URI spec it was trying to validate.
(2) Mismatch Between Validation and Consumption Steps (Double Decoding)
The filter inspects the value after only one round of URL decoding (performed during HTTP request parsing), but `urlopen()` performs an additional decodinig pass when resolving the actual local file path. The filter did not account for this extra decoding step occurring after validation, and simply truested the value it observed at check time.
- Related CWE: CWE-180 (Validate Before Canonicalize) + CWE-174 (Double Decoding of the Same Data)

## What I Learned
- 1. Equivalent Forms of a URI Scheme
The `file:` scheme doesn't require a host (authority), so `file://` and `file:/` are both treated as valid, equivalent forms for accessing a local file.
A filter that only checks for a literal prefix like `startswith("file://")` can miss spec-equivalent alternate forms like this.
- 2. Automatic Dcoding During Query String parsing
When Flask parses a query parameter via `request.args.get()`, the returned value has already been URL-decoded once. This decdoing happens automatically at the framework level, even if the developer never explicitly calls a decoding function.
- 3. Internal Decoding Inside urlopen()
When `urllib.request.urlopen()` reolves a `file://` URL into an actual local file path, it performs an additional round of URL decoding internally.
Combined this measn a single value passes through two rounds of decoding across the request pipeline, while the filter only inspects the value after the first
round - this gap is what made the doubble-URL-encoding bypass possible.
- → [concepts/ssrf.md#double-url-encoding-filter-bypass](../../../concepts/ssrf.md#double-url-encoding-filter-bypass)

## Mitigation
- (defensive side too, not just attacker POV — e.g. scheme whitelist, DNS pinning)

## Flag
`DH{...}`
