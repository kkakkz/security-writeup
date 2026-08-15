# [DreamHack Silver] Test site

## Challenge Info
- Platform: DreamHack
- Difficulty: Silver 1
- Category: Web / SSRF ( File Scheme LFI) / URL Parser Bypass

## Summary
This challenge is an image gallery site built with Flask. The `/request` route accepts a user-supplied URL, has the server fethch it via `urlopen()`, and stores the result.
The goal is to abuse this feature to read the contents of `flag.txt`.

## Analysis
1. Recon (black-box)
   - I first explored the site's routes by clicking through the UI, but this alone wasn't enough to identify a likely vulnerability candidate.
   I then checked the source code (app.py), which revealed the following routes:
   `/` : redirects to the `/vew` route
   `/request` : accpects a url parameter, has the server fetch it via `urlopen()`, and sotres the base64-encoded result.
   `/upload` : accpets a user-uploaded local file and stores it as base64-endcoded data.
   `/view` : renders both uploaded images and images fetched via `/request`
2. Locating the vulnerability
   - The vulnerability lies in `data = urlopen(url).read()` ini the `/request` route. The user-supplied url is passed directly to the server-side fetch function without any validation.
   Above this line, however, a filter does exist:
   ```python
   if url == '' or url.startswith("file://") or "flag" in url or title == '':
    return render_template('request.html')
   ```
   From the filter, I could infer that the devloper intended to block two things:
   (1) local file access via the `file://` scheme, and (2) any request containing the string "flag".
    
   
3. Trial and error
   - After confirming that the `/request` filter checks two conditions-`startswith("file://")` and `"flag" in url` - I attempted to bypass both.
   **1st Attempt (Space Bypass)**: In my local environment (Pyhton 3.14), I verified that prepending a leading space to the URL bypassed `startswith("file://")` while `urlopen()` stytill parsed it correctly.
   However, this consistently failed on the remote server (Python 3.10.4). Investigation revealed that automatic stripping of leading whitespace was introduced in a later Python patch (CVE-2023-24329) not present in the server's version.
   **2nd Attemp (Tab Bypass)**: I switched to a tab character (`\t`), since an earlier patch already presnet in the server's Python version strupped leading tabs. After working through `%09` endcodeing and a forced HTTPS redirect issue, I confirmed via RequestBin that the tab bypass did pass the filter.
   However, I still could not retrieve `flag.txt`.
   The correct bypass was `file:/` (a single slash) - a URI form semantically equivalent to `file://` per RFC 3986, but distinct from the literal `file://` prefix the filter checked for.
   The `flag` filter also required double URL endcoding rather than single encoding.

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
