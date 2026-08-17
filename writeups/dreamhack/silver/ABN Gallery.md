# [DreamHack Silver] ABN Gallery

## Challenge Info
- Platform: DreamHack
- Difficulty: Silver 1
- Category: Web / SSRF / URL Parser Bypass

## Summary
- /gallery/:id : Serves a fixed local image corresponding to the id paramter.
- /fetch: Checks whether the host extracted from the url parameter is a public IP (via hostIsPublic). If it passes, the server fetches that URL itself and returns the response to the client.
- /admin : Checks whether the request originates from a private/local IP. If it passes, it reads and returns the file specified by the log prarmeter.
This is a gallery website built with Node.js/Express. The /fetch route acts as a proxy: it checks whether the host extracted from the user-supplied url is a public IP, and if so, the server fetches that URL itself and returns the response. The /admin route only responds if the request originates from a local IP, in which case it reads and returns the file specified by the log paramter.
By bypassing /fetch's filter, the request was made to actually target the server itself (127.0.0.1), with the destination set to /admin?log= pointing to the flag's location via path traversal- retriecing the flag.

## Analysis
1. Recon (black-box)
   - For /gallery/:id, I tried inputting values like 1 and 2 for the id parameter, but deprioritized this route since I had no way to know the valid image IDs.

Reading app.js, I analyzed the extractHost function used in /fetch. It strips everything before ://, keeps only what comes before the first /, and then keeps 
only what comes before the first : within that — extracting a bare hostname from the URL.

/admin is structured to return a file via readFile(). To determine the flag's exact location, I opened the Dockerfile, which revealed both the flag path (/flag) and the app's working directory (WORKDIR /abn_gallery).

I skipped the node_modules folder since it contains too many third-party dependency folders to review manually — planning to revisit it only if no other approach worked.
2. Locating the vulnerability
   - Analyzing the code flow of /fetch, I found that the filtering stage and the actual request stage use two different parsers: filtering relies on a hand-written extractHost function (a simple string parser that only recognizes three delimiters — ://, /, and :) to determine whether the host is a public IP, while the actual request uses the URL object produced by parseIncomingUrl (which internally relies on the standard new URL() parser) passed directly 
into fetch().

I also confirmed that /admin only returns the file specified by the log parameter when the request originates from a local (private) IP.
Combining these two facts, I hypothesized that if I could deceive only the filtering logic of /fetch while making the actual request target the server itself (localhost), I could reach the internal-only /admin route through /fetch.
3. Trial and error
   - I tried to make the acual request target 127.0.0.1 while deceiving extractHost, in several different ways.
   1. userinfo@host(no colon) : http://www.google.com@127.0.0.1/... - extractHost doesn't recognize '@', so it returned the whole string `www.google.com@127.0.0.1` as-is. This isn't a valid host format, so it failed at hostIsPublic().
   2. userinfo@host (with colon): `http://www.google.com:1@127.0.0.1/...` - adding a colon made extractHost correctlyreturn `www.google.com`, passing the check. However, at the actual reqeust stage, JavaScript's fetch() rejects any URL containing credentials (userinfo, i.e. an `@`). resulting in 500 error.
   3. Backslash: `www.google.com\@127.0.0.1` - Under the WHATWG URL standard, special scheme like http/https treat `\` the same way as `/`. As a result, new URL() also stopped parsing the host at the blackslash, just like extractHost did - both parsers agreed, so the mismatch we needed never occurred.
   4. Question mark: `www.google.com?@127.0.0.1` - new URL() corretly interprets the host as `www.google.com` (since `?` starts the query string), but extractHost has no concpey of `?` as a terminator and returned the whole string `www.google.com?@127.0.0.1` - again not a valid host format, so it failed at hostIsPublic() as well.
   5. CVE-2025-59436 (octal IP notation): A hint in the official QnA pointed to this CVE. It's a bug in the npm 'ip' package (<=2.0.1) where an octal-notation IP string like "017700000001" (the octal representation of 127.0.0.1) is incorrectly classified as a public IP by isPublic(). extractHost passed this string through untouched, and hostIsPublic() returned true due to the bug, while new URL() correctly normalized the same string to "127.0.0.1" per the WHATWG URL standard's IP parsing rules — giving us exactly the mismatch we needed, but through a library bug rather than a parser-logic gap.
   Initially, omitting the port caused a "fetch failed" error, since a URL without an explicit port defaults to port 80 for the http scheme. Checking the Dockerfile confirmed the app was configured with `ENV PORT 3000`, meaning nothing was listening on port 80 inside the container. Explicitly specifying port 3000 resolved the issue, allowing the request to successfully reach the app's own /admin route and retrieve the flag.


## Final Exploit
```
/fetch?url=http://017700000001:3000/admin%3Flog=../../flag
```
- The octal-notation IP `017700000001` is passed through extractHost unmodified and misclassified as a public IP by hostIsPublic() due to CVE-2025-59436, while new URL() correctly normalizes the same string to 127.0.0.1 - causing the actual fetch to target the server itself on its internal port (3000, per the Dockerfile's ENV PORT 3000) at `/amin?log=../../flag`, where path traversal reads the flag file located at the container's filesystem root.

## Root Cause
- Validation relied on extractHost, while the actual reqeust relied on new URL() - so the value being checked and the value being used were never garuanted to match.
These attempts did not achieve an actual bypass alone. Finally, I had to exploit a bug in the npm ip package which hostisPublic() relies on internally. It is not a flaw in the application code, but a flaw in the third-party library the developer had trusted and relied on.
- Related CWE: CVE-2025-59436

## What I Learned
- Special schemes (http/https) tolerate any slash count after the colon 
  (`http:`, `http:/`, `http://` all parse identically) — see 
  [concepts/ssrf.md](../../../concepts/ssrf.md#scheme-colon-slash-count-leniency)
- URL fragments (`#...`) are never sent to the server, but naive string-matching 
  filters can still be fooled by text placed after a `#` — see 
  [concepts/ssrf.md](../../../concepts/ssrf.md#url-fragment-invisible-to-server)
- JavaScript's fetch() refuses any URL containing userinfo (`@`), unlike Python's 
  requests/curl — see 
  [concepts/ssrf.md](../../../concepts/ssrf.md#fetch-rejects-userinfo-urls)
- Octal-notation IPs (e.g. 017700000001) can bypass IP-classification libraries 
  with incomplete normalization (CVE-2025-59436) — see 
  [concepts/ssrf.md](../../../concepts/ssrf.md#octal-ip-cve-2025-59436)
## Mitigation
- Use the same parser for URL validation and the actual request.
You should parse the URL with `new URL()` and reuse the parsed result for both validation and the actual request.
This prevents the validated value and the value used for the actual request from being different.

## Flag
`DH{7hANks_f0r_vI5i71nG_7he_9A11ery:J6HfiXBcsYW5GZa/mTbqaw==}`
