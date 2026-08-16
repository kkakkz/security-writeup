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
   - (dead ends you hit, approaches that failed — this is the part that actually shows your thought process)

## Final Exploit
\```
(the actual payload / request used)
\```
- One-line explanation of why this payload worked

## Root Cause
- What the underlying flaw is (e.g. the URL scheme validator only checks for `https`, so an omitted scheme bypasses it)
- Related CWE: (e.g. CWE-918 SSRF)

## What I Learned
- (any new concept/technique from this challenge, link to the concepts file for detail)
- e.g. curl defaults to `http` when no scheme is given → see [concepts/ssrf.md](../../../concepts/ssrf.md#filter-bypass-cheatsheet)

## Mitigation
- (defensive side too, not just attacker POV — e.g. scheme whitelist, DNS pinning)

## Flag
`DH{...}`
