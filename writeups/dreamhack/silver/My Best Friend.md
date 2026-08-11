# [DreamHack Silver] My Best Friend

## Challenge Info
- Platform: DreamHack
- Difficulty: Silver 3
- Category: Web / HPP / Type Confusion / SSRF


## Summary
This challenge presents a simple greeting service: when a user submits a message, the server returns the input with a heart emoji appended.
Internally, the `/greet` endpoint receives user input and proxies the request to the internal `/api` endpoint.
The goal is to analyze the source code and manipulate the `isAdmin` variable in `/api` to bypass its conditional check (`isAdmin !== 0`) and retrieve the flag.

## Analysis
1. Recon (white-box)
   - There are 3 endpoints `/`, `/api` and `/greet`. The `/api` endpoint returns the flag only when two conditions are met: `req.ip === '::1'` (the request must originate from localhost)
   and `isAdmin !== 0`. Two things stood out during analysis. Firstm `/greet` receivfes user input and proxies the request to itself (`http://localhost:3000/api`).
   Second, `/api` checks the request's IP and rejects any request nont originating from localhost. This means direct access to `/api` is blocked - it can only be reached indirectly through `/greet`.
2. Locating the vulnerability
   - Two vulnerabilities are combined. First, the blacklist filter (`includes('admin')`) only checks for an exact substring match, so insesrting a tab character (`\t`) into the middle of `admin` breaks the match
   and bypasses the filter. Secibdm Express(qs) treats duplicate parameters as an array - since `/greet` hardcodes `admin=0` in the forwarded request, injecting an additional `admin` parameter causes `req.query.admin` to become an array rather than a single value.
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
