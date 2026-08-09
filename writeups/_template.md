# [DreamHack Silver] Test site

## Challenge Info
- Platform: DreamHack
- Difficulty: Silver
- Category: Web / SSRF
- Time to solve: (e.g. 2 hours, solved independently without a write-up)

## Summary
(2-3 lines: what the challenge asks for, what service/feature is given)

## Analysis
1. Recon (black-box)
   - (site structure, what you learned from probing requests/responses)
2. Locating the vulnerability
   - (where user input flows into a server-side request, how the filter is implemented)
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
