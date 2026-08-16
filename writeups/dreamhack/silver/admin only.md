# [DreamHack Silver] admin only

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
   3. Suspecting that the literal strings `localhost` or `127.0.0.1` were being blacklisted by a filter, I hex-encoded the IP (`http://%31%32%37%2e%30%2e%30%2e%31/getflag`), but this still returned `nope`.
   4. Switching to the correct internal port (`5000`) and adding an extra leading slash to the path, `http://127.0.0.1:5000//getflag` succeeded
   5. Using the same internal port(`5000`), I also tried fully percent-encoding the entire URL(`http%3A%2F%2F127%2E0%2E0%2E1%3A5000%2Fgetflag`),which succeeded as well.
   The exact mechanism by which the 4th and 5th payloads bypassed the filter could not be conclusively determined without access to the source code. However, contrasing these successes with the failure of encoding the IP alone (3rd attempt) suggests that the filter's behavior is sensitive to the overallURL structure - such as slask count or full-string encoding - rather than simply the literal IP string.
## Final Exploit
```
POST /profile
image_url=http://127.0.0.1:5000//getflag
```
```
POST /profile
image_url=http%3A%2F%2F127%2E0%2E0%2E1%3A5000%2Fgetflag
```
Both payloads exploit an SSRF vulnerability, causing the server to send a request to itself targeting `/getflag` (a route restricted to localhost-only access). I suspect they bypassed the filter due to gow it parses the URL's structure - though the exact logic remains unconfirmed without to the source code.
## Root Cause
- Through experimentation, the following facts were confirmed:

1. The literal string `127.0.0.1` was not blocked by the filter — submitting it 
   in plaintext, without any encoding, was accepted.
2. Reaching the correct internal port (`5000`) was a necessary condition; 
   requests to the wrong port (or no port) always failed.
3. Even with the correct port, an additional variation in the URL's form — 
   either a duplicated leading slash (`//getflag`) or fully percent-encoding 
   the entire URL — was also required for the request to succeed.
4. The exact reason why condition 3 was necessary could not be conclusively 
   determined without access to the source code. It's possible the filter 
   performs some form of exact string or pattern matching on the path or full 
   URL that these variations happened to evade, while the underlying request 
   library still resolved them to the same destination — but this remains an 
   unconfirmed hypothesis rather than a verified root cause.

## What I Learned
- 1. Docker Internal vs External Port Mapping
The port used to access a container from outside (e.g. `19974`,as seen in the browser's address bar) is often different from the port the application actually listens on inside the container (e.g. `5000`, sete via `app.run(port=5000)`). This distinction only matters for SSRF-style requests: when the server makes a request to itself, it bypasses the exteranl port mapping entirely and must target the internal port directly. The external port is meaningless in this context.

- 2. Werkzeug's Route Normalization vs Liternal Path Filtering
Flask (via Werkzeug) normalizes duplicate slashes when dispatching a route, so `//getflag` and `/getflag` reolve to the same view function. However, a filter that checks the raw path string before this noramlization occurs (e.g. `if path == "/getflag"`) would treat `//getflag` as a different string and fail to catch it. This creates a mismatch between the string the filter inspects and the path the routing layer ultmately dispatches to.

- 3. Automatic Decoding during Form Data Parsing (POST, not just GET)
I previously assumed automatic URL-decoding only applied to `request.args.get()` (query string / GET parameters). In fact, the same decoding also applies to `request.form.get()` when parsing POST body data encoded as `apllication/x-www-urlencoded`. This means percent-encoded characters (`%3A`, `%2F`, etc.) placed inside a POST form field value are also automatically decoded once before the application code ever sees them - this is what allowed the fully percent-encoded URL payload to be resolved back into a valid URL by the time it reached `requests.get()`.

The exact reason the non-encoded version of the same payload still failed remains unconfirmed - a plausible but unverified hypothesis is that the filter inspects the request at an earlier stage than the decoded form value (e.g. the raw request body), creating the same "validation point vs. consumption point" mismatch encountered in Dream Gallery


## Flag
`DH{6512d6aa2b2e22f3f5372788c41b55a5}`
