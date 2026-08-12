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
   - Initially, I tried `msg=a\tdmin=1`, assuming that a duplicate `=` sign would cause the URL parser to split the string into a new parameter. However, this failed bacuase the URL parser treats only the first `=` as the key-value delimiter - everything after it becomes part of the value. So `req.query.msg` simply received `"a\tdmin=1"` as a string, and no new parameter was created. The fix was replacing `=` with `&`, which is the actual parameter separator in URLs:
```
msg=&a\tdmin=1
```
This cuased the URL parser to treat `a\tdmin=1` as a seperate parameter, which - after tab removal by qs - became `admin=`, successfully creating the duplicate parameter needed for the exploit.
## Final Exploit
- I sent a POST request to `/greet` with the `msg` field set to `&a\tdmin=1`. Internally, the server assembled the URL as:
```
GET /api?msg=&adm\tin=1&admin=0
```
The qs parser removed the tab and treated `a\tdmin` as `admin`, creting a duplicate `admin` parameter. As a result, `req.query.admin` became `['1','0']` - an array. `Number(['1','0'])` evaluates to `NaN`, and since `NaN !== 0` is `true`, the conditional check was bypassed and the flag was returned.

## Root Cause
- There are two root causes. First, `Number()` function can receive an unexpected type (array) without the developer considering this cause. The developer assumed the `admin` parameter would always be a sinlge string, but since Express (qs) treats duplicate parameters as an array, `Number(['1','0'])` returns `NaN`, which bypasses the conditional ceck. Second, user input its directly injected into the URL without filtering special characters recognized by the URL parser (suck as `&` and tab). As a result, an attacker can inject `&` into the `msg` field to introduce additional parameters into the internal request.
- Related CWE: CWE-235: Improper Handling of Extra Parameters
               CWE-704: Incorrect Type Conversion

## What I Learned
- I solidified two concepts. First, in URL parsing, tab (`\t`) and newline (`\n`) characters are treated as whitespace and removed. Previously, I vaguely assumed they were simply ignored, but this challenge confirmed that tab characters are stripped during parameter name parsing - causing `a\tdmin` to be interpreted as `admin`. Second, duplicate paramter handling differs depending on the framework. I had been confused about whetjer the first or last value takes precedence, but now i know:
| Framework | Duplicate parameter handling |
|---|---|
| Express (qs) | treated as an array |
| Flask | first value is used |
| PHP | last value is used |
- URL parser strips tab/newline characters during parameter name parsing
   -> see [concepts/hpp.md](../../../concepts/hpp.md#url-parser-whitespace)

- Duplicate parameter handling differs by framework (Express=array, Flask=first, PHP=last)
   -> see [concepts/hpp.md](../../../concepts/hpp.md#duplicate-parameter-handlinng)

- 'Number(array)' returns 'NaN', and 'NaN ! == 0' evalutes to 'true'
   -> see [concepts/type-confusion.md](../../../concepts/type-confusion.md#number-coercion)

   
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
