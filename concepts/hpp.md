# HTTP Parameter Pollution (HPP)

## url-parser-whitespace
URL parsers treat tab (`\t`) and newline (`\n`) as whitespace and strip them during parameter name parsing.

**Example:**
`adm\tin` → parsed as `admin`

This means a blacklist checking `includes('admin')` can be bypassed by inserting a tab character.

## duplicate-parameter-handling
When the same parameter appears multiple times in a URL, behavior differs by framework:

| Framework | Behavior |
|---|---|
| Express (qs) | treated as an array `['first', 'last']` |
| Flask | first value is used |
| PHP | last value is used |

**Example:**
`?admin=1&admin=0`
- Express: `req.query.admin = ['1', '0']`
- Flask: `request.args.get('admin') = '1'`
- PHP: `$_GET['admin'] = '0'`
