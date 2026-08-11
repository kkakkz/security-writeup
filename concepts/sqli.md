## sqlite-master
SQLite metadata table. Key columns:
- `type` → 'table', 'index', 'view'
- `name` → table/index name  
- `sql` → full CREATE statement

## dbms-fingerprinting
Technique to identify the backend DB via version functions:
| DB | Function |
|---|---|
| SQLite | `sqlite_version()` |
| MySQL | `version()` |
| MSSQL | `@@version` |
| PostgreSQL | `version()` |
