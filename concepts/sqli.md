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

## json-type-confusion-perpared-statement-bypass
- JSON타입 혼동을 이용한 Prepared Statement 우회
Prepared Statement(파라미터화된 쿼리)는 SQL injection을 막는 표준적인 방어 기법이다. 사용자 입력을 SQL 구문의 일부로 해석하지 않고, **함수의 인자처럼** DB드라이버가 별도로 처리해서 전달하기 때문에 작은따옴표, 세미콜론 등 SQL 특수문자가 자동으로 이스케이프된다.

그러나 이 방어는 **입력값이 문자열일 때**를 전제로 한다. 만약 입력값이 **객체**라면, DB드라이버는 그 객체를 자체적인 규칙으로 직렬화해서 쿼리에 삽입하는데, 이 직렬화 결과가 SQL문법상 의미있는 표현이 되어버리면 의도치 않은 쿼리가 실행될 수 있다.
#### 발생조건
- 1. 웹 앱이 json body를 파싱한다 - `express.json()` 같은 미들ㅇ뤠어가 있어서 사용자가 POST body를 json 형식으로 보낼 수 있다.
- 2. 파싱된 값이 타입 검증 없이 DB쿼리에 그대로 넘어간다. - `req.body.password `가 문자열인지 객체인지 확인하지 않고 바로 `dbQuery(q, [id, password])`에 전달된다.
- 3. DB드라이버가 객체를 특정 방식으로 직렬화한다 - `mysql2`같은 드라이버는 객체를 `\`key = value 형태로 직렬화한다.
#### 공격원리
정상적인 문자열입력 경우:
```
password = "1234"
↓
WHERE password = '1234'
```
문자열은 작은따옴표로 감싸져 안전하게 삽입된다.
객체 입력 경우:
```javascript
password = { password: 1 }
```
`mysql2` 드라이버는 이 객체를 다음과 같이 직렬화한다
```sql
WHERE password = `password` = 1
```
이 SQL이 어떻게 해석되는가 : 
mySQL에서 백틱(`)은 칼럼명을 감싸는 구분자다. 따라서
1. password = \`password`  -> password 칼럼의 값과 password
