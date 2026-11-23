# SafeVault

SafeVault is a small, secure vault API. Users register, log in and keep private notes; administrators can manage users. It was developed with an AI coding assistant as pair programmer (see "How AI assistance was used") and covers three activities:

1. **Secure code** - input validation and SQL injection prevention
2. **Authentication and authorization** - bcrypt, JWT and role-based access control (RBAC)
3. **Debugging** - finding and fixing SQL injection and XSS vulnerabilities, proven by security tests

Stack: Node.js, Express, SQLite (`better-sqlite3`), `bcryptjs`, `jsonwebtoken`, and the built-in `node:test` runner.

## Run it

```bash
npm install
# optional first admin and a fixed token secret
ADMIN_USERNAME=admin ADMIN_PASSWORD='Str0ngPassw0rd!' JWT_SECRET='replace-with-a-long-random-string-32+' npm start
```

Windows PowerShell:

```powershell
npm install
$env:ADMIN_USERNAME="admin"; $env:ADMIN_PASSWORD="Str0ngPassw0rd!"; $env:JWT_SECRET="replace-with-a-long-random-string-32+"
npm start
```

## Run the security tests

```bash
npm test
```

43 tests, all passing (validation, SQL injection, XSS, authentication, RBAC).

## API

| Method | Route | Access | Purpose |
|---|---|---|---|
| POST | `/api/register` | public | Create a user (role is always `user`) |
| POST | `/api/login` | public | Get a 15-minute JWT |
| GET/POST | `/api/vault` | logged in | List / create your own notes |
| GET | `/api/vault/search?q=` | logged in | Search your own notes |
| GET | `/api/vault/:id/view` | logged in (owner) | HTML view of one note (HTML-encoded) |
| GET | `/api/admin/users`, `/api/admin/vault` | **admin** | List all users / note titles |
| DELETE | `/api/admin/users/:id` | **admin** | Delete a user |

## Activity 1 - Secure input validation and SQL injection prevention

| Where | What it does |
|---|---|
| `src/validation.js` | Allow-list rules: username `[A-Za-z0-9_]{3,30}`, strict email pattern, password 10-72 characters with upper, lower and digit, length limits on notes, control characters removed, non-string values (objects/arrays) rejected |
| `src/app.js`, `src/users.js` | **Every** query uses `?` placeholders (`db.prepare(...).run(a, b)`); user input is never concatenated into SQL |
| `src/security.js` | `escapeLike` makes `%` and `_` literal in searches |
| `src/app.js` | Only `username`, `email`, `password` are read at registration, so a client cannot send `role: admin` |

## Activity 2 - Authentication and authorization (RBAC)

- Passwords are hashed with **bcrypt** (salted); the hash is never returned by any route.
- **JWT** (HS256 pinned, issuer checked, 15 minute expiry). `alg: none`, wrong signature, expired and wrong-issuer tokens are rejected.
- The user's **role is read from the database on every request**, not from the token, so a forged `role` claim or a deleted user's old token gives nothing.
- **RBAC**: `requireRole('admin')` protects `/api/admin/*`. Anonymous callers get `401`, normal users get `403`.
- Users can only read their own notes; another user's note id returns `404` (no IDOR).
- Login uses one generic error for unknown user and wrong password, compares against a dummy hash when the user does not exist, locks the account for 15 minutes after 5 failed attempts, and the auth routes are rate limited (`429`).

## Activity 3 - Vulnerabilities found, fixes and tests

| # | Vulnerability (insecure first version) | Fix | Proof (test file) |
|---|---|---|---|
| 1 | **SQL injection** - queries built as `"... WHERE username = '" + input + "'"`. `nobody' OR '1'='1` logged in without a valid user; `admin'--` commented out the rest of the query | Parameterized queries everywhere + validation | `sql-injection.test.js` first shows the vulnerable version being exploited, then shows the fixed version rejecting 7 payloads (login, password, search, register) |
| 2 | **Stored XSS** - note text was inserted straight into HTML, so `<script>` and `<img onerror>` would run in the victim's browser | `escapeHtml` on every user value in HTML, strict CSP (`default-src 'none'`), `nosniff`, `X-Frame-Options: DENY` | `xss.test.js` (4 payloads, headers, JSON content type) |
| 3 | **Mass assignment / privilege escalation** - registration accepted a `role` from the request body | Role is never read from the client; set only by the server | `auth.test.js`, `rbac.test.js` |
| 4 | **Broken access control (IDOR)** - note ids could be opened by any logged-in user | Queries filter by `user_id`; foreign ids return 404 | `rbac.test.js` |
| 5 | **Weak authentication** - unlimited password guesses, different messages for unknown user / wrong password, role trusted from the token | Lockout, rate limit, generic errors, role loaded from the database, JWT algorithm pinned | `auth.test.js` |
| 6 | **Information leakage** - stack traces and SQL errors could reach the client | Central error handler returns generic JSON, `x-powered-by` removed | `auth.test.js` |

## How AI assistance was used

An AI coding assistant was used as a pair programmer for all three activities. Every suggestion was reviewed and the code was run before it was kept.

- **Generated the first version** of the validation rules, the parameterized queries and the bcrypt/JWT login flow from plain-language requests such as "validate username and email and prevent SQL injection".
- **Reviewed the code for vulnerabilities**: it flagged string concatenation in SQL, unencoded HTML output, a client-controlled role, missing lockout and trusting the role inside the token, and proposed the fixes listed in the table above.
- **Wrote the security tests**: attack payloads (`' OR '1'='1`, `admin'--`, `'; DROP TABLE users; --`, `UNION SELECT`, `<script>`, `<img onerror>`) plus cases for token tampering and role checks.
- **Debugging loop**: the tests were executed, a failing one was analysed and fixed (a very long UNION payload was rejected by validation with `400`, so the test now accepts either a rejection or an empty result) until all 43 passed.

Prompts that work well with Microsoft Copilot (or any assistant) for the same workflow:

1. "Write input validation for username, email and password and use parameterized queries to prevent SQL injection."
2. "Add JWT authentication and role-based access control with an admin role to this API."
3. "Review this code for SQL injection and XSS vulnerabilities and show the fix."
4. "Generate security tests with SQL injection and XSS payloads and run them."

## Project layout

```
server.js            start-up (env settings, optional admin)
src/app.js           routes
src/auth.js          JWT + RBAC middleware
src/validation.js    input validation
src/security.js      HTML encoding, headers, rate limit
src/db.js            schema
src/users.js         user creation (bcrypt)
test/*.test.js       security tests
```
