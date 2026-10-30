# SafeVault — Secure Coding, Authentication & Security Testing

A runnable, dependency-free Python WSGI demonstration of input validation, SQL injection prevention, authentication, RBAC, XSS mitigation, and regression testing. **Educational prototype; not production-ready.**

## Requirements / run
Python 3.10+ (no third-party dependencies).

```bash
python safevault.py
# in a second terminal
python -m unittest discover -s tests -v
```

API listens on `http://127.0.0.1:8000` **for local development only**. In production, use a security-reviewed framework, HTTPS termination, CSRF/cookie policy if browser sessions are added, rate limiting, audit logs, user lifecycle protections, secret encryption, and secure configuration. Never publish real patient or user information.

## Endpoints

| Method | Endpoint | Access |
| --- | --- | --- |
| POST | `/register` `{ "username":"alice", "password":"StrongPassword123!" }` | Public; creates `user` only |
| POST | `/login` same JSON | Public; returns 1-hour bearer token |
| GET | `/me` | Bearer token |
| POST | `/logout` `{}` | Bearer token; revokes session |
| POST | `/secrets` `{ "title":"Note", "content":"Example" }` | Bearer token |
| GET | `/secrets` | Bearer token; own records only |
| GET | `/admin/users` | Admin bearer token only |
| GET | `/preview?text=...` | Public; HTML-escapes content |

Send token in `Authorization: Bearer <token>`. To provision an admin **locally**, run `python safevault.py create-admin adminuser`; password is securely prompted. Do not add real credentials to GitHub.

## Security controls

- **Validation:** strict username allowlist and length rules; password and content length limits; JSON shape validation; request body size cap.
- **SQL injection prevention:** all SQL queries with dynamic user data use SQLite parameter placeholders (`?`) rather than concatenated SQL. An injection payload is included in tests.
- **Authentication:** PBKDF2-HMAC-SHA256 (310,000 iterations, random per-user salt) password hashes; opaque cryptographic session tokens stored only as SHA-256 hashes with one-hour expiration; explicit logout revocation.
- **Authorization:** `user` / `admin` role enforcement on privileged endpoint; public registration cannot assign admin; stored records scoped to authenticated owner.
- **XSS mitigation:** JSON responses by default; HTML preview uses context-appropriate escaping and a restrictive Content Security Policy. Other defense-in-depth headers included.
- **Tests:** unauthorized access, privilege escalation, SQL injection, XSS, cross-user access, admin access, logout, malformed inputs.

## Microsoft Copilot usage (documentation template)

The code is designed for the assignment's Copilot-assisted workflow. **Do not claim Copilot was used unless you actually used it.** To document your real work, record the prompts, Copilot recommendations, manual changes, and observed test results in `docs/COPILOT_LOG.md`.

## Limitations

The local WSGI server is not hardened for the Internet. No TLS, brute-force throttling, CSRF defense (bearer tokens are header-based, not cookie-based), recovery workflow, encryption at rest, production logging, or security scanning are built in. Secrets in the example database are **not encrypted at rest** and must be synthetic test data only. Use maintained libraries, a proper secret manager, and independent review for any production application.
