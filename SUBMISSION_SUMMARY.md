# SafeVault Security Project — Submission Summary

**Vulnerabilities addressed:** Unsafe SQL string interpolation could allow SQL injection; unescaped HTML could enable reflected XSS; missing login/role checks could expose records and administrator actions; trusting roles supplied during registration could enable privilege escalation; and weak input validation could permit malformed or excessive inputs.

**Fixes implemented:** All variable SQL values use bound parameters. User-generated text in HTML preview is escaped, with a restrictive Content Security Policy. Usernames, passwords, content and request bodies are validated. Passwords use salted PBKDF2-HMAC-SHA256; randomly generated bearer sessions expire and can be revoked. Sensitive endpoints enforce authenticated access, administrative access checks, and per-user data isolation. Public registration cannot create administrator accounts.

**Security verification:** The automated Python `unittest` suite covers injection attempts, XSS payload escaping, unauthorized and forbidden requests, admin provisioning, cross-user isolation, validation failures, and token revocation. Run the suite and retain its output as proof.

**Copilot assistance:** [Complete from your genuine experience: which prompts you sent, what Copilot proposed, what you independently reviewed, and which test failures were resolved. Do not claim AI assistance that did not occur.]

**Repository URL:** [Paste your real public GitHub repository URL after uploading the project.]
