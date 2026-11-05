# AI Prompt Log

This file must be updated during development, not reconstructed on the final day.

**Honesty rule:** Keep only entries that match prompts actually used, inspect the generated code, write the specific defect you found, and add the real Git commit URL after fixing it. Do not claim that a test passed unless you ran it.

## Entry 1 — 2026-11-05 — Initial architecture and permission model
- **Prompt / fair summary:** Design TrustVault using HTML/CSS/JavaScript and Python/FastAPI, with admin, owner and viewer roles, document-level read/edit grants, immediate revocation, private storage and audit logging.
- **Produced:** A modular architecture, per-document permissions, private storage and endpoint plan.
- **What needed careful review:** Role labels alone are not enough; admin must not silently inherit access to confidential files. A frontend-only check is not authorization.
- **What I did:** Implemented server-side checks in each document endpoint and a test that admin cannot download a document without a grant.
- **Commit:** Add the actual commit URL after committing this implementation.

## Entry 2 — 2026-11-05 — Authorization and IDOR tests
- **Prompt / fair summary:** Create automated tests proving one account cannot access another account's document by changing the document ID or calling the download endpoint directly.
- **Produced:** FastAPI TestClient tests for unshared access, download denial, viewer edit/delete denial and permission revocation.
- **What needed careful review:** A test that only checks a hidden button would not test the server. Tests must make authenticated HTTP requests as different users.
- **What I did:** Tests call the API as owner, viewer and admin and assert the server response. Run `pytest -q` and add any discovered failures here.
- **Commit:** Add the actual commit URL after committing the tests.

## Entry 3 — 2026-11-05 — Audit trail integrity
- **Prompt / fair summary:** Add an audit trail for successful and denied document actions, with a way to detect modifications.
- **Produced:** Central audit helper, previous-hash links and an admin verification endpoint.
- **What needed careful review:** A hash chain is not immutable against an attacker who can rewrite the whole database. It is tamper-evident for partial changes, not proof against full database compromise.
- **What I did:** Documented the limitation in THREATS.md and identified external signed checkpoints/WORM storage as production hardening.
- **Commit:** Add the actual commit URL after committing the audit implementation.

## Entry 4 — 2026-11-05 — Upload validation
- **Prompt / fair summary:** Validate document uploads by extension, size and actual content signature.
- **Produced:** An allowlist for PDF, TXT, PNG and JPEG, plus basic signature/UTF-8 checks.
- **What needed careful review:** Browser-provided MIME type is user-controlled and must not be trusted by itself. Signature checks are not malware scanning.
- **What I did:** The backend checks file bytes and limits file size; THREATS.md records the missing antivirus/sanitization control.
- **Commit:** Add the actual commit URL after committing upload validation.

## Entry 5 — 2026-11-05 — Frontend/API integration
- **Prompt / fair summary:** Build a simple HTML/CSS dashboard that calls the FastAPI backend for login, document listing, upload and admin audit views.
- **Produced:** Login and dashboard pages with role-aware display and API requests.
- **What needed careful review:** Hiding an action in the UI is only usability, not a security boundary. The API must independently enforce every permission.
- **What I did:** Kept authorization in FastAPI and added API-level tests. The initial UI is intentionally small; permission management UI can be extended without changing the security boundary.
- **Commit:** Add the actual commit URL after committing the frontend.

## Reusable project instruction
When asking an AI tool to change TrustVault:
- Treat the browser, request body, URL parameters, cookies and uploaded files as untrusted.
- Never implement authorization only in HTML/JavaScript.
- For every new endpoint, state the allowed role and document-level rule.
- Add a negative API test for an ungranted user and a revoked user.
- Do not claim audit logs are immutable unless an independently controlled external anchor exists.
- Explain limitations and update THREATS.md whenever a security assumption changes.
