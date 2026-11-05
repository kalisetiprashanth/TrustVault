# TrustVault Threat Model

> Status: implementation notes for the college project. Re-test every item against the deployed build.

## Assets and trust boundaries
- Confidential document bytes in `private_storage/`.
- User credentials, sessions, document metadata and permission grants in SQLite.
- Audit event history.
- Browser-to-FastAPI requests. The browser is untrusted; only server-side checks authorize access.

## Permission model
- Roles: `admin`, `owner`, `viewer`.
- A document owner can read, replace, delete and grant/revoke access to their own document.
- A user with a `read` grant can view metadata and download; a user with an `edit` grant can also replace the file.
- Admin can manage users and inspect audit/aggregate activity. Admin does **not** get automatic access to document contents.
- No folder inheritance. No public links. No anonymous sharing.

## Threat register

| Threat / attack | Mitigation in this build | Test / remaining limitation |
|---|---|---|
| IDOR: change document UUID in URL | Every document endpoint checks owner or current per-document grant on the server | `test_unshared_user_cannot_list_or_download`; add tests for every future endpoint |
| Direct file path guessing | Random stored UUID; storage is outside static frontend; no route exposes storage path | Verify deployed web server does not publish storage directory |
| Revoked user reuses old URL | Download endpoint re-reads permission on each request; no signed public URLs | `test_grant_then_revoke_is_immediate`; bytes already downloaded cannot be recalled |
| Viewer edits/deletes | Edit requires owner or `edit`; delete requires owner | `test_viewer_cannot_edit_or_delete` |
| Admin reads confidential content | Admin is not implicitly a document owner or grantee | `test_admin_does_not_automatically_read_documents` |
| MIME/extension spoofing | Allowlist plus file signature checks for PDF/PNG/JPEG; UTF-8 validation for TXT | `test_wrong_file_signature_is_rejected`; no antivirus or content-disarm scanning |
| Path traversal in filename | Reject path-containing names; server generates storage names | Add fuzz tests for Unicode/control characters |
| Oversized upload | Bounded read and configured maximum size | Reverse proxy must also enforce request body limits |
| Session theft | Opaque random session token stored as SHA-256 hash; HttpOnly, SameSite=Strict cookie; expiry and logout deletion | HTTPS and Secure cookies must be enabled in production; no MFA/device binding |
| CSRF | SameSite=Strict plus CSRF cookie/header comparison for state-changing requests | Test cross-origin requests and deployment proxy behavior |
| Password database exposure | Argon2 password hashing | Enforce unique strong passwords; no password reset flow or breached-password check |
| Brute-force login | Not fully mitigated in this demo | Accepted limitation: add IP/account rate limiting and alerting before production |
| SQL injection | Parameterized SQL for user values | Review every new SQL statement |
| XSS through filenames | UI inserts names using `textContent`, not HTML interpolation | Add CSP and test malicious filenames in all future UI views |
| Audit row alteration/deletion | SHA-256 hash chain and admin verification endpoint | Hash chain is tamper-evident, not tamper-proof: DB-level attacker can rewrite the full chain. Production needs signed external checkpoints / WORM storage and restricted DB credentials |
| Audit log forgery | Audit writes are centralized in backend helper | Application/database compromise can forge events; external independent logging is needed for strong evidence |
| Permission change race | Permission is checked at request time | A request authorized immediately before revocation may already be in progress; production should coordinate revocation and stream lifecycle |
| Storage/database inconsistency | File written before metadata transaction; best-effort cleanup on failure | Crash between file write and DB commit can leave orphan file; add reconciliation job |
| File malware / parser exploit | Download as attachment with `nosniff`; restricted types | No malware scanning, PDF sanitization or image re-encoding |
| Data loss / backup exposure | Not implemented in demo | Backups, encryption-at-rest, restore tests and key management are production work |
| Denial of service | Upload limit | No global rate limit, quotas or concurrent-upload cap |
| Metadata leakage | Lists only owner/shared docs; unauthorized detail/download return generic 404 | Audit administrator can see event metadata; IP retention policy is not configured |

## Deliberately accepted limitations
1. This is a seven-day educational prototype, not a certified enterprise vault.
2. SQLite is used for local setup; deploy with a persistent volume or migrate to PostgreSQL for multi-instance operation.
3. Audit hash chaining detects accidental or partial tampering but cannot prove integrity against an attacker controlling the database and application secret.
4. No MFA, malware scanning, external identity provider, retention policy, legal hold, encrypted client-side storage, or disaster recovery.
5. Once an authorized person downloads a file, the platform cannot prevent them from copying or photographing it.

## Security review checklist before deployment
- [ ] Set a long random `TRUSTVAULT_SECRET`.
- [ ] Enable HTTPS and `TRUSTVAULT_SECURE_COOKIES=true`.
- [ ] Change every demo password and remove demo users if not needed.
- [ ] Keep database and storage outside the web root; configure persistent private volumes.
- [ ] Run `pytest -q` against the exact deployed commit.
- [ ] Test all document routes as owner, grantee, ungranted viewer and admin.
- [ ] Configure reverse-proxy request size and rate limits.
- [ ] Back up database and files securely; test restore.
- [ ] Add external audit checkpointing before claiming regulatory-grade evidence.
