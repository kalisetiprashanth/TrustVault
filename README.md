# TrustVault — Secure Document Sharing with a Real Audit Trail

TrustVault is a college-project prototype built with HTML, CSS, JavaScript, Python and FastAPI. It demonstrates named-user, per-document permissions, private file storage and a hash-chained activity log.

> Educational prototype, not production-certified. Read [THREATS.md](THREATS.md) before deployment.

## Features
- Login with admin, owner and viewer roles.
- Owner-only upload, delete, permission grant and revoke.
- Per-document `read` and `edit` grants.
- Every document detail/download/edit/delete route checks current authorization on the server.
- Private storage; files are not served as static assets.
- Upload allowlist and basic content-signature validation.
- Search by filename, owner, category and date.
- Admin activity view, denied-attempt records and audit-chain verification.
- Automated API security tests.

## Permission model
- **Admin:** create users, view audit events and aggregate activity. No automatic right to read document contents.
- **Owner:** manage their own documents and grant/revoke named-user access.
- **Viewer account role:** can read/download documents explicitly shared with them.
- **Edit grant:** allows a grantee to replace a document. Only the owner can delete or share it.

## Requirements
- Python 3.10+
- pip
- Git (for version history)

## Run locally (Windows PowerShell)
```powershell
git clone <YOUR_PUBLIC_REPOSITORY_URL>
cd TrustVault
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python backend/seed.py
uvicorn backend.main:app --reload
```
Open http://127.0.0.1:8000

For macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python backend/seed.py
uvicorn backend.main:app --reload
```

## Demo credentials
These accounts are created by `python backend/seed.py` if they do not already exist:

| Role | Username | Initial password |
|---|---|---|
| Admin | `admin` | `AdminDemo!2026#Change` |
| Owner | `owner` | `OwnerDemo!2026#Change` |
| Viewer | `viewer` | `ViewerDemo!2026#Change` |
| Viewer (use as editor grantee) | `editor` | `EditorDemo!2026#Change` |

**Change all passwords before exposing the application to the internet.** The seed script does not reset passwords for existing accounts.

## Run tests
```bash
pytest -q
```
Tests use a temporary database and temporary file storage.

## API documentation
FastAPI interactive docs: http://127.0.0.1:8000/docs

| Method + endpoint | Who may call | Rule |
|---|---|---|
| `POST /auth/login` | Public | Valid credentials |
| `POST /auth/logout` | Authenticated | CSRF token required |
| `GET /users/me` | Authenticated | Current session |
| `GET /users` | Admin | User metadata |
| `POST /admin/users` | Admin | Create account; CSRF required |
| `POST /documents/upload` | Owner | Own new document; CSRF required |
| `GET /documents` | Authenticated | Own or explicitly shared documents only |
| `GET /documents/{id}` | Owner/grantee | Current document grant |
| `GET /documents/{id}/download` | Owner/grantee | Current document grant |
| `PUT /documents/{id}` | Owner or edit grantee | Current edit permission; CSRF required |
| `DELETE /documents/{id}` | Owner | Must own document; CSRF required |
| `POST /documents/{id}/permissions` | Owner | Grant read/edit to named active user; CSRF required |
| `GET /documents/{id}/permissions` | Owner | List grants |
| `DELETE /documents/{id}/permissions/{user_id}` | Owner | Revoke grant; CSRF required |
| `GET /admin/audit-logs` | Admin | Audit metadata |
| `GET /admin/audit-verify` | Admin | Verify hash chain |
| `GET /admin/activity-summary` | Admin | Aggregate activity |

All document IDs are untrusted input. The backend checks access for each document operation.

## Storage and audit notes
- Actual file bytes are stored in `private_storage/`, outside the frontend static directory.
- Database rows store random storage identifiers, not user-controlled paths.
- The audit chain detects edits/deletions that do not also rewrite the full chain. It is **not immutable** against full database control. Production evidence needs external signed checkpoints or WORM storage.
- A user who already downloaded a document can keep that copy after permission revocation.

## Deployment checklist
1. Use HTTPS.
2. Set `TRUSTVAULT_SECRET` to a long random secret.
3. Set `TRUSTVAULT_SECURE_COOKIES=true`.
4. Change/remove demo credentials.
5. Use persistent private storage and a persistent database volume.
6. Do not expose `private_storage` or the database through a static web server.
7. Configure reverse-proxy upload limits and rate limiting.
8. Run the tests on the exact deployed commit.
9. Configure backups and external audit anchoring.
10. Add monitoring, malware scanning, MFA and account recovery before production use.

## Current limitations
- No public/external sharing links.
- No MFA, password reset, antivirus scanning, file preview, version history, soft delete or retention controls.
- No external WORM audit archive.
- The included UI is a functional starter dashboard; permission grants are currently available through the API docs and can be given a dedicated UI in a later iteration.
- The included admin page shows audit activity and supports user creation; it does not provide a complete user deactivation workflow.

## Submission items still requiring your own work
- Create a public Git repository and push commits across the development week.
- Replace repository URL placeholders with the real URL.
- Add actual commit links in `PROMPTS.md`; do not invent them.
- Deploy and insert the live URL.
- Record your own five-minute demo video.
- Test the deployed app and document any changes in `THREATS.md`.
