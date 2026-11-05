import os
import re
import json
import hmac
import uuid
import hashlib
import secrets
import sqlite3
import mimetypes
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("TRUSTVAULT_DB", str(BASE_DIR / "trustvault.db")))
STORAGE_DIR = Path(os.getenv("TRUSTVAULT_STORAGE", str(BASE_DIR / "private_storage")))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
SECRET = os.getenv("TRUSTVAULT_SECRET", "development-only-change-me")
SECURE_COOKIES = os.getenv("TRUSTVAULT_SECURE_COOKIES", "false").lower() == "true"
MAX_UPLOAD = int(os.getenv("TRUSTVAULT_MAX_UPLOAD_MB", "10")) * 1024 * 1024
SESSION_COOKIE = "tv_session"
CSRF_COOKIE = "tv_csrf"
SESSION_HOURS = 8
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}

app = FastAPI(title="TrustVault API", version="1.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "frontend"), name="static")
hasher = PasswordHasher()

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def get_db():
    con = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=15000")
    return con

def init_db():
    with get_db() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents(
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS permissions(
            id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
            granted_by TEXT NOT NULL REFERENCES users(id), granted_at TEXT NOT NULL,
            UNIQUE(document_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
            actor_id TEXT, action TEXT NOT NULL, document_id TEXT,
            target_user_id TEXT, outcome TEXT NOT NULL, details TEXT NOT NULL,
            ip_address TEXT, created_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
        CREATE INDEX IF NOT EXISTS idx_permissions_user ON permissions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
        """)

@app.on_event("startup")
def startup():
    init_db()

def audit(db, actor_id, action, document_id=None, target_user_id=None,
          outcome="success", details=None, ip=None):
    """Append-only application API. Hash chain detects edits/deletions, not full DB compromise."""
    previous = db.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = previous["entry_hash"] if previous else "GENESIS"
    event = {
        "event_id": str(uuid.uuid4()), "actor_id": actor_id, "action": action,
        "document_id": document_id, "target_user_id": target_user_id,
        "outcome": outcome, "details": json.dumps(details or {}, sort_keys=True),
        "ip_address": ip, "created_at": utc_now(), "previous_hash": prev_hash
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    entry_hash = hashlib.sha256((prev_hash + canonical).encode()).hexdigest()
    db.execute("""INSERT INTO audit_logs
        (event_id,actor_id,action,document_id,target_user_id,outcome,details,ip_address,
         created_at,previous_hash,entry_hash)
         VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (event["event_id"], actor_id, action, document_id, target_user_id, outcome,
         event["details"], ip, event["created_at"], prev_hash, entry_hash))

def client_ip(request):
    # Do not trust X-Forwarded-For unless a trusted proxy is explicitly configured.
    return request.client.host if request.client else None

def get_current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Login required")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with get_db() as db:
        row = db.execute("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
            (token_hash, utc_now())).fetchone()
    if not row:
        raise HTTPException(401, "Session expired or invalid")
    return dict(row)

def current_user(request: Request):
    return get_current_user(request)

def require_role(*roles):
    def checker(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Your role cannot perform this action")
        return user
    return checker

def require_csrf(request: Request):
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get("X-CSRF-Token", "")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(403, "CSRF validation failed")

def permission_for(db, doc_id, user):
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return None, None
    if doc["owner_id"] == user["id"]:
        return doc, "owner"
    grant = db.execute("SELECT permission FROM permissions WHERE document_id=? AND user_id=?",
                       (doc_id, user["id"])).fetchone()
    return doc, grant["permission"] if grant else None

def deny_audit(request, user, action, doc_id, reason):
    # Store denied attempts without disclosing whether a document exists.
    with get_db() as db:
        audit(db, user["id"], action, doc_id, outcome="denied",
              details={"reason": reason}, ip=client_ip(request))

def safe_doc_response(doc):
    return {
        "id": doc["id"], "name": doc["original_name"], "owner_id": doc["owner_id"],
        "category": doc["category"], "mime_type": doc["mime_type"],
        "size_bytes": doc["size_bytes"], "created_at": doc["created_at"],
        "updated_at": doc["updated_at"]
    }

def validate_upload(filename, content_type, data):
    ext = Path(filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "File type not allowed. Allowed: PDF, TXT, PNG, JPG")
    if not data or len(data) > MAX_UPLOAD:
        raise HTTPException(400, f"File must be between 1 byte and {MAX_UPLOAD // (1024*1024)} MB")
    expected = {
        ".pdf": (b"%PDF-", "application/pdf"),
        ".png": (b"\x89PNG\r\n\x1a\n", "image/png"),
        ".jpg": (b"\xff\xd8\xff", "image/jpeg"),
        ".jpeg": (b"\xff\xd8\xff", "image/jpeg")
    }
    if ext in expected:
        magic, mime = expected[ext]
        if not data.startswith(magic):
            raise HTTPException(400, "File content does not match its extension")
        return mime
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "TXT file must contain UTF-8 text")
    return "text/plain"

@app.get("/")
def home():
    from fastapi.responses import FileResponse as FR
    return FR(BASE_DIR / "frontend" / "index.html")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/auth/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username=? AND active=1",
                          (username.strip().lower(),)).fetchone()
        valid = False
        if user:
            try:
                valid = hasher.verify(user["password_hash"], password)
            except (VerifyMismatchError, InvalidHashError):
                valid = False
        if not valid:
            audit(db, user["id"] if user else None, "login", outcome="denied",
                  details={"username": username.strip().lower()}, ip=client_ip(request))
            raise HTTPException(401, "Invalid username or password")
        token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions VALUES(?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(), user["id"],
                    (datetime.now(timezone.utc)+timedelta(hours=SESSION_HOURS)).isoformat(), utc_now()))
        audit(db, user["id"], "login", details={}, ip=client_ip(request))
        response = JSONResponse({"message": "Login successful", "user": {
            "id": user["id"], "username": user["username"], "full_name": user["full_name"],
            "role": user["role"]}})
        response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=SECURE_COOKIES,
                            samesite="strict", max_age=SESSION_HOURS*3600, path="/")
        response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=SECURE_COOKIES,
                            samesite="strict", max_age=SESSION_HOURS*3600, path="/")
        return response

@app.post("/auth/logout")
def logout(request: Request, user=Depends(current_user)):
    require_csrf(request)
    token = request.cookies.get(SESSION_COOKIE, "")
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        audit(db, user["id"], "logout", ip=client_ip(request))
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response

@app.get("/users/me")
def me(user=Depends(current_user)):
    return {k: user[k] for k in ("id", "username", "full_name", "role")}

@app.get("/users")
def list_users(user=Depends(require_role("admin"))):
    with get_db() as db:
        rows = db.execute("SELECT id,username,full_name,role,active,created_at FROM users ORDER BY username").fetchall()
    return [dict(r) for r in rows]

@app.post("/admin/users")
def create_user(request: Request, username: str = Form(...), full_name: str = Form(...),
                password: str = Form(...), role: str = Form(...),
                admin=Depends(require_role("admin"))):
    require_csrf(request)
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
        raise HTTPException(400, "Username must be 3-40 letters, numbers, dots, underscores or hyphens")
    if role not in {"admin", "owner", "viewer"}:
        raise HTTPException(400, "Invalid role")
    if len(password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")
    uid = str(uuid.uuid4())
    try:
        with get_db() as db:
            db.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?)",
                       (uid, username, full_name.strip(), hasher.hash(password), role, utc_now()))
            audit(db, admin["id"], "user_created", target_user_id=uid,
                  details={"username": username, "role": role}, ip=client_ip(request))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")
    return {"id": uid, "username": username, "role": role}

@app.post("/documents/upload")
async def upload_document(request: Request, file: UploadFile = File(...),
                          category: str = Form("General"),
                          user=Depends(require_role("owner"))):
    require_csrf(request)
    if not file.filename or len(file.filename) > 180 or Path(file.filename).name != file.filename:
        raise HTTPException(400, "Invalid filename")
    data = await file.read(MAX_UPLOAD + 1)
    mime = validate_upload(file.filename, file.content_type or "", data)
    doc_id, stored = str(uuid.uuid4()), str(uuid.uuid4())
    target = STORAGE_DIR / stored
    target.write_bytes(data)
    try:
        with get_db() as db:
            now = utc_now()
            db.execute("""INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?)""",
                       (doc_id, user["id"], file.filename, stored, category[:60], mime,
                        len(data), now, now))
            audit(db, user["id"], "upload", doc_id, details={"name": file.filename, "size": len(data)},
                  ip=client_ip(request))
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"message": "Uploaded", "document": {"id": doc_id, "name": file.filename}}

@app.get("/documents")
def list_documents(name: Optional[str] = None, owner: Optional[str] = None,
                   category: Optional[str] = None, date_from: Optional[str] = None,
                   date_to: Optional[str] = None, user=Depends(current_user)):
    clauses, args = [], []
    if user["role"] == "owner":
        clauses.append("(d.owner_id=? OR EXISTS(SELECT 1 FROM permissions p WHERE p.document_id=d.id AND p.user_id=?))")
        args.extend([user["id"], user["id"]])
    elif user["role"] == "viewer":
        clauses.append("(d.owner_id=? OR EXISTS(SELECT 1 FROM permissions p WHERE p.document_id=d.id AND p.user_id=?))")
        args.extend([user["id"], user["id"]])
    else:
        # Admin can inspect metadata only when they are explicitly granted access or own the document.
        clauses.append("(d.owner_id=? OR EXISTS(SELECT 1 FROM permissions p WHERE p.document_id=d.id AND p.user_id=?))")
        args.extend([user["id"], user["id"]])
    if name:
        clauses.append("LOWER(d.original_name) LIKE ?"); args.append("%"+name.lower()+"%")
    if owner:
        clauses.append("(LOWER(u.username) LIKE ? OR LOWER(u.full_name) LIKE ?)")
        args.extend(["%"+owner.lower()+"%", "%"+owner.lower()+"%"])
    if category:
        clauses.append("LOWER(d.category)=?"); args.append(category.lower())
    if date_from:
        clauses.append("substr(d.created_at,1,10)>=?"); args.append(date_from)
    if date_to:
        clauses.append("substr(d.created_at,1,10)<=?"); args.append(date_to)
    sql = """SELECT d.* FROM documents d JOIN users u ON u.id=d.owner_id WHERE """ + " AND ".join(clauses) + " ORDER BY d.created_at DESC"
    with get_db() as db:
        rows = db.execute(sql, args).fetchall()
        return [safe_doc_response(r) for r in rows]

@app.get("/documents/{doc_id}")
def document_detail(doc_id: str, request: Request, user=Depends(current_user)):
    with get_db() as db:
        doc, perm = permission_for(db, doc_id, user)
        if not doc or not perm:
            audit(db, user["id"], "view", doc_id, outcome="denied",
                  details={"reason": "not_found_or_not_authorized"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        audit(db, user["id"], "view", doc_id, ip=client_ip(request))
        return {**safe_doc_response(doc), "permission": perm}

@app.get("/documents/{doc_id}/download")
def download_document(doc_id: str, request: Request, user=Depends(current_user)):
    with get_db() as db:
        doc, perm = permission_for(db, doc_id, user)
        if not doc or not perm:
            audit(db, user["id"], "download", doc_id, outcome="denied",
                  details={"reason": "not_found_or_not_authorized"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        path = STORAGE_DIR / doc["stored_name"]
        if not path.is_file():
            audit(db, user["id"], "download", doc_id, outcome="denied",
                  details={"reason": "storage_missing"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        audit(db, user["id"], "download", doc_id, ip=client_ip(request))
        return FileResponse(path, filename=doc["original_name"], media_type="application/octet-stream",
                            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

@app.put("/documents/{doc_id}")
async def replace_document(doc_id: str, request: Request, file: UploadFile = File(...),
                           user=Depends(current_user)):
    require_csrf(request)
    data = await file.read(MAX_UPLOAD + 1)
    mime = validate_upload(file.filename or "", file.content_type or "", data)
    with get_db() as db:
        doc, perm = permission_for(db, doc_id, user)
        if not doc or perm not in {"owner", "edit"}:
            audit(db, user["id"], "edit", doc_id, outcome="denied",
                  details={"reason": "not_found_or_not_authorized"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        new_stored = str(uuid.uuid4())
        (STORAGE_DIR / new_stored).write_bytes(data)
        old_path = STORAGE_DIR / doc["stored_name"]
        db.execute("UPDATE documents SET original_name=?,stored_name=?,mime_type=?,size_bytes=?,updated_at=? WHERE id=?",
                   (file.filename, new_stored, mime, len(data), utc_now(), doc_id))
        audit(db, user["id"], "edit", doc_id, details={"new_name": file.filename}, ip=client_ip(request))
        old_path.unlink(missing_ok=True)
    return {"message": "Document updated"}

@app.delete("/documents/{doc_id}")
def delete_document(doc_id: str, request: Request, user=Depends(current_user)):
    require_csrf(request)
    with get_db() as db:
        doc, perm = permission_for(db, doc_id, user)
        if not doc or perm != "owner":
            audit(db, user["id"], "delete", doc_id, outcome="denied",
                  details={"reason": "not_found_or_not_owner"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        audit(db, user["id"], "delete", doc_id, ip=client_ip(request))
        (STORAGE_DIR / doc["stored_name"]).unlink(missing_ok=True)
        db.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    return {"message": "Document deleted"}

@app.post("/documents/{doc_id}/permissions")
def grant_permission(doc_id: str, request: Request, username: str = Form(...),
                     permission: str = Form(...), user=Depends(current_user)):
    require_csrf(request)
    if permission not in {"read", "edit"}:
        raise HTTPException(400, "Permission must be read or edit")
    with get_db() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=?", (doc_id, user["id"])).fetchone()
        if not doc:
            audit(db, user["id"], "permission_grant", doc_id, outcome="denied",
                  details={"reason": "not_owner"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        target = db.execute("SELECT * FROM users WHERE username=? AND active=1",
                            (username.strip().lower(),)).fetchone()
        if not target or target["id"] == user["id"]:
            raise HTTPException(404, "Target user not found")
        db.execute("""INSERT INTO permissions(id,document_id,user_id,permission,granted_by,granted_at)
            VALUES(?,?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET
            permission=excluded.permission,granted_by=excluded.granted_by,granted_at=excluded.granted_at""",
            (str(uuid.uuid4()), doc_id, target["id"], permission, user["id"], utc_now()))
        audit(db, user["id"], "permission_grant", doc_id, target["id"],
              details={"permission": permission}, ip=client_ip(request))
    return {"message": "Permission granted"}

@app.get("/documents/{doc_id}/permissions")
def get_permissions(doc_id: str, request: Request, user=Depends(current_user)):
    with get_db() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=?", (doc_id, user["id"])).fetchone()
        if not doc:
            raise HTTPException(404, "Document not found")
        rows = db.execute("""SELECT u.username,u.full_name,p.permission,p.granted_at
            FROM permissions p JOIN users u ON u.id=p.user_id WHERE p.document_id=?""", (doc_id,)).fetchall()
        return [dict(r) for r in rows]

@app.delete("/documents/{doc_id}/permissions/{target_user_id}")
def revoke_permission(doc_id: str, target_user_id: str, request: Request,
                      user=Depends(current_user)):
    require_csrf(request)
    with get_db() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=?", (doc_id, user["id"])).fetchone()
        if not doc:
            audit(db, user["id"], "permission_revoke", doc_id, target_user_id,
                  outcome="denied", details={"reason": "not_owner"}, ip=client_ip(request))
            db.commit()
            raise HTTPException(404, "Document not found")
        db.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?", (doc_id, target_user_id))
        audit(db, user["id"], "permission_revoke", doc_id, target_user_id,
              details={}, ip=client_ip(request))
    return {"message": "Permission revoked"}

@app.get("/admin/audit-logs")
def admin_audit_logs(limit: int = 200, user=Depends(require_role("admin"))):
    limit = max(1, min(limit, 500))
    with get_db() as db:
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/admin/audit-verify")
def verify_audit(user=Depends(require_role("admin"))):
    with get_db() as db:
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
    previous = "GENESIS"
    for row in rows:
        event = {k: row[k] for k in ("event_id","actor_id","action","document_id","target_user_id",
                  "outcome","details","ip_address","created_at","previous_hash")}
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256((previous + canonical).encode()).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(row["entry_hash"], expected):
            return {"valid": False, "broken_at": row["id"]}
        previous = row["entry_hash"]
    return {"valid": True, "checked": len(rows)}

@app.get("/admin/activity-summary")
def activity_summary(user=Depends(require_role("admin"))):
    with get_db() as db:
        rows = db.execute("SELECT action,outcome,COUNT(*) AS total FROM audit_logs GROUP BY action,outcome ORDER BY action").fetchall()
    return [dict(r) for r in rows]
