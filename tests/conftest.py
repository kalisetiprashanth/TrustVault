import os
import sys
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

TMP = tempfile.TemporaryDirectory()
os.environ["TRUSTVAULT_DB"] = str(Path(TMP.name) / "test.db")
os.environ["TRUSTVAULT_STORAGE"] = str(Path(TMP.name) / "files")
os.environ["TRUSTVAULT_SECRET"] = "test-secret-only"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from main import app, init_db, get_db, hasher, utc_now

@pytest.fixture()
def client():
    Path(os.environ["TRUSTVAULT_STORAGE"]).mkdir(exist_ok=True)
    init_db()
    with get_db() as db:
        db.execute("DELETE FROM audit_logs");db.execute("DELETE FROM permissions")
        db.execute("DELETE FROM documents");db.execute("DELETE FROM sessions");db.execute("DELETE FROM users")
        import uuid
        for name,role,pw in [("owner1","owner","OwnerPassword!123"),("viewer1","viewer","ViewerPassword!123"),
                             ("viewer2","viewer","ViewerPassword!123"),("admin1","admin","AdminPassword!123")]:
            db.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?)",
                (str(uuid.uuid4()),name,name,hasher.hash(pw),role,utc_now()))
    with TestClient(app) as c:
        yield c

def login(client, username, password):
    r=client.post("/auth/login",data={"username":username,"password":password})
    assert r.status_code==200, r.text
    # Mirror the browser's double-submit CSRF header for state-changing requests.
    client.headers.update({"X-CSRF-Token": client.cookies.get("tv_csrf")})
    return r.json()["user"]
