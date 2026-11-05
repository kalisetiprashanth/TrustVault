import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from main import get_db, init_db, hasher, utc_now
import uuid

def add_user(db, username, full_name, password, role):
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        return
    db.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?)",
               (str(uuid.uuid4()), username, full_name, hasher.hash(password), role, utc_now()))

if __name__ == "__main__":
    init_db()
    with get_db() as db:
        add_user(db, "admin", "TrustVault Administrator", "AdminDemo!2026#Change", "admin")
        add_user(db, "owner", "Demo Document Owner", "OwnerDemo!2026#Change", "owner")
        add_user(db, "viewer", "Demo Viewer", "ViewerDemo!2026#Change", "viewer")
        add_user(db, "editor", "Demo Editor", "EditorDemo!2026#Change", "viewer")
    print("Seed users created (existing users were not changed).")
    print("Change demo passwords before any public deployment.")
