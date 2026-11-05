from conftest import login
from main import get_db

def upload(client, name="secret.txt"):
    r=client.post("/documents/upload",files={"file":(name,b"top secret text","text/plain")},
                  data={"category":"Confidential"})
    assert r.status_code==200,r.text
    return r.json()["document"]["id"]

def grant(client, doc_id, username, permission="read"):
    return client.post(f"/documents/{doc_id}/permissions",
                       data={"username":username,"permission":permission})

def test_unshared_user_cannot_list_or_download(client):
    login(client,"owner1","OwnerPassword!123"); doc=upload(client)
    client.post("/auth/logout")
    login(client,"viewer1","ViewerPassword!123")
    assert all(d["id"]!=doc for d in client.get("/documents").json())
    assert client.get(f"/documents/{doc}/download").status_code==404
    assert client.get(f"/documents/{doc}").status_code==404

def test_grant_then_revoke_is_immediate(client):
    login(client,"owner1","OwnerPassword!123"); doc=upload(client)
    assert grant(client,doc,"viewer1").status_code==200
    client.post("/auth/logout")
    login(client,"viewer1","ViewerPassword!123")
    assert client.get(f"/documents/{doc}/download").status_code==200
    client.post("/auth/logout")
    login(client,"owner1","OwnerPassword!123")
    with get_db() as db:
        target=db.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()["id"]
    assert client.delete(f"/documents/{doc}/permissions/{target}").status_code==200
    client.post("/auth/logout")
    login(client,"viewer1","ViewerPassword!123")
    assert client.get(f"/documents/{doc}/download").status_code==404

def test_viewer_cannot_edit_or_delete(client):
    login(client,"owner1","OwnerPassword!123"); doc=upload(client)
    grant(client,doc,"viewer1","read")
    client.post("/auth/logout");login(client,"viewer1","ViewerPassword!123")
    assert client.delete(f"/documents/{doc}").status_code==404
    assert client.put(f"/documents/{doc}",files={"file":("new.txt",b"changed","text/plain")}).status_code==404

def test_admin_does_not_automatically_read_documents(client):
    login(client,"owner1","OwnerPassword!123"); doc=upload(client)
    client.post("/auth/logout");login(client,"admin1","AdminPassword!123")
    assert client.get(f"/documents/{doc}/download").status_code==404

def test_wrong_file_signature_is_rejected(client):
    login(client,"owner1","OwnerPassword!123")
    r=client.post("/documents/upload",files={"file":("fake.pdf",b"not a pdf","application/pdf")})
    assert r.status_code==400

def test_denied_attempt_is_audited(client):
    login(client,"owner1","OwnerPassword!123"); doc=upload(client)
    client.post("/auth/logout");login(client,"viewer2","ViewerPassword!123")
    client.get(f"/documents/{doc}/download")
    client.post("/auth/logout");login(client,"admin1","AdminPassword!123")
    logs=client.get("/admin/audit-logs").json()
    assert any(x["action"]=="download" and x["outcome"]=="denied" for x in logs)

def test_audit_chain_verifies(client):
    login(client,"admin1","AdminPassword!123")
    assert client.get("/admin/audit-verify").json()["valid"] is True
