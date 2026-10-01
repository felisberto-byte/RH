from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import zipfile

import pytest
from fastapi.testclient import TestClient

from portal.auth.dev import DevAuthProvider
from portal.integrations.docuseal import sign_payload
from portal.models import DocStatus, Document
from portal.web.app import create_app


@pytest.fixture
def app(settings, database, storage, sealer, seeded):
    return create_app(
        settings, auth=DevAuthProvider(), sealer=sealer, storage=storage, database=database
    )


def login(client: TestClient, username: str, password: str = "dev"):
    page = client.get("/login")
    token = re.search(r'name="login_csrf" value="([^"]+)"', page.text).group(1)
    return client.post(
        "/login",
        data={"username": username, "password": password, "login_csrf": token},
        follow_redirects=False,
    )


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def upload_batch(admin: TestClient, pdf: bytes, filename="folha.pdf", tipo=None):
    page = admin.get("/rh/lotes/novo")
    tipo = tipo or re.search(r'<option value="(\d+)">Recibo', page.text).group(1)
    return admin.post(
        "/rh/lotes/novo",
        data={
            "tipo": tipo,
            "competencia": "2026-09",
            "titulo": "Holerite setembro/2026",
            "chave": "matricula",
            "csrf": csrf_of(page.text),
        },
        files={"arquivo": (filename, pdf, "application/pdf")},
        follow_redirects=False,
    )


def test_login_required_and_security_headers(app):
    c = TestClient(app)
    r = c.get("/documentos", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = c.get("/login")
    assert "frame-ancestors 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_login_rejects_bad_password_and_missing_csrf(app):
    c = TestClient(app)
    assert login(c, "maria.silva", "errada").status_code == 401
    r = c.post("/login", data={"username": "maria.silva", "password": "dev", "login_csrf": "x"})
    assert r.status_code == 400


def test_end_to_end_batch_view_accept_verify(app, batch_pdf, session, tmp_path):
    admin = TestClient(app)
    assert login(admin, "rh.admin").headers["location"] == "/rh"
    r = upload_batch(admin, batch_pdf)
    assert r.status_code == 303
    report = admin.get(r.headers["location"]).text
    assert "999999" in report  # matrícula desconhecida reportada
    docs = session.query(Document).all()
    assert len(docs) == 2
    maria_doc = next(d for d in docs if d.employee.matricula == "000123")
    session.rollback()  # encerra a transação de leitura do teste

    maria = TestClient(app)
    assert login(maria, "maria.silva").headers["location"] == "/documentos"
    listing = maria.get("/documentos").text
    assert "Holerite setembro/2026" in listing
    page = maria.get(f"/documentos/{maria_doc.id}")
    assert page.status_code == 200
    csrf = csrf_of(page.text)

    # aceitar sem ter aberto o PDF é bloqueado
    r = maria.post(
        f"/documentos/{maria_doc.id}/aceite", data={"declaracao": "sim", "senha": "dev", "csrf": csrf}
    )
    assert r.status_code == 400 and "Abra e leia" in r.text

    pdf = maria.get(f"/documentos/{maria_doc.id}/pdf")
    assert pdf.headers["content-type"] == "application/pdf"
    assert len(pdf.content) > 1000

    # CSRF obrigatório
    r = maria.post(
        f"/documentos/{maria_doc.id}/aceite",
        data={"declaracao": "sim", "senha": "dev", "csrf": "forjado"},
    )
    assert r.status_code == 403

    r = maria.post(
        f"/documentos/{maria_doc.id}/aceite",
        data={"declaracao": "sim", "senha": "dev", "csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    session.rollback()
    assert session.get(Document, maria_doc.id).status == DocStatus.ASSINADO
    receipt = maria.get(f"/documentos/{maria_doc.id}/comprovante")
    assert receipt.status_code == 200 and receipt.content.startswith(b"%PDF")

    # João não acessa o documento da Maria
    joao = TestClient(app)
    login(joao, "joao.souza")
    assert joao.get(f"/documentos/{maria_doc.id}").status_code == 404
    assert joao.get(f"/documentos/{maria_doc.id}/pdf").status_code == 404

    # colaborador não acessa área do RH
    assert maria.get("/rh").status_code == 403

    # verificação pública por código e por upload do arquivo final
    code = session.get(Document, maria_doc.id).verification_code
    session.rollback()
    anon = TestClient(app)
    v = anon.get(f"/verificar/{code}")
    assert v.status_code == 200 and "Maria S." in v.text and "Silva" not in v.text
    page = anon.get("/verificar")
    tok = re.search(r'name="verify_csrf" value="([^"]+)"', page.text).group(1)
    final = maria.get(f"/documentos/{maria_doc.id}/pdf").content
    v = anon.post(
        "/verificar", data={"verify_csrf": tok}, files={"arquivo": ("x.pdf", final, "application/pdf")}
    )
    assert v.status_code == 200 and "idêntico" in v.text
    assert "AceiteColaborador" in v.text and "NÃO" not in v.text  # assinaturas válidas

    # dossiê do RH contém todas as peças íntegras
    z = admin.get(f"/rh/documentos/{maria_doc.id}/dossie")
    with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifesto.json"))
        zf.extractall(tmp_path)
    assert {
        "1-original.pdf",
        "2-emitido-selado.pdf",
        "3-com-registro.pdf",
        "4-comprovante.pdf",
        "evidencia.json",
        "auditoria/segmento.jsonl",
        "verificar.py",
        "LEIA-ME.txt",
    } <= names
    assert all(v["integro"] for v in manifest["arquivos"].values())
    # o script autônomo do dossiê confere arquivos e a cadeia sem o portal
    out = subprocess.run(
        [sys.executable, "verificar.py"], cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert out.returncode == 0 and "ÍNTEGRO" in out.stdout, out.stdout
    seg = (tmp_path / "auditoria" / "segmento.jsonl").read_text(encoding="utf-8").splitlines()
    first = json.loads(seg[0])
    first["payload"]["ip"] = "1.2.3.4"  # adulteração é detectada
    seg[0] = json.dumps(first, ensure_ascii=False)
    (tmp_path / "auditoria" / "segmento.jsonl").write_text("\n".join(seg), encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "verificar.py"], cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert out.returncode == 1 and "FALHA hash do evento" in out.stdout

    audit_page = admin.get("/rh/auditoria")
    assert "Cadeia íntegra" in audit_page.text


def test_logout_revokes_session(app):
    c = TestClient(app)
    login(c, "maria.silva")
    csrf = csrf_of(c.get("/documentos").text)
    c.post("/logout", data={"csrf": csrf})
    assert c.get("/documentos", follow_redirects=False).status_code == 303


def test_unknown_employee_without_admin_is_refused(settings, database, storage, sealer, seeded):
    users = {"fulano": {"display_name": "Fulano", "employee_id": "777", "is_admin": False}}
    app = create_app(
        settings, auth=DevAuthProvider(users), sealer=sealer, storage=storage, database=database
    )
    c = TestClient(app)
    r = login(c, "fulano")
    assert r.status_code == 403 and "cadastro" in r.text


def test_docuseal_webhook_requires_valid_hmac(settings, database, storage, sealer, seeded):
    from pydantic import SecretStr

    settings = settings.model_copy(update={"docuseal_webhook_secret": SecretStr("whsec_teste")})

    class FakeDocuseal:
        pass

    app = create_app(
        settings,
        auth=DevAuthProvider(),
        sealer=sealer,
        storage=storage,
        database=database,
        docuseal=FakeDocuseal(),
    )  # type: ignore[arg-type]
    c = TestClient(app)
    body = json.dumps({"event_type": "form.viewed", "data": {}}).encode()
    assert c.post("/webhooks/docuseal", content=body).status_code == 401
    import time

    sig = sign_payload("whsec_teste", body, int(time.time()))
    r = c.post("/webhooks/docuseal", content=body, headers={"X-Docuseal-Signature": sig})
    assert r.status_code == 200 and r.json() == {"resultado": "ignorado"}
    old = sign_payload("whsec_teste", body, int(time.time()) - 3600)
    assert (
        c.post("/webhooks/docuseal", content=body, headers={"X-Docuseal-Signature": old}).status_code
        == 401
    )
