"""Fluxo DocuSeal ponta a ponta contra um servidor DocuSeal simulado."""

from __future__ import annotations

import json
import re
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from portal.auth.dev import DevAuthProvider
from portal.integrations.docuseal import DocusealClient, sign_payload
from portal.models import Acceptance, DocStatus, Document, DocumentType, Engine
from portal.signing.pades import FIELD_FINAL, inspect_signatures, load_cert_files
from portal.web.app import create_app
from tests.conftest import make_pdf
from tests.test_web import csrf_of, login

SECRET = "whsec_teste"
DS = "https://assinatura.empresa.test"


class FakeDocuseal:
    def __init__(self):
        self.created: list[dict] = []
        self.archived: list[int] = []
        self.signed_pdf = make_pdf(["CONTRATO DE TRABALHO", "Assinado no DocuSeal"], label="")
        self.audit_pdf = make_pdf(["Trilha de auditoria DocuSeal"], label="")
        self.annex_pdf = make_pdf(["ANEXO I - Regulamento interno"], label="")
        self.completed: set[int] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        # O token da API só vai para /api/*; downloads de arquivo não o recebem.
        if path.startswith("/api/"):
            assert request.headers["X-Auth-Token"] == "token-teste"
        else:
            assert "X-Auth-Token" not in request.headers
        if request.method == "POST" and path == "/api/submissions":
            body = json.loads(request.content)
            self.created.append(body)
            n = len(self.created)
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 100 + n,
                        "submission_id": 10 + n,
                        "slug": f"slug{n}",
                        "embed_src": f"{DS}/s/slug{n}",
                    }
                ],
            )
        if request.method == "GET" and path.startswith("/api/submitters/"):
            sid = int(path.rsplit("/", 1)[1])
            return httpx.Response(
                200,
                json={
                    "id": sid,
                    "completed_at": "2026-10-01T12:00:00Z" if sid in self.completed else None,
                },
            )
        if request.method == "DELETE" and path.startswith("/api/submissions/"):
            self.archived.append(int(path.rsplit("/", 1)[1]))
            return httpx.Response(200, json={})
        if path == "/file/doc.pdf":
            return httpx.Response(200, content=self.signed_pdf)
        if path == "/file/anexo.pdf":
            return httpx.Response(200, content=self.annex_pdf)
        if path == "/file/rebaixa":
            return httpx.Response(
                302, headers={"location": "http://assinatura.empresa.test/file/doc.pdf"}
            )
        if path == "/file/audit.pdf":
            return httpx.Response(200, content=self.audit_pdf)
        return httpx.Response(404)


@pytest.fixture
def fake():
    return FakeDocuseal()


@pytest.fixture
def app(settings, database, storage, sealer, seeded, session, fake):
    s = settings.model_copy(update={"docuseal_webhook_secret": SecretStr(SECRET)})
    client = DocusealClient(DS, "token-teste", http=httpx.Client(transport=httpx.MockTransport(fake)))
    contrato = DocumentType(
        code="CONTRATO_DS",
        nome="Contrato de trabalho",
        requires_acceptance=True,
        declaration_text="Li e concordo.",
        engine=Engine.DOCUSEAL,
        docuseal_template_id=7,
    )
    session.add(contrato)
    session.commit()
    return create_app(
        s, auth=DevAuthProvider(), sealer=sealer, storage=storage, database=database, docuseal=client
    )


def webhook(c: TestClient, payload: dict):
    body = json.dumps(payload).encode()
    sig = sign_payload(SECRET, body, int(time.time()))
    return c.post("/webhooks/docuseal", content=body, headers={"X-Docuseal-Signature": sig})


def test_docuseal_end_to_end(app, fake, session, pki):
    admin = TestClient(app)
    login(admin, "rh.admin")
    tipo = session.query(DocumentType).filter_by(code="CONTRATO_DS").one().id
    session.rollback()
    csrf = csrf_of(admin.get("/rh").text)
    r = admin.post(
        "/rh/docuseal/emitir",
        data={"tipo": tipo, "matriculas": "000123", "titulo": "Contrato", "csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 200 and "1 pendência(s) criada(s): 000123" in r.text
    doc = session.query(Document).one()
    assert doc.declaration_text == "Li e concordo." and doc.declaration_sha256
    doc_id = doc.id
    session.rollback()

    maria = TestClient(app)
    login(maria, "maria.silva")
    page = maria.get(f"/documentos/{doc_id}")
    csrf = csrf_of(page.text)
    # senha errada não gera link
    r = maria.post(
        f"/documentos/{doc_id}/docuseal", data={"csrf": csrf, "senha": "x"}, follow_redirects=False
    )
    assert r.status_code == 400 and not fake.created
    r = maria.post(
        f"/documentos/{doc_id}/docuseal", data={"csrf": csrf, "senha": "dev"}, follow_redirects=False
    )
    # página intermediária com link (CSP form-action bloquearia redirecionar o POST)
    assert r.status_code == 200 and f'href="{DS}/s/slug1"' in r.text
    sub = fake.created[0]["submitters"][0]
    assert fake.created[0]["send_email"] is False and sub["external_id"] == doc_id
    assert sub["metadata"]["sAMAccountName"] == "maria.silva"
    assert "expire_at" in fake.created[0]

    # segundo clique: arquiva o envio anterior e gera um novo
    r = maria.post(
        f"/documentos/{doc_id}/docuseal", data={"csrf": csrf, "senha": "dev"}, follow_redirects=False
    )
    assert f'href="{DS}/s/slug2"' in r.text and fake.archived == [11]

    anon = TestClient(app)
    payload = {
        "event_type": "form.completed",
        "timestamp": "2026-10-01T12:00:00Z",
        "data": {
            "id": 101,
            "submission_id": 11,
            "external_id": doc_id,
            "ip": "34.120.1.2",
            "ua": "Mozilla",
            "completed_at": "2026-10-01T12:00:00Z",
            "documents": [{"name": "contrato", "url": f"{DS}/file/doc.pdf"}],
            "audit_log_url": f"{DS}/file/audit.pdf",
        },
    }
    # envio antigo (arquivado) não conclui o documento
    assert webhook(anon, payload).json() == {"resultado": "submitter_divergente"}
    payload["data"]["id"], payload["data"]["submission_id"] = 102, 12
    assert webhook(anon, payload).json() == {"resultado": "processado"}
    assert webhook(anon, payload).json() == {"resultado": "ja_processado"}  # idempotente

    session.rollback()
    doc = session.get(Document, doc_id)
    assert doc.status == DocStatus.ASSINADO
    acc = session.query(Acceptance).one()
    ev = json.loads(acc.evidence_json)
    assert ev["signatario"]["ad"]["sAMAccountName"] == "maria.silva"
    assert ev["docuseal"]["ip"] == "34.120.1.2" and acc.ip == "testclient"
    final = maria.get(f"/documentos/{doc_id}/pdf").content
    infos = inspect_signatures(final, load_cert_files([pki["ca"]]))
    assert [i.field for i in infos] == [FIELD_FINAL] and infos[0].intact
    assert maria.get(f"/documentos/{doc_id}/comprovante").status_code == 200


def test_docuseal_webhook_ssrf_blocked(app, session):
    from portal.integrations.docuseal import DocusealError

    client = app.state.ctx.docuseal
    with pytest.raises(DocusealError):
        client.download("http://169.254.169.254/computeMetadata/v1/")
    assert re.match(r"https://", DS)


def _issue_and_open(app, session) -> tuple[str, TestClient]:
    admin = TestClient(app)
    login(admin, "rh.admin")
    tipo = session.query(DocumentType).filter_by(code="CONTRATO_DS").one().id
    session.rollback()
    csrf = csrf_of(admin.get("/rh").text)
    admin.post(
        "/rh/docuseal/emitir",
        data={"tipo": tipo, "matriculas": "123", "titulo": "Contrato", "csrf": csrf},
    )
    doc_id = session.query(Document).one().id
    session.rollback()
    maria = TestClient(app)
    login(maria, "maria.silva")
    csrf = csrf_of(maria.get(f"/documentos/{doc_id}").text)
    r = maria.post(f"/documentos/{doc_id}/docuseal", data={"csrf": csrf, "senha": "dev"})
    assert r.status_code == 200
    return doc_id, maria


def test_docuseal_multiple_documents_all_sealed(app, fake, session, pki):
    doc_id, maria = _issue_and_open(app, session)
    payload = {
        "event_type": "form.completed",
        "data": {
            "id": 101,
            "submission_id": 11,
            "external_id": doc_id,
            "completed_at": "2026-10-01T12:00:00Z",
            "documents": [
                {"name": "contrato", "url": f"{DS}/file/doc.pdf"},
                {"name": "anexo", "url": f"{DS}/file/anexo.pdf"},
            ],
        },
    }
    assert webhook(TestClient(app), payload).json() == {"resultado": "processado"}
    session.rollback()
    acc = session.query(Acceptance).one()
    ev = json.loads(acc.evidence_json)
    extra = ev["documento"]["arquivos_adicionais"]
    assert len(extra) == 1 and extra[0]["nome"] == "anexo"
    assert ev["autenticacao"]["confirmacao_ao_abrir_link"] == "senha_ad"
    assert acc.reauth_method == "senha_ad+link_docuseal"
    assert acc.declaration_text == "Li e concordo."
    storage = app.state.ctx.storage
    annex = storage.get(extra[0]["key"])
    infos = inspect_signatures(annex, load_cert_files([pki["ca"]]))
    assert [i.field for i in infos] == [FIELD_FINAL] and infos[0].intact
    # o dossiê inclui o anexo selado
    admin = TestClient(app)
    login(admin, "rh.admin")
    import io
    import zipfile

    z = admin.get(f"/rh/documentos/{doc_id}/dossie")
    with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
        assert "5-adicional-1.pdf" in zf.namelist()


def test_docuseal_decline_does_not_record_agreement(app, fake, session):
    from portal.documents.docuseal_flow import DECLINE_DECLARATION

    doc_id, _ = _issue_and_open(app, session)
    payload = {
        "event_type": "form.declined",
        "data": {
            "id": 101,
            "submission_id": 11,
            "external_id": doc_id,
            "declined_at": "2026-10-01T12:00:00Z",
            "decline_reason": "Salário diferente do combinado na entrevista",
        },
    }
    assert webhook(TestClient(app), payload).json() == {"resultado": "processado"}
    session.rollback()
    doc = session.get(Document, doc_id)
    acc = session.query(Acceptance).one()
    assert doc.status == DocStatus.RECUSADO and acc.decision == "RECUSADO"
    assert acc.declaration_text == DECLINE_DECLARATION and "concordo" not in acc.evidence_json
    assert json.loads(acc.evidence_json)["motivo"].startswith("Salário")


def test_docuseal_client_refuses_scheme_downgrade_and_maps_errors(fake):
    from portal.integrations.docuseal import DocusealError

    client = DocusealClient(DS, "token-teste", http=httpx.Client(transport=httpx.MockTransport(fake)))
    with pytest.raises(DocusealError):
        client.download("http://assinatura.empresa.test/file/doc.pdf")
    with pytest.raises(DocusealError):  # redirecionamento https -> http no mesmo host
        client.download(f"{DS}/file/rebaixa")

    def boom(request):
        raise httpx.ConnectError("sem rota")

    broken = DocusealClient(DS, "t", http=httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(DocusealError):
        broken.create_submission(template_id=1, email="a@b", name="A", external_id="x", values={})
    with pytest.raises(DocusealError):
        broken.download(f"{DS}/file/doc.pdf")
    assert broken.get_submitter(1) is None
    broken.archive_submission(1)  # não propaga
