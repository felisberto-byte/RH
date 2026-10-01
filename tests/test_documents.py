from __future__ import annotations

import io
import json

import pytest
from pypdf import PdfReader

from portal import audit
from portal.auth.dev import DevAuthProvider
from portal.documents.service import (
    Actor,
    DocumentError,
    DocumentService,
    IntegrityFailure,
    NotFound,
)
from portal.models import Acceptance, AuditEvent, DocStatus, Document
from portal.signing.pades import (
    FIELD_ACCEPT,
    FIELD_ISSUE,
    FIELD_RECEIPT,
    inspect_signatures,
    load_cert_files,
)
from tests.conftest import make_pdf


@pytest.fixture
def auth():
    return DevAuthProvider()


@pytest.fixture
def svc(session, storage, settings, sealer, auth):
    return DocumentService(session, storage, settings, sealer, auth)


def actor_for(auth, username, employee_id):
    ident = auth.authenticate(username, "dev")
    return Actor(
        identity=ident,
        employee_id=employee_id,
        session_ref="s" * 64,
        ip="203.0.113.7",
        user_agent="pytest-browser/1.0",
    )


def issue(svc, seeded, who="maria", type_="holerite", pdf=None):
    pdf = pdf or make_pdf([f"Holerite {who}"])
    doc = svc.issue(
        employee=seeded[who],
        doc_type=seeded[type_],
        pdf=pdf,
        titulo="Holerite 09/2026",
        competencia="2026-09",
        created_by="rh.admin",
    )
    svc.db.commit()
    return doc


def test_full_acceptance_flow(svc, seeded, auth, pki, session):
    doc = issue(svc, seeded)
    assert doc.status == DocStatus.PENDENTE
    maria = actor_for(auth, "maria.silva", seeded["maria"].id)

    with pytest.raises(DocumentError, match="Abra e leia"):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="dev")
    svc.mark_viewed(doc, maria)
    with pytest.raises(DocumentError, match="Senha incorreta"):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="errada")
    with pytest.raises(DocumentError, match="declaração"):
        svc.accept(doc.id, maria, declaration_confirmed=False, password="dev")

    doc = svc.accept(doc.id, maria, declaration_confirmed=True, password="dev")
    assert doc.status == DocStatus.ASSINADO
    final = svc.current_pdf(doc)
    roots = load_cert_files([pki["ca"]])
    infos = {i.field: i for i in inspect_signatures(final, roots)}
    assert set(infos) == {FIELD_ISSUE, FIELD_ACCEPT}
    assert all(i.intact and i.valid for i in infos.values())

    acc = session.query(Acceptance).one()
    ev = json.loads(acc.evidence_json)
    assert ev["documento"]["sha256_apresentado"] == doc.sealed_sha256
    assert ev["signatario"]["ad"]["objectGUID"] == maria.identity.object_guid
    assert ev["contexto"]["ip"] == "203.0.113.7"
    assert ev["signatario"]["cpf_mascarado"] == "***.456.789-**"
    assert audit.sha256_hex(acc.evidence_json) == acc.evidence_sha256

    receipt = svc.receipt_pdf(doc)
    r_infos = inspect_signatures(receipt, roots)
    assert [i.field for i in r_infos] == [FIELD_RECEIPT] and r_infos[0].intact
    # evidência embutida no comprovante é idêntica à registrada
    reader = PdfReader(io.BytesIO(receipt))
    assert reader.attachments["evidencia.json"][0].decode() == acc.evidence_json
    # o comprovante embute o PDF exato que foi apresentado ao colaborador
    presented = reader.attachments["documento.pdf"][0]
    assert audit.sha256_hex(presented) == doc.sealed_sha256

    with pytest.raises(DocumentError, match="não está pendente"):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="dev")
    assert audit.verify_chain(session).ok


def test_other_employee_cannot_see_or_accept(svc, seeded, auth):
    doc = issue(svc, seeded)
    joao = actor_for(auth, "joao.souza", seeded["joao"].id)
    with pytest.raises(NotFound):
        svc.get_for_employee(doc.id, seeded["joao"].id)
    with pytest.raises(NotFound):
        svc.accept(doc.id, joao, declaration_confirmed=True, password="dev")
    assert svc.list_for_employee(seeded["joao"].id) == []


def test_refusal_requires_reason_and_records_receipt(svc, seeded, auth, session):
    doc = issue(svc, seeded)
    maria = actor_for(auth, "maria.silva", seeded["maria"].id)
    svc.mark_viewed(doc, maria)
    with pytest.raises(DocumentError, match="motivo"):
        svc.refuse(doc.id, maria, reason="curto", password="dev")
    doc = svc.refuse(doc.id, maria, reason="Horas extras de setembro não constam.", password="dev")
    assert doc.status == DocStatus.RECUSADO and doc.final_key is None and doc.receipt_key
    assert session.query(Acceptance).one().decision == "RECUSADO"


def test_informational_document_has_no_acceptance_field(svc, seeded, pki):
    doc = issue(svc, seeded, type_="informe")
    assert doc.status == DocStatus.DISPONIVEL
    infos = inspect_signatures(svc.current_pdf(doc), load_cert_files([pki["ca"]]))
    assert [i.field for i in infos] == [FIELD_ISSUE]


def test_duplicate_issue_rejected(svc, seeded):
    pdf = make_pdf(["Holerite maria"])
    issue(svc, seeded, pdf=pdf)
    with pytest.raises(DocumentError, match="idêntico"):
        issue(svc, seeded, pdf=pdf)


def test_integrity_failure_detected(svc, seeded, settings, session):
    doc = issue(svc, seeded)
    path = settings.storage_local_path / doc.sealed_key
    path.chmod(0o640)
    path.write_bytes(path.read_bytes() + b"\n%adulterado")
    with pytest.raises(IntegrityFailure):
        svc.current_pdf(doc)
    assert session.query(AuditEvent).filter_by(action="INTEGRIDADE_FALHOU").count() == 1


def test_reauth_lockout(svc, seeded, auth, settings):
    doc = issue(svc, seeded)
    maria = actor_for(auth, "maria.silva", seeded["maria"].id)
    svc.mark_viewed(doc, maria)
    for _ in range(settings.login_max_failures):
        with pytest.raises(DocumentError, match="Senha incorreta"):
            svc.accept(doc.id, maria, declaration_confirmed=True, password="x")
    with pytest.raises(DocumentError, match="Muitas tentativas"):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="dev")


def test_cancel_rules(svc, seeded, auth):
    doc = issue(svc, seeded)
    with pytest.raises(DocumentError):
        svc.cancel(doc.id, actor_ref="rh.admin", reason="")
    svc.cancel(doc.id, actor_ref="rh.admin", reason="Holerite gerado com erro")
    with pytest.raises(NotFound):
        svc.get_for_employee(doc.id, seeded["maria"].id)


def test_audit_chain_detects_tampering(svc, seeded, session):
    issue(svc, seeded)
    issue(svc, seeded, who="joao")
    assert audit.verify_chain(session).ok
    ev = session.query(AuditEvent).order_by(AuditEvent.id).first()
    ev.data = {**ev.data, "competencia": "2020-01"}
    session.commit()
    rep = audit.verify_chain(session)
    assert not rep.ok and rep.first_bad_id == ev.id


def test_adhesion_term_required(svc, seeded, auth, session):
    from portal.documents.service import AdhesionRequired
    from portal.terms import TermService

    doc = issue(svc, seeded)
    maria = actor_for(auth, "maria.silva", seeded["maria"].id)
    svc.mark_viewed(doc, maria)
    TermService(session).publish("2", "Novo termo " * 10, published_by="rh.admin")
    session.commit()
    with pytest.raises(AdhesionRequired):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="dev")


def test_totp_step_up(session, storage, settings, sealer, auth, seeded):
    import pyotp

    from portal.documents.service import MfaEnrollmentRequired
    from portal.mfa import TotpService

    s = settings.model_copy(update={"accept_mfa": "totp"})
    svc = DocumentService(session, storage, s, sealer, auth)
    doc = issue(svc, seeded)
    maria = actor_for(auth, "maria.silva", seeded["maria"].id)
    svc.mark_viewed(doc, maria)
    with pytest.raises(MfaEnrollmentRequired):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="dev", otp="000000")
    totp = TotpService(session, s.secret_key.get_secret_value(), "Teste")
    secret, uri = totp.start_enrollment(seeded["maria"])
    assert uri.startswith("otpauth://totp/")
    assert totp.confirm(seeded["maria"], pyotp.TOTP(secret).now(), ip="1.1.1.1", ua="t")
    # o código usado na confirmação não pode ser reutilizado no aceite
    with pytest.raises(DocumentError, match="autenticador"):
        svc.accept(
            doc.id, maria, declaration_confirmed=True, password="dev", otp=pyotp.TOTP(secret).now()
        )
    import time

    next_code = pyotp.TOTP(secret).at(time.time() + 30)
    doc = svc.accept(doc.id, maria, declaration_confirmed=True, password="dev", otp=next_code)
    acc = session.query(Acceptance).one()
    assert acc.reauth_method == "senha_ad+totp"
    ev = json.loads(acc.evidence_json)
    assert ev["termo_adesao"]["versao"] == "1"
    assert ev["manifestacao"]["declaracao_sha256"] == audit.sha256_hex(ev["manifestacao"]["declaracao"])


def test_storage_outage_records_nothing(svc, seeded, auth, session, monkeypatch):
    doc = issue(svc, seeded)
    maria = actor_for(auth, "maria.silva", seeded["maria"].id)
    svc.mark_viewed(doc, maria)

    def broken_put(key, data, content_type="application/pdf"):
        raise OSError("bucket indisponível")

    monkeypatch.setattr(svc.storage, "put", broken_put)
    with pytest.raises(DocumentError, match="Armazenamento indisponível"):
        svc.accept(doc.id, maria, declaration_confirmed=True, password="dev")
    session.expire_all()
    assert session.get(Document, doc.id).status == DocStatus.PENDENTE
    assert session.query(Acceptance).count() == 0
