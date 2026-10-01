from __future__ import annotations

import datetime as dt

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

from portal import audit
from portal.anchoring import anchor_audit, verify_anchor
from portal.models import AuditAnchor


def _tsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA Teste")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(key, hashes.SHA256())
    )
    return DummyTimeStamper(
        tsa_cert=asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
        tsa_key=asn1_keys.PrivateKeyInfo.load(
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
    )


def test_anchor_audit_head(session, storage):
    for i in range(3):
        audit.record(session, action="TESTE", actor_type="sistema", actor_ref="t", data={"i": i})
    session.commit()
    anchor = anchor_audit(session, storage, _tsa(), "https://tsa.example")
    assert anchor.head_event_id == 3
    token = storage.get(anchor.token_key)
    result = verify_anchor(anchor, token)
    assert result["imprint_ok"] and result["intact"] and result["valid"]
    assert not result["trusted"]  # raízes da ACT não configuradas
    # adulterar a cabeça registrada faz a verificação falhar
    forged = AuditAnchor(
        head_event_id=3, head_hash="0" * 64, tsa_url="x", token_key="x", token_sha256="x"
    )
    assert not verify_anchor(forged, token)["imprint_ok"]
    report = audit.verify_anchors(session, storage, report=audit.verify_chain(session))
    assert report.ok and report.anchors_checked == 1 and report.last_anchored_event_id == 3


def test_rewritten_chain_detected_by_anchor(session, storage):
    """Reescrever eventos e recalcular toda a cadeia passa no verify_chain,
    mas não nas âncoras (o hash carimbado pela ACT deixa de existir)."""
    from portal.models import AuditChainHead, AuditEvent

    for i in range(3):
        audit.record(session, action="TESTE", actor_type="sistema", actor_ref="t", data={"i": i})
    session.commit()
    anchor_audit(session, storage, _tsa(), "https://tsa.example")
    ev = session.get(AuditEvent, 2)
    ev.action = "ADULTERADO"
    prev = audit.GENESIS
    for e in session.query(AuditEvent).order_by(AuditEvent.id):
        e.prev_hash = prev
        e.hash = audit.compute_hash(prev, e)
        prev = e.hash
    session.get(AuditChainHead, 1).last_hash = prev
    session.commit()
    assert audit.verify_chain(session).ok  # cadeia "consistente"...
    report = audit.verify_anchors(session, storage)
    assert not report.ok and report.anchor_problems  # ...mas a âncora denuncia


def test_head_lock_refreshes_stale_identity_map(database):
    """Cenário do job anchor-audit: a sessão carrega a cabeça e, na MESMA
    transação, outra sessão grava eventos antes desta gravar o seu. Sem
    ``populate_existing`` o FOR UPDATE devolve o objeto desatualizado do
    identity map e a cadeia bifurca. (Só reproduz em PostgreSQL/READ COMMITTED.)"""
    import pytest

    from portal.models import AuditChainHead

    if database.engine.dialect.name != "postgresql":
        pytest.skip("requer PostgreSQL (PORTAL_TEST_DATABASE_URL)")
    with database.sessionmaker() as s1, database.sessionmaker() as s2:
        audit.record(s1, action="A", actor_type="sistema", actor_ref="t")
        s1.commit()
        s2.get(AuditChainHead, 1)  # carrega a cabeça (evento 1) na transação de s2
        audit.record(s1, action="B", actor_type="sistema", actor_ref="t")
        s1.commit()
        audit.record(s2, action="C", actor_type="sistema", actor_ref="t")
        s2.commit()
        assert audit.verify_chain(s2).ok
