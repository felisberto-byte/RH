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
    assert verify_anchor(anchor, token)
    # adulterar a cabeça registrada faz a verificação falhar
    forged = AuditAnchor(
        head_event_id=3, head_hash="0" * 64, tsa_url="x", token_key="x", token_sha256="x"
    )
    assert not verify_anchor(forged, token)
    assert audit.verify_chain(session).ok
