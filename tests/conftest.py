from __future__ import annotations

import datetime as dt
import io
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from portal.config import Settings
from portal.db import Database
from portal.models import DocumentType, Employee
from portal.signing.pades import Sealer
from portal.storage import LocalStorage

PFX_PASSWORD = "senha-teste"


def _cert(name: str, key, issuer_cert=None, issuer_key=None, ca=False):
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        ku = x509.KeyUsage(True, False, False, False, False, True, True, False, False)
    else:
        ku = x509.KeyUsage(True, True, False, False, False, False, False, False, False)
    b = b.add_extension(ku, critical=True)
    return b.sign(issuer_key or key, hashes.SHA256())


@pytest.fixture(scope="session")
def pki(tmp_path_factory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("pki")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _cert("AC Teste Portal", ca_key, ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert("EMPRESA TESTE LTDA:12345678000199", key, ca, ca_key)
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (d / "ecnpj.pfx").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"ecnpj",
            key,
            leaf,
            [ca],
            serialization.BestAvailableEncryption(PFX_PASSWORD.encode()),
        )
    )
    return {"ca": d / "ca.pem", "pfx": d / "ecnpj.pfx"}


def make_pdf(lines: list[str] | list[list[str]], label: str = "Assinatura do Colaborador") -> bytes:
    """Gera um PDF simples; ``lines`` pode ser lista de páginas."""
    pages = lines if lines and isinstance(lines[0], list) else [lines]
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    for page in pages:
        y = 800
        for line in page:
            c.drawString(60, y, line)
            y -= 16
        if label:
            c.line(300, 120, 540, 120)
            c.drawString(300, 105, label)
        c.showPage()
    c.save()
    return buf.getvalue()


TEST_DB_URL = os.environ.get("PORTAL_TEST_DATABASE_URL", "")


@pytest.fixture
def settings(tmp_path, pki) -> Settings:
    return Settings(
        env="test",
        base_url="http://testserver",
        company_name="Empresa Teste Ltda",
        company_cnpj="12.345.678/0001-99",
        secret_key="x" * 40,
        database_url=TEST_DB_URL or f"sqlite:///{tmp_path}/t.sqlite3",
        storage_backend="local",
        storage_local_path=tmp_path / "storage",
        auth_provider="dev",
        signing_pfx_file=pki["pfx"],
        signing_pfx_password=PFX_PASSWORD,
        signing_ca_chain_files=[pki["ca"]],
    )


@pytest.fixture
def database(settings) -> Database:
    db = Database(settings.database_url)
    if TEST_DB_URL:  # PostgreSQL real (CI): esquema limpo a cada teste
        from portal.db import Base

        Base.metadata.drop_all(db.engine)
    db.create_all()
    yield db
    db.engine.dispose()


@pytest.fixture
def session(database):
    with database.sessionmaker() as s:
        yield s


@pytest.fixture
def storage(settings) -> LocalStorage:
    return LocalStorage(settings.storage_local_path)


@pytest.fixture
def sealer(settings) -> Sealer:
    return Sealer(
        settings.signing_pfx_file,
        settings.signing_pfx_password.get_secret_value(),
        ca_chain_files=settings.signing_ca_chain_files,
    )


@pytest.fixture
def seeded(session):
    """Colaboradores alinhados aos usuários do DevAuthProvider + tipos de documento."""
    maria = Employee(matricula="000123", nome="Maria Silva", cpf="12345678909")
    joao = Employee(matricula="000456", nome="João Souza", cpf="98765432100")
    holerite = DocumentType(
        code="HOLERITE",
        nome="Recibo de pagamento (holerite)",
        requires_acceptance=True,
        declaration_text="Declaro que recebi o recibo de pagamento acima.",
        anchor_text="Assinatura do Colaborador",
        anchor_page=-1,
        anchor_box=[300, 40, 560, 110],
    )
    informe = DocumentType(
        code="INFORME",
        nome="Informe de rendimentos",
        requires_acceptance=False,
        declaration_text="Ciência.",
    )
    session.add_all([maria, joao, holerite, informe])
    session.flush()
    from portal.terms import DEFAULT_TERM_V1, TermService

    terms = TermService(session)
    term = terms.publish("1", DEFAULT_TERM_V1, published_by="rh.admin")
    for emp in (maria, joao):
        terms.register(
            emp, term, channel="papel", actor_type="rh", registered_by="rh.admin", note="teste"
        )
    session.commit()
    return {"maria": maria, "joao": joao, "holerite": holerite, "informe": informe, "term": term}


@pytest.fixture
def batch_pdf():
    """PDF único da folha: 2 colaboradores conhecidos (um com 2 páginas) e 1 desconhecido."""
    return make_pdf(
        [
            ["HOLERITE", "Matrícula: 000123", "Maria Silva"],
            ["(continuação) Maria"],
            ["HOLERITE", "Matrícula: 000456", "João Souza"],
            ["HOLERITE", "Matrícula: 999999", "Desconhecido"],
        ]
    )
