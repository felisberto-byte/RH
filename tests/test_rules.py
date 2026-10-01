"""Regras de segurança/operação: bloqueio por conta canônica, guardas de
produção, importação de colaboradores, editor de tipos, verificação pública,
páginas de erro e revalidação de sessão."""

from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.dev import DEV_USERS, DevAuthProvider
from portal.config import Settings
from portal.db import utcnow
from portal.employees import (
    EmployeeImportError,
    decode_csv,
    parse_employees_csv,
    upsert_employees,
)
from portal.models import AuditEvent, Document, DocumentType, Employee, UserSession
from portal.web.app import create_app
from tests.test_web import csrf_of, login, upload_batch


@pytest.fixture
def app(settings, database, storage, sealer, seeded):
    return create_app(
        settings,
        auth=DevAuthProvider(dict(DEV_USERS)),
        sealer=sealer,
        storage=storage,
        database=database,
    )


# ------------------------------------------------------------------ login
def test_lockout_is_shared_by_username_variants(app):
    c = TestClient(app)
    for name in ("maria.silva", "EMPRESA\\maria.silva", "Maria.Silva@empresa.local", "MARIA.SILVA"):
        assert login(c, name, "errada").status_code == 401
    assert login(c, "maria.silva", "errada").status_code == 401  # 5ª falha
    # a 6ª tentativa, mesmo com a senha certa e outra grafia, é bloqueada
    r = login(c, "empresa\\MARIA.SILVA", "dev")
    assert r.status_code == 429 and "Muitas tentativas" in r.text


# ----------------------------------------------------------- produção
PROD_OK = dict(
    env="prod",
    secret_key="x" * 40,
    base_url="https://portal.empresa.com.br",
    auth_provider="ldap",
    ldap_url="ldaps://dc01.empresa.local:636",
    trusted_proxy_hops=2,
    tsa_url="https://act.exemplo.com.br/tsa",
    database_url="postgresql+psycopg://portal:x@10.0.0.5/portal",
)


@pytest.mark.parametrize(
    "override, message",
    [
        ({"base_url": "http://portal.empresa.com.br"}, "https"),
        ({"ldap_url": "ldap://dc01:389"}, "LDAPS"),
        ({"trusted_proxy_hops": 0}, "PROXY_HOPS"),
        ({"tsa_url": ""}, "TSA"),
        ({"database_url": "sqlite:///var/x.db"}, "PostgreSQL"),
        ({"auth_provider": "dev"}, "dev"),
        ({"secret_key": "curta"}, "32"),
    ],
)
def test_prod_guards(override, message):
    Settings(**PROD_OK)  # a base é válida
    with pytest.raises(ValueError, match=message):
        Settings(**{**PROD_OK, **override})


def test_settings_errors_do_not_echo_secrets():
    with pytest.raises(ValueError) as exc:
        Settings(env="test", ldap_timeout_seconds="SEGREDO-NAO-PODE-VAZAR")
    assert "SEGREDO-NAO-PODE-VAZAR" not in str(exc.value)


# ------------------------------------------------------- colaboradores CSV
def test_csv_import_rules(session, seeded):
    with pytest.raises(EmployeeImportError, match="matrícula repetida"):
        parse_employees_csv("matricula;nome\n1;A\n1;B\n")
    with pytest.raises(EmployeeImportError, match="CPF repetido"):
        parse_employees_csv("matricula;nome;cpf\n1;A;123.456.789-09\n2;B;12345678909\n")
    with pytest.raises(EmployeeImportError, match="ativo"):
        parse_employees_csv("matricula;nome;ativo\n1;A;talvez\n")
    # NBSP e BOM de planilha
    rows = parse_employees_csv(decode_csv("﻿matricula;nome\n7;Ana  Lima\n".encode()))
    assert rows[0]["nome"] == "Ana Lima" and rows[0]["ativo"] is None

    maria = seeded["maria"]
    session.add(
        UserSession(
            token_hash="t" * 64,
            employee_id=maria.id,
            username="maria.silva",
            display_name="Maria",
            object_guid="g",
            dn="cn=m",
            csrf_token="c",
            ip="1.1.1.1",
            user_agent="x",
        )
    )
    session.commit()
    # desativar encerra as sessões; ativo vazio NÃO reativa
    res = upsert_employees(session, parse_employees_csv("matricula;nome;ativo\n000123;Maria Silva;0\n"))
    session.commit()
    assert res.deactivated == [maria.id]
    assert session.get(UserSession, "t" * 64).revoked
    upsert_employees(session, parse_employees_csv("matricula;nome\n000123;Maria Silva\n"))
    session.commit()
    assert session.get(Employee, maria.id).ativo is False
    # mesmo CPF em outra matrícula é conflito (readmissão exige tratamento do RH)
    assert session.get(Employee, maria.id).cpf == "12345678909"  # sem coluna cpf: mantém
    with pytest.raises(EmployeeImportError, match="CPF já cadastrado"):
        upsert_employees(session, parse_employees_csv("matricula;nome;cpf\n555;Outra;12345678909\n"))
    session.rollback()
    # readmissão: limpa o CPF do vínculo antigo ("-") e cadastra a nova matrícula
    csv_text = "matricula;nome;cpf\n000123;Maria Silva;-\n555;Maria Silva;12345678909\n"
    upsert_employees(session, parse_employees_csv(csv_text))
    session.commit()
    assert session.get(Employee, maria.id).cpf is None


# ------------------------------------------------------- tipos de documento
def test_type_editor_is_audited_and_does_not_change_issued_docs(app, batch_pdf, session):
    admin = TestClient(app)
    login(admin, "rh.admin")
    assert upload_batch(admin, batch_pdf).status_code == 303
    holerite = session.query(DocumentType).filter_by(code="HOLERITE").one()
    issued = session.query(Document).filter_by(document_type_id=holerite.id).first()
    old_declaration = issued.declaration_text
    tipo_id = holerite.id
    session.rollback()

    page = admin.get("/rh/tipos")
    assert page.status_code == 200 and "HOLERITE" in page.text
    form = {
        "tipo_id": tipo_id,
        "code": "HOLERITE",
        "nome": "Recibo de pagamento (holerite)",
        "declaracao": "Nova redação da declaração de ciência do recibo.",
        "natureza": "ciencia",
        "exige_aceite": "sim",
        "ancora_texto": "Assinatura do Colaborador",
        "ancora_pagina": -1,
        "ancora_caixa": "300,40,560,110",
        "motor": "nativo",
        "retencao_anos": 10,
        "ativo": "sim",
        "csrf": csrf_of(page.text),
    }
    r = admin.post("/rh/tipos", data=form, follow_redirects=False)
    assert r.status_code == 303
    ev = session.query(AuditEvent).filter_by(action="TIPO_DOCUMENTO_ALTERADO").one()
    assert ev.data["antes"]["declaration_sha256"] != ev.data["depois"]["declaration_sha256"]
    assert session.get(Document, issued.id).declaration_text == old_declaration
    # caixa inválida é recusada
    r = admin.post("/rh/tipos", data={**form, "ancora_caixa": "10,10,5,5"})
    assert r.status_code == 400 and "Caixa" in r.text


# ------------------------------------------------------- verificação pública
def test_verify_code_form_and_cancelled_document(app, batch_pdf, session):
    admin = TestClient(app)
    login(admin, "rh.admin")
    upload_batch(admin, batch_pdf)
    doc = session.query(Document).first()
    doc_id, code = doc.id, doc.verification_code
    session.rollback()
    anon = TestClient(app)
    r = anon.get("/verificar", params={"codigo": code.lower()}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/verificar/{code}"
    assert anon.get(f"/verificar/{code}").status_code == 200
    assert anon.get("/verificar", params={"codigo": "<script>"}).status_code == 400

    csrf = csrf_of(admin.get("/rh/documentos").text)
    admin.post(f"/rh/documentos/{doc_id}/cancelar", data={"motivo": "emitido errado", "csrf": csrf})
    r = anon.get(f"/verificar/{code}")
    assert r.status_code == 200 and "cancelado" in r.text and "emitido errado" not in r.text
    # o formulário de arquivo continua disponível com token próprio
    assert re.search(r'name="verify_csrf" value="[^"]+"', r.text)
    r = anon.post("/verificar", data={"verify_csrf": "x"}, files={"arquivo": ("a.pdf", b"%PDF")})
    assert r.status_code == 400 and "expirado" in r.text


# ------------------------------------------------------------ erros/saúde
def test_error_pages_are_portuguese_and_keep_navigation(app):
    c = TestClient(app)
    html = {"accept": "text/html"}
    r = c.get("/nao-existe", headers=html)
    assert r.status_code == 404 and "Página não encontrada" in r.text
    assert c.get("/nao-existe").json() == {"detail": "Página não encontrada."}
    login(c, "rh.admin")
    r = c.get("/rh/lotes/abc", headers=html)
    assert r.status_code == 400 and "Dados do formulário inválidos" in r.text
    assert "Área do RH" in r.text  # navegação do usuário logado
    assert "Traceback" not in r.text


def test_readyz_checks_database_and_certificate(app):
    c = TestClient(app)
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/readyz").json() == {"status": "ok"}
    app.state.ctx.sealer = None
    r = c.get("/readyz")
    assert r.status_code == 503 and "certificado_nao_configurado" in r.json()["falhas"]


# ------------------------------------------------------ revalidação no AD
def test_session_revoked_when_account_leaves_directory(app, session):
    c = TestClient(app)
    login(c, "maria.silva")
    assert c.get("/documentos").status_code == 200
    app.state.ctx.auth.users.pop("maria.silva")  # desabilitada/fora do grupo no AD
    sess = session.query(UserSession).filter_by(username="maria.silva").one()
    sess.validated_at = utcnow() - timedelta(hours=1)
    session.commit()
    r = c.get("/documentos", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?msg=expirou"
    session.expire_all()
    ev = session.query(AuditEvent).filter_by(action="SESSAO_REVOGADA").one()
    assert "AD" in json.dumps(ev.data, ensure_ascii=False)


# ------------------------------------------------------------ .env.example
def test_env_example_documents_every_setting_and_loads():
    from pathlib import Path

    from dotenv import dotenv_values

    path = Path(__file__).resolve().parents[1] / ".env.example"
    text_ = path.read_text(encoding="utf-8")
    for name in Settings.model_fields:
        var = f"PORTAL_{name.upper()}"
        assert re.search(rf"^(# )?{var}=", text_, re.M), f"{var} ausente do .env.example"
    for line in text_.splitlines():  # sem comentário no fim da linha
        if line and not line.startswith("#"):
            assert " #" not in line, line
    values = dotenv_values(path)
    assert values["PORTAL_ENV"] == "dev"
    s = Settings(_env_file=str(path))
    assert s.env == "dev" and s.auth_provider == "dev"
