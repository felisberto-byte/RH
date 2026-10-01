"""Linha de comando de operação: ``portal <comando>``.

Exemplos::

    portal init-db                      # cria tabelas (dev) — em produção use alembic
    portal seed                         # tipos de documento padrão
    portal import-employees colaboradores.csv
    portal ingest --tipo HOLERITE --competencia 2026-09 \
        --titulo "Holerite setembro/2026" folha_092026.pdf
    portal verify-audit                 # cadeia de hashes completa + âncoras (diário)
    portal anchor-audit                 # carimba (RFC 3161) a cabeça da cadeia — diário
    portal purge --dias 180             # expurga tentativas de login/sessões antigas (LGPD)
    portal db-app-role                  # (job de migração) cria o papel de banco do app
    portal cert-info                    # validade do e-CNPJ (renovação anual do A1)
    portal dev-cert var/dev             # gera certificado de TESTE autoassinado
    portal demo                         # (dev) colaboradores + lote de holerites de exemplo
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from portal.config import get_settings
from portal.db import Database
from portal.logs import setup_logging

log = logging.getLogger("portal.cli")

DEFAULT_TYPES = [
    {
        "code": "HOLERITE",
        "nome": "Recibo de pagamento (holerite)",
        "requires_acceptance": True,
        "declaration_text": (
            "Declaro que recebi este recibo de pagamento e tomei ciência de seu conteúdo "
            "integral, ciente de que poderei contestá-lo junto ao RH."
        ),
        "anchor_text": "Assinatura do Funcionário",
        "manifestation_kind": "ciencia",
        "retention_years": 10,
    },
    {
        "code": "CONTRATO",
        "nome": "Contrato de trabalho",
        "requires_acceptance": True,
        "declaration_text": (
            "Li integralmente e concordo com os termos deste contrato de trabalho, cuja via "
            "eletrônica tem o mesmo valor da via física."
        ),
        "anchor_text": "Assinatura do Empregado",
        "manifestation_kind": "aceite",
        "requires_totp": False,  # recomendado True após todos configurarem o autenticador
        "retention_years": 30,
    },
    {
        "code": "ADITIVO",
        "nome": "Termo aditivo ao contrato de trabalho",
        "requires_acceptance": True,
        "declaration_text": "Li integralmente e concordo com os termos deste aditivo contratual.",
        "anchor_text": "Assinatura do Empregado",
        "manifestation_kind": "aceite",
        "requires_totp": False,
        "retention_years": 30,
    },
    {
        "code": "INFORME_IR",
        "nome": "Informe de rendimentos",
        "requires_acceptance": False,
        "declaration_text": "Documento informativo.",
        "anchor_text": None,
        "manifestation_kind": "ciencia",
        "retention_years": 10,
    },
]


def _db() -> Database:
    return Database(get_settings().database_url)


def cmd_init_db(_args) -> int:
    _db().create_all()
    print("Tabelas criadas.")
    return 0


def cmd_seed(_args) -> int:
    from portal.models import DocumentType

    db = _db()
    with db.sessionmaker() as s:
        for t in DEFAULT_TYPES:
            if s.scalar(select(DocumentType).where(DocumentType.code == t["code"])) is None:
                s.add(DocumentType(**t))
                print(f"+ {t['code']}")
        from portal.terms import DEFAULT_TERM_V1, TermService

        terms = TermService(s)
        if terms.active() is None:
            terms.publish("1", DEFAULT_TERM_V1, published_by="seed")
            print("+ Termo de Adesão v1 (revise com o jurídico e publique nova versão se preciso)")
        s.commit()
    return 0


def cmd_import_employees(args) -> int:
    from portal import audit
    from portal.employees import (
        EmployeeImportError,
        decode_csv,
        parse_employees_csv,
        upsert_employees,
    )

    raw = Path(args.csv).read_bytes()
    with _db().sessionmaker() as s:
        try:
            result = upsert_employees(s, parse_employees_csv(decode_csv(raw)))
        except EmployeeImportError as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 1
        audit.record(
            s,
            action="COLABORADORES_IMPORTADOS",
            actor_type="sistema",
            actor_ref="cli",
            data={
                "arquivo": Path(args.csv).name,
                "criados": result.created,
                "atualizados": result.updated,
                "desativados": result.deactivated,
                "sha256": audit.sha256_hex(raw),
            },
        )
        s.commit()
    print(
        f"{result.created} criado(s), {result.updated} atualizado(s), "
        f"{len(result.deactivated)} desativado(s)."
    )
    return 0


def cmd_ingest(args) -> int:
    from portal.documents.ingest import DEFAULT_PATTERN, BatchImporter
    from portal.documents.service import DocumentService
    from portal.models import DocumentType
    from portal.storage import build_storage
    from portal.web.app import build_sealer

    s = get_settings()
    sealer = build_sealer(s)
    if sealer is None:
        print("Configure PORTAL_SIGNING_PFX_FILE.", file=sys.stderr)
        return 2
    with _db().sessionmaker() as db:
        doc_type = db.scalar(select(DocumentType).where(DocumentType.code == args.tipo))
        if doc_type is None:
            print(f"Tipo {args.tipo} não encontrado (rode `portal seed`).", file=sys.stderr)
            return 2
        importer = BatchImporter(db, DocumentService(db, build_storage(s), s, sealer))
        path = Path(args.arquivo)
        batch, report = importer.run(
            filename=path.name,
            data=path.read_bytes(),
            doc_type=doc_type,
            competencia=args.competencia,
            titulo=args.titulo or doc_type.nome,
            created_by=args.usuario,
            key_field=args.chave,
            pattern=args.padrao or DEFAULT_PATTERN,
        )
    print(f"Lote #{batch.id}: {len(report.created)} documento(s) publicado(s).")
    for e in report.errors:
        print(f"  ! {e}")
    if report.unmatched_pages:
        print(f"  ! páginas sem identificação: {[p + 1 for p in report.unmatched_pages]}")
    return 1 if report.errors or report.unmatched_pages else 0


def cmd_verify_audit(_args) -> int:
    """Verificação COMPLETA: cadeia inteira + cada âncora (evento ancorado
    inalterado, token íntegro e imprint = hash carimbado)."""
    from portal.audit import verify_anchors, verify_chain
    from portal.signing.pades import load_cert_files
    from portal.storage import build_storage

    s = get_settings()
    roots = load_cert_files(s.signing_trust_root_files) if s.signing_trust_root_files else None
    with _db().sessionmaker() as db:
        rep = verify_chain(db)
        verify_anchors(db, build_storage(s), trust_roots=roots, report=rep)
    if rep.ok:
        log.info(
            "auditoria íntegra: %s eventos, %s âncora(s) conferida(s), última ancorada #%s, cabeça %s",
            rep.checked,
            rep.anchors_checked,
            rep.last_anchored_event_id,
            rep.head_hash,
        )
        return 0
    log.error(
        "CADEIA DE AUDITORIA COM FALHA: evento=%s motivo=%s ancoras=%s",
        rep.first_bad_id,
        rep.reason,
        "; ".join(rep.anchor_problems) or "ok",
    )
    return 1


def cmd_db_app_role(args) -> int:
    """Cria/atualiza o papel de LOGIN da aplicação via SQL (executado pelo dono
    do esquema, no job de migração). Lê apenas PORTAL_DATABASE_URL e
    PORTAL_DB_APP_PASSWORD; os privilégios nas tabelas vêm da migração."""
    import os
    import re

    from sqlalchemy import create_engine, text

    role = args.papel
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        log.error("nome de papel inválido: %s", role)
        return 2
    url = os.environ.get("PORTAL_DATABASE_URL", "")
    password = os.environ.get("PORTAL_DB_APP_PASSWORD", "")
    if not url.startswith("postgresql") or len(password) < 16:
        log.error("defina PORTAL_DATABASE_URL (PostgreSQL, dono) e PORTAL_DB_APP_PASSWORD (>= 16)")
        return 2
    engine = create_engine(url)
    with engine.begin() as c:
        exists = c.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar()
        verb = "ALTER" if exists else "CREATE"
        # format(%I, %L) no servidor: identificador e senha corretamente citados.
        stmt = c.execute(
            text("SELECT format(CAST(:tpl AS text), CAST(:r AS text), CAST(:p AS text))"),
            {
                "tpl": f"{verb} ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L",
                "r": role,
                "p": password,
            },
        ).scalar()
        c.exec_driver_sql(str(stmt))
        grant = c.execute(
            text(
                "SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), "
                "CAST(:r AS text))"
            ),
            {"r": role},
        ).scalar()
        c.exec_driver_sql(str(grant))
    engine.dispose()
    log.info("papel %s %s", role, "atualizado" if exists else "criado")
    return 0


def cmd_purge(args) -> int:
    """Minimização (LGPD): apaga tentativas de login e sessões encerradas mais
    antigas que ``--dias``. Documentos, aceites e auditoria NÃO são tocados
    (retenção legal; bucket com política de retenção)."""
    from sqlalchemy import delete, or_

    from portal import audit
    from portal.db import utcnow
    from portal.models import LoginAttempt, UserSession

    if args.dias < 30:
        log.error("--dias deve ser >= 30 (as tentativas recentes sustentam o bloqueio por conta)")
        return 2
    cutoff = utcnow() - timedelta(days=args.dias)
    s = get_settings()
    with _db().sessionmaker() as db:
        attempts = db.execute(delete(LoginAttempt).where(LoginAttempt.at < cutoff)).rowcount  # type: ignore[attr-defined]
        idle_cut = utcnow() - timedelta(hours=s.session_absolute_hours)
        sessions = db.execute(
            delete(UserSession).where(
                or_(UserSession.revoked.is_(True), UserSession.created_at < idle_cut),
                UserSession.last_seen_at < cutoff,
            )
        ).rowcount  # type: ignore[attr-defined]
        audit.record(
            db,
            action="DADOS_OPERACIONAIS_EXPURGADOS",
            actor_type="sistema",
            actor_ref="purge",
            data={"dias": args.dias, "tentativas_login": attempts, "sessoes": sessions},
        )
        db.commit()
    log.info("expurgo: %s tentativa(s) de login e %s sessão(ões) removidas", attempts, sessions)
    return 0


def cmd_anchor_audit(_args) -> int:
    from pyhanko.sign import timestamps

    from portal.anchoring import anchor_audit
    from portal.storage import build_storage

    s = get_settings()
    if not s.tsa_url:
        print("Configure PORTAL_TSA_URL (ACT ICP-Brasil recomendada).", file=sys.stderr)
        return 2
    auth = (s.tsa_username, s.tsa_password.get_secret_value()) if s.tsa_username else None
    ts = timestamps.HTTPTimeStamper(s.tsa_url, auth=auth, timeout=20)
    with _db().sessionmaker() as db:
        a = anchor_audit(db, build_storage(s), ts, s.tsa_url)
    log.info("auditoria ancorada: evento %s (%s); token %s", a.head_event_id, a.head_hash, a.token_key)
    return 0


def cmd_cert_info(args) -> int:
    from portal.web.app import build_sealer

    sealer = build_sealer(get_settings())
    if sealer is None:
        print("Certificado não configurado.", file=sys.stderr)
        return 2
    exp = sealer.not_valid_after()
    days = (exp - datetime.now(UTC)).days
    print(f"Titular: {sealer.subject}\nVálido até: {exp:%d/%m/%Y %H:%M} UTC ({days} dias)")
    if days < args.alerta_dias:
        log.error("CERTIFICADO e-CNPJ vence em %s dia(s) (%s): renove já", days, f"{exp:%d/%m/%Y}")
        return 1
    return 0


def sample_payslips(people: list[tuple[str, str]], competencia: str) -> bytes:
    """PDF de exemplo no layout típico de holerite (uma página por colaborador)."""
    import io

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    for matricula, nome in people:
        c.setFont("Helvetica-Bold", 13)
        c.drawString(50, 800, "RECIBO DE PAGAMENTO DE SALÁRIO")
        c.setFont("Helvetica", 10)
        c.drawString(50, 780, f"Empresa Exemplo Ltda — Competência {competencia}")
        c.drawString(50, 760, f"Matrícula: {matricula}    Nome: {nome}")
        rows = [
            ("Salário base", "3.500,00", ""),
            ("Horas extras 50%", "412,50", ""),
            ("INSS", "", "389,67"),
            ("IRRF", "", "121,32"),
            ("Vale-transporte", "", "210,00"),
        ]
        y = 720
        c.drawString(50, y, "Descrição")
        c.drawString(330, y, "Proventos")
        c.drawString(440, y, "Descontos")
        for desc, prov, descs in rows:
            y -= 18
            c.drawString(50, y, desc)
            c.drawRightString(400, y, prov)
            c.drawRightString(510, y, descs)
        c.drawString(50, y - 30, "Líquido a receber: R$ 3.191,51")
        c.line(300, 120, 540, 120)
        c.drawString(300, 105, "Assinatura do Funcionário")
        c.showPage()
    c.save()
    return buf.getvalue()


def cmd_demo(args) -> int:
    """Popula o ambiente de DESENVOLVIMENTO com colaboradores e um lote de holerites."""
    from portal.auth.dev import DEV_USERS
    from portal.documents.ingest import BatchImporter
    from portal.documents.service import DocumentService
    from portal.models import DocumentType, Employee
    from portal.storage import build_storage
    from portal.web.app import build_sealer

    s = get_settings()
    if s.env == "prod":
        print("Comando disponível só fora de produção.", file=sys.stderr)
        return 2
    sealer = build_sealer(s)
    if sealer is None:
        print("Configure PORTAL_SIGNING_PFX_FILE (use `portal dev-cert`).", file=sys.stderr)
        return 2
    cmd_seed(args)
    with _db().sessionmaker() as db:
        people = []
        for username, u in DEV_USERS.items():
            if u.get("is_admin"):
                continue
            mat = u["employee_id"]
            if db.scalar(select(Employee).where(Employee.matricula == mat)) is None:
                db.add(Employee(matricula=mat, nome=u["display_name"], email=f"{username}@dev.local"))
            people.append((mat, u["display_name"]))
        db.commit()
        holerite = db.scalar(select(DocumentType).where(DocumentType.code == "HOLERITE"))
        if holerite is None:
            print("Tipo HOLERITE ausente.", file=sys.stderr)
            return 2
        importer = BatchImporter(db, DocumentService(db, build_storage(s), s, sealer))
        batch, report = importer.run(
            filename=f"folha-{args.competencia}.pdf",
            data=sample_payslips(people, args.competencia),
            doc_type=holerite,
            competencia=args.competencia,
            titulo=f"Holerite {args.competencia}",
            created_by="demo",
        )
    print(f"Lote #{batch.id}: {len(report.created)} holerite(s). Entre como maria.silva / dev.")
    return 0


def cmd_dev_cert(args) -> int:
    """Gera AC + certificado de teste (NÃO é ICP-Brasil; só para desenvolvimento)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    out = Path(args.destino)
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC)

    def build(name, key, issuer=None, issuer_key=None, ca=False):
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        b = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(issuer.subject if issuer else subj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        ku = (
            x509.KeyUsage(True, False, False, False, False, True, True, False, False)
            if ca
            else x509.KeyUsage(True, True, False, False, False, False, False, False, False)
        )
        return b.add_extension(ku, critical=True).sign(issuer_key or key, hashes.SHA256())

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = build("AC DESENVOLVIMENTO (NAO ICP-BRASIL)", ca_key, ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = build("EMPRESA DEV LTDA:00000000000000", key, ca, ca_key)
    (out / "dev-ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (out / "dev-ecnpj.pfx").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"dev", key, leaf, [ca], serialization.BestAvailableEncryption(args.senha.encode())
        )
    )
    print(f"Gerado {out / 'dev-ecnpj.pfx'} (senha: {args.senha}) e {out / 'dev-ca.pem'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="portal", description="Portal do Colaborador — operação")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db").set_defaults(fn=cmd_init_db)
    sub.add_parser("seed").set_defaults(fn=cmd_seed)
    ie = sub.add_parser("import-employees")
    ie.add_argument("csv")
    ie.set_defaults(fn=cmd_import_employees)
    ing = sub.add_parser("ingest")
    ing.add_argument("arquivo")
    ing.add_argument("--tipo", required=True)
    ing.add_argument("--competencia")
    ing.add_argument("--titulo")
    ing.add_argument("--chave", default="matricula", choices=["matricula", "cpf"])
    ing.add_argument("--padrao")
    ing.add_argument("--usuario", default="sistema-folha")
    ing.set_defaults(fn=cmd_ingest)
    sub.add_parser("verify-audit").set_defaults(fn=cmd_verify_audit)
    sub.add_parser("anchor-audit").set_defaults(fn=cmd_anchor_audit)
    dr = sub.add_parser("db-app-role")
    dr.add_argument("--papel", default="portal_app")
    dr.set_defaults(fn=cmd_db_app_role)
    pg = sub.add_parser("purge")
    pg.add_argument("--dias", type=int, default=180)
    pg.set_defaults(fn=cmd_purge)
    ci = sub.add_parser("cert-info")
    ci.add_argument("--alerta-dias", type=int, default=45)
    ci.set_defaults(fn=cmd_cert_info)
    dm = sub.add_parser("demo")
    dm.add_argument("--competencia", default="2026-09")
    dm.set_defaults(fn=cmd_demo)
    dc = sub.add_parser("dev-cert")
    dc.add_argument("destino", nargs="?", default="var/dev")
    dc.add_argument("--senha", default="dev")
    dc.set_defaults(fn=cmd_dev_cert)
    args = p.parse_args(argv)
    setup_logging()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
