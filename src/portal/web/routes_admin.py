"""Área do RH: importação de lotes, acompanhamento, dossiê e cadastro."""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from portal import audit
from portal.audit import canonical_json
from portal.documents.ingest import DEFAULT_PATTERN, BatchImporter
from portal.documents.service import DocumentError, NotFound, new_verification_code
from portal.models import (
    AuditEvent,
    Batch,
    DocStatus,
    Document,
    DocumentType,
    Employee,
    Engine,
)
from portal.web import security
from portal.web.deps import (
    CurrentUser,
    app_ctx,
    document_service,
    get_db,
    render,
    require_admin,
)

router = APIRouter(prefix="/rh")

MAX_UPLOAD = 200 * 1024 * 1024


def _check_csrf(user: CurrentUser, csrf: str) -> None:
    if not security.csrf_ok(user.session.csrf_token, csrf):
        raise HTTPException(status_code=403, detail="Formulário expirado. Recarregue a página.")


def _ip(request: Request) -> str:
    return security.client_ip(request, app_ctx(request).settings.trusted_proxy_hops)


@router.get("")
def dashboard(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    counts = dict(db.execute(select(Document.status, func.count()).group_by(Document.status)).all())
    batches = db.scalars(select(Batch).order_by(Batch.id.desc()).limit(10)).all()
    oldest_pending = db.scalars(
        select(Document)
        .where(Document.status == DocStatus.PENDENTE)
        .order_by(Document.created_at)
        .limit(10)
    ).all()
    return render(
        request,
        "admin/painel.html",
        user=user,
        counts=counts,
        batches=batches,
        oldest_pending=oldest_pending,
    )


# ------------------------------------------------------------------ lotes
@router.get("/lotes/novo")
def batch_form(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    types = db.scalars(
        select(DocumentType).where(DocumentType.ativo.is_(True), DocumentType.engine == Engine.NATIVO)
    ).all()
    return render(
        request,
        "admin/lote_novo.html",
        user=user,
        types=types,
        default_pattern=DEFAULT_PATTERN,
        error=None,
    )


@router.post("/lotes/novo")
async def batch_upload(
    request: Request,
    tipo: int = Form(...),
    competencia: str = Form(""),
    titulo: str = Form(...),
    chave: str = Form("matricula"),
    padrao: str = Form(DEFAULT_PATTERN),
    arquivo: UploadFile = File(...),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _check_csrf(user, csrf)
    doc_type = db.get(DocumentType, tipo)
    types = db.scalars(
        select(DocumentType).where(DocumentType.ativo.is_(True), DocumentType.engine == Engine.NATIVO)
    ).all()

    def fail(msg: str, code: int = 400):
        return render(
            request,
            "admin/lote_novo.html",
            status_code=code,
            user=user,
            types=types,
            default_pattern=DEFAULT_PATTERN,
            error=msg,
        )

    if doc_type is None or doc_type.engine != Engine.NATIVO:
        return fail("Tipo de documento inválido.")
    try:
        re.compile(padrao)
    except re.error:
        return fail("Expressão regular inválida.")
    data = await arquivo.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        return fail("Arquivo maior que 200 MB.", 413)
    importer = BatchImporter(db, document_service(request, db))
    try:
        # A assinatura (pyHanko) é síncrona e usa asyncio internamente: roda em thread.
        batch, _ = await run_in_threadpool(
            importer.run,
            filename=arquivo.filename or "lote",
            data=data,
            doc_type=doc_type,
            competencia=competencia or None,
            titulo=titulo.strip() or doc_type.nome,
            created_by=user.identity.username,
            key_field=chave,
            pattern=padrao,
        )
    except DocumentError as exc:
        db.rollback()
        return fail(str(exc))
    return RedirectResponse(f"/rh/lotes/{batch.id}", status_code=303)


@router.get("/lotes/{batch_id}")
def batch_detail(
    batch_id: int,
    request: Request,
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(status_code=404)
    return render(
        request,
        "admin/lote.html",
        user=user,
        batch=batch,
        doc_type=db.get(DocumentType, batch.document_type_id),
    )


# -------------------------------------------------------------- documentos
@router.get("/documentos")
def documents(
    request: Request,
    status: str = "",
    matricula: str = "",
    competencia: str = "",
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = select(Document).join(Employee).order_by(Document.created_at.desc()).limit(500)
    if status in DocStatus.__members__:
        q = q.where(Document.status == DocStatus(status))
    if matricula:
        q = q.where(Employee.matricula == matricula.strip())
    if competencia:
        q = q.where(Document.competencia == competencia.strip())
    docs = db.scalars(q).all()
    return render(
        request,
        "admin/documentos.html",
        user=user,
        docs=docs,
        status=status,
        matricula=matricula,
        competencia=competencia,
        statuses=list(DocStatus),
    )


@router.post("/documentos/{doc_id}/cancelar")
def cancel(
    doc_id: str,
    request: Request,
    motivo: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _check_csrf(user, csrf)
    try:
        document_service(request, db).cancel(
            doc_id, actor_ref=user.identity.username, reason=motivo, ip=_ip(request)
        )
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DocumentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/rh/documentos?msg=cancelado", status_code=303)


@router.get("/documentos/{doc_id}/dossie")
def dossier(
    doc_id: str,
    request: Request,
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """ZIP com todos os arquivos, a evidência e os eventos de auditoria do documento."""
    ctx = app_ctx(request)
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status_code=404)
    events = db.scalars(
        select(AuditEvent).where(AuditEvent.document_id == doc.id).order_by(AuditEvent.id)
    ).all()
    buf = io.BytesIO()
    files: dict[str, dict] = {}
    manifest = {
        "documento": doc.id,
        "codigo_verificacao": doc.verification_code,
        "status": doc.status,
        "arquivos": files,
    }
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for label, key, sha in (
            ("1-original.pdf", doc.original_key, doc.original_sha256),
            ("2-emitido-selado.pdf", doc.sealed_key, doc.sealed_sha256),
            ("3-com-aceite.pdf", doc.final_key, doc.final_sha256),
            ("4-comprovante.pdf", doc.receipt_key, doc.receipt_sha256),
        ):
            if key:
                data = ctx.storage.get(key)
                ok = audit.sha256_hex(data) == sha
                zf.writestr(label, data)
                files[label] = {"sha256": sha, "integro": ok}
        if doc.acceptance:
            zf.writestr("evidencia.json", doc.acceptance.evidence_json)
        zf.writestr(
            "auditoria.json",
            json.dumps(
                [
                    {
                        "id": e.id,
                        "data_hora_utc": audit.iso_utc(e.occurred_at),
                        "acao": e.action,
                        "ator": f"{e.actor_type}:{e.actor_ref}",
                        "ip": e.ip,
                        "user_agent": e.user_agent,
                        "dados": e.data,
                        "hash_anterior": e.prev_hash,
                        "hash": e.hash,
                    }
                    for e in events
                ],
                ensure_ascii=False,
                indent=2,
            ),
        )
        zf.writestr("manifesto.json", canonical_json(manifest))
    audit.record(
        db,
        action="DOSSIE_EXPORTADO",
        actor_type="rh",
        actor_ref=user.identity.username,
        document_id=doc.id,
        ip=_ip(request),
    )
    db.commit()
    return Response(
        buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="dossie-{doc.id}.zip"'},
    )


# --------------------------------------------------- documentos DocuSeal
@router.post("/docuseal/emitir")
def docuseal_issue(
    request: Request,
    tipo: int = Form(...),
    matriculas: str = Form(""),
    titulo: str = Form(""),
    competencia: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Cria pendências de assinatura via DocuSeal (o envio só é criado quando o
    colaborador abre o documento no portal)."""
    _check_csrf(user, csrf)
    doc_type = db.get(DocumentType, tipo)
    if doc_type is None or doc_type.engine != Engine.DOCUSEAL or not doc_type.docuseal_template_id:
        raise HTTPException(status_code=400, detail="Tipo DocuSeal inválido/sem template_id.")
    keys = [m for m in re.split(r"[\s,;]+", matriculas) if m]
    created = 0
    for key in keys:
        emp = db.scalar(select(Employee).where(Employee.matricula == key, Employee.ativo.is_(True)))
        if emp is None:
            continue
        doc = Document(
            employee_id=emp.id,
            document_type_id=doc_type.id,
            engine=Engine.DOCUSEAL,
            titulo=(titulo or doc_type.nome)[:200],
            competencia=competencia or None,
            status=DocStatus.PENDENTE,
            verification_code=new_verification_code(),
            created_by=user.identity.username,
        )
        db.add(doc)
        db.flush()
        audit.record(
            db,
            action="DOCUMENTO_EMITIDO",
            actor_type="rh",
            actor_ref=user.identity.username,
            document_id=doc.id,
            ip=_ip(request),
            data={
                "motor": "docuseal",
                "template_id": doc_type.docuseal_template_id,
                "colaborador_matricula": emp.matricula,
            },
        )
        created += 1
    db.commit()
    return RedirectResponse(f"/rh/documentos?status=PENDENTE&criados={created}", status_code=303)


# ------------------------------------------------------------ colaboradores
@router.get("/colaboradores")
def employees(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    emps = db.scalars(select(Employee).order_by(Employee.nome)).all()
    return render(request, "admin/colaboradores.html", user=user, employees=emps, error=None)


def parse_employees_csv(text: str) -> list[dict]:
    """CSV com cabeçalho: matricula;nome;cpf;email;ativo (separador ; ou ,)."""
    sample = text[:2048]
    dialect = csv.Sniffer().sniff(sample, delimiters=";,") if sample else csv.excel
    rows = []
    for i, row in enumerate(csv.DictReader(io.StringIO(text), dialect=dialect), start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if not row.get("matricula") or not row.get("nome"):
            raise DocumentError(f"Linha {i}: matrícula e nome são obrigatórios.")
        cpf = re.sub(r"\D", "", row.get("cpf", "")) or None
        if cpf and len(cpf) != 11:
            raise DocumentError(f"Linha {i}: CPF inválido.")
        rows.append(
            {
                "matricula": row["matricula"],
                "nome": row["nome"][:200],
                "cpf": cpf,
                "email": row.get("email") or None,
                "ativo": row.get("ativo", "1").lower() not in ("0", "nao", "não", "false", "n"),
            }
        )
    return rows


def upsert_employees(db: Session, rows: list[dict]) -> int:
    n = 0
    for r in rows:
        emp = db.scalar(select(Employee).where(Employee.matricula == r["matricula"]))
        if emp is None:
            emp = Employee(matricula=r["matricula"])
            db.add(emp)
        emp.nome, emp.cpf, emp.email, emp.ativo = r["nome"], r["cpf"], r["email"], r["ativo"]
        n += 1
    return n


@router.post("/colaboradores/importar")
async def employees_import(
    request: Request,
    arquivo: UploadFile = File(...),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _check_csrf(user, csrf)
    raw = await arquivo.read(10 * 1024 * 1024)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    try:
        n = upsert_employees(db, parse_employees_csv(text))
        audit.record(
            db,
            action="COLABORADORES_IMPORTADOS",
            actor_type="rh",
            actor_ref=user.identity.username,
            ip=_ip(request),
            data={"arquivo": arquivo.filename, "registros": n, "sha256": audit.sha256_hex(raw)},
        )
        db.commit()
    except (DocumentError, csv.Error) as exc:
        db.rollback()
        emps = db.scalars(select(Employee).order_by(Employee.nome)).all()
        return render(
            request,
            "admin/colaboradores.html",
            status_code=400,
            user=user,
            employees=emps,
            error=str(exc),
        )
    return RedirectResponse("/rh/colaboradores?msg=importado", status_code=303)


# ----------------------------------------------------------------- auditoria
@router.get("/auditoria")
def audit_view(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    report = audit.verify_chain(db)
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(200)).all()
    return render(request, "admin/auditoria.html", user=user, report=report, events=events)


# ------------------------------------------------------- termo de adesão
@router.get("/termo")
def term_admin(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    from portal.terms import DEFAULT_TERM_V1, TermService

    term = TermService(db).active()
    return render(
        request,
        "admin/termo.html",
        user=user,
        term=term,
        error=None,
        default_text=term.text if term else DEFAULT_TERM_V1,
    )


@router.post("/termo")
def term_publish(
    request: Request,
    versao: str = Form(""),
    texto: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from portal.terms import TermService

    _check_csrf(user, csrf)
    terms = TermService(db)
    try:
        terms.publish(versao, texto.replace("\r\n", "\n"), published_by=user.identity.username)
        db.commit()
    except ValueError as exc:
        db.rollback()
        return render(
            request,
            "admin/termo.html",
            status_code=400,
            user=user,
            term=terms.active(),
            error=str(exc),
            default_text=texto,
        )
    return RedirectResponse("/rh/termo?msg=termo", status_code=303)


@router.post("/colaboradores/{employee_id}/termo-externo")
def term_external(
    employee_id: int,
    request: Request,
    canal: str = Form("papel"),
    observacao: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Registra adesão coletada fora do portal (papel assinado ou gov.br)."""
    from portal.terms import TermService

    _check_csrf(user, csrf)
    emp = db.get(Employee, employee_id)
    terms = TermService(db)
    term = terms.active()
    if emp is None or term is None:
        raise HTTPException(status_code=404)
    if len(observacao.strip()) < 5:
        raise HTTPException(status_code=400, detail="Informe onde o termo físico está arquivado.")
    try:
        terms.register(
            emp,
            term,
            channel=canal,
            registered_by=user.identity.username,
            ip=_ip(request),
            note=observacao.strip()[:500],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return RedirectResponse("/rh/colaboradores?msg=registrado", status_code=303)


@router.post("/colaboradores/{employee_id}/mfa-redefinir")
def mfa_reset(
    employee_id: int,
    request: Request,
    motivo: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from portal.mfa import TotpService

    _check_csrf(user, csrf)
    if db.get(Employee, employee_id) is None:
        raise HTTPException(status_code=404)
    if len(motivo.strip()) < 5:
        raise HTTPException(status_code=400, detail="Informe o motivo da redefinição.")
    s = app_ctx(request).settings
    TotpService(db, s.secret_key.get_secret_value(), s.totp_issuer).reset(
        employee_id, actor_ref=user.identity.username, reason=motivo.strip()[:500], ip=_ip(request)
    )
    return RedirectResponse("/rh/colaboradores?msg=registrado", status_code=303)


@router.get("/colaboradores/{employee_id}/pacote")
def employee_package(
    employee_id: int,
    request: Request,
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Pacote com todos os documentos e comprovantes do colaborador (ex.: no
    desligamento, quando a conta do AD será desativada — LGPD arts. 18/19)."""
    ctx = app_ctx(request)
    emp = db.get(Employee, employee_id)
    if emp is None:
        raise HTTPException(status_code=404)
    docs = db.scalars(
        select(Document).where(Document.employee_id == emp.id).order_by(Document.created_at)
    ).all()
    buf = io.BytesIO()
    index = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for d in docs:
            if d.status == DocStatus.CANCELADO:
                continue
            base = f"{(d.competencia or 'sem-competencia')}_{d.document_type.code}_{d.id[:8]}"
            key, sha = (d.final_key, d.final_sha256) if d.final_key else (d.sealed_key, d.sealed_sha256)
            entry: dict[str, str | None] = {
                "documento": d.id,
                "titulo": d.titulo,
                "status": d.status,
                "codigo_verificacao": d.verification_code,
            }
            if key:
                data = ctx.storage.get(key)
                if audit.sha256_hex(data) != sha:
                    raise HTTPException(status_code=500, detail=f"Integridade falhou: {d.id}")
                zf.writestr(f"{base}.pdf", data)
                entry["arquivo"], entry["sha256"] = f"{base}.pdf", sha
            if d.receipt_key:
                zf.writestr(f"{base}_comprovante.pdf", ctx.storage.get(d.receipt_key))
                entry["comprovante_sha256"] = d.receipt_sha256
            index.append(entry)
        zf.writestr("indice.json", json.dumps(index, ensure_ascii=False, indent=2))
    audit.record(
        db,
        action="PACOTE_COLABORADOR_EXPORTADO",
        actor_type="rh",
        actor_ref=user.identity.username,
        ip=_ip(request),
        data={"matricula": emp.matricula, "documentos": len(index)},
    )
    db.commit()
    return Response(
        buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="pacote-{emp.matricula}.zip"'},
    )
