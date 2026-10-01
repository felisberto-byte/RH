"""Área do RH: importação de lotes, acompanhamento, dossiê, cadastro, tipos de
documento, termo de adesão e auditoria. Rotas síncronas (rodam em thread):
nada de E/S bloqueante no laço de eventos."""

from __future__ import annotations

import io
import json
import re
import zipfile

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import sha256_hex
from portal.documents.ingest import DEFAULT_PATTERN, BatchImporter
from portal.documents.service import DocumentError, NotFound, new_verification_code
from portal.dossier import build_dossier
from portal.employees import (
    EmployeeImportError,
    decode_csv,
    parse_employees_csv,
    revoke_sessions,
    upsert_employees,
)
from portal.models import (
    Acceptance,
    AuditAnchor,
    AuditEvent,
    Batch,
    DocStatus,
    Document,
    DocumentType,
    Employee,
    Engine,
    new_uuid,
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
_COMPETENCIA = re.compile(r"\d{4}-(0[1-9]|1[0-2])")


def _check_csrf(user: CurrentUser, csrf: str) -> None:
    if not security.csrf_ok(user.session.csrf_token, csrf):
        raise HTTPException(status_code=403, detail="Formulário expirado. Recarregue a página.")


def _ip(request: Request) -> str:
    return security.client_ip(request, app_ctx(request).settings.trusted_proxy_hops)


def _read_upload(arquivo: UploadFile, limit: int) -> bytes:
    data = arquivo.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail="Arquivo maior que o limite permitido.")
    return data


# ------------------------------------------------------------------ painel
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
    divergences = db.scalars(
        select(Acceptance)
        .where(Acceptance.decision == "RECUSADO")
        .order_by(Acceptance.accepted_at.desc())
        .limit(10)
    ).all()
    return render(
        request,
        "admin/painel.html",
        user=user,
        counts=counts,
        batches=batches,
        oldest_pending=oldest_pending,
        divergences=divergences,
    )


# ------------------------------------------------------------------ lotes
def _native_types(db: Session):
    return db.scalars(
        select(DocumentType).where(DocumentType.ativo.is_(True), DocumentType.engine == Engine.NATIVO)
    ).all()


@router.get("/lotes/novo")
def batch_form(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    return render(
        request,
        "admin/lote_novo.html",
        user=user,
        types=_native_types(db),
        default_pattern=DEFAULT_PATTERN,
        error=None,
    )


@router.post("/lotes/novo")
def batch_upload(
    request: Request,
    tipo: int = Form(0),
    competencia: str = Form(""),
    titulo: str = Form(""),
    chave: str = Form("matricula"),
    padrao: str = Form(DEFAULT_PATTERN),
    arquivo: UploadFile = File(...),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _check_csrf(user, csrf)
    types = _native_types(db)

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

    doc_type = db.get(DocumentType, tipo) if tipo else None
    if doc_type is None or doc_type.engine != Engine.NATIVO:
        return fail("Escolha um tipo de documento válido.")
    data = _read_upload(arquivo, MAX_UPLOAD)
    importer = BatchImporter(db, document_service(request, db))
    try:
        batch, _ = importer.run(
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
        raise HTTPException(status_code=404, detail="Lote não encontrado.")
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
    ctx = app_ctx(request)
    try:
        doc = document_service(request, db).cancel(
            doc_id, actor_ref=user.identity.username, reason=motivo, ip=_ip(request)
        )
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DocumentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if doc.engine == Engine.DOCUSEAL and doc.docuseal_submission_id and ctx.docuseal:
        ctx.docuseal.archive_submission(doc.docuseal_submission_id)
    return RedirectResponse("/rh/documentos?msg=cancelado", status_code=303)


@router.get("/documentos/{doc_id}/dossie")
def dossier(
    doc_id: str,
    request: Request,
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """ZIP autossuficiente (arquivos, evidência, trilha, âncoras, script de verificação)."""
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="Documento não encontrado.")
    data, manifest = build_dossier(db, app_ctx(request).storage, doc)
    audit.record(
        db,
        action="DOSSIE_EXPORTADO",
        actor_type="rh",
        actor_ref=user.identity.username,
        document_id=doc.id,
        ip=_ip(request),
        data={"arquivos": sorted(manifest["arquivos"]), "sha256_zip": sha256_hex(data)},
    )
    db.commit()
    return Response(
        data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="dossie-{doc.id}.zip"'},
    )


# --------------------------------------------------- documentos DocuSeal
def _docuseal_types(db: Session):
    return db.scalars(
        select(DocumentType).where(DocumentType.ativo.is_(True), DocumentType.engine == Engine.DOCUSEAL)
    ).all()


@router.get("/docuseal/emitir")
def docuseal_form(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    return render(
        request,
        "admin/docuseal_emitir.html",
        user=user,
        types=_docuseal_types(db),
        error=None,
        result=None,
        enabled=app_ctx(request).docuseal is not None,
    )


@router.post("/docuseal/emitir")
def docuseal_issue(
    request: Request,
    tipo: int = Form(0),
    matriculas: str = Form(""),
    titulo: str = Form(""),
    competencia: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Cria pendências de assinatura via DocuSeal (o envio só é criado quando o
    colaborador, autenticado, abre o documento no portal)."""
    _check_csrf(user, csrf)

    def page(error=None, result=None, code=200):
        return render(
            request,
            "admin/docuseal_emitir.html",
            status_code=code,
            user=user,
            types=_docuseal_types(db),
            error=error,
            result=result,
            enabled=app_ctx(request).docuseal is not None,
        )

    doc_type = db.get(DocumentType, tipo) if tipo else None
    if doc_type is None or doc_type.engine != Engine.DOCUSEAL or not doc_type.docuseal_template_id:
        return page("Tipo DocuSeal inválido ou sem template_id.", code=400)
    if competencia and not _COMPETENCIA.fullmatch(competencia):
        return page("Competência deve estar no formato AAAA-MM.", code=400)
    keys = [m for m in re.split(r"[\s,;]+", matriculas) if m]
    created, missing = [], []
    for key in keys:
        emp = db.scalar(
            select(Employee).where(
                func.ltrim(Employee.matricula, "0") == (key.lstrip("0") or "0"),
                Employee.ativo.is_(True),
            )
        )
        if emp is None:
            missing.append(key)
            continue
        declaration = doc_type.declaration_text
        doc = Document(
            id=new_uuid(),
            employee_id=emp.id,
            document_type_id=doc_type.id,
            engine=Engine.DOCUSEAL,
            titulo=(titulo or doc_type.nome)[:200],
            competencia=competencia or None,
            status=DocStatus.PENDENTE,
            declaration_text=declaration,
            declaration_sha256=sha256_hex(declaration),
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
                "declaracao_sha256": doc.declaration_sha256,
            },
        )
        created.append(emp.matricula)
    db.commit()
    return page(result={"criados": created, "nao_encontrados": missing})


# ------------------------------------------------------- tipos de documento
@router.get("/tipos")
def doc_types(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    types = db.scalars(select(DocumentType).order_by(DocumentType.code)).all()
    return render(request, "admin/tipos.html", user=user, types=types, error=None)


def _type_snapshot(t: DocumentType) -> dict:
    return {
        "code": t.code,
        "nome": t.nome,
        "requires_acceptance": t.requires_acceptance,
        "manifestation_kind": t.manifestation_kind,
        "requires_totp": t.requires_totp,
        "declaration_sha256": sha256_hex(t.declaration_text or ""),
        "anchor_text": t.anchor_text,
        "anchor_page": t.anchor_page,
        "anchor_box": list(t.anchor_box or []),
        "engine": str(t.engine),
        "docuseal_template_id": t.docuseal_template_id,
        "retention_years": t.retention_years,
        "ativo": t.ativo,
    }


@router.post("/tipos")
def doc_type_save(
    request: Request,
    tipo_id: int = Form(0),
    code: str = Form(""),
    nome: str = Form(""),
    declaracao: str = Form(""),
    natureza: str = Form("ciencia"),
    exige_aceite: str = Form(""),
    exige_totp: str = Form(""),
    ancora_texto: str = Form(""),
    ancora_pagina: int = Form(-1),
    ancora_caixa: str = Form("300,40,560,110"),
    motor: str = Form("nativo"),
    docuseal_template_id: str = Form(""),
    retencao_anos: int = Form(10),
    ativo: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Cria/edita um tipo. Alterações são auditadas (valores antigo e novo) e
    NÃO afetam documentos já emitidos (a declaração é fotografada na emissão)."""
    _check_csrf(user, csrf)

    def fail(msg: str):
        types = db.scalars(select(DocumentType).order_by(DocumentType.code)).all()
        return render(request, "admin/tipos.html", status_code=400, user=user, types=types, error=msg)

    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9_]{2,32}", code):
        return fail("Código inválido (use letras maiúsculas, números e _).")
    if len(nome.strip()) < 3 or len(declaracao.strip()) < 10:
        return fail("Informe o nome e o texto completo da declaração.")
    if natureza not in ("ciencia", "aceite") or motor not in ("nativo", "docuseal"):
        return fail("Natureza ou motor inválido.")
    try:
        box = [int(v) for v in ancora_caixa.split(",")]
        if len(box) != 4 or box[2] <= box[0] or box[3] <= box[1]:
            raise ValueError
    except ValueError:
        return fail("Caixa da âncora inválida (x1,y1,x2,y2).")
    template_id = int(docuseal_template_id) if docuseal_template_id.strip().isdigit() else None
    if motor == "docuseal" and not template_id:
        return fail("Tipos DocuSeal exigem o template_id.")
    t = db.get(DocumentType, tipo_id) if tipo_id else None
    before = _type_snapshot(t) if t else None
    if t is None:
        t = DocumentType(code=code)
        db.add(t)
    t.code, t.nome, t.declaration_text = code, nome.strip()[:120], declaracao.strip()
    t.manifestation_kind, t.requires_acceptance = natureza, exige_aceite == "sim"
    t.requires_totp, t.anchor_text = exige_totp == "sim", ancora_texto.strip() or None
    t.anchor_page, t.anchor_box = ancora_pagina, box
    t.engine = Engine(motor)
    t.docuseal_template_id, t.retention_years = template_id, max(1, retencao_anos)
    t.ativo = ativo == "sim"
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return fail("Já existe um tipo com este código.")
    audit.record(
        db,
        action="TIPO_DOCUMENTO_ALTERADO" if before else "TIPO_DOCUMENTO_CRIADO",
        actor_type="rh",
        actor_ref=user.identity.username,
        ip=_ip(request),
        data={"antes": before, "depois": _type_snapshot(t)},
    )
    db.commit()
    return RedirectResponse("/rh/tipos?msg=registrado", status_code=303)


# ------------------------------------------------------------ colaboradores
@router.get("/colaboradores")
def employees(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    emps = db.scalars(select(Employee).order_by(Employee.nome)).all()
    return render(request, "admin/colaboradores.html", user=user, employees=emps, error=None)


@router.post("/colaboradores/importar")
def employees_import(
    request: Request,
    arquivo: UploadFile = File(...),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _check_csrf(user, csrf)
    raw = arquivo.file.read(10 * 1024 * 1024 + 1)
    try:
        result = upsert_employees(db, parse_employees_csv(decode_csv(raw)))
        audit.record(
            db,
            action="COLABORADORES_IMPORTADOS",
            actor_type="rh",
            actor_ref=user.identity.username,
            ip=_ip(request),
            data={
                "arquivo": arquivo.filename,
                "criados": result.created,
                "atualizados": result.updated,
                "desativados": result.deactivated,
                "sha256": sha256_hex(raw),
            },
        )
        db.commit()
    except (EmployeeImportError, IntegrityError) as exc:
        db.rollback()
        msg = str(exc) if isinstance(exc, EmployeeImportError) else "Dados conflitantes no CSV."
        emps = db.scalars(select(Employee).order_by(Employee.nome)).all()
        return render(
            request,
            "admin/colaboradores.html",
            status_code=400,
            user=user,
            employees=emps,
            error=msg,
        )
    return RedirectResponse("/rh/colaboradores?msg=importado", status_code=303)


@router.post("/colaboradores/{employee_id}/desvincular")
def employee_unlink(
    employee_id: int,
    request: Request,
    motivo: str = Form(""),
    csrf: str = Form(""),
    user: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Remove o vínculo com a conta do AD (ex.: conta recriada na readmissão).
    O próximo login com a matrícula correta cria o novo vínculo."""
    _check_csrf(user, csrf)
    emp = db.get(Employee, employee_id)
    if emp is None:
        raise HTTPException(status_code=404, detail="Colaborador não encontrado.")
    if len(motivo.strip()) < 10:
        raise HTTPException(status_code=400, detail="Descreva o motivo (mínimo 10 caracteres).")
    old_guid, old_user = emp.ad_object_guid, emp.ad_username
    emp.ad_object_guid = None
    emp.ad_username = None
    revoke_sessions(db, emp.id)
    audit.record(
        db,
        action="VINCULO_AD_REMOVIDO",
        actor_type="rh",
        actor_ref=user.identity.username,
        ip=_ip(request),
        data={
            "matricula": emp.matricula,
            "objectGUID_anterior": old_guid,
            "usuario_anterior": old_user,
            "motivo": motivo.strip()[:500],
        },
    )
    db.commit()
    return RedirectResponse("/rh/colaboradores?msg=registrado", status_code=303)


# ----------------------------------------------------------------- auditoria
@router.get("/auditoria")
def audit_view(
    request: Request, user: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)
):
    """Verificação INCREMENTAL a partir da última âncora (a completa roda no job
    diário ``portal verify-audit``)."""
    last = db.scalar(select(AuditAnchor).order_by(AuditAnchor.id.desc()))
    if last is not None:
        ev = db.get(AuditEvent, last.head_event_id)
        if ev is None or ev.hash != last.head_hash:
            report = audit.ChainReport(
                False, 0, last.head_event_id, "evento ancorado foi alterado ou removido"
            )
        else:
            report = audit.verify_chain(db, start_after_id=last.head_event_id, start_hash=last.head_hash)
            report.last_anchored_event_id = last.head_event_id
    else:
        report = audit.verify_chain(db)
    anchors = db.scalars(select(AuditAnchor).order_by(AuditAnchor.id.desc()).limit(10)).all()
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(200)).all()
    return render(
        request, "admin/auditoria.html", user=user, report=report, events=events, anchors=anchors
    )


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
        term = terms.publish(versao, texto.replace("\r\n", "\n"), published_by=user.identity.username)
        # Cópia imutável do texto publicado (bucket com retenção).
        app_ctx(request).storage.put(
            f"termos/{term.id}/termo-v{term.version}.txt", term.text.encode(), "text/plain"
        )
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
    """Registra adesão coletada FORA do portal (papel assinado ou gov.br)."""
    from portal.terms import TermService

    _check_csrf(user, csrf)
    if canal not in ("papel", "govbr"):
        raise HTTPException(status_code=400, detail="Canal inválido: use papel ou gov.br.")
    emp = db.get(Employee, employee_id)
    if emp is None:
        raise HTTPException(status_code=404, detail="Colaborador não encontrado.")
    terms = TermService(db)
    term = terms.active()
    if term is None:
        raise HTTPException(
            status_code=400, detail="Nenhum termo publicado; publique em 'Termo de adesão'."
        )
    if len(observacao.strip()) < 5:
        raise HTTPException(status_code=400, detail="Informe onde o termo físico está arquivado.")
    try:
        terms.register(
            emp,
            term,
            channel=canal,
            actor_type="rh",
            registered_by=user.identity.username,
            ip=_ip(request),
            note=observacao.strip()[:500],
        )
        db.commit()
    except (ValueError, IntegrityError) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc) or "Termo já aceito.") from exc
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
        raise HTTPException(status_code=404, detail="Colaborador não encontrado.")
    if len(motivo.strip()) < 5:
        raise HTTPException(status_code=400, detail="Informe o motivo da redefinição.")
    s = app_ctx(request).settings
    revoke_sessions(db, employee_id)
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
        raise HTTPException(status_code=404, detail="Colaborador não encontrado.")
    docs = db.scalars(
        select(Document).where(Document.employee_id == emp.id).order_by(Document.created_at)
    ).all()
    buf = io.BytesIO()
    index = []

    def read(key: str, sha: str | None, doc_id: str) -> bytes:
        data = ctx.storage.get(key)
        if sha and sha256_hex(data) != sha:
            audit.record(
                db,
                action="INTEGRIDADE_FALHOU",
                actor_type="sistema",
                actor_ref="portal",
                document_id=doc_id,
                data={"key": key, "esperado": sha},
            )
            db.commit()
            raise HTTPException(status_code=500, detail=f"Falha de integridade: {doc_id}")
        return data

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
                zf.writestr(f"{base}.pdf", read(key, sha, d.id))
                entry["arquivo"], entry["sha256"] = f"{base}.pdf", sha
            if d.receipt_key:
                zf.writestr(f"{base}_comprovante.pdf", read(d.receipt_key, d.receipt_sha256, d.id))
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
