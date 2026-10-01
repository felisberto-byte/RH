"""Regras de negócio: emissão, visualização, aceite/recusa e cancelamento."""

from __future__ import annotations

import io
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from portal import __version__, audit
from portal.audit import canonical_json, sha256_hex
from portal.auth.base import AuthProvider, DirectoryUnavailable, Identity
from portal.config import Settings
from portal.db import utcnow
from portal.locks import account_lock, recent_failures
from portal.models import (
    Acceptance,
    AuditEvent,
    Batch,
    DocStatus,
    Document,
    DocumentType,
    Employee,
    Engine,
    LoginAttempt,
    new_uuid,
)
from portal.signing.anchors import resolve_placement
from portal.signing.pades import Sealer, SealingError
from portal.signing.receipt import ReceiptData, build_receipt_pdf
from portal.storage import ObjectExistsError, Storage

log = logging.getLogger(__name__)

MAX_PDF_BYTES = 20 * 1024 * 1024
MAX_PDF_PAGES = 200
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sem 0/O/1/I

LEGAL_NOTE = (
    "Manifestação eletrônica realizada no Portal do Colaborador mediante autenticação com as "
    "credenciais corporativas (Active Directory) e confirmação no ato. A integridade do "
    "documento é garantida pelo hash SHA-256 e pela assinatura digital PAdES com certificado "
    "ICP-Brasil da empresa. Meio de comprovação de autoria e integridade admitido pelas partes, "
    "nos termos do art. 10, § 2º, da MP nº 2.200-2/2001."
)

# Texto exibido no formulário de divergência e registrado na evidência.
REFUSAL_DECLARATION = "Registro divergência em relação a este documento pelo motivo que descrevo abaixo."

KIND_LABELS = {
    # natureza: (cabeçalho do carimbo, título do comprovante, rótulo da decisão)
    "ciencia": ("CIÊNCIA ELETRÔNICA DO COLABORADOR", "Comprovante de Ciência Eletrônica", "CIÊNCIA"),
    "aceite": ("ACEITE ELETRÔNICO DO COLABORADOR", "Comprovante de Aceite Eletrônico", "ACEITE"),
}


class DocumentError(Exception):
    """Erro de regra de negócio com mensagem exibível."""


class NotFound(DocumentError):
    pass


class IntegrityFailure(DocumentError):
    pass


class AdhesionRequired(DocumentError):
    """O colaborador ainda não aceitou o Termo de Adesão vigente."""


class MfaEnrollmentRequired(DocumentError):
    """O segundo fator (TOTP) é exigido e ainda não foi configurado."""


@dataclass(frozen=True)
class Actor:
    """Quem está agindo + contexto da requisição (para a trilha de auditoria)."""

    identity: Identity
    employee_id: int | None
    session_ref: str
    ip: str
    user_agent: str
    login_at: datetime | None = None
    client_port: str | None = None

    @property
    def ref(self) -> str:
        return self.identity.username


@dataclass
class PreparedIssue:
    """Resultado da fase 1 da emissão (validação + selo), sem gravar nada."""

    employee: Employee
    doc_type: DocumentType
    pdf: bytes
    sealed: bytes
    original_sha256: str
    sealed_sha256: str
    anchor_source: str | None
    titulo: str
    competencia: str | None


def new_verification_code() -> str:
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def mask_cpf(cpf: str | None) -> str | None:
    if not cpf or len(cpf) != 11:
        return None
    return f"***.{cpf[3:6]}.{cpf[6:9]}-**"


def validate_pdf(data: bytes, max_bytes: int | None = MAX_PDF_BYTES) -> int:
    if max_bytes is not None and len(data) > max_bytes:
        raise DocumentError("PDF maior que o limite de 20 MB.")
    if not data.startswith(b"%PDF-"):
        raise DocumentError("O arquivo enviado não é um PDF.")
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise DocumentError("PDF protegido por senha não é suportado.")
        pages = len(reader.pages)
    except PdfReadError as exc:
        raise DocumentError(f"PDF inválido: {exc}") from exc
    if pages < 1 or (max_bytes is not None and pages > MAX_PDF_PAGES):
        raise DocumentError(f"PDF deve ter entre 1 e {MAX_PDF_PAGES} páginas.")
    return pages


class DocumentService:
    def __init__(
        self,
        db: Session,
        storage: Storage,
        settings: Settings,
        sealer: Sealer | None,
        auth: AuthProvider | None = None,
    ):
        self.db = db
        self.storage = storage
        self.s = settings
        self.sealer = sealer
        self.auth = auth
        self.tz = ZoneInfo(settings.timezone)

    # ================================================================ leitura
    def list_for_employee(self, employee_id: int) -> list[Document]:
        return list(
            self.db.scalars(
                select(Document)
                .where(Document.employee_id == employee_id, Document.status != DocStatus.CANCELADO)
                .order_by(Document.created_at.desc())
            )
        )

    def get_for_employee(self, doc_id: str, employee_id: int | None) -> Document:
        doc = self.db.get(Document, doc_id)
        # Mesmo erro para "não existe" e "não é seu" (não revela existência).
        if doc is None or employee_id is None or doc.employee_id != employee_id:
            raise NotFound("Documento não encontrado.")
        if doc.status == DocStatus.CANCELADO:
            raise NotFound("Documento não encontrado.")
        return doc

    def _read_verified(self, key: str | None, expected_sha256: str | None, doc: Document) -> bytes:
        if not key or not expected_sha256:
            raise NotFound("Arquivo ainda não disponível.")
        data = self.storage.get(key)
        if sha256_hex(data) != expected_sha256:
            audit.record(
                self.db,
                action="INTEGRIDADE_FALHOU",
                actor_type="sistema",
                actor_ref="portal",
                document_id=doc.id,
                data={"key": key, "esperado": expected_sha256},
            )
            self.db.commit()
            raise IntegrityFailure("Falha de integridade do arquivo. O RH foi notificado.")
        return data

    def current_pdf(self, doc: Document) -> bytes:
        if doc.final_key:
            return self._read_verified(doc.final_key, doc.final_sha256, doc)
        return self._read_verified(doc.sealed_key, doc.sealed_sha256, doc)

    def receipt_pdf(self, doc: Document) -> bytes:
        return self._read_verified(doc.receipt_key, doc.receipt_sha256, doc)

    def mark_viewed(self, doc: Document, actor: Actor, *, mode: str = "inline", size: int = 0) -> None:
        """Registra a abertura do PDF. ``mode``: "inline" (visualizador do portal)
        ou "download". A evidência lista todas as aberturas antes da decisão."""
        first = doc.first_viewed_at is None
        if first:
            doc.first_viewed_at = utcnow()
        audit.record(
            self.db,
            action="DOCUMENTO_VISUALIZADO",
            actor_type="colaborador",
            actor_ref=actor.ref,
            document_id=doc.id,
            ip=actor.ip,
            user_agent=actor.user_agent,
            data={
                "primeira_visualizacao": first,
                "modo": mode if mode in ("inline", "download") else "inline",
                "bytes": size,
                "sha256": doc.final_sha256 or doc.sealed_sha256,
            },
        )
        self.db.commit()

    # ================================================================ storage
    def _put(self, key: str, data: bytes) -> None:
        """Gravação create-only e idempotente: se o objeto já existe com o MESMO
        conteúdo (retentativa), segue; se o conteúdo difere, é erro."""
        try:
            self.storage.put(key, data)
        except ObjectExistsError as exc:
            if sha256_hex(self.storage.get(key)) != sha256_hex(data):
                raise DocumentError(f"conflito no armazenamento ({key})") from exc
        except Exception as exc:  # noqa: BLE001 - indisponibilidade do bucket/disco
            log.exception("falha ao gravar %s no armazenamento", key)
            self.db.rollback()
            raise DocumentError(
                "Armazenamento indisponível no momento. Nada foi registrado; tente novamente "
                "em instantes."
            ) from exc

    # ================================================================ emissão
    def _find_duplicate(
        self, employee_id: int, doc_type_id: int, competencia: str | None, original_sha: str
    ) -> Document | None:
        comp = (
            Document.competencia.is_(None)
            if competencia is None
            else Document.competencia == competencia
        )
        return self.db.scalar(
            select(Document).where(
                Document.employee_id == employee_id,
                Document.document_type_id == doc_type_id,
                comp,
                Document.original_sha256 == original_sha,
                Document.status != DocStatus.CANCELADO,
            )
        )

    def prepare_issue(
        self,
        *,
        employee: Employee,
        doc_type: DocumentType,
        pdf: bytes,
        titulo: str,
        competencia: str | None,
    ) -> PreparedIssue:
        """Fase 1 — valida e sela, SEM gravar nada nem manter travas (a chamada
        à ACT pode demorar)."""
        if self.sealer is None:
            raise DocumentError("Certificado de assinatura (e-CNPJ) não configurado.")
        if doc_type.engine != Engine.NATIVO:
            raise DocumentError("Este tipo de documento é emitido pelo DocuSeal.")
        validate_pdf(pdf)
        original_sha = sha256_hex(pdf)
        if self._find_duplicate(employee.id, doc_type.id, competencia, original_sha) is not None:
            raise DocumentError("Documento idêntico já emitido para este colaborador.")
        placement = None
        try:
            if doc_type.requires_acceptance:
                placement = resolve_placement(
                    pdf,
                    anchor_text=doc_type.anchor_text,
                    anchor_page=doc_type.anchor_page,
                    anchor_box=doc_type.anchor_box,
                )
            sealed = self.sealer.seal_issue(pdf, placement=placement)
        except (SealingError, ValueError) as exc:
            raise DocumentError(str(exc)) from exc
        return PreparedIssue(
            employee=employee,
            doc_type=doc_type,
            pdf=pdf,
            sealed=sealed,
            original_sha256=original_sha,
            sealed_sha256=sha256_hex(sealed),
            anchor_source=placement.source if placement else None,
            titulo=titulo[:200],
            competencia=competencia,
        )

    def persist_issue(
        self, p: PreparedIssue, *, created_by: str, batch: Batch | None = None
    ) -> Document:
        """Fase 2 — grava arquivos e registro (o chamador faz commit logo em seguida)."""
        doc_type = p.doc_type
        declaration = doc_type.declaration_text
        doc = Document(
            id=new_uuid(),  # definido já: compõe as chaves do armazenamento
            employee_id=p.employee.id,
            document_type_id=doc_type.id,
            engine=Engine.NATIVO,
            batch_id=batch.id if batch else None,
            titulo=p.titulo,
            competencia=p.competencia,
            status=DocStatus.PENDENTE if doc_type.requires_acceptance else DocStatus.DISPONIVEL,
            declaration_text=declaration,
            declaration_sha256=sha256_hex(declaration),
            verification_code=new_verification_code(),
            original_sha256=p.original_sha256,
            sealed_sha256=p.sealed_sha256,
            created_by=created_by,
        )
        doc.original_key = f"documentos/{doc.id}/original-{p.original_sha256[:16]}.pdf"
        doc.sealed_key = f"documentos/{doc.id}/emitido-{p.sealed_sha256[:16]}.pdf"
        self._put(doc.original_key, p.pdf)
        self._put(doc.sealed_key, p.sealed)
        self.db.add(doc)
        try:
            self.db.flush()
        except IntegrityError as exc:  # emissão concorrente idêntica
            raise DocumentError("Documento idêntico já emitido para este colaborador.") from exc
        audit.record(
            self.db,
            action="DOCUMENTO_EMITIDO",
            actor_type="rh",
            actor_ref=created_by,
            document_id=doc.id,
            data={
                "colaborador_matricula": p.employee.matricula,
                "tipo": doc_type.code,
                "competencia": p.competencia,
                "sha256_original": p.original_sha256,
                "sha256_emitido": p.sealed_sha256,
                "declaracao_sha256": doc.declaration_sha256,
                "ancora": p.anchor_source,
                "lote": batch.id if batch else None,
            },
        )
        return doc

    def issue(
        self,
        *,
        employee: Employee,
        doc_type: DocumentType,
        pdf: bytes,
        titulo: str,
        competencia: str | None,
        created_by: str,
        batch: Batch | None = None,
    ) -> Document:
        prepared = self.prepare_issue(
            employee=employee, doc_type=doc_type, pdf=pdf, titulo=titulo, competencia=competencia
        )
        return self.persist_issue(prepared, created_by=created_by, batch=batch)

    # ========================================================= aceite/recusa
    def _record_attempt(self, key: str, ip: str, ok: bool) -> None:
        self.db.add(LoginAttempt(username=key, ip=ip, success=ok, purpose="aceite"))
        self.db.commit()  # registra e libera a trava da conta

    def step_up(
        self, actor: Actor, password: str | None, otp: str | None, *, require_totp: bool = False
    ) -> str:
        """Confirmação no ato: senha do AD e, se exigido, código TOTP.

        Serializada por conta (trava + contagem + bind + registro) e com commit
        próprio: o consumo do código TOTP e a tentativa ficam registrados mesmo
        que a etapa seguinte (selo) falhe.
        """
        key = actor.identity.username.lower()
        need_totp = require_totp or self.s.accept_mfa == "totp"
        totp = None
        if need_totp:
            from portal.mfa import TotpService

            totp = TotpService(self.db, self.s.secret_key.get_secret_value(), self.s.totp_issuer)
            if actor.employee_id is None or not totp.is_enrolled(actor.employee_id):
                raise MfaEnrollmentRequired("Configure o aplicativo autenticador antes de continuar.")
        account_lock(self.db, key)
        if recent_failures(self.db, key=key, minutes=self.s.login_lockout_minutes) >= (
            self.s.login_max_failures
        ):
            self.db.rollback()
            raise DocumentError("Muitas tentativas. Aguarde alguns minutos.")
        factors: list[str] = []
        if self.s.accept_reauth == "password":
            if self.auth is None:
                raise DocumentError("Provedor de autenticação indisponível.")
            try:
                ok = bool(password) and self.auth.verify_password(actor.identity, password or "")
            except DirectoryUnavailable as exc:
                self.db.rollback()
                raise DocumentError(
                    "Diretório indisponível no momento. Nada foi registrado; tente novamente."
                ) from exc
            if not ok:
                self._record_attempt(key, actor.ip, False)
                raise DocumentError("Senha incorreta. Confirme com a mesma senha do computador.")
            factors.append("senha_ad")
        if totp is not None:
            if not totp.verify(actor.employee_id, otp or ""):  # type: ignore[arg-type]
                self._record_attempt(key, actor.ip, False)
                raise DocumentError("Código do autenticador inválido ou já utilizado.")
            factors.append("totp")
        self._record_attempt(key, actor.ip, True)
        return "+".join(factors) or "sessao_ad"

    def adhesion(self, employee_id: int) -> dict | None:
        from portal.terms import TermService

        terms = TermService(self.db)
        term = terms.active()
        if term is None:
            if self.s.require_adhesion_term:
                raise AdhesionRequired("Nenhum Termo de Adesão publicado. Procure o RH.")
            return None
        acc = terms.acceptance_of(employee_id, term)
        if acc is None:
            if self.s.require_adhesion_term:
                raise AdhesionRequired("Aceite o Termo de Adesão antes de continuar.")
            return None
        return {
            "versao": term.version,
            "sha256": term.sha256,
            "canal": acc.channel,
            "registrado_por": acc.registered_by,
            "objectGUID": acc.ad_object_guid,
            "evidencia_sha256": acc.evidence_sha256,
            "aceito_em_utc": audit.iso_utc(acc.accepted_at),
        }

    def _views(self, doc: Document) -> list[dict]:
        events = self.db.scalars(
            select(AuditEvent)
            .where(AuditEvent.document_id == doc.id, AuditEvent.action == "DOCUMENTO_VISUALIZADO")
            .order_by(AuditEvent.id)
        )
        return [
            {
                "data_hora_utc": audit.iso_utc(ev.occurred_at),
                "modo": (ev.data or {}).get("modo", "inline"),
                "ip": ev.ip,
                "usuario": ev.actor_ref,
            }
            for ev in events
        ]

    def _evidence(
        self,
        doc: Document,
        actor: Actor,
        *,
        decision: str,
        declaration: str,
        reason: str | None,
        reauth: str,
        at: datetime,
        adhesion: dict | None,
        mfa: dict | None,
    ) -> dict:
        emp = doc.employee
        views = self._views(doc)
        first = doc.first_viewed_at
        return {
            "versao": 2,
            "tipo": "manifestacao_eletronica",
            "natureza": doc.document_type.manifestation_kind,
            "decisao": decision,
            "documento": {
                "id": doc.id,
                "titulo": doc.titulo,
                "tipo": doc.document_type.code,
                "competencia": doc.competencia,
                "codigo_verificacao": doc.verification_code,
                "sha256_original": doc.original_sha256,
                "sha256_apresentado": doc.sealed_sha256,
                "primeira_abertura_utc": audit.iso_utc(first) if first else None,
                "segundos_entre_abertura_e_manifestacao": int((at - first).total_seconds())
                if first
                else None,
                "aberturas": views,
            },
            "signatario": {
                "nome": emp.nome,
                "matricula": emp.matricula,
                "cpf_mascarado": mask_cpf(emp.cpf),
                "ad": {
                    "sAMAccountName": actor.identity.username,
                    "userPrincipalName": actor.identity.upn,
                    "objectGUID": actor.identity.object_guid,
                    "dn": actor.identity.dn,
                },
            },
            "autenticacao": {
                "login": "Active Directory (LDAPS bind)",
                "login_em_utc": audit.iso_utc(actor.login_at) if actor.login_at else None,
                "confirmacao_no_ato": reauth,
                "segundo_fator": mfa,
                "sessao_ref": actor.session_ref,
            },
            "contexto": {
                "ip": actor.ip,
                "porta_origem": actor.client_port,
                "user_agent": actor.user_agent,
            },
            "termo_adesao": adhesion,
            "manifestacao": {
                "declaracao": declaration,
                "declaracao_sha256": sha256_hex(declaration),
                "motivo_recusa": reason,
                "data_hora_utc": audit.iso_utc(at),
                "data_hora_local": at.astimezone(self.tz).isoformat(timespec="seconds"),
                "fuso": self.s.timezone,
                "fonte_de_tempo": "relógio do servidor (UTC) + carimbo do tempo da ACT na assinatura"
                if self.s.tsa_url
                else "relógio do servidor (UTC), SEM carimbo do tempo de terceiro",
            },
            "sistema": {
                "portal_versao": __version__,
                "base_url": self.s.base_url,
                "empresa": self.s.company_name,
                "cnpj": self.s.company_cnpj,
                "certificado_selo": self.sealer.subject if self.sealer else None,
                "act_carimbo_do_tempo": self.s.tsa_url or None,
            },
        }

    def _check_pending(self, doc: Document | None, actor: Actor) -> Document:
        if doc is None or doc.employee_id != actor.employee_id:
            raise NotFound("Documento não encontrado.")
        if doc.status != DocStatus.PENDENTE:
            raise DocumentError("Este documento não está pendente de manifestação.")
        if doc.engine != Engine.NATIVO:
            raise DocumentError("Este documento é assinado pelo fluxo DocuSeal.")
        if self.s.require_view_before_accept and doc.first_viewed_at is None:
            raise DocumentError("Abra e leia o documento antes de registrar sua decisão.")
        return doc

    def _lock_pending(self, doc_id: str, actor: Actor) -> Document:
        doc = self.db.execute(
            select(Document)
            .where(Document.id == doc_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        return self._check_pending(doc, actor)

    @staticmethod
    def declaration_for(doc: Document) -> str:
        return doc.declaration_text or doc.document_type.declaration_text

    def accept(
        self,
        doc_id: str,
        actor: Actor,
        *,
        declaration_confirmed: bool,
        password: str | None,
        otp: str | None = None,
        declaration_sha256: str | None = None,
    ) -> Document:
        if not declaration_confirmed:
            raise DocumentError("Marque a declaração para confirmar.")
        return self._manifest(
            doc_id,
            actor,
            decision="ACEITO",
            reason=None,
            password=password,
            otp=otp,
            shown_declaration_sha256=declaration_sha256,
        )

    def refuse(
        self, doc_id: str, actor: Actor, *, reason: str, password: str | None, otp: str | None = None
    ) -> Document:
        reason = (reason or "").strip()
        if len(reason) < 10:
            raise DocumentError("Descreva o motivo da divergência (mínimo 10 caracteres).")
        return self._manifest(
            doc_id, actor, decision="RECUSADO", reason=reason[:2000], password=password, otp=otp
        )

    def _manifest(
        self,
        doc_id: str,
        actor: Actor,
        *,
        decision: str,
        reason: str | None,
        password: str | None,
        otp: str | None,
        shown_declaration_sha256: str | None = None,
    ) -> Document:
        if self.sealer is None:
            raise DocumentError("Certificado de assinatura (e-CNPJ) não configurado.")
        # 1) checagens sem trava, termo e confirmação (com commit próprio)
        doc = self._check_pending(self.db.get(Document, doc_id), actor)
        declaration = self.declaration_for(doc) if decision == "ACEITO" else REFUSAL_DECLARATION
        if (
            decision == "ACEITO"
            and shown_declaration_sha256 is not None
            and (shown_declaration_sha256 != sha256_hex(declaration))
        ):
            raise DocumentError("A declaração foi atualizada. Recarregue a página e leia novamente.")
        adhesion = self.adhesion(doc.employee_id)
        reauth = self.step_up(actor, password, otp, require_totp=doc.document_type.requires_totp)
        mfa = None
        if "totp" in reauth and actor.employee_id is not None:
            from portal.mfa import TotpService

            mfa = TotpService(self.db, self.s.secret_key.get_secret_value(), self.s.totp_issuer).info(
                actor.employee_id
            )
        # 2) trava o documento e confere de novo (pode ter mudado no intervalo)
        doc = self._lock_pending(doc_id, actor)
        sealed = self._read_verified(doc.sealed_key, doc.sealed_sha256, doc)

        at = utcnow()
        evidence = self._evidence(
            doc,
            actor,
            decision=decision,
            declaration=declaration,
            reason=reason,
            reauth=reauth,
            at=at,
            adhesion=adhesion,
            mfa=mfa,
        )
        evidence_json = canonical_json(evidence)
        evidence_sha = sha256_hex(evidence_json)
        local = at.astimezone(self.tz)
        verify_url = f"{self.s.base_url.rstrip('/')}/verificar/{doc.verification_code}"
        stamp_title, receipt_title, decision_label = KIND_LABELS.get(
            doc.document_type.manifestation_kind, KIND_LABELS["aceite"]
        )

        # 3) gera TODOS os arquivos antes de gravar qualquer coisa
        final = None
        try:
            if decision == "ACEITO":
                final = self.sealer.seal_acceptance(
                    sealed,
                    stamp_lines=[
                        stamp_title,
                        f"{doc.employee.nome} · matrícula {doc.employee.matricula}",
                        f"Usuário AD: {actor.identity.username}",
                        f"{local:%d/%m/%Y %H:%M:%S} ({self.s.timezone}) · IP {actor.ip}",
                        f"Documento SHA-256: {(doc.sealed_sha256 or '')[:24]}...",
                        f"Evidência SHA-256: {evidence_sha[:24]}...",
                        f"Verificar: {verify_url}",
                    ],
                    reason=f"{decision_label.title()} eletrônica(o) do colaborador; evidência SHA-256 "
                    f"{evidence_sha}",
                )
            final_sha = sha256_hex(final) if final else None
            receipt_rows = [
                ("Decisão", decision_label if decision == "ACEITO" else "DIVERGÊNCIA REGISTRADA"),
                ("Documento", f"{doc.titulo} ({doc.document_type.nome})"),
                ("Competência", doc.competencia or "—"),
                ("ID do documento", doc.id),
                ("Código de verificação", doc.verification_code),
                ("SHA-256 do documento apresentado", doc.sealed_sha256 or ""),
            ]
            if final_sha:
                receipt_rows.append(("SHA-256 do documento com o registro", final_sha))
            receipt_rows += [
                ("Colaborador", f"{doc.employee.nome} — matrícula {doc.employee.matricula}"),
                ("CPF", mask_cpf(doc.employee.cpf) or "—"),
                ("Usuário AD", f"{actor.identity.username} ({actor.identity.upn or '—'})"),
                ("objectGUID (AD)", actor.identity.object_guid),
                (
                    "Data/hora",
                    f"{local:%d/%m/%Y %H:%M:%S} ({self.s.timezone}) — {audit.iso_utc(at)} UTC",
                ),
                (
                    "Primeira abertura do documento",
                    doc.first_viewed_at.astimezone(self.tz).strftime("%d/%m/%Y %H:%M:%S")
                    if doc.first_viewed_at
                    else "—",
                ),
                ("Endereço IP", actor.ip),
                ("Navegador", actor.user_agent[:300]),
                ("Autenticação", f"AD (LDAPS) + confirmação no ato: {reauth}"),
                (
                    "Termo de adesão",
                    f"versão {adhesion['versao']} ({adhesion['canal']})" if adhesion else "—",
                ),
                (
                    "Carimbo do tempo",
                    "ACT na assinatura" if self.s.tsa_url else "não utilizado (hora do servidor)",
                ),
            ]
            if reason:
                receipt_rows.append(("Motivo informado", reason))
            receipt = build_receipt_pdf(
                ReceiptData(
                    company_name=self.s.company_name,
                    company_cnpj=self.s.company_cnpj,
                    title=receipt_title
                    if decision == "ACEITO"
                    else "Comprovante de Registro de Divergência",
                    rows=receipt_rows,
                    declaration=declaration,
                    declaration_label="Declaração confirmada pelo colaborador"
                    if decision == "ACEITO"
                    else "Declaração de divergência registrada pelo colaborador",
                    evidence_sha256=evidence_sha,
                    verification_url=verify_url,
                    legal_note=LEGAL_NOTE,
                ),
                evidence_json,
                document_pdf=sealed,
            )
            receipt = self.sealer.seal_receipt(receipt)
        except SealingError as exc:
            self.db.rollback()
            raise DocumentError(
                "Não foi possível concluir agora (falha no selo/carimbo do tempo). "
                "Nada foi registrado; tente novamente em instantes."
            ) from exc
        receipt_sha = sha256_hex(receipt)

        # 4) grava arquivos e, por fim, o registro
        if final is not None and final_sha:
            doc.final_key = f"documentos/{doc.id}/registrado-{final_sha[:16]}.pdf"
            doc.final_sha256 = final_sha
            self._put(doc.final_key, final)
        doc.receipt_key = f"documentos/{doc.id}/comprovante-{receipt_sha[:16]}.pdf"
        doc.receipt_sha256 = receipt_sha
        self._put(doc.receipt_key, receipt)

        self.db.add(
            Acceptance(
                document_id=doc.id,
                employee_id=doc.employee_id,
                decision=decision,
                reason=reason,
                source="portal",
                ad_object_guid=actor.identity.object_guid,
                ad_username=actor.identity.username,
                ad_upn=actor.identity.upn,
                ip=actor.ip,
                user_agent=actor.user_agent[:512],
                accepted_at=at,
                reauth_method=reauth,
                session_ref=actor.session_ref,
                document_sha256=doc.sealed_sha256 or "",
                declaration_text=declaration,
                evidence_json=evidence_json,
                evidence_sha256=evidence_sha,
            )
        )
        doc.status = DocStatus.ASSINADO if decision == "ACEITO" else DocStatus.RECUSADO
        doc.completed_at = at
        audit.record(
            self.db,
            action="DOCUMENTO_ACEITO" if decision == "ACEITO" else "DOCUMENTO_RECUSADO",
            actor_type="colaborador",
            actor_ref=actor.ref,
            document_id=doc.id,
            ip=actor.ip,
            user_agent=actor.user_agent,
            data={
                "natureza": doc.document_type.manifestation_kind,
                "evidencia_sha256": evidence_sha,
                "sha256_apresentado": doc.sealed_sha256,
                "sha256_final": doc.final_sha256,
                "sha256_comprovante": receipt_sha,
                "objectGUID": actor.identity.object_guid,
            },
        )
        try:
            self.db.commit()
        except IntegrityError as exc:  # manifestação concorrente do mesmo documento
            self.db.rollback()
            raise DocumentError("Este documento já possui manifestação registrada.") from exc
        return doc

    # ============================================================== RH
    def cancel(self, doc_id: str, *, actor_ref: str, reason: str, ip: str | None = None) -> Document:
        if len((reason or "").strip()) < 5:
            raise DocumentError("Informe o motivo do cancelamento.")
        # Trava e recarrega: um aceite em andamento pode concluir antes.
        doc = self.db.execute(
            select(Document)
            .where(Document.id == doc_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if doc is None:
            raise NotFound("Documento não encontrado.")
        if doc.status not in (DocStatus.PENDENTE, DocStatus.DISPONIVEL):
            self.db.rollback()
            raise DocumentError(
                "Documento com manifestação registrada (ou já cancelado) não pode ser cancelado; "
                "emita um documento retificador."
            )
        doc.status = DocStatus.CANCELADO
        doc.cancel_reason = reason.strip()[:1000]
        audit.record(
            self.db,
            action="DOCUMENTO_CANCELADO",
            actor_type="rh",
            actor_ref=actor_ref,
            document_id=doc.id,
            ip=ip,
            data={"motivo": doc.cancel_reason},
        )
        self.db.commit()
        return doc

    def find_by_hash_or_code(self, value: str) -> Document | None:
        value = value.strip()
        if len(value) == 64:
            value = value.lower()
            return self.db.scalar(
                select(Document).where(
                    (Document.sealed_sha256 == value)
                    | (Document.final_sha256 == value)
                    | (Document.receipt_sha256 == value)
                )
            )
        return self.db.scalar(select(Document).where(Document.verification_code == value.upper()))


def to_local(dt: datetime | None, tz: str) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(ZoneInfo(tz)).strftime("%d/%m/%Y %H:%M")
