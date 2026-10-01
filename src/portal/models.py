"""Modelo de dados do portal.

Princípios:
- Os PDFs ficam no armazenamento de objetos (GCS com retenção/WORM); o banco
  guarda metadados, hashes SHA-256 e a evidência do aceite.
- A trilha de auditoria (``AuditEvent``) é encadeada por hash: cada evento
  inclui o hash do anterior, o que torna detectável qualquer alteração ou
  remoção de eventos.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from portal.db import Base, utcnow


def new_uuid() -> str:
    return str(uuid.uuid4())


class DocStatus(enum.StrEnum):
    PENDENTE = "PENDENTE"  # aguardando aceite do colaborador
    DISPONIVEL = "DISPONIVEL"  # apenas para consulta (não exige aceite)
    ASSINADO = "ASSINADO"  # aceite registrado e selado
    RECUSADO = "RECUSADO"  # colaborador registrou divergência
    CANCELADO = "CANCELADO"  # cancelado/substituído pelo RH


class Engine(enum.StrEnum):
    NATIVO = "nativo"  # aceite no próprio portal + selo PAdES (padrão)
    DOCUSEAL = "docuseal"  # modelo DocuSeal, link entregue só dentro do portal


class Employee(Base):
    __tablename__ = "colaboradores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    matricula: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    nome: Mapped[str] = mapped_column(String(200))
    cpf: Mapped[str | None] = mapped_column(String(11), unique=True, nullable=True)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    ad_object_guid: Mapped[str | None] = mapped_column(String(36), unique=True, nullable=True)
    ad_username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ativo: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    documents: Mapped[list[Document]] = relationship(back_populates="employee")


class DocumentType(Base):
    """Tipo de documento com layout padronizado e âncora fixa de aceite."""

    __tablename__ = "tipos_documento"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True)
    nome: Mapped[str] = mapped_column(String(120))
    requires_acceptance: Mapped[bool] = mapped_column(Boolean, default=True)
    declaration_text: Mapped[str] = mapped_column(Text)
    # Âncora do campo de aceite: texto procurado no PDF (ex.: "Assinatura do
    # Colaborador"); se não for encontrado, usa página/caixa fixas.
    anchor_text: Mapped[str | None] = mapped_column(String(200), nullable=True)
    anchor_page: Mapped[int] = mapped_column(Integer, default=-1)  # -1 = última página
    anchor_box: Mapped[list[int]] = mapped_column(JSON, default=lambda: [300, 40, 560, 110])
    engine: Mapped[Engine] = mapped_column(Enum(Engine, native_enum=False), default=Engine.NATIVO)
    docuseal_template_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retention_years: Mapped[int] = mapped_column(Integer, default=10)
    ativo: Mapped[bool] = mapped_column(Boolean, default=True)


class Batch(Base):
    __tablename__ = "lotes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(128))
    filename: Mapped[str] = mapped_column(String(255))
    source_sha256: Mapped[str] = mapped_column(String(64))
    document_type_id: Mapped[int] = mapped_column(ForeignKey("tipos_documento.id"))
    competencia: Mapped[str | None] = mapped_column(String(7), nullable=True)
    total_documents: Mapped[int] = mapped_column(Integer, default=0)
    report: Mapped[dict] = mapped_column(JSON, default=dict)


class Document(Base):
    __tablename__ = "documentos"
    __table_args__ = (
        UniqueConstraint("employee_id", "document_type_id", "competencia", "original_sha256"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    employee_id: Mapped[int] = mapped_column(ForeignKey("colaboradores.id"), index=True)
    document_type_id: Mapped[int] = mapped_column(ForeignKey("tipos_documento.id"))
    engine: Mapped[Engine] = mapped_column(Enum(Engine, native_enum=False), default=Engine.NATIVO)
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("lotes.id"), nullable=True)
    titulo: Mapped[str] = mapped_column(String(200))
    competencia: Mapped[str | None] = mapped_column(String(7), nullable=True)  # AAAA-MM
    status: Mapped[DocStatus] = mapped_column(Enum(DocStatus, native_enum=False), index=True)
    verification_code: Mapped[str] = mapped_column(String(20), unique=True, index=True)

    # Hashes SHA-256 (hex) de cada versão do arquivo. Documentos do motor
    # DocuSeal só têm hash/arquivo depois de concluídos (final_*).
    original_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sealed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    final_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    receipt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Chaves no armazenamento de objetos.
    original_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sealed_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    final_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    receipt_key: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(128))
    first_viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Integração DocuSeal (motor opcional).
    docuseal_submission_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    docuseal_submitter_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    docuseal_signing_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    employee: Mapped[Employee] = relationship(back_populates="documents")
    document_type: Mapped[DocumentType] = relationship()
    acceptance: Mapped[Acceptance | None] = relationship(back_populates="document")


class Acceptance(Base):
    """Evidência do aceite (ou da recusa) do colaborador."""

    __tablename__ = "aceites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documentos.id"), unique=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("colaboradores.id"))
    decision: Mapped[str] = mapped_column(String(10))  # ACEITO | RECUSADO
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="portal")  # portal | docuseal

    ad_object_guid: Mapped[str] = mapped_column(String(36))
    ad_username: Mapped[str] = mapped_column(String(128))
    ad_upn: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ip: Mapped[str] = mapped_column(String(45))
    user_agent: Mapped[str] = mapped_column(String(512))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reauth_method: Mapped[str] = mapped_column(String(32))
    session_ref: Mapped[str] = mapped_column(String(64))
    document_sha256: Mapped[str] = mapped_column(String(64))
    declaration_text: Mapped[str] = mapped_column(Text)

    # JSON canônico com toda a evidência e o seu hash; o mesmo hash é impresso
    # no comprovante e embutido na assinatura PAdES de aceite.
    evidence_json: Mapped[str] = mapped_column(Text)
    evidence_sha256: Mapped[str] = mapped_column(String(64))

    document: Mapped[Document] = relationship(back_populates="acceptance")


class AuditEvent(Base):
    __tablename__ = "auditoria"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_type: Mapped[str] = mapped_column(String(16))  # colaborador | rh | sistema
    actor_ref: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(48), index=True)
    document_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class AuditChainHead(Base):
    """Linha única usada como trava (SELECT ... FOR UPDATE) do encadeamento."""

    __tablename__ = "auditoria_cabeca"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_event_id: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str] = mapped_column(String(64))


class UserSession(Base):
    __tablename__ = "sessoes"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    employee_id: Mapped[int | None] = mapped_column(ForeignKey("colaboradores.id"))
    username: Mapped[str] = mapped_column(String(128))
    display_name: Mapped[str] = mapped_column(String(200))
    object_guid: Mapped[str] = mapped_column(String(36))
    upn: Mapped[str | None] = mapped_column(String(256), nullable=True)
    dn: Mapped[str] = mapped_column(String(512))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    csrf_token: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(45))
    user_agent: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class LoginAttempt(Base):
    __tablename__ = "tentativas_login"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    success: Mapped[bool] = mapped_column(Boolean)
    purpose: Mapped[str] = mapped_column(String(16), default="login")  # login | aceite
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AdhesionTerm(Base):
    """Versão do "Termo de Adesão ao Uso de Meios Eletrônicos" (MP 2.200-2, art. 10, § 2º)."""

    __tablename__ = "termos_adesao"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(20), unique=True)
    text: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    published_by: Mapped[str] = mapped_column(String(128))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AdhesionAcceptance(Base):
    __tablename__ = "termos_adesao_aceites"
    __table_args__ = (UniqueConstraint("employee_id", "term_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("colaboradores.id"), index=True)
    term_id: Mapped[int] = mapped_column(ForeignKey("termos_adesao.id"))
    channel: Mapped[str] = mapped_column(String(16))  # portal | papel | govbr
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ad_object_guid: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    registered_by: Mapped[str] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    term: Mapped[AdhesionTerm] = relationship()


class TotpCredential(Base):
    """Segundo fator (TOTP, RFC 6238) exigido no ato do aceite, sob controle
    exclusivo do colaborador — a senha do AD pode ser redefinida pela TI."""

    __tablename__ = "mfa_totp"

    employee_id: Mapped[int] = mapped_column(ForeignKey("colaboradores.id"), primary_key=True)
    secret_enc: Mapped[str] = mapped_column(String(255))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_step: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditAnchor(Base):
    """Ancoragem periódica do hash da cadeia de auditoria em carimbo do tempo."""

    __tablename__ = "auditoria_ancoras"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    head_event_id: Mapped[int] = mapped_column(Integer)
    head_hash: Mapped[str] = mapped_column(String(64))
    tsa_url: Mapped[str] = mapped_column(String(255))
    token_key: Mapped[str] = mapped_column(String(255))
    token_sha256: Mapped[str] = mapped_column(String(64))
