"""Importação em lote dos PDFs gerados pelo sistema de folha/contabilidade.

Formatos aceitos:
- **PDF único** com os documentos de todos os colaboradores em sequência:
  cada página é associada a um colaborador por expressão regular aplicada ao
  texto da página (ex.: ``Matr[íi]cula:?\\s*(\\d+)``). Páginas sem
  identificação são tratadas como continuação do documento anterior.
- **ZIP** com um PDF por colaborador, nomeado ``<matricula>_<qualquer>.pdf``
  (ou ``<cpf>_...``).

Cada documento é selado individualmente com o e-CNPJ ao ser emitido.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field

import regex
from pypdf import PdfReader, PdfWriter
from sqlalchemy import select
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import sha256_hex
from portal.documents.service import MAX_PDF_BYTES, DocumentError, DocumentService, validate_pdf
from portal.models import Batch, DocumentType, Employee

DEFAULT_PATTERN = r"Matr[íi]cula\s*[:nº°.]*\s*(\d{1,12})"
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_TOTAL = 300 * 1024 * 1024
REGEX_TIMEOUT_SECONDS = 1.0


@dataclass
class Group:
    key: str
    pages: list[int] = field(default_factory=list)


@dataclass
class IngestReport:
    created: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    unmatched_pages: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "criados": len(self.created),
            "erros": self.errors,
            "paginas_sem_identificacao": self.unmatched_pages,
            "documentos": self.created,
        }


def normalize_key(raw: str, key_field: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if key_field == "cpf":
        return digits.zfill(11)
    return digits.lstrip("0") or "0"


def compile_pattern(pattern: str):
    """Valida a expressão informada pelo RH: tamanho, exatamente um grupo de
    captura e execução com limite de tempo (evita travar o servidor — ReDoS)."""
    if not pattern or len(pattern) > 200:
        raise DocumentError("Expressão regular vazia ou longa demais (máx. 200 caracteres).")
    try:
        rx = regex.compile(pattern, regex.IGNORECASE)
    except regex.error as exc:
        raise DocumentError(f"Expressão regular inválida: {exc}") from exc
    if rx.groups != 1:
        raise DocumentError("A expressão regular deve ter exatamente um grupo de captura (...).")
    return rx


def split_by_employee(pdf: bytes, pattern: str = DEFAULT_PATTERN) -> tuple[list[Group], list[int]]:
    rx = compile_pattern(pattern)
    reader = PdfReader(io.BytesIO(pdf))
    groups: list[Group] = []
    unmatched: list[int] = []
    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        try:
            m = rx.search(text, timeout=REGEX_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            raise DocumentError(
                f"A expressão regular demorou demais na página {i + 1}; simplifique o padrão."
            ) from exc
        if m:
            key = m.group(1)
            if groups and groups[-1].key == key:
                groups[-1].pages.append(i)
            else:
                groups.append(Group(key, [i]))
        elif groups:
            groups[-1].pages.append(i)  # página de continuação
        else:
            unmatched.append(i)
    return groups, unmatched


def extract_pages(pdf: bytes, pages: list[int]) -> bytes:
    reader = PdfReader(io.BytesIO(pdf))
    writer = PdfWriter()
    for i in pages:
        writer.add_page(reader.pages[i])
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def iter_zip(data: bytes) -> Iterator[tuple[str, bytes]]:
    """Itera os PDFs do ZIP UM POR VEZ (não mantém todos em memória)."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ZIP_ENTRIES:
            raise DocumentError("ZIP com arquivos demais.")
        if sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
            raise DocumentError("ZIP descompactado excede o limite.")
        for info in infos:
            name = info.filename.rsplit("/", 1)[-1]
            if not name.lower().endswith(".pdf") or name.startswith("."):
                continue
            if info.file_size > MAX_PDF_BYTES:
                raise DocumentError(f"{name}: PDF maior que 20 MB.")
            with zf.open(info) as fh:
                payload = fh.read(MAX_PDF_BYTES + 1)
            if len(payload) > MAX_PDF_BYTES:  # tamanho declarado no ZIP era falso
                raise DocumentError(f"{name}: PDF maior que 20 MB.")
            yield name, payload


class BatchImporter:
    def __init__(self, db: Session, service: DocumentService):
        self.db = db
        self.svc = service

    def _employee_index(self, key_field: str) -> dict[str, Employee]:
        emps = self.db.scalars(select(Employee).where(Employee.ativo.is_(True))).all()
        if key_field == "cpf":
            return {normalize_key(e.cpf, "cpf"): e for e in emps if e.cpf}
        return {normalize_key(e.matricula, "matricula"): e for e in emps}

    def run(
        self,
        *,
        filename: str,
        data: bytes,
        doc_type: DocumentType,
        competencia: str | None,
        titulo: str,
        created_by: str,
        key_field: str = "matricula",
        pattern: str = DEFAULT_PATTERN,
    ) -> tuple[Batch, IngestReport]:
        """Importa um lote. Cada documento é selado FORA de transação (a ACT pode
        demorar) e gravado em transação curta própria: a trava global da trilha
        de auditoria nunca fica presa durante o lote, e uma falha isolada não
        desfaz os documentos já publicados."""
        if competencia and not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", competencia):
            raise DocumentError("Competência deve estar no formato AAAA-MM.")
        if key_field not in ("matricula", "cpf"):
            raise DocumentError("Chave de identificação inválida.")
        compile_pattern(pattern)
        is_zip = data[:4] == b"PK\x03\x04"
        if not is_zip:
            validate_pdf(data, max_bytes=None)
        report = IngestReport()
        batch = Batch(
            created_by=created_by,
            filename=filename[:255],
            source_sha256=sha256_hex(data),
            document_type_id=doc_type.id,
            competencia=competencia,
            report={"situacao": "em processamento"},
        )
        self.db.add(batch)
        self.db.commit()
        index = self._employee_index(key_field)
        self.db.commit()  # encerra a transação de leitura

        def parts() -> Iterator[tuple[str, bytes, str]]:
            if is_zip:
                for name, pdf in iter_zip(data):
                    m = re.match(r"^(\d{1,14})[_\-. ]", name)
                    if not m:
                        report.errors.append({"arquivo": name, "erro": "nome sem matrícula/CPF"})
                        continue
                    yield m.group(1), pdf, name
            else:
                groups, report.unmatched_pages = split_by_employee(data, pattern)
                for g in groups:
                    yield (
                        g.key,
                        extract_pages(data, g.pages),
                        f"páginas {g.pages[0] + 1}-{g.pages[-1] + 1}",
                    )

        try:
            for raw_key, pdf, origin in parts():
                emp = index.get(normalize_key(raw_key, key_field))
                if emp is None:
                    report.errors.append(
                        {"origem": origin, "chave": raw_key, "erro": "colaborador não cadastrado/ativo"}
                    )
                    continue
                try:
                    prepared = self.svc.prepare_issue(
                        employee=emp,
                        doc_type=doc_type,
                        pdf=pdf,
                        titulo=titulo,
                        competencia=competencia,
                    )
                    self.db.commit()  # fim da leitura (checagem de duplicidade)
                    doc = self.svc.persist_issue(prepared, created_by=created_by, batch=batch)
                    self.db.commit()
                except DocumentError as exc:
                    self.db.rollback()
                    report.errors.append({"origem": origin, "chave": raw_key, "erro": str(exc)})
                    continue
                report.created.append(
                    {"documento": doc.id, "matricula": emp.matricula, "origem": origin}
                )
        except DocumentError as exc:  # erro do arquivo como um todo (ZIP, regex...)
            self.db.rollback()
            report.errors.append({"origem": filename, "erro": str(exc)})

        batch = self.db.get(Batch, batch.id) or batch
        batch.total_documents = len(report.created)
        batch.report = report.as_dict()
        audit.record(
            self.db,
            action="LOTE_IMPORTADO",
            actor_type="rh",
            actor_ref=created_by,
            data={
                "lote": batch.id,
                "arquivo": batch.filename,
                "sha256": batch.source_sha256,
                "criados": len(report.created),
                "erros": len(report.errors),
                "paginas_sem_identificacao": report.unmatched_pages,
            },
        )
        self.db.commit()
        return batch, report
