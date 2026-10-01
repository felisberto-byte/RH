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
from dataclasses import dataclass, field

from pypdf import PdfReader, PdfWriter
from sqlalchemy import select
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import sha256_hex
from portal.documents.service import DocumentError, DocumentService, validate_pdf
from portal.models import Batch, DocumentType, Employee

DEFAULT_PATTERN = r"Matr[íi]cula\s*[:nº°.]*\s*(\d{1,12})"
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_TOTAL = 500 * 1024 * 1024


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


def split_by_employee(pdf: bytes, pattern: str = DEFAULT_PATTERN) -> tuple[list[Group], list[int]]:
    rx = re.compile(pattern, re.IGNORECASE)
    reader = PdfReader(io.BytesIO(pdf))
    groups: list[Group] = []
    unmatched: list[int] = []
    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        m = rx.search(text)
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


def iter_zip(data: bytes) -> list[tuple[str, bytes]]:
    items = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ZIP_ENTRIES:
            raise DocumentError("ZIP com arquivos demais.")
        for info in infos:
            name = info.filename.rsplit("/", 1)[-1]
            if not name.lower().endswith(".pdf") or name.startswith("."):
                continue
            total += info.file_size
            if total > MAX_ZIP_TOTAL:
                raise DocumentError("ZIP descompactado excede o limite de 500 MB.")
            items.append((name, zf.read(info)))
    return items


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
        if competencia and not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", competencia):
            raise DocumentError("Competência deve estar no formato AAAA-MM.")
        if key_field not in ("matricula", "cpf"):
            raise DocumentError("Chave de identificação inválida.")
        report = IngestReport()
        batch = Batch(
            created_by=created_by,
            filename=filename[:255],
            source_sha256=sha256_hex(data),
            document_type_id=doc_type.id,
            competencia=competencia,
        )
        self.db.add(batch)
        self.db.flush()
        index = self._employee_index(key_field)

        if data[:4] == b"PK\x03\x04":
            parts = []
            for name, pdf in iter_zip(data):
                m = re.match(r"^(\d{1,14})[_\-. ]", name)
                if not m:
                    report.errors.append({"arquivo": name, "erro": "nome sem matrícula/CPF"})
                    continue
                parts.append((m.group(1), pdf, name))
        else:
            validate_pdf(data)
            groups, report.unmatched_pages = split_by_employee(data, pattern)
            parts = [
                (g.key, extract_pages(data, g.pages), f"páginas {g.pages[0] + 1}-{g.pages[-1] + 1}")
                for g in groups
            ]

        for raw_key, pdf, origin in parts:
            emp = index.get(normalize_key(raw_key, key_field))
            if emp is None:
                report.errors.append(
                    {"origem": origin, "chave": raw_key, "erro": "colaborador não cadastrado/ativo"}
                )
                continue
            try:
                with self.db.begin_nested():
                    doc = self.svc.issue(
                        employee=emp,
                        doc_type=doc_type,
                        pdf=pdf,
                        titulo=titulo,
                        competencia=competencia,
                        created_by=created_by,
                        batch=batch,
                    )
            except DocumentError as exc:
                report.errors.append({"origem": origin, "chave": raw_key, "erro": str(exc)})
                continue
            report.created.append({"documento": doc.id, "matricula": emp.matricula, "origem": origin})

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
