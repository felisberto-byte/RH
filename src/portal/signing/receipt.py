"""Geração do "Comprovante de Aceite Eletrônico" (manifesto de evidências).

O comprovante é um PDF autônomo que resume a evidência do aceite e traz, como
anexo embutido, o JSON canônico da evidência (``evidencia.json``). Depois de
gerado ele é certificado com o e-CNPJ (``Sealer.seal_receipt``).
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from pyhanko.pdf_utils import embed, generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

_FONT = "PortalVera"
_FONT_BOLD = "PortalVeraBd"


def _register_fonts() -> None:
    if _FONT in pdfmetrics.getRegisteredFontNames():
        return
    import reportlab

    base = Path(reportlab.__file__).parent / "fonts"
    pdfmetrics.registerFont(TTFont(_FONT, str(base / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(base / "VeraBd.ttf")))


@dataclass(frozen=True)
class ReceiptData:
    company_name: str
    company_cnpj: str
    title: str
    rows: list[tuple[str, str]]  # (rótulo, valor)
    declaration: str
    evidence_sha256: str
    verification_url: str
    legal_note: str
    declaration_label: str = "Declaração aceita pelo colaborador"


def build_receipt_pdf(data: ReceiptData, evidence_json: str, document_pdf: bytes | None = None) -> bytes:
    """Gera o comprovante com anexos embutidos ANTES do selo: ``evidencia.json``
    e, se informado, o PDF exato apresentado ao colaborador — o comprovante
    selado fica autossuficiente como prova."""
    _register_fonts()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=data.title,
        author=data.company_name,
        subject="Comprovante de aceite eletrônico",
    )
    h1 = ParagraphStyle("h1", fontName=_FONT_BOLD, fontSize=14, leading=18, spaceAfter=4)
    small = ParagraphStyle("s", fontName=_FONT, fontSize=8, leading=10.5)
    body = ParagraphStyle("b", fontName=_FONT, fontSize=9, leading=12)
    label = ParagraphStyle("l", fontName=_FONT_BOLD, fontSize=8.5, leading=11)
    mono = ParagraphStyle("m", fontName=_FONT, fontSize=7.5, leading=10, wordWrap="CJK")

    def p(text: str, style=body) -> Paragraph:
        return Paragraph(escape(text).replace("\n", "<br/>"), style)

    story = [
        p(data.title, h1),
        p(f"{data.company_name} — CNPJ {data.company_cnpj}", small),
        Spacer(1, 6 * mm),
    ]
    table = Table(
        [[p(k, label), p(v, mono if _looks_technical(v) else body)] for k, v in data.rows],
        colWidths=[48 * mm, None],
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9ced6")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f4f7")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story += [
        table,
        Spacer(1, 5 * mm),
        p(data.declaration_label, label),
        p(data.declaration),
        Spacer(1, 5 * mm),
        p("SHA-256 da evidência (evidencia.json, anexo a este PDF)", label),
        p(data.evidence_sha256, mono),
        Spacer(1, 3 * mm),
        p("Verificação", label),
        p(data.verification_url, mono),
        Spacer(1, 6 * mm),
        p(data.legal_note, small),
    ]
    doc.build(story)
    files = [
        (
            "evidencia.json",
            evidence_json.encode("utf-8"),
            "application/json",
            "Evidência do aceite (JSON canônico)",
        )
    ]
    if document_pdf is not None:
        files.append(
            (
                "documento.pdf",
                document_pdf,
                "application/pdf",
                "Documento exatamente como apresentado ao colaborador",
            )
        )
    return _attach(buf.getvalue(), files)


def _looks_technical(v: str) -> bool:
    return len(v) >= 32 and " " not in v


def _attach(pdf: bytes, files: list[tuple[str, bytes, str, str]]) -> bytes:
    w = IncrementalPdfFileWriter(io.BytesIO(pdf))
    for name, payload, mime, description in files:
        ef = embed.EmbeddedFileObject.from_file_data(
            w,
            data=payload,
            mime_type=mime,
            params=embed.EmbeddedFileParams(embed_size=True, embed_checksum=True),
        )
        embed.embed_file(
            w,
            embed.FileSpec(
                file_spec_string=name,
                file_name=name,
                embedded_data=ef,
                description=description,
                af_relationship=generic.NameObject("/Data"),
            ),
        )
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()
