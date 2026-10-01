"""Localização da âncora (posição fixa) do campo de aceite no PDF.

O colaborador não escolhe onde "assina": o campo de assinatura é criado pelo
sistema, no momento da emissão, na posição definida pelo tipo de documento.
A posição pode ser:
1. relativa a um texto-âncora impresso pelo sistema de folha
   (ex.: "Assinatura do Colaborador"); ou
2. fixa (página + caixa em pontos PDF), quando o texto não existir.
"""

from __future__ import annotations

import io
import unicodedata
from dataclasses import dataclass

from pypdf import PdfReader


@dataclass(frozen=True)
class Placement:
    page: int  # índice 0-based
    box: tuple[int, int, int, int]  # (x1, y1, x2, y2) em pontos, origem inferior esquerda
    source: str  # "texto" | "fixa"


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.lower().split())


def find_text(pdf: bytes, needle: str) -> tuple[int, float, float, float] | None:
    """Retorna (página, x, y, tamanho_da_fonte) da 1ª ocorrência de ``needle``
    (comparação sem acentos/caixa)."""
    target = _norm(needle)
    reader = PdfReader(io.BytesIO(pdf))
    for page_index, page in enumerate(reader.pages):
        hits: list[tuple[float, float, float]] = []

        def visitor(text, cm, tm, _font, size, hits=hits):
            if text and target in _norm(text):
                x = cm[0] * tm[4] + cm[2] * tm[5] + cm[4]
                y = cm[1] * tm[4] + cm[3] * tm[5] + cm[5]
                effective = abs((size or 10) * (tm[3] or 1) * (cm[3] or 1))
                hits.append((x, y, effective))

        page.extract_text(visitor_text=visitor)
        if hits:
            return page_index, hits[0][0], hits[0][1], hits[0][2]
    return None


def resolve_placement(
    pdf: bytes,
    *,
    anchor_text: str | None,
    anchor_page: int,
    anchor_box: list[int] | tuple[int, int, int, int],
    gap_factor: float = 1.8,
) -> Placement:
    reader = PdfReader(io.BytesIO(pdf))
    n_pages = len(reader.pages)
    x1, y1, x2, y2 = (int(v) for v in anchor_box)
    width, height = x2 - x1, y2 - y1
    if width <= 0 or height <= 0:
        raise ValueError("anchor_box inválida: use (x1, y1, x2, y2) com x2>x1 e y2>y1")

    if anchor_text:
        found = find_text(pdf, anchor_text)
        if found is not None:
            page, x, y, font_size = found
            mb = reader.pages[page].mediabox
            # Campo acima do rótulo e da linha de assinatura que normalmente fica
            # logo acima dele (≈ 1,8 × o tamanho da fonte do rótulo), alinhado à
            # esquerda do texto e recortado aos limites da página.
            gap = max(8.0, gap_factor * font_size)
            bx1 = max(float(mb.left), min(x, float(mb.right) - width))
            by1 = min(y + gap, float(mb.top) - height)
            return Placement(page, (int(bx1), int(by1), int(bx1 + width), int(by1 + height)), "texto")

    page = anchor_page if anchor_page >= 0 else n_pages + anchor_page
    if not 0 <= page < n_pages:
        raise ValueError(f"anchor_page {anchor_page} fora do documento ({n_pages} páginas)")
    return Placement(page, (x1, y1, x2, y2), "fixa")
