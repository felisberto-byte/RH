from __future__ import annotations

from portal.signing.anchors import resolve_placement
from portal.signing.pades import FIELD_ACCEPT, FIELD_ISSUE, inspect_signatures, load_cert_files
from tests.conftest import make_pdf


def test_anchor_by_text_is_above_label():
    pdf = make_pdf(["Holerite 09/2026"])
    p = resolve_placement(
        pdf, anchor_text="assinatura do COLABORADOR", anchor_page=-1, anchor_box=[300, 40, 560, 110]
    )
    assert p.source == "texto"
    assert p.page == 0
    x1, y1, x2, y2 = p.box
    assert x1 == 300 and y1 > 105 and (x2 - x1, y2 - y1) == (260, 70)


def test_anchor_fallback_fixed_box_last_page():
    pdf = make_pdf([["p1"], ["p2"]], label="")
    p = resolve_placement(pdf, anchor_text="inexistente", anchor_page=-1, anchor_box=[10, 20, 30, 40])
    assert p.source == "fixa" and p.page == 1 and p.box == (10, 20, 30, 40)


def test_issue_then_accept_keeps_both_signatures_valid(sealer, pki):
    pdf = make_pdf(["Holerite 09/2026"])
    p = resolve_placement(
        pdf, anchor_text="Assinatura do Colaborador", anchor_page=-1, anchor_box=[300, 40, 560, 110]
    )
    sealed = sealer.seal_issue(pdf, placement=p)
    final = sealer.seal_acceptance(sealed, stamp_lines=["ACEITE", "Maria — 100% ok"], reason="Aceite")
    assert final.startswith(sealed)  # atualização incremental: bytes anteriores intactos
    infos = {i.field: i for i in inspect_signatures(final, load_cert_files([pki["ca"]]))}
    assert set(infos) == {FIELD_ISSUE, FIELD_ACCEPT}
    for i in infos.values():
        assert i.intact and i.valid and i.trusted, i
    assert infos[FIELD_ISSUE].docmdp_ok is True


def test_tampering_breaks_certification(sealer, pki):
    pdf = make_pdf(["Holerite"])
    sealed = sealer.seal_issue(pdf, placement=None)
    assert b"ReportLab" in sealed  # dicionário /Info não comprimido, dentro do intervalo assinado
    tampered = sealed.replace(b"ReportLab", b"ReportLaX", 1)
    infos = inspect_signatures(tampered, load_cert_files([pki["ca"]]))
    assert not infos[0].intact


def test_policy_oid_and_commitment_embedded(pki):
    import io

    from pyhanko.pdf_utils.reader import PdfFileReader

    from portal.signing.pades import Sealer
    from tests.conftest import PFX_PASSWORD

    oid = "2.16.76.1.7.1.11.1.1"  # PA_PAdES_AD_RB v1.1 (exemplo; confirme na LPA do ITI)
    sealer = Sealer(
        pki["pfx"],
        PFX_PASSWORD,
        ca_chain_files=[pki["ca"]],
        policy_oid=oid,
        # hash em hexadecimal, como publicado na LPA (AD-RB v1.1)
        policy_hash_b64="95752d26ca974d46675ae7fb787b606a71ea941f26b59f6b6a321f97d63b9cb1",
        policy_uri="http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_1.der",
    )
    sealed = sealer.seal_issue(make_pdf(["Holerite"]), placement=None)
    sig = next(iter(PdfFileReader(io.BytesIO(sealed)).embedded_signatures))
    attrs = {a["type"].native: a for a in sig.signer_info["signed_attrs"]}
    pol = attrs["signature_policy_identifier"]["values"][0].chosen
    assert pol["sig_policy_id"].dotted == oid
    assert pol["sig_policy_hash"]["digest"].native.hex().startswith("95752d26")
    assert "commitment_type" in attrs
    infos = inspect_signatures(sealed, load_cert_files([pki["ca"]]))
    assert infos[0].intact and infos[0].valid


def test_stamp_text_is_latin1_safe():
    from portal.signing.pades import winansi_safe

    assert winansi_safe("Ação · matrícula — SHA… Ştefan ✓") == "Ação · matrícula - SHA... Stefan ?"


def _pdf_with_text_field() -> bytes:
    import io

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.drawString(60, 800, "Holerite com campo editável")
    c.acroForm.textfield(name="salario", value="1000,00", x=60, y=700, width=120, height=20)
    c.save()
    return buf.getvalue()


def test_pdf_with_editable_fields_is_rejected(sealer):
    import pytest

    from portal.signing.pades import SealingError

    with pytest.raises(SealingError, match="formulário editáveis"):
        sealer.seal_issue(_pdf_with_text_field(), placement=None)


def test_after_acceptance_document_is_locked(sealer, pki):
    """O campo de aceite trava o documento: uma assinatura/alteração posterior
    deixa de ser 'permitida' para as assinaturas anteriores."""
    import io

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields

    pdf = make_pdf(["Contrato"])
    p = resolve_placement(
        pdf, anchor_text="Assinatura do Colaborador", anchor_page=-1, anchor_box=[300, 40, 560, 110]
    )
    final = sealer.seal_acceptance(
        sealer.seal_issue(pdf, placement=p), stamp_lines=["ACEITE"], reason="Aceite"
    )
    roots = load_cert_files([pki["ca"]])
    assert all(i.docmdp_ok is not False for i in inspect_signatures(final, roots))
    # tentativa de acrescentar um novo campo de assinatura depois do aceite
    w = IncrementalPdfFileWriter(io.BytesIO(final))
    fields.append_signature_field(w, fields.SigFieldSpec("Intruso", on_page=0, box=(10, 10, 60, 40)))
    out = io.BytesIO()
    w.write(out)
    infos = {i.field: i for i in inspect_signatures(out.getvalue(), roots)}
    assert infos[FIELD_ACCEPT].modification_level == "OTHER" or not infos[FIELD_ACCEPT].docmdp_ok


def test_stamp_text_nbsp_and_controls():
    from pyhanko.pdf_utils.generic import encode_pdfdocencoding

    from portal.signing.pades import winansi_safe

    out = winansi_safe("Maria Aparecida­Silva\x07 — R$ 1.000")
    assert out == "Maria AparecidaSilva - R$ 1.000"
    encode_pdfdocencoding(out)  # não levanta: a linha inteira fica em PDFDocEncoding


def test_policy_hash_length_validated(pki):
    import pytest

    from portal.signing.pades import Sealer, SealingError
    from tests.conftest import PFX_PASSWORD

    with pytest.raises(SealingError, match="bytes"):
        Sealer(
            pki["pfx"], PFX_PASSWORD, policy_oid="2.16.76.1.7.1.11.1.1", policy_hash_b64="YWJjZA=="
        )  # 4 bytes, não 32


def test_ltv_mode_with_document_timestamps(sealer, pki):
    """PAdES-LTA: carimbos de documento aparecem na inspeção (antes quebravam)."""
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    from portal.signing.pades import load_cert_files as lcf
    from tests.test_anchoring import _tsa

    tsa: DummyTimeStamper = _tsa()
    sealer.timestamper = tsa
    sealer.ltv_roots = lcf([pki["ca"]]) + [tsa.tsa_cert]
    sealed = sealer.seal_issue(make_pdf(["Holerite LTA"]), placement=None)
    infos = inspect_signatures(sealed, lcf([pki["ca"]]) + [tsa.tsa_cert])
    kinds = {i.field.split(":")[0] for i in infos}
    assert FIELD_ISSUE in kinds and "carimbo" in kinds
    assert all(i.intact for i in infos)
