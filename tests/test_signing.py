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
