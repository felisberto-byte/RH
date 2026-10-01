"""Selo PAdES com o e-CNPJ A1 da empresa (pyHanko).

Sequência (cada passo é uma atualização incremental, preservando as
assinaturas anteriores):

1. **Emissão** (``seal_issue``): cria o campo de assinatura vazio
   ``AceiteColaborador`` na âncora fixa e aplica uma assinatura de
   *certificação* (DocMDP P=2: só permite preencher/assinar campos). Qualquer
   outra alteração posterior no documento invalida a certificação.
2. **Aceite** (``seal_acceptance``): assina o campo ``AceiteColaborador`` com
   carimbo visível contendo identificação do colaborador, data/hora e o hash
   da evidência. A assinatura criptográfica é da empresa (selo do sistema);
   a manifestação de vontade do colaborador é provada pela evidência do aceite
   (identidade AD + reautenticação + IP + data/hora + hash), registrada na
   trilha de auditoria e no comprovante.
3. **Comprovante** (``seal_receipt``): certifica (DocMDP P=1) o comprovante de
   aceite gerado pelo portal.

Com ``tsa_url`` configurado as assinaturas recebem carimbo do tempo
(PAdES B-T). Recomenda-se uma ACT credenciada na ICP-Brasil.
"""

from __future__ import annotations

import base64
import io
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from asn1crypto import algos, core
from asn1crypto import x509 as asn1_x509
from pyhanko.pdf_utils import text as pdf_text
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.ades.api import CAdESSignedAttrSpec, GenericCommitment
from pyhanko.sign.ades.cades_asn1 import (
    SignaturePolicyId,
    SignaturePolicyIdentifier,
    SigPolicyQualifierInfo,
    SigPolicyQualifierInfos,
)
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator import ValidationContext

from portal.signing.anchors import Placement

FIELD_ISSUE = "SeloEmpresaEmissao"
FIELD_ACCEPT = "AceiteColaborador"
FIELD_RECEIPT = "SeloEmpresaComprovante"
FIELD_FINAL = "SeloEmpresaFinal"


def _decode_policy_hash(value: str) -> bytes:
    """Aceita o hash da política em hexadecimal (como publicado na LPA) ou base64."""
    v = value.strip()
    if len(v) in (64, 96, 128) and all(c in "0123456789abcdefABCDEF" for c in v):
        return bytes.fromhex(v)
    return base64.b64decode(v)


_STAMP_REPLACEMENTS = str.maketrans(
    {"…": "...", "—": "-", "–": "-", "‘": "'", "’": "'", "“": '"', "”": '"', "•": "·"}
)


def winansi_safe(text: str) -> str:
    """Mantém o texto representável na fonte padrão do carimbo.

    Na prática só o Latin-1 renderiza corretamente (acentos do português, "·");
    pontuação tipográfica é trocada por equivalente ASCII e outros caracteres
    viram a letra-base (ex.: "ł" -> "l") ou "?".
    """
    out = []
    for ch in text.translate(_STAMP_REPLACEMENTS):
        if ord(ch) < 256:
            out.append(ch)
            continue
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
        out.append(base if base and all(ord(c) < 256 for c in base) else "?")
    return "".join(out)


class SealingError(Exception):
    pass


@dataclass(frozen=True)
class SignatureInfo:
    field: str
    signer_subject: str
    signing_time: datetime | None
    timestamped: bool
    intact: bool
    valid: bool
    trusted: bool
    docmdp_ok: bool | None
    coverage: str
    modification_level: str


class Sealer:
    def __init__(
        self,
        pfx_file: Path,
        pfx_password: str,
        *,
        ca_chain_files: list[Path] | None = None,
        location: str = "Brasil",
        tsa_url: str = "",
        tsa_auth: tuple[str, str] | None = None,
        policy_oid: str = "",
        policy_hash_b64: str = "",
        policy_hash_alg: str = "sha256",
        policy_uri: str = "",
        ltv_trust_roots: list[Path] | None = None,
    ):
        try:
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_file,
                ca_chain_files=[str(p) for p in (ca_chain_files or [])] or None,
                passphrase=pfx_password.encode() if pfx_password else None,
            )
        except Exception as exc:  # noqa: BLE001 - mensagem clara para operação
            raise SealingError(f"não foi possível carregar o certificado A1: {exc}") from exc
        if signer is None:
            raise SealingError("não foi possível carregar o certificado A1 (senha incorreta?)")
        self.signer = signer
        self.location = location
        self.timestamper = (
            timestamps.HTTPTimeStamper(tsa_url, auth=tsa_auth, timeout=15) if tsa_url else None
        )
        # PAdES B-LT/B-LTA: embute cadeia + CRL/OCSP (DSS) e carimbo de documento,
        # para que a assinatura continue verificável após o vencimento do A1.
        self.ltv_vc: ValidationContext | None = None
        if ltv_trust_roots:
            if self.timestamper is None:
                raise SealingError("LTV exige uma TSA configurada (PORTAL_TSA_URL)")
            self.ltv_vc = ValidationContext(
                trust_roots=load_cert_files(ltv_trust_roots), allow_fetching=True
            )
        # Política de assinatura ICP-Brasil (DOC-ICP-15.03, ex.: PA_PAdES_AD_RB/AD_RT).
        # O OID e o hash vêm da LPA publicada pelo ITI; pyHanko apenas embute o
        # identificador — cabe a nós cumprir as regras da política.
        self.policy_id: SignaturePolicyIdentifier | None = None
        if policy_oid:
            if not policy_hash_b64:
                raise SealingError("política de assinatura exige o hash (signature_policy_hash_b64)")
            spec = {
                "sig_policy_id": policy_oid,
                "sig_policy_hash": algos.DigestInfo(
                    {
                        "digest_algorithm": {"algorithm": policy_hash_alg},
                        "digest": _decode_policy_hash(policy_hash_b64),
                    }
                ),
            }
            if policy_uri:
                spec["sig_policy_qualifiers"] = SigPolicyQualifierInfos(
                    [
                        SigPolicyQualifierInfo(
                            {
                                "sig_policy_qualifier_id": "sp_uri",
                                "sig_qualifier": core.IA5String(policy_uri),
                            }
                        )
                    ]
                )
            self.policy_id = SignaturePolicyIdentifier(
                name="signature_policy_id", value=SignaturePolicyId(spec)
            )

    # ------------------------------------------------------------------ util
    @property
    def certificate(self) -> asn1_x509.Certificate:
        return self.signer.signing_cert

    @property
    def subject(self) -> str:
        return self.certificate.subject.human_friendly

    def not_valid_after(self) -> datetime:
        return self.certificate["tbs_certificate"]["validity"]["not_after"].native

    def _meta(
        self, field_name: str, reason: str, *, commitment=None, **kw
    ) -> signers.PdfSignatureMetadata:
        cades = None
        if self.policy_id is not None or commitment is not None:
            cades = CAdESSignedAttrSpec(
                signature_policy_identifier=self.policy_id, commitment_type=commitment
            )
        if self.ltv_vc is not None:
            kw.setdefault("embed_validation_info", True)
            kw.setdefault("validation_context", self.ltv_vc)
            kw.setdefault("use_pades_lta", True)
        return signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason,
            location=self.location,
            md_algorithm="sha256",
            subfilter=fields.SigSeedSubFilter.PADES,
            cades_signed_attr_spec=cades,
            **kw,
        )

    @staticmethod
    def _writer(pdf: bytes) -> IncrementalPdfFileWriter:
        try:
            w = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
        except Exception as exc:  # noqa: BLE001
            raise SealingError(f"PDF inválido: {exc}") from exc
        if w.prev.encrypted:
            raise SealingError("PDF criptografado/protegido não é suportado")
        return w

    # --------------------------------------------------------------- emissão
    def seal_issue(
        self, pdf: bytes, *, placement: Placement | None, reason: str = "Emissão do documento"
    ) -> bytes:
        """Certifica o documento; se ``placement`` for dado, cria o campo de aceite."""
        w = self._writer(pdf)
        existing = list(PdfFileReader(io.BytesIO(pdf), strict=False).embedded_signatures)
        if existing:
            raise SealingError("o PDF de origem já contém assinaturas; envie o PDF sem assinatura")
        if placement is not None:
            fields.append_signature_field(
                w,
                fields.SigFieldSpec(
                    FIELD_ACCEPT,
                    on_page=placement.page,
                    box=placement.box,
                    readable_field_name="Aceite do colaborador",
                ),
            )
            perm = fields.MDPPerm.FILL_FORMS
        else:
            perm = fields.MDPPerm.NO_CHANGES
        meta = self._meta(
            FIELD_ISSUE,
            reason,
            commitment=GenericCommitment.PROOF_OF_ORIGIN.asn1,
            certify=True,
            docmdp_permissions=perm,
        )
        out = signers.PdfSigner(
            meta,
            self.signer,
            timestamper=self.timestamper,
            new_field_spec=fields.SigFieldSpec(FIELD_ISSUE),
        ).sign_pdf(w)
        return out.getvalue()

    # ----------------------------------------------------------------- aceite
    def seal_acceptance(self, sealed_pdf: bytes, *, stamp_lines: list[str], reason: str) -> bytes:
        w = self._writer(sealed_pdf)
        style = TextStampStyle(
            stamp_text="\n".join(winansi_safe(line).replace("%", "%%") for line in stamp_lines),
            # Fonte padrão (Courier/WinAnsi): o caminho OpenType do pyHanko gerou
            # espaçamento incorreto entre letras nos visualizadores (pdfium/Chrome).
            text_box_style=pdf_text.TextBoxStyle(font_size=7, leading=9),
            border_width=1,
            background_opacity=0,
        )
        meta = self._meta(FIELD_ACCEPT, reason)
        try:
            out = signers.PdfSigner(
                meta, self.signer, timestamper=self.timestamper, stamp_style=style
            ).sign_pdf(w, existing_fields_only=True)
        except Exception as exc:  # noqa: BLE001
            raise SealingError(f"falha ao aplicar o selo de aceite: {exc}") from exc
        return out.getvalue()

    # ------------------------------------------------------------ comprovante
    def seal_receipt(self, pdf: bytes) -> bytes:
        w = self._writer(pdf)
        meta = self._meta(
            FIELD_RECEIPT,
            "Comprovante de aceite eletrônico",
            commitment=GenericCommitment.PROOF_OF_ORIGIN.asn1,
            certify=True,
            docmdp_permissions=fields.MDPPerm.NO_CHANGES,
        )
        out = signers.PdfSigner(
            meta,
            self.signer,
            timestamper=self.timestamper,
            new_field_spec=fields.SigFieldSpec(FIELD_RECEIPT),
        ).sign_pdf(w)
        return out.getvalue()

    # ------------------------------------------------- selo final (DocuSeal)
    def seal_final(self, pdf: bytes, *, reason: str) -> bytes:
        """Assinatura de aprovação (incremental) sobre um PDF já assinado por
        terceiros (ex.: resultado do DocuSeal). Deve ser a ÚLTIMA assinatura:
        o DocuSeal achata/reescreve o PDF e invalidaria um selo aplicado antes."""
        w = self._writer(pdf)
        meta = self._meta(FIELD_FINAL, reason)
        try:
            out = signers.PdfSigner(
                meta,
                self.signer,
                timestamper=self.timestamper,
                new_field_spec=fields.SigFieldSpec(FIELD_FINAL),
            ).sign_pdf(w)
        except Exception as exc:  # noqa: BLE001
            raise SealingError(f"falha ao aplicar o selo final: {exc}") from exc
        return out.getvalue()


def inspect_signatures(pdf: bytes, trust_roots: list[asn1_x509.Certificate]) -> list[SignatureInfo]:
    """Valida as assinaturas embutidas (integridade, cadeia, DocMDP)."""
    vc = ValidationContext(trust_roots=trust_roots, allow_fetching=False)
    reader = PdfFileReader(io.BytesIO(pdf), strict=False)
    infos = []
    for sig in reader.embedded_signatures:
        st = validate_pdf_signature(sig, vc)
        infos.append(
            SignatureInfo(
                field=sig.field_name,
                signer_subject=st.signing_cert.subject.human_friendly,
                signing_time=st.signer_reported_dt,
                timestamped=st.timestamp_validity is not None,
                intact=st.intact,
                valid=st.valid,
                trusted=st.trusted,
                docmdp_ok=st.docmdp_ok,
                coverage=st.coverage.name if st.coverage else "",
                modification_level=st.modification_level.name if st.modification_level else "",
            )
        )
    return infos


def load_cert_files(paths: list[Path]) -> list[asn1_x509.Certificate]:
    from pyhanko.keys import load_certs_from_pemder

    return list(load_certs_from_pemder([str(p) for p in paths]))


__all__ = [
    "FIELD_ACCEPT",
    "FIELD_FINAL",
    "FIELD_ISSUE",
    "FIELD_RECEIPT",
    "Sealer",
    "SealingError",
    "SignatureInfo",
    "inspect_signatures",
    "load_cert_files",
]
