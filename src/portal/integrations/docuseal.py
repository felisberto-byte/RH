"""Adaptador opcional para o DocuSeal (edição open-source, auto-hospedado).

Limitações da edição open-source (verificadas no código-fonte/README do
projeto): SSO/SAML, formulário de assinatura *embutido* e criação de envios a
partir de PDF avulso (``/api/submissions/pdf``) são recursos Pro. Por isso:

- o DocuSeal é usado apenas para **modelos fixos** criados no próprio DocuSeal
  (ex.: contrato de trabalho, aditivos), com os campos pré-preenchidos via API
  (``POST /api/submissions`` com ``template_id``);
- o link de assinatura **não é enviado por e-mail** (``send_email: false``): o
  portal cria o envio somente quando o colaborador, já autenticado no AD,
  clica em "Assinar", e o redireciona ao link. Assim a identidade AD fica
  vinculada à sessão que abriu o link (evento ``DOCUSEAL_LINK_ABERTO``);
- a conclusão chega por webhook (``form.completed``) assinado com HMAC
  (cabeçalho ``X-Docuseal-Signature: <ts>.<hex>``).

O selo da empresa (e-CNPJ) é aplicado pelo PORTAL sobre o PDF devolvido pelo
DocuSeal (ver ``documents/docuseal_flow.py``); no DocuSeal recomenda-se
``CERTS={"enabled":false}`` para não haver um segundo certificado autoassinado.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

MAX_DOWNLOAD = 30 * 1024 * 1024
log = logging.getLogger(__name__)


class DocusealError(Exception):
    pass


def sign_payload(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"{ts}.{mac}"


def verify_signature(
    secret: str, body: bytes, header: str | None, *, tolerance: int = 300, now: int | None = None
) -> bool:
    if not secret or not header or "." not in header:
        return False
    ts_raw, sig = header.split(".", 1)
    try:
        ts = int(ts_raw)
    except ValueError:
        return False
    now = int(time.time()) if now is None else now
    if abs(now - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


@dataclass(frozen=True)
class SubmitterLink:
    submission_id: int
    submitter_id: int
    signing_url: str


class DocusealClient:
    def __init__(self, base_url: str, token: str, *, http: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        base = urlsplit(self.base_url)
        self._scheme, self._host = base.scheme, base.netloc
        self.http = http or httpx.Client(timeout=20)
        self.headers = {"X-Auth-Token": token}

    def _api(self, method: str, path: str, **kw) -> httpx.Response:
        """Chamada à API (único destino que recebe o token)."""
        try:
            return self.http.request(method, f"{self.base_url}/api/{path}", headers=self.headers, **kw)
        except httpx.HTTPError as exc:
            raise DocusealError(f"DocuSeal indisponível: {type(exc).__name__}") from exc

    def create_submission(
        self,
        *,
        template_id: int,
        email: str,
        name: str,
        external_id: str,
        values: dict[str, str],
        metadata: dict[str, str] | None = None,
        expire_at: datetime | None = None,
        completed_redirect_url: str | None = None,
        role: str | None = None,
    ) -> SubmitterLink:
        submitter: dict = {
            "email": email,
            "name": name,
            "external_id": external_id,
            "send_email": False,
            # Campos pré-preenchidos e bloqueados (o colaborador não altera).
            "values": values,
            "readonly_fields": list(values),
            # Identidade AD de quem abriu o link (aparece na API e nos webhooks).
            "metadata": metadata or {},
        }
        if role:
            submitter["role"] = role
        payload: dict = {"template_id": template_id, "send_email": False, "submitters": [submitter]}
        if expire_at is not None:
            payload["expire_at"] = expire_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        if completed_redirect_url:
            payload["completed_redirect_url"] = completed_redirect_url
        r = self._api("POST", "submissions", json=payload)
        if r.status_code >= 400:
            raise DocusealError(f"DocuSeal recusou o envio ({r.status_code}): {r.text[:300]}")
        try:
            data = r.json()
            items = data if isinstance(data, list) else data.get("submitters", [])
            if not items:
                raise DocusealError("DocuSeal não retornou o signatário")
            sub = items[0]
            url = sub.get("embed_src") or f"{self.base_url}/s/{sub['slug']}"
            link = SubmitterLink(int(sub["submission_id"]), int(sub["id"]), url)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise DocusealError("resposta inesperada do DocuSeal ao criar o envio") from exc
        self._check_host(url)
        return link

    def get_submitter(self, submitter_id: int) -> dict | None:
        try:
            r = self._api("GET", f"submitters/{int(submitter_id)}")
            return r.json() if r.status_code == 200 else None
        except (DocusealError, ValueError):
            return None

    def archive_submission(self, submission_id: int) -> None:
        """Arquiva (invalida) um envio anterior; falhas são registradas e ignoradas."""
        try:
            r = self._api("DELETE", f"submissions/{int(submission_id)}")
            if r.status_code >= 400 and r.status_code != 404:
                log.warning("DocuSeal não arquivou o envio %s (%s)", submission_id, r.status_code)
        except DocusealError as exc:
            log.warning("DocuSeal não arquivou o envio %s: %s", submission_id, exc)

    def _check_host(self, url: str) -> None:
        # Evita SSRF e rebaixamento de esquema: só o próprio servidor DocuSeal,
        # com o MESMO esquema e host:porta da URL configurada.
        parts = urlsplit(url)
        if parts.scheme != self._scheme or parts.netloc != self._host:
            raise DocusealError(f"URL fora do servidor DocuSeal: {parts.scheme}://{parts.netloc}")

    def download(self, url: str, _depth: int = 0) -> bytes:
        """Baixa arquivo (PDF assinado, trilha). As URLs de arquivo do DocuSeal
        são assinadas: o token da API NÃO é enviado (nem em redirecionamentos)."""
        self._check_host(url)
        try:
            with self.http.stream("GET", url, follow_redirects=False) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    if _depth >= 3:
                        raise DocusealError("redirecionamentos demais ao baixar do DocuSeal")
                    location = str(r.url.join(r.headers.get("location", "")))
                    return self.download(location, _depth + 1)
                if r.status_code >= 400:
                    raise DocusealError(f"falha ao baixar arquivo do DocuSeal ({r.status_code})")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > MAX_DOWNLOAD:
                        raise DocusealError("arquivo do DocuSeal excede o limite")
                return bytes(buf)
        except httpx.HTTPError as exc:
            raise DocusealError(f"falha de rede ao baixar do DocuSeal: {type(exc).__name__}") from exc
