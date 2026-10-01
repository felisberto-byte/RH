"""Segundo fator TOTP (RFC 6238) para o ato do aceite.

O segredo é cifrado em repouso (Fernet, chave derivada de PORTAL_SECRET_KEY
via HKDF) e cada código só pode ser usado uma vez (proteção contra replay).
"""

from __future__ import annotations

import base64
import io
import time

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from markupsafe import Markup
from sqlalchemy.orm import Session

from portal import audit
from portal.db import utcnow
from portal.models import Employee, TotpCredential

STEP = 30


def _fernet(secret_key: str) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"portal-totp-v1", info=b"totp-secret").derive(
        secret_key.encode()
    )
    return Fernet(base64.urlsafe_b64encode(key))


class TotpService:
    def __init__(self, db: Session, secret_key: str, issuer: str):
        self.db = db
        self.f = _fernet(secret_key)
        self.issuer = issuer

    def get(self, employee_id: int) -> TotpCredential | None:
        return self.db.get(TotpCredential, employee_id)

    def is_enrolled(self, employee_id: int) -> bool:
        cred = self.get(employee_id)
        return cred is not None and cred.confirmed_at is not None

    def _secret(self, cred: TotpCredential) -> str:
        try:
            return self.f.decrypt(cred.secret_enc.encode()).decode()
        except InvalidToken as exc:  # chave do portal trocada sem migrar segredos
            raise RuntimeError("segredo TOTP ilegível (PORTAL_SECRET_KEY mudou?)") from exc

    def start_enrollment(self, employee: Employee) -> tuple[str, str]:
        """Cria (ou recria, se não confirmado) o segredo; devolve (segredo, uri)."""
        cred = self.get(employee.id)
        if cred is not None and cred.confirmed_at is not None:
            raise ValueError("segundo fator já configurado")
        secret = pyotp.random_base32()
        enc = self.f.encrypt(secret.encode()).decode()
        if cred is None:
            cred = TotpCredential(employee_id=employee.id, secret_enc=enc)
            self.db.add(cred)
        else:
            cred.secret_enc = enc
        self.db.commit()
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=employee.ad_username or employee.matricula, issuer_name=self.issuer
        )
        return secret, uri

    def pending_uri(self, employee: Employee) -> tuple[str, str] | None:
        cred = self.get(employee.id)
        if cred is None or cred.confirmed_at is not None:
            return None
        secret = self._secret(cred)
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=employee.ad_username or employee.matricula, issuer_name=self.issuer
        )
        return secret, uri

    def _match_step(self, secret: str, code: str, now: float | None = None) -> int | None:
        code = (code or "").strip().replace(" ", "")
        if not (len(code) == 6 and code.isdigit()):
            return None
        now = time.time() if now is None else now
        totp = pyotp.TOTP(secret)
        for drift in (0, -1, 1):
            step = int(now // STEP) + drift
            if totp.at(step * STEP) == code:
                return step
        return None

    def confirm(self, employee: Employee, code: str, *, ip: str, ua: str) -> bool:
        cred = self.get(employee.id)
        if cred is None or cred.confirmed_at is not None:
            return False
        step = self._match_step(self._secret(cred), code)
        if step is None:
            return False
        cred.confirmed_at = utcnow()
        cred.last_used_step = step
        audit.record(
            self.db,
            action="MFA_CONFIGURADO",
            actor_type="colaborador",
            actor_ref=employee.ad_username or employee.matricula,
            ip=ip,
            user_agent=ua,
            data={"metodo": "totp", "matricula": employee.matricula},
        )
        self.db.commit()
        return True

    def verify(self, employee_id: int, code: str, now: float | None = None) -> bool:
        """Valida e consome o código (não pode ser reutilizado)."""
        cred = self.get(employee_id)
        if cred is None or cred.confirmed_at is None:
            return False
        step = self._match_step(self._secret(cred), code, now)
        if step is None or step <= cred.last_used_step:
            return False
        cred.last_used_step = step
        return True

    def reset(self, employee_id: int, *, actor_ref: str, reason: str, ip: str | None) -> None:
        cred = self.get(employee_id)
        if cred is not None:
            self.db.delete(cred)
        audit.record(
            self.db,
            action="MFA_REDEFINIDO",
            actor_type="rh",
            actor_ref=actor_ref,
            ip=ip,
            data={"employee_id": employee_id, "motivo": reason},
        )
        self.db.commit()


def qr_svg(uri: str) -> Markup:
    """SVG do QR code, gerado localmente (sem serviço externo) e seguro para inserir no HTML."""
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode()
    return Markup(svg[svg.index("<svg") :])  # noqa: S704 - conteúdo gerado por nós
