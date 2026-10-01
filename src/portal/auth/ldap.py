"""Autenticação no Active Directory via LDAPS (porta 636), através da VPN
GCP <-> rede local. O Windows Server continua servindo apenas AD/DNS; o portal
só faz *binds* LDAP de leitura.

Fluxo:
1. *bind* com a conta de serviço (somente leitura) e busca do usuário;
2. checagens: conta habilitada, grupo de acesso (com grupos aninhados);
3. *bind* com o DN do usuário e a senha digitada (prova de posse da senha).
"""

from __future__ import annotations

import logging
import re
import ssl
import uuid

from ldap3 import BASE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from portal.auth.base import AuthError, DirectoryUnavailable, Identity
from portal.config import Settings

log = logging.getLogger(__name__)

UAC_ACCOUNTDISABLE = 0x0002
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

GENERIC_ERROR = "Usuário ou senha inválidos."
BLOCKED_ERROR = "Não foi possível entrar. Se o problema persistir, procure a TI."

# Subcódigos do AD em "AcceptSecurityContext error, data XXX". Só 532/773 são
# devolvidos com a senha CORRETA, então só eles ganham mensagem específica;
# os demais (775 bloqueio, 533 desabilitada...) não podem revelar se a conta
# existe (enumeração de usuários) e são apenas registrados no log.
AD_BIND_ERRORS = {
    "525": GENERIC_ERROR,
    "52e": GENERIC_ERROR,
    "530": BLOCKED_ERROR,
    "531": BLOCKED_ERROR,
    "532": "Sua senha expirou. Altere-a em um computador da empresa e tente novamente.",
    "533": BLOCKED_ERROR,
    "701": BLOCKED_ERROR,
    "773": "É necessário trocar a senha antes do primeiro acesso.",
    "775": BLOCKED_ERROR,
}
_DATA_RE = re.compile(r"data ([0-9a-f]{3})", re.IGNORECASE)

_USERNAME_RE = re.compile(r"^[\w.\-@]{1,128}$")


def normalize_username(raw: str) -> str:
    name = raw.strip()
    if "\\" in name:  # DOMINIO\usuario
        name = name.split("\\", 1)[1]
    if not _USERNAME_RE.match(name):
        raise AuthError("Usuário ou senha inválidos.")
    return name


def bind_error_message(result: dict | None) -> str:
    msg = (result or {}).get("message", "") or ""
    m = _DATA_RE.search(msg)
    code = m.group(1).lower() if m else None
    log.info("bind LDAP recusado (subcódigo AD %s)", code or "n/d")
    return AD_BIND_ERRORS.get(code or "", GENERIC_ERROR)


class LdapAuthProvider:
    def __init__(self, settings: Settings):
        self.s = settings
        tls = None
        if settings.ldap_url.startswith("ldaps://"):
            # ldap3 NÃO valida o certificado por padrão (CERT_NONE): exigir sempre.
            tls = Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ca_certs_file=str(settings.ldap_ca_cert_file) if settings.ldap_ca_cert_file else None,
                valid_names=settings.ldap_tls_valid_names or None,
            )
        self.server = Server(
            settings.ldap_url,
            use_ssl=settings.ldap_url.startswith("ldaps://"),
            tls=tls,
            connect_timeout=settings.ldap_timeout_seconds,
        )

    # ----------------------------------------------------------- conexões
    def _connection(self, user: str, password: str) -> Connection:
        return Connection(
            self.server,
            user=user,
            password=password,
            auto_bind=False,
            read_only=True,
            raise_exceptions=False,
            receive_timeout=self.s.ldap_timeout_seconds,
        )

    def _service_conn(self) -> Connection:
        conn = self._connection(self.s.ldap_bind_dn, self.s.ldap_bind_password.get_secret_value())
        try:
            ok = conn.bind()
        except LDAPException as exc:
            raise DirectoryUnavailable("Diretório indisponível. Tente novamente em instantes.") from exc
        if not ok:
            raise DirectoryUnavailable("Falha na conta de serviço do diretório. Avise a TI.")
        return conn

    # ------------------------------------------------------------- consultas
    def _find_user(self, conn: Connection, username: str) -> dict:
        flt = self.s.ldap_user_filter.format(username=escape_filter_chars(username))
        attrs = [
            "distinguishedName",
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "mail",
            "objectGUID",
            "userAccountControl",
            self.s.ldap_employee_id_attr,
        ]
        conn.search(self.s.ldap_base_dn, flt, SUBTREE, attributes=attrs, size_limit=2)
        entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
        if len(entries) != 1:
            raise AuthError("Usuário ou senha inválidos.")
        return entries[0]

    def _in_group(self, conn: Connection, user_dn: str, group_dn: str) -> bool:
        if not group_dn:
            return False
        flt = f"(memberOf:{MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group_dn)})"
        conn.search(user_dn, flt, BASE, attributes=["cn"])
        return any(e.get("type") == "searchResEntry" for e in conn.response or [])

    @staticmethod
    def _first(attrs: dict, name: str) -> str | None:
        v = attrs.get(name)
        if isinstance(v, list):
            v = v[0] if v else None
        return str(v) if v not in (None, "") else None

    # ---------------------------------------------------------------- API
    def authenticate(self, username: str, password: str) -> Identity:
        username = normalize_username(username)
        if not password:
            # Bind com senha vazia é um "unauthenticated bind" que o AD aceita.
            raise AuthError("Usuário ou senha inválidos.")
        conn = self._service_conn()
        try:
            entry = self._find_user(conn, username)
            attrs = entry["attributes"]
            raw = entry.get("raw_attributes", {})
            dn = entry["dn"]
            uac = int(self._first(attrs, "userAccountControl") or 0)
            if uac & UAC_ACCOUNTDISABLE:
                log.info("login recusado: conta desabilitada (%s)", username)
                raise AuthError(BLOCKED_ERROR)
            guid_raw = (raw.get("objectGUID") or [b""])[0]
            if len(guid_raw) != 16:
                raise AuthError("Conta sem objectGUID válido no diretório.")
            object_guid = str(uuid.UUID(bytes_le=bytes(guid_raw)))
            is_admin = self._in_group(conn, dn, self.s.ldap_group_admin_dn)
            if self.s.ldap_group_users_dn and not (
                is_admin or self._in_group(conn, dn, self.s.ldap_group_users_dn)
            ):
                raise AuthError("Seu usuário não tem acesso ao Portal do Colaborador.")
        finally:
            conn.unbind()

        self._bind_user(dn, password)
        return Identity(
            username=self._first(attrs, "sAMAccountName") or username,
            display_name=self._first(attrs, "displayName") or username,
            object_guid=object_guid,
            dn=dn,
            upn=self._first(attrs, "userPrincipalName"),
            email=self._first(attrs, "mail"),
            employee_id=self._first(attrs, self.s.ldap_employee_id_attr),
            is_admin=is_admin,
        )

    def _bind_user(self, dn: str, password: str) -> None:
        if not password:
            raise AuthError("Usuário ou senha inválidos.")
        conn = self._connection(dn, password)
        try:
            ok = conn.bind()
        except LDAPException as exc:
            raise DirectoryUnavailable("Diretório indisponível. Tente novamente em instantes.") from exc
        try:
            if not ok:
                raise AuthError(bind_error_message(conn.result))
        finally:
            conn.unbind()

    def verify_password(self, identity: Identity, password: str) -> bool:
        try:
            self._bind_user(identity.dn, password)
        except DirectoryUnavailable:
            raise
        except AuthError:
            return False
        return True
