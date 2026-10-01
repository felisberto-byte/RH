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

# Mensagem ÚNICA para qualquer falha que não prove a senha: usuário inexistente,
# senha errada, conta bloqueada/desabilitada/expirada. Inclui a dica do bloqueio
# para quem tem certeza da senha, sem revelar o estado de nenhuma conta.
GENERIC_ERROR = (
    "Usuário ou senha inválidos. Se tem certeza da senha, sua conta pode estar bloqueada: procure a TI."
)
# Só exibida DEPOIS de a senha ser comprovada (conta desabilitada no AD).
BLOCKED_ERROR = "Não foi possível entrar. Se o problema persistir, procure a TI."

# Subcódigos do AD em "AcceptSecurityContext error, data XXX". Só 532/773 são
# devolvidos com a senha CORRETA, então só eles ganham mensagem específica.
# O AD devolve 775 (bloqueio), 533 (desabilitada) etc. mesmo com senha ERRADA:
# eles recebem a mensagem genérica (sem enumeração) e o subcódigo vai ao log.
AD_BIND_ERRORS = {
    "532": "Sua senha expirou. Altere-a em um computador da empresa e tente novamente.",
    "773": "É necessário trocar a senha antes do primeiro acesso.",
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

    def _identity_from(self, conn: Connection, entry: dict, fallback_username: str) -> Identity:
        """Monta a identidade e aplica as checagens de conta (habilitada, grupos).
        Só deve ser chamado DEPOIS de provada a senha (ou na revalidação), para
        que mensagens diferentes não revelem quais contas existem."""
        attrs = entry["attributes"]
        raw = entry.get("raw_attributes", {})
        dn = entry["dn"]
        uac = int(self._first(attrs, "userAccountControl") or 0)
        if uac & UAC_ACCOUNTDISABLE:
            log.info("acesso recusado: conta desabilitada (%s)", fallback_username)
            raise AuthError(BLOCKED_ERROR)
        guid_raw = (raw.get("objectGUID") or [b""])[0]
        if len(guid_raw) != 16:
            raise AuthError("Conta sem objectGUID válido no diretório.")
        is_admin = self._in_group(conn, dn, self.s.ldap_group_admin_dn)
        if self.s.ldap_group_users_dn and not (
            is_admin or self._in_group(conn, dn, self.s.ldap_group_users_dn)
        ):
            raise AuthError("Seu usuário não tem acesso ao Portal do Colaborador.")
        return Identity(
            username=self._first(attrs, "sAMAccountName") or fallback_username,
            display_name=self._first(attrs, "displayName") or fallback_username,
            object_guid=str(uuid.UUID(bytes_le=bytes(guid_raw))),
            dn=dn,
            upn=self._first(attrs, "userPrincipalName"),
            email=self._first(attrs, "mail"),
            employee_id=self._first(attrs, self.s.ldap_employee_id_attr),
            is_admin=is_admin,
        )

    # ---------------------------------------------------------------- API
    def authenticate(self, username: str, password: str) -> Identity:
        username = normalize_username(username)
        if not password:
            # Bind com senha vazia é um "unauthenticated bind" que o AD aceita.
            raise AuthError(GENERIC_ERROR)
        conn = self._service_conn()
        try:
            try:
                entry = self._find_user(conn, username)
            except AuthError:
                raise AuthError(GENERIC_ERROR) from None
            # 1º prova a senha; só então revela estado da conta (desabilitada,
            # fora do grupo) — sem isso dá para enumerar contas sem senha.
            self._bind_user(entry["dn"], password)
            return self._identity_from(conn, entry, username)
        finally:
            conn.unbind()

    def refresh(self, identity: Identity) -> Identity | None:
        """Revalida a conta durante a sessão (sem senha): ainda existe, está
        habilitada e nos grupos? ``None`` = sessão deve ser encerrada."""
        conn = self._service_conn()
        try:
            try:
                entry = self._find_user(conn, identity.username)
                fresh = self._identity_from(conn, entry, identity.username)
            except AuthError:
                return None
            if fresh.object_guid != identity.object_guid:
                return None
            return fresh
        finally:
            conn.unbind()

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
