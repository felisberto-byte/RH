"""Testes do provedor LDAP com conexões falsas (sem AD real)."""

from __future__ import annotations

import uuid

import pytest

from portal.auth.base import AuthError, DirectoryUnavailable
from portal.auth.ldap import (
    BLOCKED_ERROR,
    GENERIC_ERROR,
    LdapAuthProvider,
    bind_error_message,
    normalize_username,
)
from portal.config import Settings

GUID = uuid.UUID("6f1c2a3b-1111-2222-3333-444455556666")
USER_DN = "CN=Maria Silva,OU=Usuarios,DC=empresa,DC=local"


class FakeConn:
    """Imita ldap3.Connection: bind/search/unbind com respostas programadas."""

    def __init__(self, directory, user, password):
        self.d, self.user, self.password = directory, user, password
        self.response, self.result = [], {}

    def bind(self):
        if self.d.down:
            from ldap3.core.exceptions import LDAPSocketOpenError

            raise LDAPSocketOpenError("down")
        ok = self.d.passwords.get(self.user) == self.password and bool(self.password)
        self.result = {} if ok else {"message": f"80090308: LdapErr, data {self.d.bind_code}, v4563"}
        self.d.binds.append(self.user)
        return ok

    def search(self, base, flt, scope, attributes=None, size_limit=0):
        self.d.searches.append((base, flt))
        if "memberOf" in flt:
            ok = any(g in flt for g in self.d.groups)
            self.response = [{"type": "searchResEntry", "dn": base}] if ok else []
            return
        self.response = (
            []
            if not self.d.entry
            else [
                {
                    "type": "searchResEntry",
                    "dn": USER_DN,
                    "attributes": self.d.entry,
                    "raw_attributes": {"objectGUID": [GUID.bytes_le]},
                }
            ]
        )

    def unbind(self):
        pass


class FakeDirectory:
    def __init__(self):
        self.down = False
        self.bind_code = "52e"
        self.passwords = {"CN=svc": "svc-pass", USER_DN: "certa"}
        self.groups = ["CN=GG_Portal_Colaboradores"]
        self.binds, self.searches = [], []
        self.entry = {
            "sAMAccountName": "maria.silva",
            "userPrincipalName": "maria.silva@empresa.local",
            "displayName": "Maria Silva",
            "mail": "maria@empresa.com.br",
            "userAccountControl": 512,
            "employeeNumber": "000123",
        }


@pytest.fixture
def directory():
    return FakeDirectory()


@pytest.fixture
def provider(directory, monkeypatch):
    s = Settings(
        env="test",
        ldap_url="ldaps://dc01.empresa.local:636",
        ldap_bind_dn="CN=svc",
        ldap_bind_password="svc-pass",
        ldap_base_dn="DC=empresa,DC=local",
        ldap_group_users_dn="CN=GG_Portal_Colaboradores",
        ldap_group_admin_dn="CN=GG_Portal_RH",
    )
    p = LdapAuthProvider(s)
    monkeypatch.setattr(p, "_connection", lambda user, pw: FakeConn(directory, user, pw))
    return p


def test_tls_requires_certificate_validation(provider):
    import ssl

    assert provider.server.ssl is True
    assert provider.server.tls.validate == ssl.CERT_REQUIRED


def test_successful_login_maps_identity(provider, directory):
    ident = provider.authenticate("EMPRESA\\maria.silva", "certa")
    assert ident.object_guid == str(GUID)
    assert ident.employee_id == "000123" and not ident.is_admin
    assert directory.binds == ["CN=svc", USER_DN]


def test_filter_is_escaped(provider, directory):
    with pytest.raises(AuthError):
        provider.authenticate("a*)(uid=*", "x")  # caracteres inválidos rejeitados antes do LDAP
    assert directory.searches == []
    provider.authenticate("maria.silva", "certa")
    assert "maria.silva" in directory.searches[0][1]


def test_empty_password_never_reaches_ad(provider, directory):
    with pytest.raises(AuthError):
        provider.authenticate("maria.silva", "")
    assert directory.binds == []


def test_wrong_password_and_locked_are_generic(provider, directory):
    with pytest.raises(AuthError, match=GENERIC_ERROR):
        provider.authenticate("maria.silva", "errada")
    directory.bind_code = "775"
    with pytest.raises(AuthError) as exc:
        provider.authenticate("maria.silva", "errada")
    assert str(exc.value) == BLOCKED_ERROR


def test_disabled_account_and_group_membership(provider, directory):
    directory.entry["userAccountControl"] = 514
    with pytest.raises(AuthError, match="procure a TI"):
        provider.authenticate("maria.silva", "certa")
    directory.entry["userAccountControl"] = 512
    directory.groups = []
    with pytest.raises(AuthError, match="não tem acesso"):
        provider.authenticate("maria.silva", "certa")


def test_directory_down(provider, directory):
    directory.down = True
    with pytest.raises(DirectoryUnavailable):
        provider.authenticate("maria.silva", "certa")


def test_reauth(provider):
    ident = provider.authenticate("maria.silva", "certa")
    assert provider.verify_password(ident, "certa")
    assert not provider.verify_password(ident, "errada")
    assert not provider.verify_password(ident, "")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("maria.silva", "maria.silva"),
        ("EMPRESA\\joao", "joao"),
        ("ana@empresa.local", "ana@empresa.local"),
    ],
)
def test_normalize_username(raw, expected):
    assert normalize_username(raw) == expected


def test_password_expired_message_is_specific():
    assert "expirou" in bind_error_message({"message": "AcceptSecurityContext error, data 532, v"})
