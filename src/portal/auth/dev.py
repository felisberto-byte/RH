"""Provedor de autenticação SOMENTE para desenvolvimento local e testes.

A configuração recusa ``auth_provider=dev`` quando ``env=prod``.
"""

from __future__ import annotations

import hmac
import uuid

from portal.auth.base import AuthError, Identity

DEV_PASSWORD = "dev"  # noqa: S105 - credencial fictícia de desenvolvimento

DEV_USERS: dict[str, dict] = {
    "maria.silva": {"display_name": "Maria Silva", "employee_id": "000123", "is_admin": False},
    "joao.souza": {"display_name": "João Souza", "employee_id": "000456", "is_admin": False},
    "rh.admin": {"display_name": "Ana RH", "employee_id": "000900", "is_admin": True},
}


class DevAuthProvider:
    def __init__(self, users: dict[str, dict] | None = None, password: str = DEV_PASSWORD):
        self.users = users if users is not None else DEV_USERS
        self.password = password

    def _identity(self, username: str) -> Identity:
        u = self.users[username]
        return Identity(
            username=username,
            display_name=u["display_name"],
            object_guid=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{username}.dev.local")),
            dn=f"CN={u['display_name']},OU=Usuarios,DC=dev,DC=local",
            upn=f"{username}@dev.local",
            email=f"{username}@dev.local",
            employee_id=u.get("employee_id"),
            is_admin=bool(u.get("is_admin")),
        )

    def authenticate(self, username: str, password: str) -> Identity:
        username = username.strip().lower()
        if username not in self.users or not hmac.compare_digest(password, self.password):
            raise AuthError("Usuário ou senha inválidos.")
        return self._identity(username)

    def refresh(self, identity: Identity) -> Identity | None:
        if identity.username not in self.users:
            return None
        return self._identity(identity.username)

    def verify_password(self, identity: Identity, password: str) -> bool:
        return identity.username in self.users and hmac.compare_digest(password, self.password)
