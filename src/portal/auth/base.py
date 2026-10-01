from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AuthError(Exception):
    """Falha de autenticação com mensagem segura para exibir ao usuário."""


class DirectoryUnavailable(AuthError):
    pass


@dataclass(frozen=True)
class Identity:
    username: str  # sAMAccountName
    display_name: str
    object_guid: str  # objectGUID do AD (identificador imutável)
    dn: str
    upn: str | None = None
    email: str | None = None
    employee_id: str | None = None  # matrícula (atributo employeeID no AD)
    is_admin: bool = False


class AuthProvider(Protocol):
    def authenticate(self, username: str, password: str) -> Identity:
        """Valida as credenciais e devolve a identidade; lança AuthError."""

    def verify_password(self, identity: Identity, password: str) -> bool:
        """Reautenticação (step-up) no momento do aceite."""

    def refresh(self, identity: Identity) -> Identity | None:
        """Revalida a conta (habilitada/grupos) sem senha; None = encerrar sessão."""
