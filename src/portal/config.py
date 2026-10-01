"""Configuração do portal, lida de variáveis de ambiente (prefixo PORTAL_).

Segredos (senha do e-CNPJ, senha da conta de serviço do AD, chaves de sessão)
devem vir do Secret Manager do GCP, montados como variáveis de ambiente ou
arquivos no Cloud Run, e nunca devem ser versionados.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PORTAL_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Geral ---------------------------------------------------------------
    env: Literal["dev", "test", "prod"] = "prod"
    base_url: str = "http://localhost:8000"
    company_name: str = "Empresa"
    company_cnpj: str = ""
    timezone: str = "America/Sao_Paulo"
    secret_key: SecretStr = SecretStr("")

    # --- Banco de dados -----------------------------------------------------
    database_url: str = "sqlite:///var/portal.sqlite3"

    # --- Armazenamento de PDFs ---------------------------------------------
    storage_backend: Literal["local", "gcs"] = "local"
    storage_local_path: Path = Path("var/storage")
    storage_gcs_bucket: str = ""

    # --- Autenticação -------------------------------------------------------
    auth_provider: Literal["ldap", "dev"] = "ldap"
    session_idle_minutes: int = 30
    session_absolute_hours: int = 8
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    # Número de proxies confiáveis à frente da aplicação (Google LB = 1, Cloud
    # Run direto = 1). Usado para extrair o IP real do X-Forwarded-For.
    trusted_proxy_hops: int = 0

    # --- Active Directory (LDAPS via VPN) -----------------------------------
    ldap_url: str = "ldaps://dc01.empresa.local:636"
    ldap_ca_cert_file: Path | None = None
    ldap_bind_dn: str = ""
    ldap_bind_password: SecretStr = SecretStr("")
    ldap_base_dn: str = ""
    ldap_user_filter: str = (
        "(&(objectCategory=person)(objectClass=user)"
        "(|(sAMAccountName={username})(userPrincipalName={username})))"
    )
    # Matrícula eSocial (até 30 caracteres): employeeNumber comporta 512;
    # employeeID só 16. Use o atributo que a TI preencher.
    ldap_employee_id_attr: str = "employeeNumber"
    # Nomes aceitos no certificado do DC (útil ao conectar por IP).
    ldap_tls_valid_names: list[str] = Field(default_factory=list)
    ldap_group_users_dn: str = ""
    ldap_group_admin_dn: str = ""
    ldap_timeout_seconds: int = 5

    # --- Assinatura (e-CNPJ A1 / PAdES) -------------------------------------
    signing_pfx_file: Path | None = None
    signing_pfx_password: SecretStr = SecretStr("")
    signing_ca_chain_files: list[Path] = Field(default_factory=list)
    signing_location: str = "Brasil"
    # Carimbo do tempo RFC 3161 (recomendado: ACT credenciada ICP-Brasil).
    tsa_url: str = ""
    tsa_username: str = ""
    tsa_password: SecretStr = SecretStr("")
    # Política de assinatura ICP-Brasil (DOC-ICP-15.03), opcional.
    signature_policy_oid: str = ""
    signature_policy_hash_b64: str = ""
    signature_policy_hash_alg: str = "sha256"
    signature_policy_uri: str = ""

    # Validação de longo prazo (PAdES B-LT/LTA): embute cadeia + CRL/OCSP e
    # carimbo de documento. Exige TSA e as raízes ICP-Brasil em trust_root_files.
    signing_ltv: bool = False
    signing_trust_root_files: list[Path] = Field(default_factory=list)

    # --- Aceite --------------------------------------------------------------
    # "password": o colaborador redigita a senha do AD no momento do aceite.
    accept_reauth: Literal["password", "none"] = "password"
    # Segundo fator no ato do aceite (recomendado em produção: "totp").
    accept_mfa: Literal["none", "totp"] = "none"
    totp_issuer: str = "Portal do Colaborador"
    # Exige aceite do Termo de Adesão vigente antes de usar o portal.
    require_adhesion_term: bool = True
    # Cabeçalho com a porta de origem do cliente, se o balanceador o fornecer
    # (relevante para identificar usuários atrás de CGNAT).
    client_port_header: str = ""
    require_view_before_accept: bool = True
    public_verification: bool = True

    # --- DocuSeal (opcional) -------------------------------------------------
    docuseal_enabled: bool = False
    docuseal_url: str = ""
    docuseal_api_token: SecretStr = SecretStr("")
    docuseal_webhook_secret: SecretStr = SecretStr("")

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.env == "prod":
            if len(self.secret_key.get_secret_value()) < 32:
                raise ValueError("PORTAL_SECRET_KEY deve ter pelo menos 32 caracteres em produção")
            if self.auth_provider == "dev":
                raise ValueError("auth_provider=dev é proibido em produção")
            if self.accept_reauth != "password":
                raise ValueError("Em produção o aceite exige reautenticação (accept_reauth=password)")
        if self.signing_ltv and not (self.tsa_url and self.signing_trust_root_files):
            raise ValueError("signing_ltv exige PORTAL_TSA_URL e PORTAL_SIGNING_TRUST_ROOT_FILES")
            if not self.base_url.startswith("https://"):
                raise ValueError("PORTAL_BASE_URL deve usar https em produção")
            if self.auth_provider == "ldap" and not self.ldap_url.startswith("ldaps://"):
                raise ValueError("Em produção use LDAPS (ldaps://) para o AD")
        if self.docuseal_enabled and not (
            self.docuseal_url and self.docuseal_webhook_secret.get_secret_value()
        ):
            raise ValueError("DocuSeal habilitado requer PORTAL_DOCUSEAL_URL e WEBHOOK_SECRET")
        return self

    @property
    def secure_cookies(self) -> bool:
        return self.base_url.startswith("https://")


@lru_cache
def get_settings() -> Settings:
    return Settings()
