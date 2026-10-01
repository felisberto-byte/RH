from portal.auth.base import AuthError, AuthProvider, DirectoryUnavailable, Identity

__all__ = ["AuthError", "AuthProvider", "DirectoryUnavailable", "Identity", "build_provider"]


def build_provider(settings) -> AuthProvider:
    if settings.auth_provider == "dev":
        from portal.auth.dev import DevAuthProvider

        return DevAuthProvider()
    from portal.auth.ldap import LdapAuthProvider

    return LdapAuthProvider(settings)
