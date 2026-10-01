# ADR 0004 — LDAPS direto agora; Keycloak/OIDC como alvo

**Situação:** aceita · **Data:** 2026-10-01

## Contexto

O login precisa usar as credenciais do AD sem hospedar aplicações web no Windows Server.
Opções estudadas:

| Opção | Prós | Contras |
|---|---|---|
| **A. LDAPS direto do portal** (via Cloud VPN) | simples; nada novo no DC além do certificado | o portal vê a senha; MFA precisa ser implementado no app |
| **B. GCDS + Google Password Sync + "Sign in with Google"** | sem VPN; 2SV do Google grátis | Password Sync em **todo DC gravável** e DC com saída HTTPS; limite de 50 licenças Cloud Identity Free |
| **C. Managed Microsoft AD + trust** | gerenciado | ~US$ 288/mês; muitas portas RPC na VPN; não resolve o login web |
| **D. AD FS em VM separada** | SAML padrão | desaconselhado pela Microsoft; Windows + WAP |
| **E. Keycloak (VM no GCP) com federação LDAPS** | OIDC padrão, MFA (TOTP/WebAuthn), *step-up*, *brute force* | mais um serviço para operar |

Observações técnicas:
- *simple bind* sobre LDAPS continua funcionando com *LDAP signing/channel binding*
  exigidos (ADV190023);
- o `ldap3` não valida certificado por padrão;
- cada bind com falha incrementa `badPwdCount` no AD.

## Decisão

- **MVP: opção A**, atrás da interface `AuthProvider`, com:
  - validação obrigatória do certificado LDAPS;
  - busca + bind com filtro escapado e grupo aninhado (`1.2.840.113556.1.4.1941`);
  - rejeição de senha vazia;
  - mensagens genéricas;
  - limite de tentativas abaixo do limite de bloqueio do AD;
  - **TOTP no próprio portal** no ato do aceite (`PORTAL_ACCEPT_MFA=totp`).
- **Alvo: opção E (Keycloak)**, quando houver mais aplicações ou necessidade de
  WebAuthn. O portal passa a ser cliente OIDC, e o *step-up* do aceite vira
  `max_age=0`/`acr_values`.
- Matrícula no atributo **`employeeNumber`**: `employeeID` aceita só 16 caracteres, e a
  matrícula do eSocial tem até 30. O vínculo imutável é o **objectGUID**.

## Consequências

- O portal manipula senhas apenas em memória, durante o bind; nada é armazenado.
- Contas compartilhadas (ex.: "producao01") quebram a identificação unívoca. O processo
  de RH/TI deve garantir uma conta pessoal por colaborador.
- A TI pode redefinir senhas, e por isso o TOTP sob controle do colaborador é
  recomendado em produção.
