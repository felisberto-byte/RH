# Integração com o Active Directory

O portal autentica os colaboradores com **LDAPS (TCP 636)** nos controladores de domínio,
por uma **VPN entre o GCP e a rede da empresa**. O Windows Server continua só com AD/DNS:
nenhuma aplicação web, agente ou papel novo é instalado nele. A única mudança é um
certificado de servidor para o LDAPS.

## 1. Pré-requisitos no AD (TI)

### 1.1 Certificado LDAPS no DC

- Certificado de servidor com o **FQDN do DC** no CN ou SAN (ex.: `dc01.empresa.local`)
  e EKU **Server Authentication** (1.3.6.1.5.5.7.3.1).
- Pode ser emitido por uma **AC privada fora do DC** (openssl, step-ca). Não é preciso
  instalar o AD CS no controlador.
- Importe o certificado com a chave privada no repositório *Computador local → Pessoal*
  (ou *NTDS\Pessoal*). O DC passa a aceitar LDAPS automaticamente.
- Teste de uma máquina da rede:
  `openssl s_client -connect dc01.empresa.local:636 -showcerts`.
- Entregue ao time do portal o **certificado da AC** (PEM): ele vai para
  `PORTAL_LDAP_CA_CERT_FILE`.

### 1.2 Endurecimento (recomendado)

Com o LDAPS funcionando, exija assinatura e *channel binding* do LDAP
(`LDAP server signing requirements = Require signing`, `LdapEnforceChannelBinding = 1/2`).
*Simple bind* sobre TLS continua funcionando nesse modo (Microsoft ADV190023). Antes de
exigir, verifique nos eventos 2887/3039 se há clientes legados.

### 1.3 Conta de serviço (somente leitura)

- Usuário comum, **sem privilégios**, só para busca, por exemplo
  `CN=svc-portal,OU=Servicos,...`.
- Marcar "A conta é confidencial e não pode ser delegada"; negar logon interativo/RDP
  por GPO.
- Senha aleatória com mais de 30 caracteres, guardada no **Secret Manager**
  (`PORTAL_LDAP_BIND_PASSWORD`) e com rotação periódica.

### 1.4 Grupos

| Grupo | Uso | Variável |
|---|---|---|
| `GG_Portal_Colaboradores` | quem pode entrar no portal (aceita grupos aninhados) | `PORTAL_LDAP_GROUP_USERS_DN` |
| `GG_Portal_RH` | Área do RH (importar lotes, dossiês, termo) | `PORTAL_LDAP_GROUP_ADMIN_DN` |

Mantenha **separados** quem administra o AD e quem opera o DP. Quem redefine senhas não
deveria conseguir operar o portal em nome de colaboradores.

### 1.5 Matrícula no AD

Preencha a matrícula de cada colaborador no atributo **`employeeNumber`** (aceita até 512
caracteres; a matrícula do eSocial tem até 30). O `employeeID` só aceita 16. O portal usa
o atributo de `PORTAL_LDAP_EMPLOYEE_ID_ATTR` e ignora zeros à esquerda
(`000123` = `123`).

No primeiro login o portal grava o **objectGUID** no cadastro do colaborador. Esse é o
vínculo definitivo: se outra conta tentar usar a mesma matrícula, o login é recusado e o
evento `VINCULO_AD_CONFLITO` é registrado. O CPF **não** precisa estar no AD; ele fica
só no cadastro do portal.

### 1.6 Política de bloqueio

Cada senha errada no portal incrementa o `badPwdCount` da conta no AD. Configure
`PORTAL_LOGIN_MAX_FAILURES` **abaixo** do `lockoutThreshold` do domínio. Assim um ataque
de força bruta no portal bloqueia primeiro no portal (por usuário e por IP), sem travar a
conta do Windows do colaborador.

## 2. Rede (GCP ↔ empresa)

- **Cloud VPN:** use HA VPN (2 túneis, BGP via Cloud Router) se o firewall da empresa
  suportar BGP. Caso contrário, use Classic VPN baseada em rotas, com rotas estáticas.
  Custo de referência em southamerica-east1: US$ 0,075 por túnel-hora, cerca de US$ 55
  por túnel por mês.
- **Cloud Run → VPC:** use *Direct VPC egress* com `private-ranges-only`, sub-rede `/26`
  ou maior e *network tag* `ldap-client`.
- **Firewall da empresa:** permitir **somente** a sub-rede de saída do Cloud Run →
  IPs dos DCs, TCP 636. **Nunca** exponha a porta 636 à internet.
- **DNS:** para que a validação TLS use o FQDN, crie uma zona privada no Cloud DNS com
  registros A dos DCs, ou uma zona de encaminhamento para o DNS do AD. A segunda exige
  rota de volta para `35.199.192.0/19` pela VPN e liberação da porta 53. Alternativa:
  conectar por IP e informar o nome do certificado em `PORTAL_LDAP_TLS_VALID_NAMES`.

## 3. Configuração do portal

```dotenv
PORTAL_AUTH_PROVIDER=ldap
PORTAL_LDAP_URL=ldaps://dc01.empresa.local:636
PORTAL_LDAP_CA_CERT_FILE=/secrets/ad-ca/ad-ca.pem
PORTAL_LDAP_BIND_DN=CN=svc-portal,OU=Servicos,DC=empresa,DC=local
PORTAL_LDAP_BIND_PASSWORD=<Secret Manager>
PORTAL_LDAP_BASE_DN=OU=Usuarios,DC=empresa,DC=local
PORTAL_LDAP_EMPLOYEE_ID_ATTR=employeeNumber
PORTAL_LDAP_GROUP_USERS_DN=CN=GG_Portal_Colaboradores,OU=Grupos,DC=empresa,DC=local
PORTAL_LDAP_GROUP_ADMIN_DN=CN=GG_Portal_RH,OU=Grupos,DC=empresa,DC=local
PORTAL_LOGIN_MAX_FAILURES=5          # < lockoutThreshold do domínio
```

## 4. Como o login funciona

1. O usuário pode ser digitado como `maria.silva`, `EMPRESA\maria.silva` ou
   `maria.silva@empresa.local`.
2. O portal faz bind com a conta de serviço e busca o usuário com filtro escapado
   (`sAMAccountName` ou `userPrincipalName`).
3. Recusa contas desabilitadas (`userAccountControl` bit 2) e confere o grupo com
   `LDAP_MATCHING_RULE_IN_CHAIN` (grupos aninhados).
4. Faz bind com o **DN do usuário e a senha digitada**. Senha vazia é recusada antes,
   porque o AD aceita *unauthenticated bind*.
5. Mensagens ao usuário:
   - genéricas para senha errada, conta bloqueada ou desabilitada (sem revelar se a
     conta existe);
   - específicas apenas para **senha expirada** (532) e **troca obrigatória** (773), que
     o AD só retorna quando a senha está correta.

   O subcódigo vai para o log.
6. No aceite, um **novo bind** com a senha confirma a presença do titular. Com
   `PORTAL_ACCEPT_MFA=totp`, também é exigido o código do aplicativo autenticador.

## 5. Problemas comuns

| Sintoma | Causa provável |
|---|---|
| "Diretório indisponível" | VPN fora, firewall bloqueando a 636, DNS sem resolver o FQDN |
| Erro de certificado no log | AC errada em `PORTAL_LDAP_CA_CERT_FILE` ou FQDN fora do SAN |
| "Falha na conta de serviço" | Senha da `svc-portal` expirada ou conta bloqueada |
| "Não encontramos seu cadastro" | `employeeNumber` vazio no AD ou matrícula não importada no portal |
| "Seu cadastro está vinculado a outro usuário" | Duas contas AD com a mesma matrícula (conta duplicada/recriada) |
| Colaborador de chão de fábrica não consegue entrar | Senha expirada ou troca obrigatória: trocar em um computador da empresa |

## 6. Evolução: Keycloak/OIDC

Ver [ADR 0004](adr/0004-autenticacao-ldaps-agora-keycloak-depois.md). Com mais
aplicações ou necessidade de WebAuthn/passkeys, coloque um **Keycloak** (VM pequena no
GCP) federando o AD por LDAPS (modo READ_ONLY, `objectGUID` como UUID, *brute force
detection* abaixo do limite do AD). O portal passa a ser cliente OIDC e a confirmação no
aceite vira `max_age=0`/`acr_values`. O `AuthProvider` atual isola essa troca.
