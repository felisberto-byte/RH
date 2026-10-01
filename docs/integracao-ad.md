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
- No primeiro certificado, a KB 321051 orienta **reiniciar o DC**. Na renovação, use a
  operação `renewServerCertificate` do rootDSE ou reinicie. Gere a chave com um
  provedor compatível com o Schannel. Se usar AC própria (openssl/step-ca), importe o
  PFX de modo que o Schannel enxergue a chave, e documente o procedimento de renovação.
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
- Além do login, ela faz a revalidação periódica das sessões (seção 4). Se a senha dela
  expirar, ninguém entra ("Falha na conta de serviço"), mas as sessões abertas continuam.

### 1.4 Grupos

| Grupo | Uso | Variável |
|---|---|---|
| `GG_Portal_Colaboradores` | quem pode entrar no portal (aceita grupos aninhados) | `PORTAL_LDAP_GROUP_USERS_DN` |
| `GG_Portal_RH` | Área do RH (lotes, tipos, colaboradores, dossiês, termo, auditoria); também dá acesso ao portal | `PORTAL_LDAP_GROUP_ADMIN_DN` |

Mantenha **separados** quem administra o AD e quem opera o DP. Quem redefine senhas não
deveria conseguir operar o portal em nome de colaboradores.

Desabilitar a conta ou tirá-la dos grupos vale também para quem já está logado: a sessão
é revogada na próxima revalidação, em até `PORTAL_SESSION_REVALIDATE_MINUTES` (10).

### 1.5 Matrícula e vínculo da conta

Preencha a matrícula de cada colaborador no atributo **`employeeNumber`** (aceita até 512
caracteres; a matrícula do eSocial tem até 30). O `employeeID` só aceita 16. O portal usa
o atributo de `PORTAL_LDAP_EMPLOYEE_ID_ATTR` (padrão `employeeNumber`) e ignora zeros à
esquerda (`000123` = `123`). O CPF **não** precisa estar no AD; ele fica só no cadastro
do portal.

No primeiro login o portal localiza o cadastro pela matrícula e grava nele o
**objectGUID** da conta (`VINCULO_AD_CRIADO`). Esse é o vínculo definitivo, conferido a
cada login e a cada revalidação da sessão:

| Situação | Resultado | Evento |
|---|---|---|
| Outra conta do AD com a matrícula de um cadastro já vinculado (conta recriada ou duplicada) | login recusado | `VINCULO_AD_CONFLITO` |
| `employeeNumber` da conta vinculada alterado e diferente do cadastro | login recusado; sessões abertas revogadas | `VINCULO_AD_DIVERGENTE` / `SESSAO_REVOGADA` |

**Readmissão com conta nova no AD** (mesma matrícula): a TI preenche o `employeeNumber`
da conta nova e o RH usa *Colaboradores → Desvincular conta do AD*, com motivo
(`VINCULO_AD_REMOVIDO`; encerra as sessões do cadastro). O próximo login da conta nova
cria o vínculo. Se a TI reativar a conta antiga, nada precisa ser feito. Matrícula nova é
um cadastro novo (ver [guia-rh.md](guia-rh.md)). Só o RH desfaz um vínculo, e a ação fica
na auditoria.

### 1.6 Política de bloqueio

Cada senha errada no portal é um *bind* errado e incrementa o `badPwdCount` da conta no
AD. Para o portal bloquear **antes** do Windows (sem travar a conta do colaborador):

| Portal | AD (GPO do domínio ou PSO que se aplique) | Regra |
|---|---|---|
| `PORTAL_LOGIN_MAX_FAILURES` (5) | *Account lockout threshold* (`lockoutThreshold`) | portal **abaixo** do AD |
| `PORTAL_LOGIN_LOCKOUT_MINUTES` (15) | *Reset account lockout counter after* (`lockOutObservationWindow`) | portal **maior ou igual** ao AD |

O portal conta as falhas dos últimos `PORTAL_LOGIN_LOCKOUT_MINUTES`. Com janela menor que
a do AD, o contador do portal zeraria antes do `badPwdCount` e novas tentativas
bloqueariam a conta no AD.

- **Por conta canônica:** a chave é o usuário sem `DOMINIO\` nem `@sufixo`, em
  minúsculas. `EMPRESA\maria.silva`, `Maria.Silva` e `maria.silva@empresa.local`
  compartilham o contador. Checagem, *bind* e registro são serializados por conta (trava
  consultiva do PostgreSQL), então tentativas em paralelo não passam do limite. As
  confirmações de senha no ato (seção 4) usam o contador do `sAMAccountName`.
- **UPN diferente do `sAMAccountName`** (ex.: `msilva` e `maria.silva@empresa.com.br`):
  as duas formas têm contadores separados. Padronize o prefixo do UPN ou mantenha
  2 × `PORTAL_LOGIN_MAX_FAILURES` abaixo do `lockoutThreshold`.
- **Por IP:** só falhas de login, limite alto (`PORTAL_LOGIN_MAX_FAILURES_PER_IP`, 50)
  para não bloquear o NAT do escritório; barra a mesma senha tentada em muitas contas.
  O IP real depende de `PORTAL_TRUSTED_PROXY_HOPS` (ver
  [implantacao-gcp.md](implantacao-gcp.md)); o Cloud Armor ainda limita requisições por
  IP em `/login`.

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
# Só ao conectar por IP (JSON): nomes aceitos no certificado do DC
# PORTAL_LDAP_TLS_VALID_NAMES=["dc01.empresa.local"]
# Abaixo do lockoutThreshold do domínio
PORTAL_LOGIN_MAX_FAILURES=5
# Maior ou igual à janela de contagem do AD (lockOutObservationWindow)
PORTAL_LOGIN_LOCKOUT_MINUTES=15
PORTAL_LOGIN_MAX_FAILURES_PER_IP=50
PORTAL_SESSION_REVALIDATE_MINUTES=10
```

Comentários sempre em linha própria, como no `.env.example` (que lista todas as
variáveis). Em produção o portal não inicia com `ldap://`: exige `ldaps://`, e o
certificado do DC é sempre validado. No Terraform, as `PORTAL_LDAP_*` vêm das variáveis
`ldap_*`, a senha do segredo `ldap-bind-password`, a AC do segredo `ad-ca-pem`; limites e
`PORTAL_LDAP_TLS_VALID_NAMES` vão em `extra_env` (ver
[implantacao-gcp.md](implantacao-gcp.md)).

## 4. Como o login funciona

1. O usuário pode ser digitado como `maria.silva`, `EMPRESA\maria.silva` ou
   `maria.silva@empresa.local`. Senha vazia é recusada antes de qualquer consulta,
   porque o AD aceita *unauthenticated bind*.
2. O portal confere os limites da conta canônica e do IP (1.6). Estourados, recusa
   ("Muitas tentativas. Aguarde alguns minutos.") **sem** consultar o AD.
3. Faz bind com a conta de serviço e busca o usuário com filtro escapado
   (`sAMAccountName` ou `userPrincipalName`). Usuário inexistente ou ambíguo recebe a
   mesma mensagem de senha errada.
4. **Bind primeiro:** faz bind com o **DN do usuário e a senha digitada** antes de olhar
   o estado da conta.
5. Só com a senha correta recusa contas desabilitadas (`userAccountControl` bit 2),
   confere o grupo com `LDAP_MATCHING_RULE_IN_CHAIN` (grupos aninhados) e o vínculo
   `objectGUID` × matrícula (1.5). Assim mensagens diferentes não servem para descobrir
   quais contas existem.
6. Mensagens ao usuário:
   - senha errada, usuário inexistente **e** recusa do AD por bloqueio (775), conta
     desabilitada (533) ou expirada (701), ou restrição de horário/estação (530/531):
     sempre a mesma mensagem, "Usuário ou senha inválidos. Se tem certeza da senha, sua
     conta pode estar bloqueada: procure a TI.". O AD devolve esses subcódigos mesmo com
     senha errada; uma mensagem diferente revelaria que a conta existe;
   - conta desabilitada detectada após a senha correta: "Não foi possível entrar. Se o
     problema persistir, procure a TI.";
   - específicas apenas para **senha expirada** (532) e **troca obrigatória** (773), que
     o AD só retorna quando a senha está correta;
   - fora do grupo ou vínculo divergente: só depois da senha correta.

   O subcódigo vai para o log, onde a TI distingue bloqueio, senha errada e conta
   desabilitada.
7. **Durante a sessão**, a cada `PORTAL_SESSION_REVALIDATE_MINUTES` (10) o portal busca a
   conta com a conta de serviço. Conta desabilitada ou inexistente, fora do grupo,
   `objectGUID` diferente, vínculo divergente ou cadastro inativo revogam a sessão
   (`SESSAO_REVOGADA`, com o motivo). A participação no grupo do RH também é atualizada.
   AD indisponível não derruba sessões; a revalidação fica para a próxima requisição.
8. **Confirmação no ato:** ciência/aceite, divergência, abertura do link DocuSeal, aceite
   do Termo de Adesão e cadastro do autenticador fazem um **novo bind** com a senha
   digitada, com a mesma trava e o mesmo contador da conta. Na manifestação e no
   DocuSeal, com `PORTAL_ACCEPT_MFA=totp` ou tipo marcado *exige TOTP*, também é exigido
   o código do aplicativo autenticador (ver [arquitetura.md](arquitetura.md)).

## 5. Problemas comuns

| Sintoma | Causa provável |
|---|---|
| "Diretório indisponível" | VPN fora, firewall bloqueando a 636, DNS sem resolver o FQDN |
| Erro de certificado no log | AC errada em `PORTAL_LDAP_CA_CERT_FILE` ou FQDN fora do SAN |
| "Falha na conta de serviço" | Senha da `svc-portal` expirada ou conta bloqueada |
| "Muitas tentativas" | Limite da conta atingido: aguardar `PORTAL_LOGIN_LOCKOUT_MINUTES`. Se atinge muitos usuários ao mesmo tempo, conferir o limite por IP e `PORTAL_TRUSTED_PROXY_HOPS` (com valor errado, todos aparecem com o IP do balanceador) |
| "Não foi possível entrar... procure a TI" | Conta bloqueada, desabilitada ou expirada no AD, ou restrição de horário/estação (subcódigo no log) |
| "Seu usuário não tem acesso ao Portal do Colaborador" | Conta fora de `GG_Portal_Colaboradores` (e de `GG_Portal_RH`) |
| "Não encontramos seu cadastro" | `employeeNumber` vazio no AD ou matrícula não importada no portal |
| "Seu cadastro está vinculado a outro usuário" | Duas contas AD com a mesma matrícula (conta duplicada/recriada). Na readmissão, o RH desvincula (1.5) |
| "Sua conta do AD não corresponde ao cadastro vinculado" | `employeeNumber` da conta vinculada foi alterado (`VINCULO_AD_DIVERGENTE`) |
| "Cadastro inativo" | Colaborador desativado pelo RH no portal |
| "Sua sessão expirou" no meio do uso | Revalidação revogou a sessão (`SESSAO_REVOGADA`, motivo na auditoria) ou tempo de inatividade/absoluto da sessão |
| Colaborador de chão de fábrica não consegue entrar | Senha expirada ou troca obrigatória: trocar em um computador da empresa |

## 6. Evolução: Keycloak/OIDC

Ver [ADR 0004](adr/0004-autenticacao-ldaps-agora-keycloak-depois.md). Com mais
aplicações ou necessidade de WebAuthn/passkeys, coloque um **Keycloak** (VM pequena no
GCP) federando o AD por LDAPS (modo READ_ONLY, `objectGUID` como UUID, *brute force
detection* abaixo do limite do AD). O portal passa a ser cliente OIDC e a confirmação no
aceite vira `max_age=0`/`acr_values`. O `AuthProvider` atual isola essa troca.
