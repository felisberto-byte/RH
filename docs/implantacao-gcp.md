# Implantação no Google Cloud

Arquitetura alvo (detalhes em [arquitetura.md](arquitetura.md)), toda em
**southamerica-east1 (São Paulo)**:

| Recurso | Terraform | Observação |
|---|---|---|
| Cloud Run (portal) | `run.tf` | `ingress` só do Load Balancer (URL `run.app` desativada); Direct VPC egress `PRIVATE_RANGES_ONLY`; tag `ldap-client`; memória `web_memory` (2Gi) e tempo de requisição `web_request_timeout_seconds` (900 s) |
| Cloud Run Jobs + Scheduler | `jobs.tf` | `migrate` (manual, conta de serviço própria) e quatro jobs agendados; ver [Jobs](#jobs) |
| HTTPS Load Balancer + Cloud Armor | `lb.tf` | certificado gerenciado, TLS 1.2+, limite por IP em `/login`, `/verificar` e confirmações (`POST` de aceite, recusa, termo e DocuSeal), WAF OWASP (`waf_preview`), restrição por país; a regra de prioridade 1500 libera só `GET /readyz` antes do filtro por país |
| Cloud SQL PostgreSQL 16 | `database.tf` | IP privado, SSL obrigatório, backup diário + PITR 7 dias; usuário `portal_owner` criado pelo Terraform, `portal_app` criado pelo job `migrate` |
| Cloud Storage | `storage.tf` | WORM (*retention policy*), versionamento, acesso público bloqueado |
| Secret Manager | `secrets.tf` | réplica só em São Paulo; e-CNPJ, senhas e raízes ICP-Brasil carregados **fora** do Terraform; gerados: `database-url` (aplicação), `database-url-owner` e `db-app-password` (só o job `migrate`) |
| VPC, firewall, DNS privado | `network.tf` | só 636 para os DCs; zona privada com os FQDNs dos DCs |
| Cloud VPN (Classic, rotas estáticas) | `vpn.tf` | para HA VPN (BGP), ver §6 |
| Logs e monitoramento | `monitoring.tf` | métricas por log, alertas por e-mail, *uptime check* em `/readyz`, **bucket de logs de auditoria** com retenção longa (cópia imutável dos eventos) e logs de *Data Access* do GCS e do Secret Manager; ver [Monitoramento](#monitoramento) |

### Jobs

`NOME` é `var.name` (padrão `portal`). Horários em America/Sao_Paulo.

| Job | Comando | Quando | Conta de serviço |
|---|---|---|---|
| `NOME-migrate` | `portal db-app-role --papel portal_app && alembic -x app_role=portal_app upgrade head` | manual: antes do 1º deploy do serviço e após cada nova imagem | `NOME-migrate`, a única que lê `database-url-owner` e `db-app-password` |
| `NOME-anchor-audit` | `portal anchor-audit` | diário, 02:15 | `NOME-run` |
| `NOME-verify-audit` | `portal verify-audit` | diário, 02:45 | `NOME-run` |
| `NOME-cert-info` | `portal cert-info --alerta-dias 45` | segunda, 07:50 | `NOME-run` |
| `NOME-purge` | `portal purge --dias 180` | domingo, 03:30 | `NOME-run` |

Os jobs agendados usam a mesma imagem, variáveis e segredos do serviço e conectam ao banco
como `portal_app`. O que cada rotina faz está em [operacao.md](operacao.md).

### Monitoramento

As métricas filtram `jsonPayload.message`, por isso o Terraform define
`PORTAL_LOG_FORMAT=json` (formato das mensagens em
[arquitetura.md](arquitetura.md#logs)).

| Métrica | Origem | Alerta por e-mail |
|---|---|---|
| `integridade-falhou` | evento `INTEGRIDADE_FALHOU` | sim |
| `cadeia-falhou` | `CADEIA DE AUDITORIA COM FALHA` (`verify-audit`) | sim |
| `certificado-vence` | `CERTIFICADO e-CNPJ vence` (`cert-info`) | sim |
| `job-falhou` | qualquer log `severity>=ERROR` de um job `NOME-*` | sim |
| `login-falhou` | evento `LOGIN_FALHOU` | não (só métrica) |
| `erro-inesperado` | `erro inesperado ref=` no serviço | não (só métrica) |

- Os alertas só são criados com `alert_emails` preenchido. Qualquer ocorrência dispara o
  e-mail. Procedimentos em [operacao.md](operacao.md).
- *Uptime check* `NOME-readyz` em `https://DOMINIO/readyz` a cada 5 min (banco acessível
  e certificado de selo dentro da validade). Com `alert_emails`, falha por 10 min gera
  o alerta "Portal: indisponível (readyz)". A maioria dos verificadores do Google fica
  fora do Brasil, por isso a regra 1500 do Cloud Armor libera só `GET /readyz` antes do
  filtro por país.
- O *sink* do bucket de logs de auditoria copia as linhas `auditoria <AÇÃO> ...`
  (filtro `jsonPayload.message:"auditoria "`).

## 1. Pré-requisitos

- Projeto GCP com faturamento, na organização da empresa.
- Domínio do portal (ex.: `portal.empresa.com.br`) com acesso ao DNS.
- Do lado da TI (ver [integracao-ad.md](integracao-ad.md)):
  - certificado LDAPS nos DCs;
  - conta `svc-portal`;
  - grupos;
  - `employeeNumber` preenchido;
  - firewall com IPsec.
- e-CNPJ A1 (.pfx) e senha. Se o `.pfx` não trouxer as ACs intermediárias, a cadeia em
  PEM.
- Raízes da ICP-Brasil publicadas pelo ITI, em um único arquivo PEM.
- **ACT ICP-Brasil** (carimbo do tempo): exigida em produção, salvo `allow_no_tsa = true`.
  Recomendado: a LPA/OID da política PAdES a usar.
- E-mails que receberão os alertas (`alert_emails`).

## 2. Imagem

```bash
gcloud auth configure-docker southamerica-east1-docker.pkg.dev
# o repositório é criado pelo Terraform (artifact_registry); na 1ª vez:
#   terraform apply -target=google_artifact_registry_repository.portal
docker build -t southamerica-east1-docker.pkg.dev/PROJ/portal/portal:0.1.0 .
docker push southamerica-east1-docker.pkg.dev/PROJ/portal/portal:0.1.0
```

## 3. Infraestrutura — 1ª aplicação

A ordem é: base do Terraform → segredos → job `portal-migrate` → restante (serviço e
jobs agendados).

### Variáveis

Além das de rede, AD e empresa (ver `terraform.tfvars.example`):

| Variável | Padrão | Uso |
|---|---|---|
| `tsa_url` | `""` | ACT RFC 3161. Em produção, vazio só é aceito com `allow_no_tsa` |
| `allow_no_tsa` | `false` | opera **sem** carimbo do tempo; a ausência fica registrada em cada evidência |
| `signing_ltv` | `false` | PAdES-LTA (dados de validação embutidos); exige `tsa_url` e o segredo `icp-raizes-pem` |
| `ecnpj_chain_separate` | `false` | `true` se a cadeia do e-CNPJ não estiver no `.pfx`: cria o segredo `ecnpj-cadeia-pem` e o configura em `PORTAL_SIGNING_CA_CHAIN_FILES` |
| `extra_env` | `{}` | variáveis `PORTAL_*` **não secretas** (ex.: `PORTAL_LOGIN_MAX_FAILURES`, `PORTAL_SESSION_IDLE_MINUTES`); só aceita o prefixo `PORTAL_` e prevalece sobre os valores do `run.tf`. Lista completa em `.env.example` |
| `alert_emails` | `[]` | destinatários dos alertas; vazio = métricas e *uptime check* sem alerta |
| `web_memory` | `2Gi` | memória do serviço (a selagem de lotes grandes consome bastante) |
| `web_request_timeout_seconds` | `900` | tempo máximo de uma requisição (a importação de lote é síncrona) |

### Base

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars    # ajuste os valores
export TF_VAR_vpn_shared_secret='...'           # PSK do IPsec (não versionar)
terraform init
# 1) base + job de migração, sem o serviço e os jobs agendados (os segredos
#    externos ainda não têm valor):
terraform apply -target=google_secret_manager_secret.external \
                -target=google_sql_user.owner -target=google_cloud_run_v2_job.migrate \
                -target=google_storage_bucket.documents \
                -target=google_compute_vpn_tunnel.onprem -target=google_dns_record_set.dc
```

### Carregar os segredos (fora do Terraform)

```bash
gcloud secrets versions add portal-ecnpj-pfx          --data-file=empresa.pfx
printf '%s' 'SENHA_DO_PFX' | gcloud secrets versions add portal-ecnpj-pfx-password --data-file=-
printf '%s' 'SENHA_SVC'    | gcloud secrets versions add portal-ldap-bind-password --data-file=-
gcloud secrets versions add portal-ad-ca-pem          --data-file=ad-ca.pem
gcloud secrets versions add portal-icp-raizes-pem     --data-file=icp-raizes.pem
# se ecnpj_chain_separate = true (cadeia fora do .pfx):
gcloud secrets versions add portal-ecnpj-cadeia-pem   --data-file=ecnpj-cadeia.pem
# se houver ACT com usuário/senha:
printf '%s' 'SENHA_ACT'    | gcloud secrets versions add portal-tsa-password --data-file=-
shred -u empresa.pfx    # não deixe cópias do e-CNPJ pelo caminho
```

> `terraform output secrets_to_load` lista os segredos a carregar.
>
> `portal-icp-raizes-pem` é obrigatório: as raízes (e, se quiser, as intermediárias) da
> ICP-Brasil baixadas do site do ITI, concatenadas em PEM (converta as que vierem em DER
> com `openssl x509 -inform DER`). É montado em `/secrets/icp-raizes/icp-raizes.pem` e
> usado na validação de assinaturas em `/verificar`, no LTV e na conferência das âncoras
> pelo `verify-audit`.
>
> O segredo `portal-tsa-password` só é exigido se `tsa_username` estiver preenchido.
> Se não houver ACT, deixe-o vazio e o Cloud Run não o referencia.

### Migrar o banco

```bash
gcloud run jobs execute portal-migrate --region southamerica-east1 --wait
```

O job conecta como `portal_owner` (dono do esquema). Ele cria ou atualiza o papel
`portal_app` via SQL, fora do `cloudsqlsuperuser` e com a senha de `db-app-password`, e
aplica o Alembic: esquema, gatilhos de imutabilidade, privilégios mínimos do
`portal_app` e semente da cabeça da cadeia de auditoria (detalhes em
[arquitetura.md](arquitetura.md#defesa-em-profundidade-no-banco)). O serviço e os jobs
agendados conectam como `portal_app`, por isso a migração vem antes deles.

### Aplicar o restante

```bash
terraform apply
terraform output     # IP do LB, IP da VPN, sub-rede de saída, segredos
```

- Crie o registro **A** de `domain` apontando para `load_balancer_ip`. O certificado
  gerenciado fica ativo em 15–60 min. Depois, `https://DOMINIO/readyz` deve responder
  200, e o *uptime check* `NOME-readyz` deve ficar verde.
- No firewall da empresa:
  - túnel IPsec (IKEv2) para `vpn_gateway_ip`;
  - rota de volta para `run_egress_subnet` (e para `35.199.192.0/19`, se usar
    encaminhamento de DNS);
  - liberar **somente** `run_egress_subnet` → DCs na porta TCP 636.

### A cada nova imagem

```bash
# terraform.tfvars: image = ".../portal:NOVA_VERSAO"
terraform apply -target=google_cloud_run_v2_job.migrate
gcloud run jobs execute portal-migrate --region southamerica-east1 --wait
terraform apply      # serviço e jobs agendados com a nova imagem
```

## 4. Dados iniciais

```bash
# tipos de documento padrão + Termo de Adesão v1 (idempotente). Usa um job agendado
# com outro argumento: mesma imagem, variáveis e conta do portal (portal_app).
gcloud run jobs execute portal-verify-audit --region southamerica-east1 --args=seed --wait
```

O `seed` cria `HOLERITE` e `INFORME_IR` como ciência e `CONTRATO` e `ADITIVO` como aceite.
Depois, pela **Área do RH** (detalhes no [Guia do RH](guia-rh.md)):
1. revise e publique o **Termo de Adesão** (validado pelo jurídico);
2. importe o **CSV de colaboradores** (`matricula;nome;cpf;email;ativo`);
3. revise os tipos em **Tipos**: natureza (ciência/aceite), exigência de TOTP e
   texto-âncora exatamente como impresso pela folha (ex.: "Assinatura do Funcionário")
   ou a caixa fixa. As alterações são auditadas e não afetam documentos já emitidos.

## 5. Checklist de produção

- [ ] `PORTAL_ENV=prod` (definido pelo Terraform). O portal recusa subir sem HTTPS em
      `PORTAL_BASE_URL`, segredo forte, LDAPS, `PORTAL_TRUSTED_PROXY_HOPS`, PostgreSQL,
      ACT (salvo `allow_no_tsa`) e, com DocuSeal, URL https.
- [ ] `PORTAL_TRUSTED_PROXY_HOPS=2` (LB externo → Cloud Run; já no `run.tf`). Confira em
      um aceite de teste que o IP no comprovante é o do seu computador, não o do LB.
- [ ] `PORTAL_LOGIN_MAX_FAILURES` abaixo do limite de bloqueio do AD (ajuste por
      `extra_env`).
- [ ] `accept_mfa = "totp"` (recomendado; ver documento jurídico).
- [ ] ACT ICP-Brasil configurada (`tsa_url`, `allow_no_tsa = false`) e job
      `anchor-audit` executando.
- [ ] Segredo `icp-raizes-pem` carregado; `/verificar` valida o selo de um documento de
      teste.
- [ ] Política ICP-Brasil (OID/hash/URI) validada no **Verificador do ITI** com um
      documento de teste.
- [ ] **Certificado dedicado ao selo** (não o mesmo e-CNPJ usado no e-CAC/eSocial),
      idealmente importado no Cloud KMS (HSM).
- [ ] Política PAdES na versão compatível com a raiz da cadeia (v5 → v1.1; v12 → v1.2+).
- [ ] Cadeia ICP-Brasil completa: o `.pfx` deve conter as ACs intermediárias. Se não
      contiver, use `ecnpj_chain_separate = true` e carregue `ecnpj-cadeia-pem`.
- [ ] Job `portal-migrate` executado com a imagem em produção.
- [ ] Teste de restauração do Cloud SQL e do bucket.
- [ ] Temporalidade aprovada → `lock_retention_policy = true` (**irreversível**).
- [ ] `alert_emails` preenchido e *uptime check* de `/readyz` verde.
- [ ] Cláusulas-padrão da ANPD no contrato Google Cloud; ROPA e aviso de privacidade
      atualizados.

## 6. Variações

- **HA VPN (99,99%)**: se o firewall suportar BGP, troque `vpn.tf` por
  `google_compute_ha_vpn_gateway` + `google_compute_router` + 2 túneis + interfaces e
  peers BGP. A Classic VPN só aceita rotas estáticas para túneis novos desde 2025.
- **Sem Load Balancer** (ambiente de teste): mude `ingress` para
  `INGRESS_TRAFFIC_ALL` e `default_uri_disabled` para `false`, use a URL `run.app` e
  `PORTAL_TRUSTED_PROXY_HOPS=1` (via `extra_env`). Isso dispensa o Cloud Armor; não use
  em produção.
- **Faixas não RFC 1918 na rede local:** `PRIVATE_RANGES_ONLY` só envia à VPC destinos
  RFC 1918. Se a rede da empresa usa 100.64/10 ou IPs públicos internamente, use
  `ALL_TRAFFIC`. Nesse caso a saída para a internet (ACT) passa a exigir Cloud NAT.
- **HA VPN com um único IP público na empresa:** é possível
  (`SINGLE_IP_INTERNALLY_REDUNDANT`), com SLA menor, se o roteador suportar BGP.
- **DocuSeal CE**, se for usado:
  - **Onde rodar:** VM pequena (e2-small/medium) com Docker Compose. O Sidekiq e o
    Redis rodam embutidos e exigem CPU sempre ligada. Banco no mesmo Cloud SQL (outro
    banco e usuário).
  - **Segredos:** `SECRET_KEY_BASE` e `ENCRYPTION_SECRET` fixados pelo Secret Manager.
  - **Proxy:** nginx na frente, com `real_ip` confiando nas faixas do Google. Sem isso,
    o DocuSeal registra o IP do balanceador.
  - **Assinatura:** use `CERTS={"enabled":false}` para que o DocuSeal não assine com
    certificado próprio. Assim o selo PAdES ICP-Brasil do portal é a única assinatura,
    e **o e-CNPJ nunca entra no banco do DocuSeal**.
  - **Carimbo do tempo:** não configure ACT no DocuSeal. Se a ACT falhar, ele grava um
    carimbo falso com a hora local, sem erro. O portal carimba.
  - **Webhook:** `https://DOMINIO/webhooks/docuseal`, com o segredo HMAC em
    `PORTAL_DOCUSEAL_WEBHOOK_SECRET`.
  - **No portal:** `PORTAL_DOCUSEAL_ENABLED` e `PORTAL_DOCUSEAL_URL` (https em produção)
    vão em `extra_env`. O Terraform não cria os segredos `PORTAL_DOCUSEAL_API_TOKEN` e
    `PORTAL_DOCUSEAL_WEBHOOK_SECRET`: acrescente-os em `external_secrets` e `secret_env`
    (nunca em `extra_env`).
  - **Contas:** ative o TOTP para os usuários do RH no DocuSeal (todos são
    administradores no CE).
  - **Idioma:** o DocuSeal só tem pt-PT; `pt-BR` gera erro 500.
  - **Licença:** AGPLv3 com termo 7(b) (manter a atribuição). Modificar o código
    obriga a oferecer o fonte aos usuários.

  Não faz parte deste Terraform.

## 7. Evoluções recomendadas

- **e-CNPJ no Cloud KMS (HSM):** importe a chave do A1 (PKCS#8, `RSA_SIGN_PKCS1_2048_SHA256`,
  proteção HSM, cerca de US$ 1/mês) e assine por um `Signer` do pyHanko que chama
  `asymmetricSign`. Assim o `.pfx` nunca fica em contêiner. Confirme antes com a AC se a
  política do certificado permite a importação.
- **Retenção a partir do desligamento:** ative `defaultEventBasedHold` no bucket e libere
  o *hold* dos objetos do colaborador no desligamento. O prazo de retenção passa a contar
  a partir daí, que é o marco da prescrição trabalhista.
- **CI/CD:** GitHub Actions com **Workload Identity Federation direta**, sem chave de
  conta de serviço, restrita ao repositório e à branch. Publique a imagem no Artifact
  Registry de São Paulo e implante fixando o *digest* da imagem, executando
  `portal-migrate` antes do serviço.
- **Políticas da organização:**
  - `constraints/gcp.resourceLocations` (só São Paulo);
  - `iam.disableServiceAccountKeyCreation`;
  - `storage.publicAccessPrevention`;
  - `sql.restrictPublicIp`;
  - `iam.allowedPolicyMemberDomains`.
- **Projetos separados** para produção e homologação.

## 8. Custos de referência

Estimativa de lista em São Paulo (pesquisa de set/2026; confirme na calculadora do GCP):

| Item | US$/mês |
|---|---|
| Cloud Run do portal (1 instância mínima) | 14–20 |
| Cloud Run Jobs | ~1 |
| Cloud SQL Enterprise `db-custom-1-3840` zonal, 20 GB SSD + backups | 80–90 |
| HA VPN, 2 túneis (Classic, 1 túnel: ~55) | ~110 |
| Load Balancer externo + Cloud Armor Standard | ~28 |
| GCS, Secret Manager, KMS, Scheduler, Logging | < 5 |
| **Total (com HA VPN)** | **~235–260** |
| Variante enxuta (Classic VPN, banco *shared-core* sem SLA) | ~110–130 |
| DocuSeal CE em VM e2-small (opcional) | +~25 |
| ACT ICP-Brasil | por carimbo; fontes citam a partir de R$ 0,06 (cotar) |

Nenhum item é cobrado por colaborador. São Paulo custa cerca de 1,5× us-central1.
