# Implantação no Google Cloud

Arquitetura alvo (detalhes em [arquitetura.md](arquitetura.md)), toda em
**southamerica-east1 (São Paulo)**:

| Recurso | Terraform | Observação |
|---|---|---|
| Cloud Run (portal) | `run.tf` | `ingress` só do Load Balancer; Direct VPC egress `PRIVATE_RANGES_ONLY`; tag `ldap-client` |
| Cloud Run Jobs + Scheduler | `jobs.tf` | `migrate` (manual), `anchor-audit` (diário 02:15), `verify-audit` (diário 02:45), `cert-info` (semanal) |
| HTTPS Load Balancer + Cloud Armor | `lb.tf` | certificado gerenciado, TLS 1.2+, limite por IP em `/login` e `/verificar`, restrição por país |
| Cloud SQL PostgreSQL 16 | `database.tf` | IP privado, SSL obrigatório, backup diário + PITR 7 dias |
| Cloud Storage | `storage.tf` | WORM (*retention policy*), versionamento, acesso público bloqueado |
| Secret Manager | `secrets.tf` | réplica só em São Paulo; e-CNPJ e senhas carregados **fora** do Terraform |
| VPC, firewall, DNS privado | `network.tf` | só 636 para os DCs; zona privada com os FQDNs dos DCs |
| Cloud VPN (Classic, rotas estáticas) | `vpn.tf` | para HA VPN (BGP), ver §6 |
| Logs | `monitoring.tf` | métricas (`INTEGRIDADE_FALHOU`, `LOGIN_FALHOU`, falha de jobs), **bucket de logs de auditoria** com retenção longa (cópia imutável dos eventos) e logs de *Data Access* do GCS e do Secret Manager |

## 1. Pré-requisitos

- Projeto GCP com faturamento, na organização da empresa.
- Domínio do portal (ex.: `portal.empresa.com.br`) com acesso ao DNS.
- Do lado da TI (ver [integracao-ad.md](integracao-ad.md)):
  - certificado LDAPS nos DCs;
  - conta `svc-portal`;
  - grupos;
  - `employeeNumber` preenchido;
  - firewall com IPsec.
- e-CNPJ A1 (.pfx) e senha.
- **Recomendado:** contrato com uma **ACT ICP-Brasil** (carimbo do tempo) e a LPA/OID da
  política PAdES a usar.

## 2. Imagem

```bash
gcloud auth configure-docker southamerica-east1-docker.pkg.dev
# o repositório é criado pelo Terraform (artifact_registry); na 1ª vez:
#   terraform apply -target=google_artifact_registry_repository.portal
docker build -t southamerica-east1-docker.pkg.dev/PROJ/portal/portal:0.1.0 .
docker push southamerica-east1-docker.pkg.dev/PROJ/portal/portal:0.1.0
```

## 3. Infraestrutura — 1ª aplicação

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars    # ajuste os valores
export TF_VAR_vpn_shared_secret='...'           # PSK do IPsec (não versionar)
terraform init
# 1) tudo menos o Cloud Run (os segredos externos ainda não têm valor):
terraform apply -target=google_secret_manager_secret.external \
                -target=google_sql_user.portal -target=google_storage_bucket.documents \
                -target=google_compute_vpn_tunnel.onprem -target=google_dns_record_set.dc
```

### Carregar os segredos (fora do Terraform)

```bash
gcloud secrets versions add portal-ecnpj-pfx          --data-file=empresa.pfx
printf '%s' 'SENHA_DO_PFX' | gcloud secrets versions add portal-ecnpj-pfx-password --data-file=-
printf '%s' 'SENHA_SVC'    | gcloud secrets versions add portal-ldap-bind-password --data-file=-
gcloud secrets versions add portal-ad-ca-pem          --data-file=ad-ca.pem
# se houver ACT com usuário/senha:
printf '%s' 'SENHA_ACT'    | gcloud secrets versions add portal-tsa-password --data-file=-
shred -u empresa.pfx    # não deixe cópias do e-CNPJ pelo caminho
```

> O segredo `portal-tsa-password` só é exigido se `tsa_username` estiver preenchido.
> Se não houver ACT, deixe-o vazio e o Cloud Run não o referencia.

### Aplicar o restante

```bash
terraform apply
terraform output     # IP do LB, IP da VPN, sub-rede de saída, segredos
```

- Crie o registro **A** de `domain` apontando para `load_balancer_ip`. O certificado
  gerenciado fica ativo em 15–60 min.
- No firewall da empresa:
  - túnel IPsec (IKEv2) para `vpn_gateway_ip`;
  - rota de volta para `run_egress_subnet` (e para `35.199.192.0/19`, se usar
    encaminhamento de DNS);
  - liberar **somente** `run_egress_subnet` → DCs na porta TCP 636.

## 4. Banco e dados iniciais

```bash
gcloud run jobs execute portal-migrate --region southamerica-east1 --wait
# seed (tipos de documento + termo v1) e importação de colaboradores: use um job
# avulso com a mesma imagem, ou rode localmente via Cloud SQL Auth Proxy:
gcloud run jobs create portal-seed --image IMAGEM --region southamerica-east1 \
  --command portal --args seed  # (copie env/segredos do job migrate pelo console)
```

Depois, pela **Área do RH**:
1. revise e publique o **Termo de Adesão** (validado pelo jurídico);
2. importe o **CSV de colaboradores**;
3. ajuste os **tipos de documento**: texto-âncora exatamente como impresso pela folha
   (ex.: "Assinatura do Funcionário") ou a caixa fixa.

## 5. Checklist de produção

- [ ] `PORTAL_ENV=prod` (o portal recusa subir sem HTTPS, segredo forte ou LDAPS).
- [ ] `PORTAL_TRUSTED_PROXY_HOPS=2` (LB externo → Cloud Run). Confira em um aceite de
      teste que o IP no comprovante é o do seu computador, não o do LB.
- [ ] `PORTAL_LOGIN_MAX_FAILURES` abaixo do limite de bloqueio do AD.
- [ ] `PORTAL_ACCEPT_MFA=totp` (recomendado; ver documento jurídico).
- [ ] ACT ICP-Brasil configurada (`tsa_url`) e job `anchor-audit` executando.
- [ ] Política ICP-Brasil (OID/hash/URI) validada no **Verificador do ITI** com um
      documento de teste.
- [ ] **Certificado dedicado ao selo** (não o mesmo e-CNPJ usado no e-CAC/eSocial),
      idealmente importado no Cloud KMS (HSM).
- [ ] Política PAdES na versão compatível com a raiz da cadeia (v5 → v1.1; v12 → v1.2+).
- [ ] Cadeia ICP-Brasil completa: o `.pfx` deve conter as ACs intermediárias. Se não
      contiver, empacote os PEM na imagem e use `PORTAL_SIGNING_CA_CHAIN_FILES`.
- [ ] Teste de restauração do Cloud SQL e do bucket.
- [ ] Temporalidade aprovada → `lock_retention_policy = true` (**irreversível**).
- [ ] Alertas do Cloud Monitoring nas métricas de `monitoring.tf` (e-mail do RH/TI).
- [ ] Cláusulas-padrão da ANPD no contrato Google Cloud; ROPA e aviso de privacidade
      atualizados.

## 6. Variações

- **HA VPN (99,99%)**: se o firewall suportar BGP, troque `vpn.tf` por
  `google_compute_ha_vpn_gateway` + `google_compute_router` + 2 túneis + interfaces e
  peers BGP. A Classic VPN só aceita rotas estáticas para túneis novos desde 2025.
- **Sem Load Balancer** (ambiente de teste): mude `ingress` para
  `INGRESS_TRAFFIC_ALL`, use a URL `run.app` e `PORTAL_TRUSTED_PROXY_HOPS=1`. Isso
  dispensa o Cloud Armor; não use em produção.
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
  Registry de São Paulo e implante fixando o *digest* da imagem.
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
