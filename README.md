# Portal do Colaborador — DP Digital com aceite eletrônico

Portal (intranet) onde cada colaborador acessa **seus** documentos de Departamento
Pessoal — holerites, contratos, aditivos, informes — e registra **aceite/ciência ou
divergência** com evidência suficiente para uma *assinatura eletrônica avançada*,
sem ferramenta paga por usuário.

- **Login com a conta do Active Directory** (LDAPS pela VPN GCP ↔ empresa). O
  Windows Server continua só com AD/DNS. A conta é vinculada ao cadastro pelo
  `objectGUID`, revalidada no AD durante a sessão e protegida por limite de falhas
  por conta (abaixo do bloqueio do AD).
- **Documentos selados com o e-CNPJ A1** (PAdES, ICP-Brasil) na emissão, com carimbo
  do tempo (obrigatório em produção, salvo `PORTAL_ALLOW_NO_TSA=true`, que fica
  registrado na evidência).
- **Campo de aceite em posição fixa**, definido pelo tipo de documento: o
  colaborador não escolhe onde "assina". Cada tipo tem natureza **ciência**
  (holerite, informe) ou **aceite** (contrato, aditivo) e pode exigir TOTP; a
  declaração é fixada no documento no momento da emissão.
- **Evidência da manifestação**: usuário AD (objectGUID), reautenticação (senha do AD
  e TOTP quando o tipo exige ou `PORTAL_ACCEPT_MFA=totp`), IP, navegador, data/hora,
  hash SHA-256 do documento e da declaração exibidos. Tudo vai para uma trilha de auditoria encadeada por hash,
  ancorada em carimbo do tempo, e para um comprovante PDF selado. Divergência registra
  frase fixa e o motivo, nunca a declaração de concordância.
- **Prova fora do sistema**: verificação pública em `/verificar` (código ou upload do
  PDF) e dossiê probatório (ZIP) com script `verificar.py` autônomo.
- **Área do RH**: importação de lotes, editor de tipos de documento, colaboradores
  (CSV), termo de adesão, pendências DocuSeal, auditoria e dossiê.
- **DocuSeal (opcional)** para modelos fixos, como contratos. A edição open-source
  não embute o formulário nem cria envios a partir de PDF avulso (recursos Pro).
  Por isso os holerites usam o motor nativo do portal. O selo final do e-CNPJ em
  todos os PDFs do envio é aplicado pelo portal.

## Documentação

| Documento | Para quem |
|---|---|
| [Arquitetura](docs/arquitetura.md) e [decisões (ADRs)](docs/adr/) | TI / desenvolvimento |
| [Assinatura e validade jurídica](docs/assinatura-e-validade-juridica.md) | Jurídico / RH / TI |
| [Integração com o AD](docs/integracao-ad.md) | TI (infraestrutura Windows) |
| [Implantação no GCP](docs/implantacao-gcp.md) e [`infra/terraform`](infra/terraform) | TI / nuvem |
| [Operação (runbook)](docs/operacao.md) | TI / RH |
| [Guia do RH](docs/guia-rh.md) | Departamento Pessoal |
| [`.env.example`](.env.example) (todas as variáveis `PORTAL_*`, comentadas) | TI / desenvolvimento |

## Como funciona (resumo)

```
Sistema de folha ──PDF/ZIP──▶ RH importa lote ──▶ separa por matrícula ──▶ sela com e-CNPJ
                                                   (cria campo "AceiteColaborador")
Colaborador ──login AD──▶ Meus documentos ──▶ abre PDF ──▶ ciência/aceite ou divergência
        (senha do AD [+ TOTP]) ──▶ selo no campo fixo + comprovante PDF selado + trilha de auditoria
```

## Rodando localmente

Requisitos: Python 3.11+ (ou Docker).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # PORTAL_ENV=dev, PORTAL_AUTH_PROVIDER=dev, SQLite
portal dev-cert var/dev          # certificado de TESTE (não é ICP-Brasil)
export PORTAL_SIGNING_PFX_FILE=var/dev/dev-ecnpj.pfx PORTAL_SIGNING_PFX_PASSWORD=dev \
       PORTAL_SIGNING_TRUST_ROOT_FILES='["var/dev/dev-ca.pem"]'
alembic upgrade head
portal demo                      # tipos, termo v1, colaboradores e holerites de exemplo
uvicorn portal.web.asgi:app --reload
```

Usuários de desenvolvimento (senha `dev`): `maria.silva` e `joao.souza`
(colaboradores) e `rh.admin` (RH). O `portal demo` já cria os colaboradores e um lote
de holerites. Para testar com seus PDFs, use **Área do RH → Importar lote**.

Com Docker: `docker compose up --build` (portal em http://localhost:8000, PostgreSQL).
Na subida o certificado de teste é gerado só se ainda não existir, e rodam a migração e
o `portal seed`; para os dados de exemplo, `docker compose exec portal portal demo`.
Para subir também o DocuSeal (http://localhost:3000): `docker compose --profile docuseal up`.
O banco `docuseal` é criado por [`infra/dev/postgres-init.sql`](infra/dev/postgres-init.sql)
apenas na primeira criação do volume; com um volume anterior, crie-o com
`docker compose exec db createdb -U portal docuseal`.

Saúde: `/healthz` (vivacidade) e `/readyz` (banco e certificado de selo dentro da
validade; responde 503 com a lista de falhas).

### Testes e qualidade

```bash
pytest            # SQLite: unidade + integração (assinatura real com PKI de teste)

# PostgreSQL real (banco DESCARTÁVEL: o esquema é recriado a cada teste e são criados papéis).
# Roda a suíte inteira e mais 3 testes exclusivos: migração (esquema = modelos, gatilhos,
# privilégios do papel da aplicação), `portal db-app-role` e trava da cabeça da cadeia.
docker run --rm -d --name portal-pg -p 5432:5432 -e POSTGRES_USER=portal \
  -e POSTGRES_PASSWORD=portal -e POSTGRES_DB=portal postgres:16-alpine
PORTAL_TEST_DATABASE_URL=postgresql+psycopg://portal:portal@localhost:5432/portal pytest

ruff check src tests migrations && ruff format --check src tests && mypy src
```

A CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) roda lint, tipos, a suíte
no SQLite e no PostgreSQL e `alembic upgrade`/`check`/`downgrade`.

## Operação (CLI)

| Comando | Para quê |
|---|---|
| `portal seed` | tipos de documento padrão (`HOLERITE` e `INFORME_IR` = ciência; `CONTRATO` e `ADITIVO` = aceite) e Termo de Adesão v1 |
| `portal import-employees arquivo.csv` | cadastro/atualização de colaboradores (`matricula;nome;cpf;email;ativo`; regras no [Guia do RH](docs/guia-rh.md)) |
| `portal ingest --tipo HOLERITE --competencia 2026-09 folha.pdf` | importação automatizada de lote |
| `portal verify-audit` | verificação **completa**: cadeia inteira + cada âncora (evento ancorado inalterado, token íntegro, imprint = hash carimbado); em falha registra `CADEIA DE AUDITORIA COM FALHA` (ERROR) e sai 1 |
| `portal anchor-audit` | carimba (RFC 3161) a cabeça da cadeia (exige `PORTAL_TSA_URL`) |
| `portal cert-info --alerta-dias 45` | validade do e-CNPJ (renovação anual do A1); abaixo do limite registra `CERTIFICADO e-CNPJ vence` (ERROR) e sai 1 |
| `portal purge --dias 180` | LGPD: apaga tentativas de login e sessões encerradas mais antigas que N dias (mínimo 30); registra `DADOS_OPERACIONAIS_EXPURGADOS`. Documentos, aceites e auditoria nunca são apagados |
| `portal db-app-role --papel portal_app` | job de migração (dono do esquema): cria/atualiza o papel de login da aplicação com a senha de `PORTAL_DB_APP_PASSWORD`; os GRANTs vêm de `alembic -x app_role=portal_app upgrade head` |
| `portal init-db`, `portal dev-cert`, `portal demo` | somente desenvolvimento |

Os comandos emitem logs JSON (`severity`/`message`) para o Cloud Logging
(`PORTAL_LOG_FORMAT=text` para leitura local); código de saída ≠ 0 dispara os
alertas. Agendamento dos jobs e alertas: [Operação](docs/operacao.md) e
[Implantação no GCP](docs/implantacao-gcp.md).

## Estrutura

```
src/portal/
  auth/            # AD via LDAPS (produção) e provedor de desenvolvimento
  signing/         # PAdES (pyHanko), âncoras do campo de aceite, comprovante
  documents/       # emissão, ciência/aceite/divergência, importação de lotes, fluxo DocuSeal
  integrations/    # cliente DocuSeal (API + webhook HMAC)
  web/             # FastAPI + Jinja2 (sem build de front-end): colaborador, RH, /verificar
  audit.py         # trilha de auditoria encadeada por hash (verificação completa e incremental)
  anchoring.py     # ancoragem da trilha em carimbo do tempo
  dossier.py       # dossiê probatório (ZIP com verificar.py autônomo)
  employees.py     # importação CSV de colaboradores
  locks.py         # serialização e limite de tentativas de login por conta
  terms.py, mfa.py # termo de adesão versionado e TOTP
  config.py, logs.py # configuração (PORTAL_*) e logs estruturados
migrations/        # Alembic: esquema, gatilhos de imutabilidade e GRANTs do papel da aplicação
infra/terraform/   # GCP: Cloud Run (serviço e jobs), Cloud SQL, GCS com retenção, Secret Manager, VPN, alertas
infra/dev/         # inicialização do PostgreSQL do docker compose
docs/              # arquitetura, ADRs, jurídico, AD, implantação, operação
```

## Antes de ir para produção

Veja o checklist em [`docs/implantacao-gcp.md`](docs/implantacao-gcp.md) (inclui o job
`portal-migrate`, que roda antes do primeiro deploy e após cada nova imagem) e os pontos
que **dependem de validação jurídica** em
[`docs/assinatura-e-validade-juridica.md`](docs/assinatura-e-validade-juridica.md):
texto do termo de adesão, política ICP-Brasil (OID e hash da LPA), ACT para carimbo
do tempo e tabela de temporalidade.
