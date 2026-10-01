# Portal do Colaborador — DP Digital com aceite eletrônico

Portal (intranet) onde cada colaborador acessa **seus** documentos de Departamento
Pessoal — holerites, contratos, aditivos, informes — e registra **aceite/ciência ou
divergência** com evidência suficiente para uma *assinatura eletrônica avançada*,
sem ferramenta paga por usuário.

- **Login com a conta do Active Directory** (LDAPS pela VPN GCP ↔ empresa). O
  Windows Server continua só com AD/DNS.
- **Documentos selados com o e-CNPJ A1** (PAdES, ICP-Brasil, carimbo do tempo
  opcional), no momento da importação do lote da folha.
- **Campo de aceite em posição fixa**, definido pelo tipo de documento: o
  colaborador não escolhe onde "assina".
- **Evidência do aceite**: usuário AD (objectGUID), reautenticação (senha e,
  opcionalmente, TOTP), IP, navegador, data/hora e hash SHA-256 do documento
  exibido. Tudo vai para uma trilha de auditoria encadeada por hash e para um
  comprovante PDF selado.
- **DocuSeal (opcional)** para modelos fixos, como contratos. A edição open-source
  não embute o formulário nem cria envios a partir de PDF avulso (recursos Pro).
  Por isso os holerites usam o motor nativo do portal.

## Documentação

| Documento | Para quem |
|---|---|
| [Arquitetura](docs/arquitetura.md) e [decisões (ADRs)](docs/adr/) | TI / desenvolvimento |
| [Assinatura e validade jurídica](docs/assinatura-e-validade-juridica.md) | Jurídico / RH / TI |
| [Integração com o AD](docs/integracao-ad.md) | TI (infraestrutura Windows) |
| [Implantação no GCP](docs/implantacao-gcp.md) e [`infra/terraform`](infra/terraform) | TI / nuvem |
| [Operação (runbook)](docs/operacao.md) | TI / RH |
| [Guia do RH](docs/guia-rh.md) | Departamento Pessoal |

## Como funciona (resumo)

```
Sistema de folha ──PDF/ZIP──▶ RH importa lote ──▶ separa por matrícula ──▶ sela com e-CNPJ
                                                   (cria campo "AceiteColaborador")
Colaborador ──login AD──▶ Meus documentos ──▶ abre PDF ──▶ aceita (senha [+ TOTP])
        ──▶ selo de aceite no campo fixo + comprovante PDF selado + trilha de auditoria
```

## Rodando localmente

Requisitos: Python 3.11+ (ou Docker).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # PORTAL_ENV=dev, PORTAL_AUTH_PROVIDER=dev
portal dev-cert var/dev          # certificado de TESTE (não é ICP-Brasil)
export PORTAL_SIGNING_PFX_FILE=var/dev/dev-ecnpj.pfx PORTAL_SIGNING_PFX_PASSWORD=dev
alembic upgrade head
portal demo                      # tipos, termo v1, colaboradores e holerites de exemplo
uvicorn portal.web.asgi:app --reload
```

Usuários de desenvolvimento (senha `dev`): `maria.silva` e `joao.souza`
(colaboradores) e `rh.admin` (RH). O `portal demo` já cria os colaboradores e um lote
de holerites. Para testar com seus PDFs, use **Área do RH → Importar lote**.

Com Docker: `docker compose up --build` (portal em http://localhost:8000).
Para subir também o DocuSeal: `docker compose --profile docuseal up`.

### Testes e qualidade

```bash
pytest            # unidade + integração (assinatura real com PKI de teste)
ruff check src tests && mypy src
```

## Operação (CLI)

| Comando | Para quê |
|---|---|
| `portal seed` | tipos de documento padrão e Termo de Adesão v1 |
| `portal import-employees arquivo.csv` | cadastro/atualização de colaboradores |
| `portal ingest --tipo HOLERITE --competencia 2026-09 folha.pdf` | importação automatizada de lote |
| `portal verify-audit` | confere a cadeia de hashes da auditoria |
| `portal anchor-audit` | carimba (RFC 3161) a cabeça da cadeia (agendar diariamente) |
| `portal cert-info --alerta-dias 45` | validade do e-CNPJ (renovação anual do A1) |

## Estrutura

```
src/portal/
  auth/            # AD via LDAPS (produção) e provedor de desenvolvimento
  signing/         # PAdES (pyHanko), âncoras do campo de aceite, comprovante
  documents/       # emissão, aceite/recusa, importação de lotes, fluxo DocuSeal
  integrations/    # cliente DocuSeal (API + webhook HMAC)
  web/             # FastAPI + Jinja2 (sem build de front-end)
  audit.py         # trilha de auditoria encadeada por hash
  anchoring.py     # ancoragem da trilha em carimbo do tempo
  terms.py, mfa.py # termo de adesão versionado e TOTP
migrations/        # Alembic (PostgreSQL em produção; gatilhos append-only)
infra/terraform/   # GCP: Cloud Run, Cloud SQL, GCS com retenção, Secret Manager, VPN
docs/              # arquitetura, ADRs, jurídico, AD, implantação, operação
```

## Antes de ir para produção

Veja o checklist em [`docs/implantacao-gcp.md`](docs/implantacao-gcp.md) e os pontos
que **dependem de validação jurídica** em
[`docs/assinatura-e-validade-juridica.md`](docs/assinatura-e-validade-juridica.md):
texto do termo de adesão, política ICP-Brasil (OID e hash da LPA), ACT para carimbo
do tempo e tabela de temporalidade.
