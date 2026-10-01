# ADR 0003 — Python + FastAPI + pyHanko, páginas renderizadas no servidor

**Situação:** aceita, com atualização ao final · **Data:** 2026-10-01

## Contexto

O núcleo técnico é a assinatura PAdES com controle fino:
- certificação/DocMDP;
- campos pré-criados e carimbos visíveis;
- política ICP-Brasil, TSA e LTV;
- validação com análise de diferenças.

Opções avaliadas:
- **pyHanko** (Python, MIT): cobre tudo isso e foi testado neste projeto.
- **EU DSS** (Java, LGPL): mais completo, mas exige uma JVM.
- **Demoiselle Signer** (Java, LGPL): nativo ICP-Brasil.
- **iText** (AGPL/comercial).
- **@signpdf** (Node): básico demais.

## Decisão

- Back-end em **Python 3.11+ / FastAPI**, com **SQLAlchemy 2 + Alembic** e
  **PostgreSQL** em produção (SQLite em desenvolvimento e testes).
- Interface em **Jinja2 renderizado no servidor**, CSS próprio e **sem JavaScript
  obrigatório**. Isso dispensa build de front-end, mantém a CSP restritiva e funciona
  em celulares simples.
- Assinatura e validação com **pyHanko**; comprovante com **ReportLab**; leitura de PDF
  com **pypdf**; AD com **ldap3**.

## Consequências

- Um único serviço e uma única linguagem, fáceis de auditar.
- Se a conformidade estrita com DOC-ICP-15 exigir motor de políticas (validação de LPA),
  o Demoiselle Signer pode entrar como *sidecar* de validação sem trocar a stack.
- Em celulares sem visualizador de PDF embutido, o colaborador usa "Baixar PDF".
  Melhoria futura: pdf.js empacotado localmente.

## Atualização (revisão adversarial)

A stack se mantém. Gatilhos, privilégios dos papéis e travas consultivas existem só no
PostgreSQL, por isso o CI roda os testes também contra um PostgreSQL real, além do
SQLite. Os logs saem em JSON estruturado (`PORTAL_LOG_FORMAT`, padrão `json` em
produção) para o Cloud Logging.
