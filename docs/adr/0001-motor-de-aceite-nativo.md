# ADR 0001 — Aceite nativo no portal; DocuSeal só para modelos fixos

**Situação:** aceita, com atualização ao final · **Data:** 2026-10-01

## Contexto

O escopo previa o DocuSeal open-source como motor de assinatura. A verificação no
código-fonte (README, `config/routes.rb`) e testes contra a imagem `docuseal/docuseal:3.3.0`
mostraram que, na edição **Community (gratuita)**:

- **não** existe criação de envio/modelo a partir de PDF avulso via API
  (`/api/submissions/pdf`, `/api/templates/pdf` respondem "This feature is available in
  Pro Edition"). Holerites são um PDF diferente por colaborador vindo da folha.
- **não** existe formulário de assinatura embutido (`<docuseal-form>` é Pro), e a
  página de assinatura envia `X-Frame-Options: SAMEORIGIN`.
- **não** existe SSO/SAML/LDAP. O signatário é identificado apenas pelo link (`/s/{slug}`).
- o PDF final é "achatado" e reescrito. Um selo e-CNPJ aplicado antes é removido ou
  invalidado.
- a assinatura própria do DocuSeal é `adbe.pkcs7.detached`, sem política ICP-Brasil.
- atrás do balanceador do GCP, o IP registrado é o do balanceador.

O Pro on-premises custa cerca de US$ 20 por operador por mês, mais cerca de US$ 0,20 por
documento via API (valor não confirmado no site do fornecedor).

## Decisão

1. O **motor padrão é nativo**: o portal exibe o PDF selado, colhe o aceite com
   reautenticação e aplica o selo de aceite em um campo **pré-criado na posição fixa**
   (ver ADR 0002). Nenhuma licença é necessária.
2. O **DocuSeal fica opcional**, para documentos que já são **modelos fixos** (contrato,
   aditivo) e para os quais se queira a experiência de assinatura desenhada. O link é
   criado só depois da confirmação do colaborador logado no AD, nunca por e-mail. O
   selo e-CNPJ é aplicado pelo portal **depois** da conclusão.
3. O código mantém o motor por tipo de documento (`tipos_documento.engine`). Comprar o
   Pro no futuro não muda o modelo de dados.

## Consequências

- Atende todos os requisitos do escopo (âncora fixa, identidade AD, trilha, e-CNPJ) sem
  custo por usuário.
- A experiência de aceite é a do portal (checkbox + senha [+ TOTP]), sem "desenhar"
  assinatura. Para documentos trabalhistas isso é adequado: a validade decorre da
  evidência, não do rabisco (ver documento jurídico).
- Se o DocuSeal for usado, ele vira mais um sistema para operar (VM, Postgres, backup,
  AGPL §13 se for modificado).

## Atualização (revisão adversarial)

A decisão se mantém. O caminho DocuSeal foi endurecido:

- **Só modelos fixos:** um tipo com motor `docuseal` exige `docuseal_template_id`. O RH
  emite as pendências por lista de matrículas (Área do RH → "DocuSeal"). O envio só é
  criado quando o colaborador autenticado abre o documento e confirma a senha do AD (e o
  TOTP, se o tipo exigir). Um novo link arquiva o envio anterior e expira em 2 horas.
- **Token da API** só vai para `{DOCUSEAL_URL}/api/*`. Os downloads (URLs assinadas) vão
  sem token, no mesmo esquema e host:porta da URL configurada, também nos
  redirecionamentos (sem rebaixar https para http). Em produção a URL deve ser https.
- **Todos os PDFs do envio** recebem o selo final do e-CNPJ. O primeiro é o documento
  principal; os demais ficam em `evidencia.documento.arquivos_adicionais` e no dossiê.
- **Recusa** (`form.declined`) registra a frase fixa `DECLINE_DECLARATION` e o motivo,
  nunca a declaração de concordância.
- **Vínculo com o AD:** vale o evento `DOCUSEAL_LINK_ABERTO` do **mesmo** signatário que
  concluiu; sem ele nada é registrado (`DOCUSEAL_SEM_VINCULO_AD`). A evidência v2 traz os
  fatores confirmados ao abrir o link, o horário local com fuso e a trilha do DocuSeal.
- **Webhook** processado fora do laço de eventos (thread com sessão própria). Falha de
  rede ou de selo responde 502 e o DocuSeal reenvia; os arquivos só são gravados depois
  de todos gerados.
- No DocuSeal, use `CERTS={"enabled":false}`: o único certificado é o selo do portal.

Fluxo completo em `docs/arquitetura.md` (Fluxo DocuSeal).
