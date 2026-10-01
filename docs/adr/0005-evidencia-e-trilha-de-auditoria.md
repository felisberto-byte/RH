# ADR 0005 — Evidência canônica, trilha encadeada por hash e ancoragem

**Situação:** aceita, com atualização ao final · **Data:** 2026-10-01

## Contexto

Se o colaborador impugnar a autenticidade, o ônus de provar recai sobre o empregador
(CPC art. 429, II). A prova precisa ser verificável por perito **sem confiar no sistema
em produção**.

## Decisão

1. **Evidência canônica por manifestação.** É um JSON com chaves ordenadas e separadores
   fixos, e contém:
   - documento: id, hashes original/apresentado, 1ª visualização;
   - signatário: nome, matrícula, CPF mascarado, objectGUID/UPN/DN;
   - autenticação: login, fatores da confirmação, sessão;
   - contexto: IP, porta, navegador;
   - termo de adesão: versão e hash;
   - declaração e seu hash, data/hora UTC e local;
   - sistema: versão e certificado.

   O SHA-256 dessa evidência fica:
   - na tabela `aceites` (somente inclusão);
   - na razão da assinatura PAdES de aceite;
   - no comprovante, que embute o JSON e o PDF apresentado.
2. **Trilha de auditoria encadeada.** Cada evento grava
   `hash = SHA-256(hash_anterior ‖ JSON canônico)`. A cabeça é serializada com
   `SELECT … FOR UPDATE`. No PostgreSQL, gatilhos bloqueiam UPDATE/DELETE em
   `auditoria`, `aceites`, `termos_adesao_aceites` e `auditoria_ancoras`.
   `portal verify-audit` e a tela do RH conferem a cadeia.
3. **Ancoragem diária.** `portal anchor-audit` carimba (RFC 3161, ACT ICP-Brasil) o hash
   da cabeça. É um carimbo por dia, não por evento, e prova por terceiro que o histórico
   até ali já existia.
4. **Arquivos imutáveis.** Gravação *create-only* no GCS, com *retention policy* por
   classe. O hash é conferido em toda leitura.
5. **Dossiê exportável.** O dossiê por documento (ZIP com PDFs, evidência, eventos e
   manifesto de integridade) e o pacote por colaborador podem ser exportados, por
   exemplo no desligamento, quando a conta AD é desativada.

## Consequências

- Alterar o banco diretamente quebra a cadeia, o que é detectável. Remover eventos
  recentes depois da última âncora é detectável pela comparação com a cabeça ancorada.
- O IP é dado pessoal (LGPD). A retenção da trilha segue a do documento.

## Atualização (revisão adversarial)

- **Âncoras verificadas:** o token RFC 3161 cobre
  `SHA-256("portal-auditoria:<evento>:<hash>")` da cabeça. `portal verify-audit` (job
  diário) confere a cadeia inteira e cada âncora: o evento ancorado mantém o hash, o
  token está íntegro e o *imprint* é igual ao hash carimbado. Uma cadeia reescrita de
  forma "consistente" falha nessa conferência. Em falha, o comando registra
  `CADEIA DE AUDITORIA COM FALHA` (severity ERROR, com alerta) e sai com código 1. A tela
  do RH faz a verificação incremental a partir da última âncora.
- **Dossiê autossuficiente:** inclui todas as versões do PDF (com adicionais e trilha do
  DocuSeal), `evidencia.json`, o segmento contínuo da cadeia, os tokens `.tsr`, o texto
  do termo referenciado, `manifesto.json` e `verificar.py`. O script usa só a biblioteca
  padrão do Python, confere hashes, encadeamento e *imprint* das âncoras e sai com 0
  quando o dossiê está ÍNTEGRO. Lista de arquivos em `docs/arquitetura.md`.
- **Gatilhos** também bloqueiam TRUNCATE nas tabelas somente-inclusão. `auditoria_cabeca`
  só avança, sem recuar nem ser apagada (a migração semeia a cabeça). O termo de adesão
  publicado é imutável, exceto `active`.
- **Papéis:** `portal_owner` é o dono do esquema e só o job de migração o usa. A
  aplicação conecta como `portal_app` (`portal db-app-role`, sem superusuário), com
  SELECT/INSERT nas tabelas somente-inclusão, SELECT/INSERT/UPDATE em
  `auditoria_cabeca` e `termos_adesao` e CRUD nas demais. Assim ela não remove gatilhos
  nem tabelas. Um teste no PostgreSQL real cobre esquema, gatilhos e privilégios.
- **Evidência v2:** registra a natureza (ciência/aceite) e a declaração fotografada na
  emissão (texto e SHA-256, conferido contra o hash da declaração exibida). Registra
  também as aberturas do documento, o histórico do TOTP (quando usado) e a fonte de
  tempo, inclusive quando a produção opera sem ACT (`PORTAL_ALLOW_NO_TSA=true`). Na
  divergência, guarda a frase fixa de recusa e o motivo.
- **Termo de adesão:** o aceite pelo portal gera comprovante PDF selado com o texto
  integral e a evidência embutida. O RH só registra adesões externas, pelos canais
  "papel" e "gov.br".
- **LGPD:** `portal purge --dias N` (mínimo 30) apaga tentativas de login e sessões
  encerradas antigas (`DADOS_OPERACIONAIS_EXPURGADOS`). Documentos, aceites e auditoria
  nunca são apagados.
