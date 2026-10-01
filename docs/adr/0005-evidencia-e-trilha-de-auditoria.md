# ADR 0005 — Evidência canônica, trilha encadeada por hash e ancoragem

**Situação:** aceita · **Data:** 2026-10-01

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
