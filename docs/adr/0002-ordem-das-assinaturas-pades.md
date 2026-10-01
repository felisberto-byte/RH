# ADR 0002 — Ordem e forma das assinaturas PAdES

**Situação:** aceita · **Data:** 2026-10-01

## Contexto

Os documentos precisam do selo da empresa (e-CNPJ A1, ICP-Brasil) e do registro do
aceite do colaborador, que não tem certificado. Validadores (pyHanko, Acrobat, ITI)
analisam as revisões incrementais do PDF e reprovam alterações não permitidas após uma
assinatura. Testes com pyHanko 0.37 mostraram que:

- assinar um **campo pré-existente** depois de uma certificação DocMDP P=2 é aceito
  (`FORM_FILLING`, `docmdp_ok=True`);
- **anexar** um arquivo (evidência) ao PDF depois do selo gera `SuspiciousModification`
  e reprova a assinatura da empresa, com ou sem certificação;
- DSS/carimbo de documento (LTV/LTA) são atualizações permitidas.

## Decisão

1. **Emissão:** na mesma revisão, o sistema cria o campo vazio `AceiteColaborador` na
   âncora do tipo de documento e aplica a assinatura de **certificação** com
   `DocMDP P=2`. Leva `commitment-type` "prova de origem", política ICP-Brasil (se
   configurada) e carimbo do tempo (se houver ACT). Documentos sem aceite usam `P=1`.
2. **Aceite:** o sistema assina **somente** o campo `AceiteColaborador`, com carimbo
   visível (nome, matrícula, usuário AD, data/hora, IP, hashes, URL de verificação). A
   razão da assinatura contém o SHA-256 da evidência.
3. **Comprovante:** é um PDF **separado**. Leva embutidos `evidencia.json` e o PDF
   exatamente como apresentado, e recebe certificação `P=1`. O PDF do documento nunca
   recebe anexos.
4. **DocuSeal:** o selo e-CNPJ é aplicado **por último**, como assinatura de aprovação
   incremental (`SeloEmpresaFinal`) sobre o PDF devolvido pelo DocuSeal.
5. **LTV:** com `PORTAL_SIGNING_LTV=true`, as assinaturas viram PAdES B-LTA (DSS +
   carimbo de documento). Assim continuam verificáveis após o vencimento anual do A1.

## Consequências

- Um único PDF mostra as duas assinaturas válidas; o comprovante é autossuficiente.
- O signatário criptográfico das duas assinaturas é a empresa. Isso fica explícito no
  carimbo e no comprovante.
- A1 está sendo extinto (Res. CG ICP-Brasil 211/2024 → "Selo Eletrônico" SE-S/SE-H). A
  classe `Sealer` recebe qualquer `pyhanko.sign.Signer`, e trocar para SE-S, Cloud KMS
  ou PSC é uma mudança de construtor.
