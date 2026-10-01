# Operação (runbook)

## Rotinas

| Frequência | Rotina | Como |
|---|---|---|
| A cada folha | Importar o lote de holerites | Área do RH → **Importar lote**, ou Cloud Run Job `portal ingest …` a partir de um bucket de entrada. Confira o relatório: matrículas desconhecidas e páginas sem identificação **não são publicadas**. |
| Diária | Ancorar a trilha de auditoria | Cloud Scheduler → Cloud Run Job `portal anchor-audit` (exige `PORTAL_TSA_URL`). |
| Diária | Conferir integridade da trilha | Cloud Run Job `portal verify-audit`; alerta se o código de saída ≠ 0. |
| Semanal | Validade do e-CNPJ | `portal cert-info --alerta-dias 45`; alerta se ≠ 0. |
| Mensal | Pendências antigas | Área do RH → Painel → "Pendências mais antigas". |
| Por evento | Desligamento | Área do RH → Colaboradores → **Pacote de documentos** (entregar ao ex-colaborador antes de desativar a conta AD). |
| Por evento | Troca de celular do colaborador | Área do RH → Colaboradores → **Redefinir autenticador** (motivo obrigatório; fica na auditoria). |

## Renovação anual do e-CNPJ A1

1. Adquira o novo A1 **antes** do vencimento (`portal cert-info`).
2. Crie uma **nova versão** dos segredos `ecnpj-pfx` e `ecnpj-pfx-password` no Secret
   Manager. Nunca sobrescreva nem destrua a versão antiga antes do corte.
3. Atualize o serviço do Cloud Run para a nova versão (`terraform apply` ou
   `gcloud run services update`).
4. Emita um documento de teste e valide em `/verificar` e no Verificador do ITI.
5. Depois do corte, **desabilite** a versão antiga do segredo. Mantenha o certificado
   público antigo para validação; documentos já selados continuam válidos pelo carimbo
   do tempo.
6. Registre a troca (data, serial antigo e novo) no registro de mudanças.

> Pela Resolução CG ICP-Brasil 211/2024 o A1 será substituído pelo **Selo Eletrônico
> (SE-S/SE-H)**. A troca é de certificado e construtor do `Sealer`; ver
> [ADR 0002](adr/0002-ordem-das-assinaturas-pades.md).

## Backup e recuperação

- **Cloud SQL:** backups automáticos diários e PITR (7 dias ou mais). Teste a restauração
  trimestralmente.
- **GCS:** *retention policy* por classe e *Object Versioning*. Os objetos são
  create-only, então não há sobrescrita.
- A integridade cruzada é garantida pelos hashes: após uma restauração, rode
  `portal verify-audit` e exporte alguns dossiês. O manifesto indica se cada PDF confere
  com o hash do banco.

## Incidentes

| Sinal | Ação |
|---|---|
| Evento `INTEGRIDADE_FALHOU` | Um PDF não confere com o hash registrado. Isole o objeto, compare com as versões do bucket, abra incidente de segurança. |
| `verify-audit` falhou | A cadeia foi alterada. Preserve o banco (snapshot) e compare com a última âncora (`auditoria_ancoras`). |
| Muitos `LOGIN_FALHOU` de um IP | Possível força bruta. Bloqueie no Cloud Armor e confira bloqueios no AD. |
| `VINCULO_AD_CONFLITO` | Duas contas AD reivindicam a mesma matrícula. Verifique com a TI antes de corrigir. |
| `DOCUSEAL_SEM_VINCULO_AD` ou `DOCUSEAL_SUBMITTER_DIVERGENTE` | Conclusão no DocuSeal sem sessão do portal ou com link antigo. Não aceite como manifestação; investigue. |
| Vazamento de dados pessoais | LGPD: avaliar risco e comunicar a ANPD e os titulares em **3 dias úteis** (Res. CD/ANPD 15/2024). Manter registro do incidente por 5 anos. |

## Roadmap

1. **Keycloak/OIDC** (ADR 0004): WebAuthn/passkeys e SSO para outras aplicações.
2. **Visualizador pdf.js empacotado**, para celulares sem leitor de PDF embutido.
3. **Notificações por e-mail** (Workspace SMTP relay) de novos documentos e de cada
   aceite. Isso reforça a prova contra alegação de documento unilateral.
4. **Acesso de ex-colaboradores** por OTP no e-mail pessoal cadastrado no RH (LGPD
   arts. 18/19).
5. **Renovação de carimbos de arquivamento** (B-LTA,
   `PdfTimeStamper.update_archival_timestamp_chain`) antes do vencimento da ACT,
   gravando novas versões dos PDFs.
6. **Fluxo de nível 3** (rescisão, menores, estáveis), com múltiplos signatários e
   assistência.
7. **Teste de conformidade no Verificador do ITI** (API) no CI, com amostras seladas
   pelo certificado de homologação.
8. **Vínculos múltiplos** (uma pessoa com várias matrículas): modelo pessoa(CPF) 1:N
   vínculo(matrícula).
