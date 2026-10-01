# Assinatura, evidência e validade jurídica

> **Aviso:** este documento organiza a pesquisa técnica que orientou o projeto; **não é
> parecer jurídico**. Os textos legais foram consultados por fontes secundárias, porque
> o ambiente de pesquisa não tinha acesso a planalto.gov.br e gov.br/iti. Valide com o
> jurídico trabalhista antes do uso em produção, em especial os itens marcados com ⚖️.

## 1. Base legal

| Norma | O que importa para o portal |
|---|---|
| **MP 2.200-2/2001, art. 10** | Documentos eletrônicos são válidos "para todos os fins legais". § 1º: a assinatura ICP-Brasil presume-se verdadeira **em relação aos signatários**. **§ 2º**: outros meios de comprovação de autoria e integridade valem "desde que admitido pelas partes como válido ou aceito pela pessoa a quem for oposto o documento". É a base do aceite do colaborador. |
| **Lei 14.063/2020, art. 4º** | Define assinatura simples, **avançada** e qualificada. O **caput do art. 2º** restringe a lei a interações com o poder público, mas os tribunais usam os critérios da avançada como referência em relações privadas: (a) associação **unívoca** ao signatário; (b) dados de criação sob **controle exclusivo** com elevado nível de confiança; (c) **qualquer modificação posterior detectável**. |
| **CPC arts. 408, 411, 428 e 429** | Art. 408, p.u.: a declaração de **ciência** prova a ciência, não o fato (base da redação "recebi e tomei ciência"). Impugnada a autenticidade, o **ônus é de quem produziu o documento** (art. 429, II; STJ Tema Repetitivo 1061, REsp 1.846.649/MA). A evidência precisa ser autossuficiente. |
| **CLT art. 830; CPC arts. 439–441** | Impugnada uma cópia, apresenta-se o original. No documento eletrônico, o original é o **PDF nativo assinado + evidência**, não uma impressão. O dossiê exporta os bytes originais. |
| **CLT art. 464** | O salário é pago contra recibo assinado. O parágrafo único equipara o **comprovante de depósito bancário** ao recibo. O aceite do holerite prova **ciência/entrega**, não o pagamento. |
| **CLT arts. 443, 444, 468, 75-C, 452-A, 428** | Contratos e aditivos podem ser eletrônicos. O art. 468 anula alteração prejudicial ou sem mútuo consentimento, qualquer que seja a assinatura. |
| **Lei 13.874/2019, art. 3º, X; Decreto 10.278/2020** | Arquivamento digital equiparado ao físico. O decreto regula apenas documentos **digitalizados** (papel escaneado). Os PDFs da folha são nato-digitais. |
| **LGPD (Lei 13.709/2018)** | Bases art. 7º II/V/VI (e art. 11 II a/d para dado sensível na folha). **Não** usar consentimento. Aplicam-se art. 16 I (retenção), arts. 18/19 (acesso, inclusive de ex-colaboradores), arts. 37/46 (registro e segurança) e Res. CD/ANPD 15/2024 (incidente em 3 dias úteis). |

Jurisprudência citada nas fontes (confirmar ⚖️):
- STJ REsp 2.159.442/PR (2024), REsp 2.205.708/PR (2025) e REsp 2.197.156/SP (2026) —
  assinatura em plataforma não ICP-Brasil é válida quando aceita pelas partes e houver
  prova de autoria e integridade;
- TRT-18 IRDR Tema 51 (2025);
- TST: a jurisprudência sobre contracheques sem assinatura é **dividida**. Há turmas
  que os tratam como prova unilateral. Já cartões de ponto sem assinatura não são
  inválidos por si, porque o art. 74 da CLT não exige assinatura. O valor da assinatura
  varia por tipo de documento.

## 2. Como o portal atende aos critérios da "avançada"

| Critério | Como o portal atende | Onde no código |
|---|---|---|
| **Unívoca** | Login no AD com conta **pessoal** e vínculo imutável `objectGUID` ↔ matrícula. Há conflito de vínculo se outra conta reivindicar a mesma matrícula. | `auth/ldap.py`, `routes_public.login` |
| **Controle exclusivo** | Reautenticação no ato (senha do AD) e, recomendado, **TOTP** em aplicativo do próprio colaborador. A TI pode redefinir senha, mas não tem o TOTP; redefinição do TOTP é registrada. | `documents/service.step_up`, `mfa.py` |
| **Modificação detectável** | PDF certificado (DocMDP) com hash conferido a cada leitura, evidência com hash na assinatura e no comprovante, trilha encadeada e ancorada em carimbo do tempo. | `signing/pades.py`, `audit.py`, `anchoring.py` |
| **Admitido pelas partes** (MP art. 10 § 2º) | **Termo de Adesão** versionado, aceito antes do primeiro uso. Cada manifestação referencia versão e hash do termo. Para quem já é colaborador, recomenda-se coletar também em papel ou gov.br e registrar no portal. | `terms.py`, `/termo`, `/rh/termo` |
| **Informação e liberdade** | O documento precisa ser aberto antes do aceite. Há caminho de **divergência** com motivo. O pagamento não depende do aceite (termo, item 5). | `require_view_before_accept`, `/recusa` |

O termo de adesão assinado sob subordinação pode ser questionado por vício de
consentimento (CLT art. 9º). Ele **reforça**, mas não substitui, a evidência de cada
documento. Ofereça sempre a alternativa assistida ou presencial.

**A assinatura e-CNPJ sozinha não prova o aceite.** Ela prova autoria e integridade do
lado da empresa. O colaborador não é signatário do certificado. Por isso o projeto separa
três camadas:
1. selo de emissão (empresa);
2. evidência de manifestação (colaborador);
3. selo sobre documento + evidência (empresa, com carimbo do tempo).

## 3. Redação recomendada por tipo de documento ⚖️

| Nível | Documentos | Requisitos no portal |
|---|---|---|
| 1 | Holerite, informe de rendimentos, avisos | Declaração de **ciência** ("declaro que recebi…"), **nunca** "concordo com os valores". Senha no ato. Divergência disponível. |
| 2 | Contrato, aditivo, políticas internas, férias | Leitura integral, **TOTP obrigatório**, aceitar/recusar explícitos, sem aceite por omissão. |
| 3 | Rescisão, pedido de demissão, acordo art. 484-A, menores (art. 439), estáveis (art. 500) | **Fora do escopo do aceite simples.** Exige assistência (responsável/sindicato), gov.br/ICP do colaborador ou fluxo presencial com o RH. |

Os textos padrão estão em `src/portal/cli.py` (`DEFAULT_TYPES`) e
`src/portal/terms.py` (`DEFAULT_TERM_V1`). **Revise-os com o jurídico** e republique pela
Área do RH.

## 4. ICP-Brasil: selo da empresa

- **Formato:** PAdES (`ETSI.CAdES.detached`), SHA-256, `signing-certificate-v2`,
  `commitment-type` = prova de origem.
- **Política ICP-Brasil (DOC-ICP-15.03):** a assinatura ICP-Brasil "conforme" carrega o
  identificador de uma política aprovada. No PAdES existem só AD-RB (11), AD-RT (12),
  AD-RC (13) e AD-RA (14); não há AD-RV. Valores extraídos dos arquivos `.der` oficiais
  das políticas (confira na LPA vigente em politicas.icpbrasil.gov.br):

  | Política | OID | Raízes aceitas | Vigência para assinar | SHA-256 do `.der` |
  |---|---|---|---|---|
  | PA_PAdES_AD_RB v1.1 | `2.16.76.1.7.1.11.1.1` | v5, v2 | até 02/03/2029 | `95752d26ca974d46675ae7fb787b606a71ea941f26b59f6b6a321f97d63b9cb1` |
  | PA_PAdES_AD_RB v1.2 | `2.16.76.1.7.1.11.1.2` | v12, v5 | 12/06/2025 a 22/10/2037 | `84ed4620c6531e4a4853adecc9e2496926c823418dd3141963ed9c4f9704a03d` |
  | PA_PAdES_AD_RB v1.3 | `2.16.76.1.7.1.11.1.3` | v12, v5 | desde 23/07/2025 | conferir na LPA |
  | PA_PAdES_AD_RT v1.1 / v1.2 / v1.3 | `2.16.76.1.7.1.12.1.1` / `.2` / `.3` | idem | idem | conferir na LPA |

  **Escolha a versão conforme a raiz da cadeia do certificado.** Certificados emitidos na
  **AC Raiz v12** exigem política v1.2 ou superior; o Verificador do ITI reprova v1.1
  nesse caso. A AD-RT exige carimbo do tempo de **ACT ICP-Brasil**: o
  `timeStampTrustCondition` aceita só raízes ICP-Brasil.

  Configure:
  - `PORTAL_SIGNATURE_POLICY_OID`;
  - `PORTAL_SIGNATURE_POLICY_HASH_B64` (aceita o hash em hexadecimal, como na tabela);
  - `PORTAL_SIGNATURE_POLICY_URI`.

  O pyHanko só embute o identificador. O cumprimento das regras da política é
  responsabilidade do portal: PAdES, SHA-256, `signing-certificate-v2` e `sigPolicyId`,
  todos já presentes. **Valide amostras no Verificador do ITI** (validar.iti.gov.br)
  antes de entrar em produção. A própria política AD-RB adverte que, sem carimbo do
  tempo, a validação futura depende de referência temporal acordada entre as partes.
  Com certificado de 1 ano e guarda de muitos anos, AD-RT (ou B-LTA) é, na prática,
  necessária.
- **Carimbo do tempo:** prefira uma ACT credenciada na ICP-Brasil (Serpro, Certisign,
  Valid, BRy, Prodesp e outras), cobrada por carimbo. TSAs gratuitas (FreeTSA, Sectigo)
  dão só prova técnica e têm limite de taxa, inviáveis para lotes.
- **Validade de longo prazo:** o A1 vale 1 ano. Use `PORTAL_SIGNING_LTV=true` (B-LTA,
  com DSS e carimbo de documento) com as raízes do arquivo `ACcompactado.zip` do ITI em
  `PORTAL_SIGNING_TRUST_ROOT_FILES`, e planeje a renovação periódica de carimbos de
  arquivamento (ver [operacao.md](operacao.md)).
- **Guarda do certificado:** o e-CNPJ da empresa também dá acesso ao e-CAC, ao eSocial e
  a outros sistemas do governo. Colocá-lo em um servidor exposto à internet aumenta
  muito o dano em caso de vazamento. **Use um certificado dedicado ao selo de
  documentos**: um e-CNPJ separado ou, quando disponível, o Selo Eletrônico, que não traz
  CPF de responsável. Guarde-o no Secret Manager ou, melhor, importado no Cloud KMS
  (HSM), com acesso restrito e auditado.
- **Fim do A1:** pela Resolução CG ICP-Brasil 211/2024, A1/A2 deixam de existir e entra o
  **Selo Eletrônico** SE-S/SE-H. O Demoiselle Signer, do Serpro, já reconhece os OIDs de
  política de certificado: SE-S `2.16.76.1.2.201`, SE-H `.202`, AE-S `.203` e AE-H
  `.204`. Segundo fontes secundárias:
  - certificados da cadeia v5 podem ser usados até 02/03/2029;
  - a emissão de A1 na v10 termina em 31/12/2026;
  - o selo **não pode** ser usado como manifestação de vontade da empresa. Para o lado
    da empresa em **contratos**, prefira a assinatura qualificada de um representante
    legal ⚖️.

  O `Sealer` aceita qualquer `Signer` do pyHanko; a troca é de configuração e construtor.
  Antes da troca, confira o *keyUsage* do novo certificado: o pyHanko exige
  `nonRepudiation` por padrão.
- **Adobe Acrobat** pode mostrar o selo A1 como "validade desconhecida": a entrada
  ICP-Brasil na AATL seria restrita a A2/A3/A4. Oriente os usuários a validar pela página
  **/verificar** do portal e pelo Verificador do ITI.

## 5. Evidência registrada em cada aceite

Arquivo `evidencia.json`, embutido no comprovante e gravado na tabela `aceites`:

```json
{
  "versao": 1, "tipo": "manifestacao_eletronica", "decisao": "ACEITO",
  "documento": {"id": "…", "codigo_verificacao": "ABCD-EFGH-JKLM",
                "sha256_original": "…", "sha256_apresentado": "…",
                "primeira_visualizacao_utc": "…"},
  "signatario": {"nome": "…", "matricula": "…", "cpf_mascarado": "***.456.789-**",
                 "ad": {"sAMAccountName": "…", "userPrincipalName": "…",
                        "objectGUID": "…", "dn": "…"}},
  "autenticacao": {"login": "Active Directory (LDAPS bind)", "login_em_utc": "…",
                   "reautenticacao_no_ato": "senha_ad+totp", "sessao_ref": "…"},
  "contexto": {"ip": "…", "porta_origem": "…", "user_agent": "…"},
  "termo_adesao": {"versao": "1", "sha256": "…", "canal": "portal", "aceito_em_utc": "…"},
  "manifestacao": {"declaracao": "…", "declaracao_sha256": "…",
                   "data_hora_utc": "…", "data_hora_local": "…", "fuso": "America/Sao_Paulo"},
  "sistema": {"portal_versao": "0.1.0", "certificado_selo": "…"}
}
```

Não se coleta geolocalização por GPS nem *fingerprint* do dispositivo, pelo princípio da
necessidade (LGPD art. 6º, III). A **porta de origem** só é registrada se o balanceador
a informar (`PORTAL_CLIENT_PORT_HEADER`). Ela é relevante para identificar usuários atrás
de CGNAT (STJ REsp 1.784.156/SP).

## 6. Temporalidade (proposta para aprovação) ⚖️

| Classe | Prazo sugerido | Fundamento (resumo) |
|---|---|---|
| Holerites, férias, 13º, FGTS/INSS | ≥ 10 anos do pagamento | prescrição trabalhista de 5 anos (CF 7º XXIX), FGTS 5 anos (STF ARE 709.212), previdenciário |
| Contratos, aditivos, registro, rescisão | indeterminado ou ≥ 30 anos | prova de tempo de serviço; ação declaratória imprescritível (CLT 11 § 1º) |
| Menores de 18 | prazo + período até a maioridade | prescrição não corre (CLT 440) |
| ASO/PCMSO (se vier a ser publicado) | 20 anos após o desligamento | NR-7 |
| Evidências e trilha | igual ao documento | — |
| Logs de segurança | ≥ 6 meses; incidentes 5 anos | Marco Civil art. 15 (aplicabilidade a confirmar); Res. ANPD 15/2024 |

Cada bucket do GCS tem **um único** prazo de retenção, e prefixos não têm retenção
própria. Para prazos diferentes por classe, use **buckets separados por classe**
(evolução prevista no código) ou retenção por objeto, que só pode ser habilitada na
criação do bucket. O prazo do bucket atual é um **mínimo** (10 anos): documentos de
prazo maior continuam guardados, e a eliminação ao fim do prazo (LGPD art. 16) é um
processo controlado pela aplicação.

## 7. Pendências para o jurídico ⚖️

1. Texto final do **Termo de Adesão** e forma de coleta para quem já é colaborador
   (papel, gov.br ou portal).
2. Redação das declarações por tipo de documento; checar **CCT/ACT** sobre entrega e
   assinatura de holerites.
3. Se contratos e aditivos exigirão **TOTP** (recomendado) ou assinatura qualificada do
   colaborador.
4. Fluxo do nível 3 (rescisão, menores, estáveis).
5. Tabela de temporalidade e acesso de ex-colaboradores (pacote no desligamento,
   atendimento pelo encarregado em 15 dias).
6. Aviso de privacidade, ROPA (art. 37), encarregado (art. 41) e cláusulas-padrão da
   ANPD no contrato com o Google Cloud (Res. CD/ANPD 19/2024). Para a empresa como
   controladora, o conjunto aplicável é o **BR SCC controlador→operador** (`br-c2p`) do
   Cloud Data Processing Addendum.
7. **Acessibilidade:** a Lei 13.146/2015 (LBI), art. 63, exige sites acessíveis. O fluxo
   de aceite e a alternativa assistida devem atender colaboradores com deficiência,
   inclusive os contratados por cota.
8. **Aprendizes menores de 18:** aplicam-se LGPD art. 14 e Enunciado ANPD 1/2023, além
   da assistência na rescisão (CLT art. 439).
