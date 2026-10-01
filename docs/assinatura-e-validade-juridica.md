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
| **Unívoca** | Login com a conta **pessoal** do AD (bind LDAPS com a senha do próprio usuário). O vínculo `objectGUID` ↔ matrícula é fixado no primeiro login. Outra conta reivindicando a matrícula, ou matrícula do AD diferente da do cadastro, bloqueia o acesso (`VINCULO_AD_CONFLITO` / `VINCULO_AD_DIVERGENTE`). Só o RH desfaz o vínculo ("Desvincular conta do AD", na readmissão), com motivo e evento `VINCULO_AD_REMOVIDO`. A sessão é revalidada no AD a cada `PORTAL_SESSION_REVALIDATE_MINUTES` (10): conta desabilitada, fora do grupo ou com vínculo divergente perde a sessão (`SESSAO_REVOGADA`). | `auth/ldap.py`, `routes_public.login`, `web/deps.py` |
| **Controle exclusivo** | Confirmação no ato com a senha do AD (limite de falhas por conta) e **TOTP** quando o tipo exige ("Exige TOTP") ou com `PORTAL_ACCEPT_MFA=totp`. Cada código vale uma única vez. Cadastrar o autenticador exige a senha do AD no ato, e a tela mostra desde quando ele está configurado ("não reconhece? procure o RH"). A redefinição pelo RH encerra as sessões e gera `MFA_REDEFINIDO`. Quem redefine a senha no AD não tem o TOTP já cadastrado. A evidência registra a data do cadastro e as redefinições: cadastro ou redefinição pouco antes do aceite é sinal a examinar. | `documents/service.step_up`, `mfa.py`, `routes_account.py` |
| **Modificação detectável** | PDF certificado (DocMDP) com hash conferido a cada leitura, evidência com hash na assinatura e no comprovante, trilha encadeada, ancorada diariamente em carimbo do tempo e protegida por gatilhos no banco (seção 6). | `signing/pades.py`, `audit.py`, `anchoring.py` |
| **Declaração exibida = registrada** | A declaração é fixada no documento na emissão (texto e SHA-256). Editar o tipo depois não altera documentos emitidos. O formulário envia o SHA-256 da declaração exibida e o servidor recusa se ele divergir ("A declaração foi atualizada"). A divergência registra uma frase fixa e o motivo, **nunca** a declaração de concordância. | `documents/service._manifest` |
| **Admitido pelas partes** (MP art. 10 § 2º) | **Termo de Adesão** versionado, aceito antes do primeiro uso (`PORTAL_REQUIRE_ADHESION_TERM`). No portal, o aceite exige a senha do AD e confere id e SHA-256 da versão lida: se o RH publicou outra no meio tempo, a nova é exibida. Gera um **comprovante PDF selado** com o e-CNPJ (texto integral do termo + evidência JSON embutida), baixável em `/termo/comprovante`. Adesões em papel ou gov.br são registradas pelo RH, com o local de arquivamento. O RH **não** pode registrar adesão "portal" em nome do colaborador. Cada manifestação referencia versão, hash e canal do termo. | `terms.py`, `routes_account.py` (`/termo`), `/rh/termo`, `/rh/colaboradores` |
| **Informação e liberdade** | O documento precisa ser aberto antes do aceite. Há caminho de **divergência** com motivo, e as divergências aparecem no painel do RH. O pagamento não depende do aceite (termo, item 5). | `require_view_before_accept`, `/recusa` |

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
| 1 | Holerite, informe de rendimentos, avisos | Natureza **ciência**: declaração "declaro que recebi…", **nunca** "concordo com os valores". Senha no ato. Divergência disponível. |
| 2 | Contrato, aditivo, políticas internas, férias | Natureza **aceite**: leitura integral, **TOTP** ("Exige TOTP" no tipo), aceitar/recusar explícitos, sem aceite por omissão. |
| 3 | Rescisão, pedido de demissão, acordo art. 484-A, menores (art. 439), estáveis (art. 500) | **Fora do escopo do aceite simples.** Exige assistência (responsável/sindicato), gov.br/ICP do colaborador ou fluxo presencial com o RH. |

A natureza do tipo (`ciencia` ou `aceite`) define o carimbo visível ("CIÊNCIA ELETRÔNICA
DO COLABORADOR" ou "ACEITE ELETRÔNICO DO COLABORADOR"), o título do comprovante e os
textos da tela. A divergência gera o "Comprovante de Registro de Divergência". O
`portal seed` cria HOLERITE e INFORME_IR como ciência e CONTRATO e ADITIVO como aceite.
Estes dois vêm **sem** TOTP obrigatório, para não travar quem ainda não configurou o
autenticador: marque "Exige TOTP" assim que possível.

Os textos padrão estão em `src/portal/cli.py` (`DEFAULT_TYPES`) e
`src/portal/terms.py` (`DEFAULT_TERM_V1`). **Revise-os com o jurídico.** Ajuste as
declarações em Área do RH > Tipos: cada alteração é auditada com antes e depois
(`TIPO_DOCUMENTO_ALTERADO`) e não afeta documentos já emitidos. Publique o termo revisado
como nova versão em Área do RH > Termo de adesão; uma versão publicada não pode ser
alterada.

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
  dão só prova técnica e têm limite de taxa, inviáveis para lotes. Em produção o portal
  não inicia sem `PORTAL_TSA_URL`, salvo com a declaração explícita
  `PORTAL_ALLOW_NO_TSA=true`. Nesse caso, a ausência fica registrada em cada evidência
  (`fonte_de_tempo` "SEM carimbo do tempo de terceiro", `act_carimbo_do_tempo` nulo) e no
  comprovante ("Carimbo do tempo: não utilizado"). Também não há ancoragem da trilha,
  porque `portal anchor-audit` exige a ACT.
- **Validade de longo prazo:** o A1 vale 1 ano. Use `PORTAL_SIGNING_LTV=true` (B-LTA,
  com DSS e carimbo de documento) com as raízes do arquivo `ACcompactado.zip` do ITI em
  `PORTAL_SIGNING_TRUST_ROOT_FILES` (no GCP, segredo `icp-raizes-pem`; ver
  [implantacao-gcp.md](implantacao-gcp.md)), e planeje a renovação periódica de carimbos
  de arquivamento (ver [operacao.md](operacao.md)). As mesmas raízes validam as
  assinaturas dos PDFs enviados à página `/verificar`.
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

## 5. Evidência registrada em cada manifestação

Arquivo `evidencia.json` (JSON canônico), embutido no comprovante e gravado na tabela
`aceites`. Exemplo de ciência no motor nativo:

```json
{
  "versao": 2, "tipo": "manifestacao_eletronica", "natureza": "ciencia", "decisao": "ACEITO",
  "documento": {"id": "…", "titulo": "…", "tipo": "HOLERITE", "competencia": "2026-09",
                "codigo_verificacao": "ABCD-EFGH-JKLM",
                "sha256_original": "…", "sha256_apresentado": "…",
                "primeira_abertura_utc": "…", "segundos_entre_abertura_e_manifestacao": 42,
                "aberturas": [{"data_hora_utc": "…", "modo": "inline", "ip": "…", "usuario": "…"}]},
  "signatario": {"nome": "…", "matricula": "…", "cpf_mascarado": "***.456.789-**",
                 "ad": {"sAMAccountName": "…", "userPrincipalName": "…",
                        "objectGUID": "…", "dn": "…"}},
  "autenticacao": {"login": "Active Directory (LDAPS bind)", "login_em_utc": "…",
                   "confirmacao_no_ato": "senha_ad+totp",
                   "segundo_fator": {"configurado_em_utc": "…", "redefinicoes_utc": []},
                   "sessao_ref": "…"},
  "contexto": {"ip": "…", "porta_origem": "…", "user_agent": "…"},
  "termo_adesao": {"versao": "1", "sha256": "…", "canal": "portal", "registrado_por": "…",
                   "objectGUID": "…", "evidencia_sha256": "…", "aceito_em_utc": "…"},
  "manifestacao": {"declaracao": "…", "declaracao_sha256": "…", "motivo_recusa": null,
                   "data_hora_utc": "…", "data_hora_local": "…", "fuso": "America/Sao_Paulo",
                   "fonte_de_tempo": "relógio do servidor (UTC) + carimbo do tempo da ACT na assinatura"},
  "sistema": {"portal_versao": "0.1.0", "base_url": "…", "empresa": "…", "cnpj": "…",
              "certificado_selo": "…", "act_carimbo_do_tempo": "…"}
}
```

- **Divergência:** `decisao` = `RECUSADO`, `declaracao` = frase fixa ("Registro
  divergência em relação a este documento pelo motivo que descrevo abaixo.") e
  `motivo_recusa` com o texto do colaborador (mínimo 10 caracteres).
- **Segundo fator:** `segundo_fator` só é preenchido quando houve TOTP (senão é `null`).
  Traz a data do cadastro do autenticador e as redefinições feitas pelo RH.
- **Termo de adesão:** `canal` é `portal`, `papel` ou `govbr`. Na adesão pelo portal,
  `evidencia_sha256` aponta para a evidência própria do termo, embutida no comprovante
  de adesão.
- **Tudo ou nada:** o PDF com o registro e o comprovante, já selados, são gerados antes
  de qualquer gravação. Se o selo, o carimbo do tempo, o armazenamento ou o diretório
  falhar, nenhuma manifestação é registrada e o colaborador vê uma mensagem clara para
  tentar de novo. Cada documento admite uma única manifestação.

**Fluxo DocuSeal** (`tipo` = `manifestacao_eletronica_docuseal`, também versão 2):
- o link de assinatura só é criado depois que o colaborador, autenticado no portal,
  confirma senha (e TOTP, se o tipo exigir). A evidência usa o evento
  `DOCUSEAL_LINK_ABERTO` do **mesmo signatário** que concluiu e registra os fatores
  confirmados (`autenticacao.confirmacao_ao_abrir_link`: `senha_ad` ou `senha_ad+totp`),
  além de IP, navegador, sessão e termo (bloco `portal`). Conclusão sem esse vínculo não
  é aceita como manifestação (`DOCUSEAL_SEM_VINCULO_AD`);
- registra os dados do DocuSeal (ids, IP, navegador, datas), a **trilha do DocuSeal**
  (PDF e SHA-256) e o bloco `tempo` (UTC, hora local e fuso). A data/hora é a informada
  pelo DocuSeal no webhook;
- **todos** os PDFs do envio recebem o selo final do e-CNPJ. O primeiro é o documento
  principal; os demais ficam em `documento.arquivos_adicionais` e no dossiê;
- a recusa no DocuSeal registra a frase fixa "Recusei a assinatura deste documento na
  plataforma DocuSeal pelo motivo informado." e o motivo, **nunca** a declaração de
  concordância;
- se o download, o selo ou o carimbo falhar, nada é registrado e o webhook responde
  erro, para o DocuSeal reenviar;
- no DocuSeal, configure `CERTS={"enabled":false}`: o único certificado no PDF deve ser o
  selo da empresa, aplicado pelo portal.

Não se coleta geolocalização por GPS nem *fingerprint* do dispositivo, pelo princípio da
necessidade (LGPD art. 6º, III). A **porta de origem** só é registrada se o balanceador
a informar (`PORTAL_CLIENT_PORT_HEADER`). Ela é relevante para identificar usuários atrás
de CGNAT (STJ REsp 1.784.156/SP).

## 6. Preservação e conferência da prova

- **Banco somente-inclusão.** No PostgreSQL, gatilhos bloqueiam `UPDATE`, `DELETE` e
  `TRUNCATE` em `auditoria`, `aceites`, `termos_adesao_aceites` e `auditoria_ancoras`. A
  `auditoria_cabeca` só avança, e o termo publicado (`termos_adesao`) é imutável, exceto
  o campo `active`. A aplicação usa o papel `portal_app`, que não é dono das tabelas e não
  consegue remover os gatilhos. Só o job de migração usa `portal_owner` (ver
  [implantacao-gcp.md](implantacao-gcp.md)).
- **Trilha ancorada e verificada todo dia.** Cada evento carrega o SHA-256 do anterior
  ([ADR 0005](adr/0005-evidencia-e-trilha-de-auditoria.md)). Às 02:15,
  `portal anchor-audit` carimba a cabeça da cadeia na ACT. Às 02:45,
  `portal verify-audit` recalcula a cadeia inteira e confere cada âncora: o evento ancorado mantém o hash
  carimbado, o token está íntegro e o *imprint* é igual a esse hash. Uma falha gera alerta
  ("CADEIA DE AUDITORIA COM FALHA"). Graças às âncoras, nem uma cadeia reescrita de forma
  consistente passa despercebida. Eventos posteriores à última âncora (até um dia) contam
  só com o encadeamento. A tela Auditoria da Área do RH verifica de forma incremental, a
  partir da última âncora.
- **Cancelamento e retificação.** Só documentos sem manifestação (pendentes ou
  disponíveis) podem ser cancelados, com motivo. Documento com ciência, aceite ou
  divergência não é cancelado nem alterado: emita um documento retificador. O cancelado
  continua consultável em `/verificar`, como cancelado e com a data (o motivo é interno).
  O mesmo PDF só pode ser emitido de novo ao mesmo colaborador, no mesmo tipo e
  competência, depois de cancelado o anterior.
- **Verificação por terceiros.** A página `/verificar` aceita o código de verificação ou
  o upload do PDF. Ela compara o hash com os registrados e valida as assinaturas com as
  raízes ICP-Brasil configuradas.
- **Dossiê autossuficiente** (Área do RH > Documentos > Dossiê). O ZIP contém:
  - `1-original.pdf`, `2-emitido-selado.pdf`, `3-com-registro.pdf` e `4-comprovante.pdf`;
  - no DocuSeal, `5-adicional-N.pdf` (envio com vários PDFs) e `6-trilha-docuseal.pdf`;
  - `evidencia.json` e `termo/termo-vX.txt` (texto do termo referenciado);
  - `auditoria/segmento.jsonl` (segmento contínuo da cadeia, com o conteúdo exatamente
    como foi encadeado) e `auditoria/ancoras/*.tsr` (carimbos RFC 3161);
  - `manifesto.json`, `LEIA-ME.txt` e `verificar.py`.

  O `verificar.py` usa só a biblioteca padrão do Python (3.9+). Ele confere o hash de
  cada arquivo do manifesto, o encadeamento do segmento, a presença de todos os eventos do
  documento no segmento, o *imprint* das âncoras e que o segmento termina no evento
  carimbado, e sai
  com código 0 quando o resultado é ÍNTEGRO. As assinaturas PAdES e a assinatura da ACT no
  `.tsr` são validadas fora do script (Verificador do ITI; `openssl ts -verify` ou
  validador da ACT), como explica o `LEIA-ME.txt`. Assim, um perito confere a prova sem
  acesso ao sistema, o que atende ao ônus do art. 429, II, do CPC (seção 1).

## 7. Temporalidade (proposta para aprovação) ⚖️

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

Dados operacionais seguem outro prazo. Todo domingo, `portal purge --dias 180`
(mínimo 30 dias) apaga tentativas de login e sessões encerradas mais antigas que o prazo
e registra o evento `DADOS_OPERACIONAIS_EXPURGADOS`. Documentos, aceites e trilha de
auditoria nunca são expurgados por ele.

## 8. Pendências para o jurídico ⚖️

1. Texto final do **Termo de Adesão** e forma de coleta para quem já é colaborador
   (papel, gov.br ou portal).
2. Redação das declarações por tipo de documento; checar **CCT/ACT** sobre entrega e
   assinatura de holerites.
3. Quais tipos exigirão **TOTP** (recomendado para contratos e aditivos; configurável
   por tipo) ou assinatura qualificada do colaborador.
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
9. **Carimbo do tempo:** contratar ACT ICP-Brasil. Operar sem ACT
   (`PORTAL_ALLOW_NO_TSA=true`) enfraquece a prova de data e elimina a ancoragem da
   trilha. Se for o caso, registre a decisão por escrito.
