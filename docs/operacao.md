# Operação (runbook)

Jobs, métricas e alertas são criados pelo Terraform (ver
[implantacao-gcp.md](implantacao-gcp.md#jobs)). Nos exemplos, `NOME` é `var.name` (padrão
`portal`) e a região é `southamerica-east1`. A rotina do RH na interface está no
[Guia do RH](guia-rh.md).

## Rotinas

| Frequência | Rotina | Como |
|---|---|---|
| A cada folha | Importar o lote de holerites | Área do RH → **Importar lote**, ou `portal ingest --tipo … arquivo.pdf` (automação). Confira o relatório: colaboradores não cadastrados ou inativos e páginas sem identificação **não são publicados**. |
| Diária, 02:15 | Ancorar a trilha de auditoria | Job `NOME-anchor-audit` (`portal anchor-audit`): confere a cadeia até a cabeça e carimba na ACT de `PORTAL_TSA_URL` (RFC 3161) o valor `SHA-256("portal-auditoria:<evento>:<hash>")`. O token vai para `auditoria/ancoras/` no bucket e para `auditoria_ancoras` (evento `AUDITORIA_ANCORADA`). Sem `PORTAL_TSA_URL` o job sai com 2; com `allow_no_tsa` ele falha todo dia. |
| Diária, 02:45 | Verificação completa da trilha | Job `NOME-verify-audit` (`portal verify-audit`): cadeia inteira e cada âncora (evento ancorado inalterado, token íntegro, *imprint* igual ao hash carimbado). Em falha registra `CADEIA DE AUDITORIA COM FALHA` (ERROR) e sai 1. A tela **Auditoria** do RH faz só a verificação incremental, a partir da última âncora. |
| Semanal, segunda 07:50 | Validade do e-CNPJ | Job `NOME-cert-info` (`portal cert-info --alerta-dias 45`): com menos de 45 dias registra `CERTIFICADO e-CNPJ vence` (ERROR) e sai 1. |
| Semanal, domingo 03:30 | Expurgo (LGPD) | Job `NOME-purge` (`portal purge --dias 180`, mínimo 30): apaga tentativas de login e sessões encerradas com mais de 180 dias e registra `DADOS_OPERACIONAIS_EXPURGADOS` com as quantidades. Documentos, aceites, termos e auditoria nunca são apagados. |
| A cada nova imagem | Migração do banco | Job `NOME-migrate` **antes** de atualizar o serviço e os jobs ([implantacao-gcp.md](implantacao-gcp.md#a-cada-nova-imagem)). |
| Mensal | Pendências e divergências | Área do RH → Painel: "Pendências mais antigas" e "Divergências registradas pelos colaboradores". |
| Trimestral | Teste de restauração | Ver [Backup e recuperação](#backup-e-recuperação). |
| Por evento | Desligamento, readmissão, troca de celular, termo em papel ou gov.br | [Guia do RH](guia-rh.md#situações-do-dia-a-dia). |

Para reexecutar um job (por exemplo, depois de corrigir a causa de uma falha) e ver o
resultado:

```bash
gcloud run jobs execute portal-verify-audit --region southamerica-east1 --wait
gcloud run jobs executions list --job portal-verify-audit --region southamerica-east1
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="portal-verify-audit"' --freshness 1d
```

## Alertas por e-mail

Chegam aos endereços de `alert_emails` com o título `Portal: <métrica>` (tabela em
[implantacao-gcp.md](implantacao-gcp.md#monitoramento)). `cadeia-falhou` e
`certificado-vence` saem de um job e por isso chegam junto com `job-falhou`: trate pelo
mais específico.

### `integridade-falhou`

Evento `INTEGRIDADE_FALHOU`: ao entregar um PDF ou comprovante (ao colaborador ou no
pacote do colaborador), o arquivo lido do bucket não confere com o SHA-256 do banco. A
entrega é recusada.

1. Ache o documento na linha `auditoria INTEGRIDADE_FALHOU evento=<id> documento=<id>`. O
   evento guarda a chave do objeto e o hash esperado.
2. Exporte o dossiê do documento: o `manifesto.json` marca `"integro": false` no arquivo
   divergente.
3. Liste o objeto e suas versões (`gcloud storage ls --all-versions
   gs://$(terraform output -raw documents_bucket)/documentos/<id>/`) e calcule o
   `sha256sum` de cada uma. Compare com a evidência (`evidencia.json`) e com o evento
   `DOCUMENTO_EMITIDO` da trilha. Se o objeto confere com eles, o que mudou foi o registro
   em `documentos` (banco); se não confere, foi o armazenamento.
4. Abra incidente de segurança. Não apague objetos (a retenção do bucket também impede).

### `cadeia-falhou`

O `verify-audit` encontrou um evento alterado (`hash não confere`), um evento removido
(`prev_hash não confere`), eventos truncados (`cabeça da cadeia não confere`) ou uma
âncora com problema (`não tem mais o hash carimbado`, `token alterado`, `carimbo
inválido`, `token ilegível`).

1. Leia a linha `CADEIA DE AUDITORIA COM FALHA: evento=… motivo=… ancoras=…` nos logs do
   job.
2. Só `token ilegível` pode ser falha momentânea de leitura do bucket: reexecute o job. Os
   demais motivos indicam adulteração.
3. Preserve antes de qualquer ação (`gcloud sql backups create --instance portal-pg`). Não
   tente "consertar" a cadeia.
4. Delimite o problema. A última âncora íntegra prova o histórico até o evento ancorado.
   Compare o banco com uma cópia anterior ao problema (`gcloud sql instances clone
   portal-pg portal-pg-pericia --point-in-time <data>`) e com as linhas
   `auditoria <AÇÃO> evento=<id>` do bucket de logs `NOME-auditoria`.
5. Com a credencial da aplicação, os gatilhos impedem alterar ou apagar eventos. Uma
   alteração exigiu o dono do esquema (`portal_owner`) ou um administrador do Cloud SQL:
   consulte os logs de acesso ao segredo `NOME-database-url-owner` e os do Cloud SQL.
6. Abra incidente de segurança e envolva o jurídico. Enquanto a cadeia estiver quebrada, o
   `anchor-audit` também falha, porque confere a cadeia antes de carimbar.

### `certificado-vence`

O e-CNPJ vence em menos de 45 dias. Siga a [renovação](#renovação-anual-do-e-cnpj-a1). O
alerta se repete toda segunda até a troca. Se o certificado vencer, `/readyz` responde 503
(`certificado_fora_da_validade`) e emissões, manifestações e adesões ao termo param, porque
o portal recusa selar com certificado vencido. Consultas e downloads continuam, e os
documentos já selados seguem válidos pelo carimbo do tempo.

### `job-falhou`

Log com severity ERROR ou maior de qualquer job `NOME-*`, inclusive `NOME-migrate`. Abra a
execução (comandos em [Rotinas](#rotinas)) e veja a causa:

| Job | Causas comuns | Ação |
|---|---|---|
| `anchor-audit` | ACT fora do ar ou credencial errada (`PORTAL_TSA_URL`, segredo `NOME-tsa-password`); `PORTAL_TSA_URL` vazio; cadeia inválida | Corrija e reexecute. Um dia sem âncora só alonga o intervalo coberto pela próxima. Cadeia inválida: ver [`cadeia-falhou`](#cadeia-falhou). |
| `verify-audit` | Ver [`cadeia-falhou`](#cadeia-falhou) | |
| `cert-info` | Ver [`certificado-vence`](#certificado-vence); "Certificado não configurado" (sai 2) | Confira o segredo e a variável do e-CNPJ. |
| `purge` | Banco indisponível | Reexecute. |
| `migrate` | `PORTAL_DB_APP_PASSWORD` com menos de 16 caracteres; erro do Alembic | Não atualize o serviço até a migração terminar com sucesso. |

### Indisponível (`readyz`)

O *uptime check* `NOME-readyz` falha há 10 minutos (alerta "Portal: indisponível
(readyz)"). `/healthz` só diz se o processo responde e é o *probe* do Cloud Run; `/readyz`
confere o banco e o certificado de selo. O Cloud Armor libera `GET /readyz` de qualquer
país.

```bash
curl -s https://DOMINIO/readyz
# HTTP 503: {"status":"indisponivel","falhas":["banco"]}
```

| Falha | Ação |
|---|---|
| `banco` | Veja o estado da instância `portal-pg` (manutenção, conexões, disco) e o segredo `NOME-database-url`. O log `readyz: banco indisponível` traz o erro. |
| `certificado_fora_da_validade` | e-CNPJ vencido, ou ainda não válido (versão nova do segredo com início futuro). Renove, ou desabilite a versão nova do segredo e force nova revisão (passo 4 da renovação). |
| `certificado_nao_configurado` | A revisão está sem `PORTAL_SIGNING_PFX_FILE`: confira o `run.tf`. |
| Sem resposta JSON (tempo esgotado, 403, 502, erro de TLS) | O problema está antes da aplicação: DNS, certificado gerenciado, Load Balancer, Cloud Armor ou nenhuma instância saudável. Instâncias que não sobem (senha do e-CNPJ errada, configuração de produção inválida) aparecem nos logs do serviço `NOME-web`. |

## Logs

O formato está em [arquitetura.md](arquitetura.md#logs): JSON com `severity` e `message`
(use `PORTAL_LOG_FORMAT=text` para ler localmente). Consultas úteis no Logs Explorer ou
com `gcloud logging read`:

| Para achar | Filtro |
|---|---|
| Erro informado por um usuário (código de referência da página de erro) | `jsonPayload.message:"erro inesperado ref=<código>"` (traz o `stack_trace`) |
| Eventos de um documento | `jsonPayload.message:"documento=<id>"` |
| Um tipo de evento | `jsonPayload.message:"auditoria LOGIN_FALHOU"` |
| Execuções de um job | `resource.type="cloud_run_job" AND resource.labels.job_name="portal-verify-audit"` |
| Webhooks do DocuSeal com erro | `jsonPayload.message:"webhook DocuSeal falhou"` |

A linha de auditoria traz só a ação e os ids. O evento completo está na tabela `auditoria`
e nos dossiês; a tela **Auditoria** do RH mostra os 200 mais recentes. O bucket de logs
`NOME-auditoria` guarda uma cópia dessas linhas, com retenção longa.

## Incidentes

| Sinal | Ação |
|---|---|
| Pico na métrica `login-falhou` ou colaboradores vendo "Muitas tentativas" | Possível força bruta. O portal limita por conta canônica e por IP (`PORTAL_LOGIN_MAX_FAILURES_PER_IP`, 50); ver [integracao-ad.md](integracao-ad.md#16-política-de-bloqueio). Identifique os IPs (tela Auditoria) e bloqueie no Cloud Armor (`gcloud compute security-policies rules create 900 --security-policy portal-armor --src-ip-ranges <IP>/32 --action deny-403`; regra temporária, o próximo `terraform apply` a remove). Confira bloqueios no AD. Se o NAT do escritório atingir o limite por IP, aumente-o via `extra_env`. |
| `VINCULO_AD_CONFLITO` ou `VINCULO_AD_DIVERGENTE` | Login recusado: a conta do AD não corresponde ao vínculo (objectGUID) ou à matrícula do cadastro. Confirme com a TI qual conta é da pessoa antes de agir. Readmissão e conta recriada: [Guia do RH](guia-rh.md#situações-do-dia-a-dia) e [integracao-ad.md](integracao-ad.md#15-matrícula-e-vínculo-da-conta). |
| `SESSAO_REVOGADA` | Esperado: a revalidação no AD (a cada `PORTAL_SESSION_REVALIDATE_MINUTES`, 10) encerrou a sessão por conta desabilitada ou fora do grupo, cadastro inativo ou vínculo divergente (campo `motivo`). AD indisponível não derruba sessões. Investigue só se for inesperado. |
| Colaborador não reconhece o autenticador ("configurado desde …") ou uma manifestação | Possível uso da senha por terceiro. RH: **Redefinir autenticador** (encerra as sessões). TI: troca a senha do AD. Levante na trilha `LOGIN`, `MFA_CONFIGURADO` e as manifestações do período (IP, navegador), exporte os dossiês e envolva o jurídico. |
| `DOCUSEAL_SEM_VINCULO_AD` ou `DOCUSEAL_SUBMITTER_DIVERGENTE` | Conclusão no DocuSeal sem sessão do portal ou com link antigo. Não aceite como manifestação; investigue. |
| Assinado no DocuSeal, mas pendente no portal | O webhook falhou (log `webhook DocuSeal falhou`): o portal respondeu 502 e o DocuSeal reenvia. Causas: DocuSeal inacessível para baixar os PDFs e a trilha (os downloads usam URLs assinadas, sem o token da API) ou falha no selo e-CNPJ. Corrigida a causa, o reenvio conclui. |
| Métrica `erro-inesperado` ou usuário informa um código | Busque `erro inesperado ref=<código>`. A operação que falhou não registrou nada; o usuário pode repetir. |
| Vazamento de dados pessoais | LGPD: avaliar risco e comunicar a ANPD e os titulares em **3 dias úteis** (Res. CD/ANPD 15/2024). Manter registro do incidente por 5 anos. |

## Adesão externa ao termo

O RH registra adesões coletadas fora do portal (passo a passo no
[Guia do RH](guia-rh.md#termo-de-adesão-em-papel-ou-govbr)). Controles:

- Canais aceitos: papel e gov.br. A adesão "portal" só nasce do próprio colaborador
  autenticado, com a senha do AD no ato, e gera comprovante PDF selado com o e-CNPJ (texto
  integral do termo e evidência embutidos). O RH não consegue registrá-la por ele.
- O registro vale para a versão vigente e gera `TERMO_ACEITO` com canal, versão, SHA-256
  do termo, quem registrou e onde o original está arquivado. Repetir a mesma versão é
  recusado.
- O portal não guarda o original. O papel assinado e o PDF assinado no gov.br (conferido
  em validar.iti.gov.br) ficam no arquivo da empresa, no local informado.
- No PostgreSQL o termo publicado é imutável (gatilho). Uma correção é uma nova versão,
  que exige nova adesão de todos, inclusive de quem aderiu em papel ou gov.br.

## Renovação anual do e-CNPJ A1

1. Adquira o novo A1 **antes** do vencimento (alerta `certificado-vence`). Confira titular
   e validade (`openssl pkcs12 -info -in novo.pfx -nokeys`). Se possível, exporte o
   `.pfx` com a mesma senha do atual: assim só um segredo muda.
2. Crie uma **nova versão** de `NOME-ecnpj-pfx` (`gcloud secrets versions add
   portal-ecnpj-pfx --data-file=novo.pfx`) e, se mudaram, de `NOME-ecnpj-pfx-password` e
   de `NOME-ecnpj-cadeia-pem` (com `ecnpj_chain_separate`). Faça isso em sequência:
   instâncias que subirem com o `.pfx` novo e a senha antiga não iniciam. Nunca destrua a
   versão antiga antes do corte.
3. Os jobs leem a versão `latest` a cada execução. O serviço a lê ao iniciar cada
   instância: force uma nova revisão (`gcloud run services update portal-web --region
   southamerica-east1 --update-labels ecnpj=AAAAMMDD`).
4. Confirme: `gcloud run jobs execute portal-cert-info --region southamerica-east1 --wait`
   (nova data nos logs) e `/readyz`. Emita um documento de teste e valide-o em
   `/verificar` e no Verificador do ITI. Se algo falhar, desabilite a versão nova
   (`gcloud secrets versions disable <versão> --secret portal-ecnpj-pfx`) e repita o
   passo 3.
5. Depois do corte, **desabilite** a versão antiga do segredo. Mantenha o certificado
   público antigo para validação; documentos já selados continuam válidos pelo carimbo
   do tempo.
6. Registre a troca (data, serial antigo e novo) no registro de mudanças.

Quando o ITI publicar novas raízes ou ACs, ou ao trocar de ACT, crie nova versão de
`NOME-icp-raizes-pem` e force nova revisão do mesmo modo.

> Pela Resolução CG ICP-Brasil 211/2024 o A1 será substituído pelo **Selo Eletrônico
> (SE-S/SE-H)**. A troca é de certificado e construtor do `Sealer`; ver
> [ADR 0002](adr/0002-ordem-das-assinaturas-pades.md).

## Backup e recuperação

- **Cloud SQL:** backups automáticos diários (30 retidos) e PITR de 7 dias, no Brasil.
  Teste a restauração trimestralmente. Restaure numa instância nova (`gcloud sql
  instances clone … --point-in-time`) e compare antes de trocar: manifestações posteriores
  ao ponto escolhido somem do banco, mas os PDFs e comprovantes (com a evidência
  embutida) continuam no bucket.
- **GCS:** *retention policy*, *Object Versioning* e *soft delete* de 30 dias. A conta do
  portal só cria e lê objetos, então não há sobrescrita.
- A integridade cruzada é garantida pelos hashes: após uma restauração, rode o job
  `verify-audit` e exporte alguns dossiês. O manifesto indica se cada PDF confere com o
  hash do banco.

## Roadmap

1. **Keycloak/OIDC** (ADR 0004): WebAuthn/passkeys e SSO para outras aplicações.
2. **Visualizador pdf.js empacotado**, para celulares sem leitor de PDF embutido.
3. **Notificações por e-mail** (Workspace SMTP relay) de novos documentos e de cada
   aceite. Isso reforça a prova contra alegação de documento unilateral. Atenção: contas
   Cloud Identity Free **não têm caixa de e-mail**, então use o e-mail pessoal
   cadastrado no RH.
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
9. **Buckets por classe documental**, com prazos de retenção distintos: holerites, por
   exemplo 10 anos, e contratos, por exemplo 30 anos.
