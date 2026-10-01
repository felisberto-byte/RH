# Guia do RH

A **Área do RH** aparece para quem está no grupo do RH no AD. Abas: Painel, Importar lote,
DocuSeal, Documentos, Colaboradores, Tipos, Termo de adesão e Auditoria. Toda ação fica na
trilha de auditoria.

## Primeiro uso

1. **Termo de Adesão** (aba *Termo de adesão*): a instalação já publica a versão 1 com um
   texto-padrão. Revise-o com o jurídico e, se mudar algo, publique a versão 2 **antes** de
   liberar o acesso. Uma versão publicada não pode ser editada: cada correção é uma nova
   versão, e todos precisam aderir de novo no próximo acesso. Para quem aderir fora do
   portal, ver [Termo de adesão em papel ou gov.br](#termo-de-adesão-em-papel-ou-govbr).
2. **Colaboradores** (*Colaboradores → Importar*): ver
   [Importar colaboradores](#importar-colaboradores-csv).
3. **Tipos de documento** (aba *Tipos*): confira cada tipo. A instalação cria `HOLERITE` e
   `INFORME_IR` como ciência (o informe não pede manifestação) e `CONTRATO` e `ADITIVO`
   como aceite.

| Campo do tipo | O que define |
|---|---|
| Declaração | Texto que o colaborador confirma. É fotografado no documento na emissão: alterá-lo não muda documentos já emitidos. Valide a redação com o jurídico ([assinatura-e-validade-juridica.md](assinatura-e-validade-juridica.md), seção 3). |
| Natureza | **Ciência** ("recebi e tomei ciência": holerite, informe, aviso) ou **Aceite** (concordância: contrato, aditivo, acordo). Muda o carimbo, o comprovante e os textos da tela. |
| Exige manifestação | Desmarcado, o documento fica só disponível para consulta. |
| Exige TOTP | Pede também o código do aplicativo autenticador no ato. Recomendado para aceites depois que os colaboradores configurarem o autenticador; quem não tiver é levado a configurá-lo antes de se manifestar. Se a TI definiu `PORTAL_ACCEPT_MFA=totp`, o código já vale para todos os tipos. |
| Texto-âncora, página e caixa | Onde o registro é carimbado (motor nativo). O campo é criado logo acima do texto-âncora, que deve ser igual ao que a folha imprime (ex.: "Assinatura do Funcionário"). Se o texto não existir no PDF, vale a caixa fixa (`x1,y1,x2,y2` em pontos), que por padrão fica no canto inferior direito da última página. |
| Motor | **Nativo** (lote de PDFs, aba *Importar lote*) ou **DocuSeal** (modelo com campos, aba *DocuSeal*; exige o id do template). |
| Retenção | Prazo de guarda do tipo, em anos. É informativo: a proteção contra exclusão vem da retenção do bucket. |
| Ativo | Tipos inativos não aparecem para emissão. |

Cada alteração registra `TIPO_DOCUMENTO_CRIADO` ou `TIPO_DOCUMENTO_ALTERADO`, com os
valores antes e depois.

## Importar colaboradores (CSV)

*Colaboradores → Importar* (ou `portal import-employees arquivo.csv`). Cabeçalho
`matricula;nome;cpf;email;ativo`, separador `;` ou `,`, UTF-8 ou Latin-1, até 10 MB
(modelo em `exemplos/colaboradores.csv`). A matrícula precisa ser **igual** à cadastrada no
AD (atributo `employeeNumber`); zeros à esquerda são ignorados.

| Coluna | Vazia ou ausente | Preenchida |
|---|---|---|
| `matricula`, `nome` | obrigatórias | o nome é sempre atualizado |
| `ativo` | novo: ativo; já cadastrado: **mantém** (nunca reativa um desligado) | `1`, `sim`, `s`, `true` ou `ativo` ativa; `0`, `nao`, `não`, `n`, `false` ou `inativo` desativa e encerra as sessões abertas |
| `cpf`, `email` | mantém o cadastrado | grava o valor; `-` limpa o campo |

O arquivo inteiro é recusado, com o número da linha, se houver matrícula ou CPF repetidos
no próprio arquivo, CPF sem 11 dígitos, CPF já usado por outra matrícula ou valor
desconhecido em `ativo`. A importação fica na auditoria (`COLABORADORES_IMPORTADOS`, com o
SHA-256 do arquivo).

Na readmissão com matrícula nova, o CPF continua no cadastro antigo. Inclua antes a
matrícula antiga com `cpf` igual a `-`, no mesmo arquivo (acima da linha nova) ou numa
importação anterior.

## A cada folha

1. Exporte do sistema de folha **um PDF com todos os holerites**, com a matrícula escrita
   em cada página ("Matrícula: 000123"), ou **um ZIP com um PDF por colaborador**, com
   arquivos nomeados `000123_qualquercoisa.pdf`.
2. Área do RH → **Importar lote**: escolha o tipo, a competência (AAAA-MM) e o título
   que o colaborador verá, por exemplo "Holerite setembro/2026".
3. Confira o **relatório do lote**:
   - **colaborador não cadastrado/ativo:** importe ou reative o colaborador e reenvie só o
     PDF dele. Reenviar o mesmo arquivo não duplica os já publicados (aparecem como
     "Documento idêntico já emitido"), mas um arquivo exportado de novo pela folha pode
     gerar documentos repetidos;
   - **páginas sem identificação:** a matrícula não foi encontrada no texto. O PDF pode
     ser uma imagem escaneada (sem texto) ou ter outro formato; ajuste a "expressão
     regular" nas opções avançadas.
4. Os colaboradores já veem os documentos em **Meus documentos → Pendentes e novos**.

## Contratos e aditivos (DocuSeal)

Para documentos com campos preenchidos no DocuSeal, como o contrato de admissão. Exige a
integração configurada pela TI e um tipo com motor DocuSeal.

1. Aba *DocuSeal*: escolha o tipo, o título e a competência (opcional) e cole as
   matrículas, separadas por espaço, vírgula ou linha.
2. O resultado lista as pendências criadas e as matrículas não encontradas ou inativas. O
   portal não impede pendências repetidas: confira a lista antes de enviar e cancele a que
   sobrar.
3. O colaborador vê a pendência em *Meus documentos*. O envio no DocuSeal só é criado
   quando ele, já logado no portal, abre o documento; nada é enviado por e-mail. Ao
   concluir, todos os PDFs recebem o selo da empresa (e-CNPJ) e o comprovante do portal.
   Uma recusa no DocuSeal é registrada como divergência, com o motivo.

## Acompanhamento

- **Painel:** totais por situação, últimos lotes, pendências mais antigas e
  **Divergências registradas pelos colaboradores** (colaborador, documento, motivo e data).
- **Documentos:** filtre por situação, matrícula ou competência (até 500, do mais recente
  para o mais antigo). A situação mostra o motivo da divergência ou do cancelamento.
- **Auditoria:** eventos recentes, carimbos do tempo diários (âncoras) e conferência da
  trilha desde a última âncora. Se aparecer "Cadeia QUEBRADA", acione a TI. A verificação
  completa roda todo dia e alerta a TI.

### Divergência

Em vez da ciência ou do aceite, o colaborador registrou a frase fixa "Registro divergência
em relação a este documento pelo motivo que descrevo abaixo." e o motivo (no DocuSeal: "Recusei
a assinatura deste documento na plataforma DocuSeal pelo motivo informado."). Isso nunca
vale como concordância. Analise o motivo e trate com o colaborador. Se procede, emita um
**documento retificador** (PDF corrigido, por novo lote ou pelo DocuSeal). O documento com
divergência não pode ser cancelado: ele é o registro da contestação.

### Cancelar e reemitir

- Só documentos **Pendente** ou **Disponível** (sem manifestação) podem ser cancelados, com
  motivo. O documento some da lista do colaborador. Em `/verificar` aparece como
  cancelado, com a data; o motivo é interno. No DocuSeal, o envio é arquivado.
- Depois de cancelar, o mesmo PDF pode ser importado de novo para o mesmo colaborador
  (reemissão). Sem cancelar, o portal recusa um PDF idêntico para o mesmo colaborador,
  tipo e competência.
- Se o colaborador se manifestar antes de o cancelamento concluir, o cancelamento é
  recusado.
- Documento com ciência, aceite ou divergência não é cancelado nem apagado: emita um
  retificador.

## Dossiê probatório

*Documentos → Dossiê* baixa um ZIP que pode ser conferido sem o portal: todas as versões do
PDF, o comprovante, a evidência (`evidencia.json`), o trecho da trilha de auditoria com os
carimbos do tempo, o texto do termo de adesão, o `manifesto.json` com o hash de cada
arquivo, o `LEIA-ME.txt` e o `verificar.py` (lista completa em
[arquitetura.md](arquitetura.md#dossiê-probatório)). Use-o em fiscalizações e processos. A
exportação fica na auditoria.

Para conferir, em qualquer computador com Python 3.9 ou superior (sem internet e sem
instalar nada), extraia o ZIP e rode na pasta:

```
python3 verificar.py
```

O script confere o hash de cada arquivo, o encadeamento da trilha e as âncoras, e termina
com `RESULTADO: ÍNTEGRO` (código de saída 0) ou `DIVERGÊNCIAS ENCONTRADAS` (1). As
assinaturas ICP-Brasil dos PDFs são validadas em validar.iti.gov.br.

- Os carimbos do tempo da trilha são diários (02:15). O dossiê inclui a trilha do
  primeiro evento do documento até o carimbo que cobre o último (a manifestação); se a
  manifestação for de hoje, o script avisa que ainda não há carimbo: exporte de novo a
  partir do dia seguinte.
- `FALHA` no script ou `"integro": false` no manifesto: acione a TI
  ([operacao.md](operacao.md#integridade-falhou)).

## Pacote do colaborador

*Colaboradores → Pacote de documentos* baixa um ZIP com a versão atual de cada documento
não cancelado, os comprovantes e um `indice.json` (título, situação, código de verificação
e hashes). Use no desligamento ou quando o colaborador pedir cópia (LGPD). Se algum
arquivo falhar na conferência de integridade, o pacote não é gerado e a TI é alertada.

## Termo de adesão em papel ou gov.br

Para quem não usa o portal, ou para reforçar a adesão de quem já era admitido.

1. Entregue o texto da **versão vigente** (aba *Termo de adesão*) para assinatura em papel
   ou pelo gov.br.
2. Arquive o original (papel, ou PDF assinado no gov.br e conferido em validar.iti.gov.br).
   O portal não guarda o arquivo.
3. *Colaboradores → Termo em papel/gov.br*: escolha o canal e informe onde o original está
   arquivado.

- O registro vale para a versão vigente e não pode ser repetido. Com ele, o colaborador
  acessa os documentos sem passar pelo termo no portal.
- O RH não registra adesão "pelo portal". Essa só o próprio colaborador faz, com a senha
  do AD, e ele baixa o comprovante selado na página do termo.
- Uma nova versão publicada exige nova adesão de todos, inclusive de quem aderiu em papel
  ou gov.br.

## Situações do dia a dia

| Situação | O que fazer |
|---|---|
| Colaborador esqueceu a senha | É a senha do computador (AD): a TI redefine. |
| "Muitas tentativas. Aguarde alguns minutos." | Senhas erradas demais na mesma conta (qualquer forma de digitar o usuário conta junto). Aguarde 15 minutos; se persistir, a TI confere bloqueio no AD. |
| Trocou ou perdeu o celular (autenticador) | Confirme a identidade pessoalmente. *Colaboradores → Redefinir autenticador*, com motivo: as sessões dele são encerradas e, na próxima manifestação que pedir o código, ele cadastra o novo celular digitando a senha do AD. |
| Não reconhece o autenticador ("configurado desde …") | Pode ser uso indevido da senha: redefina o autenticador, peça à TI a troca da senha e acione a segurança ([operacao.md](operacao.md#incidentes)). |
| Desligamento | Gere o *Pacote de documentos* e entregue ao ex-colaborador. Depois desative no CSV (`ativo` igual a `0`), o que encerra as sessões. Quando a TI desativa a conta no AD, as sessões abertas caem em até 10 minutos. |
| Readmissão com a mesma matrícula | Reative no CSV (`ativo` igual a `1`). Se a TI criou uma conta nova no AD, o login mostra "Seu cadastro está vinculado a outro usuário": confirmado com a TI que a conta nova é da pessoa, use *Colaboradores → Desvincular conta do AD*, com motivo. O próximo login cria o vínculo novo. |
| Readmissão com matrícula nova | Inclua a matrícula nova no CSV, limpando antes o CPF do cadastro antigo (`-`). Se a TI reaproveitou a conta antiga do AD, o login mostra "Sua conta do AD não corresponde ao cadastro vinculado": desvincule a conta do cadastro **antigo**. |
| "Seu cadastro está vinculado a outro usuário" fora de readmissão | Pode haver duas contas no AD com a mesma matrícula. Acione a TI e não desvincule sem confirmar. |
| "Cadastro inativo" ou "Não encontramos seu cadastro" | Reative ou importe o colaborador, ou peça à TI para corrigir a matrícula no AD. |
| Colaborador sem computador ou celular | Ofereça o atendimento presencial (o termo prevê o meio físico) e o termo em papel. |
| Fiscalização pede comprovação | Dossiê do documento e página **/verificar** (código ou upload do PDF). Validação ICP-Brasil em validar.iti.gov.br. |

## Boas práticas

- Não use contas genéricas ou compartilhadas no AD para colaboradores.
- Quem administra o AD não deve operar o portal pelo RH, e vice-versa.
- Redefina autenticador ou desvincule conta do AD só depois de confirmar a identidade da
  pessoa. O motivo informado fica na auditoria.
- Holerite é **ciência**, não concordância com valores. O pagamento é comprovado pelo
  depósito bancário (CLT art. 464, parágrafo único).
