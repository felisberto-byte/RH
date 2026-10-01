# Guia do RH

## Primeiro uso

1. **Termo de Adesão** (Área do RH → *Termo de adesão*): revise o texto com o jurídico e
   publique a versão 1. Todo colaborador aceita o termo no primeiro acesso. Para quem
   assinou em papel ou pelo gov.br, registre em *Colaboradores → Termo em papel/gov.br*,
   informando onde o documento está arquivado.
2. **Colaboradores** (Área do RH → *Colaboradores → Importar*): envie um CSV
   `matricula;nome;cpf;email;ativo` (modelo em `exemplos/colaboradores.csv`). A matrícula
   precisa ser **igual** à cadastrada no AD (atributo `employeeNumber`); zeros à esquerda
   são ignorados.
3. **Tipos de documento:** confira se o texto-âncora corresponde ao que o sistema de
   folha imprime, por exemplo "Assinatura do Funcionário". O campo de aceite é criado
   logo acima desse texto. Se o texto não existir no PDF, o portal usa a posição fixa do
   tipo, que por padrão fica no canto inferior direito da última página.

## A cada folha

1. Exporte do sistema de folha **um PDF com todos os holerites**, com a matrícula escrita
   em cada página ("Matrícula: 000123"), ou **um ZIP com um PDF por colaborador**, com
   arquivos nomeados `000123_qualquercoisa.pdf`.
2. Área do RH → **Importar lote**: escolha o tipo, a competência (AAAA-MM) e o título
   que o colaborador verá, por exemplo "Holerite setembro/2026".
3. Confira o **relatório do lote**:
   - **matrícula não cadastrada:** importe o colaborador e reenvie só o PDF dele (os
     documentos já publicados não se repetem);
   - **páginas sem identificação:** a matrícula não foi encontrada no texto. O PDF pode
     ser uma imagem escaneada (sem texto) ou ter outro formato; ajuste a "expressão
     regular" nas opções avançadas.
4. Os colaboradores já veem os documentos em **Meus documentos → Pendentes**.

## Acompanhamento

- **Painel:** totais por situação e pendências mais antigas.
- **Documentos:** filtre por situação, matrícula ou competência. Pelo **Dossiê** você
  baixa um ZIP com todas as versões do PDF, a evidência, os eventos de auditoria e um
  manifesto de integridade. Use-o em fiscalizações e processos.
- **Divergência registrada:** o colaborador contestou o documento, com o motivo
  informado. Corrija, **cancele** o documento original se ainda estiver pendente, ou
  emita um documento retificador.
- **Cancelar:** só é possível para documentos sem manifestação. Documentos aceitos não
  são apagados; emita um retificador.

## Situações do dia a dia

| Situação | O que fazer |
|---|---|
| Colaborador esqueceu a senha | É a senha do computador (AD): a TI redefine. |
| Trocou de celular (autenticador) | *Colaboradores → Redefinir autenticador*, com motivo. No próximo aceite ele configura de novo. |
| Desligamento | *Colaboradores → Pacote de documentos* **antes** de a TI desativar a conta. Entregue ao ex-colaborador. |
| "Seu cadastro está vinculado a outro usuário" | Há duas contas AD com a mesma matrícula. Acione a TI. |
| Colaborador sem computador ou celular | Ofereça o atendimento presencial (o termo prevê o meio físico). |
| Fiscalização pede comprovação | Dossiê do documento e página **/verificar** (código ou upload do PDF). Validação ICP-Brasil em validar.iti.gov.br. |

## Boas práticas

- Não use contas genéricas ou compartilhadas no AD para colaboradores.
- Quem administra o AD não deve operar o portal pelo RH, e vice-versa.
- Holerite é **ciência**, não concordância com valores. O pagamento é comprovado pelo
  depósito bancário (CLT art. 464, parágrafo único).
