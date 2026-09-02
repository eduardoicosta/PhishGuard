# Arquitetura de Privacidade — PhishGuard 2.0

> Documento de referência para auditoria técnica e jurídica.
> Base legal: Lei 13.709/2018 (LGPD).

O PhishGuard analisa e-mails e mensagens — ou seja, opera exatamente sobre o
tipo de dado mais sensível que um usuário possui. A resposta arquitetural a esse
risco é simples de enunciar e difícil de implementar por acidente:

> **O produto nunca guarda o que o usuário escreveu ou recebeu.**

Este documento explica como essa promessa é implementada, onde ela está no
código e como um auditor pode verificá-la sem confiar na nossa palavra.

---

## 1. Onde mora cada garantia

| Garantia | Arquivo | Como verificar |
|---|---|---|
| Anonimização de PII antes da IA | `privacidade.py` | `python tests/test_conformidade_lgpd.py` |
| Retenção zero de conteúdo | `persistencia.py` | `GET /api/privacidade/auditoria` |
| Pseudonimização de titulares | `privacidade.py` (`pseudonimizar`) | Testes de escopo e estabilidade |
| Manifesto público | `privacidade.py` (`MANIFESTO_LGPD`) | `GET /api/privacidade` |
| Direito à eliminação (Art. 18) | `api.py` | `DELETE /api/privacidade/meus-dados` |
| Expurgo de dados legados | `scripts/migrar_lgpd_zero_retencao.py` | Execução manual pelo operador |

A separação em módulos é deliberada: **a conformidade é auditável em um único
lugar**. Se `persistencia.py` não escreve conteúdo, nenhum endpoint escreve —
porque nenhum outro módulo fala com o banco.

---

## 2. O fluxo de um e-mail, do DOM ao descarte

```
[1] Extensão (content.js)
      extrai assunto, corpo e remetente do DOM do Gmail/Outlook
                    │
                    ▼  (mensagem interna — nunca sai da máquina do usuário)
[2] Service worker (background.js)
      POST /analisar-email  (origem chrome-extension://, sem CORS/PNA)
                    │
                    ▼
[3] API — analisar_email()            ← o payload existe apenas nesta função
      ├── privacidade.mascarar_pii(corpo)      ← ANONIMIZAÇÃO PREVENTIVA
      ├── privacidade.mascarar_remetente()     ← remove nome de exibição
      ├── Camada 1: ensemble RF + XGBoost      ← 100% local, sem rede
      └── Camada 2: Gemini                     ← recebe SÓ o texto anonimizado
                    │
                    ├──► resposta ao usuário (veredito + explicação + selo)
                    │
                    └──► persistencia.EventoTelemetria  ← SÓ METADADOS
                              canal, veredito, score, domínio,
                              hashes, contadores, latência
[4] Fim da requisição → o corpo do e-mail é coletado pelo garbage collector.
```

O ponto crítico é o passo 3: `payload.corpo_texto` é uma variável local. Não é
logado (o logger imprime apenas metadados), não é devolvido na resposta, e o
único caminho até o disco — `EventoTelemetria` — é um dataclass cujos campos
não admitem texto livre do usuário. O teste
`test_evento_de_telemetria_nao_possui_campo_de_conteudo` falha o build se
alguém adicionar um campo como `mensagem` ou `corpo`.

---

## 3. PII Masking — o que é removido e por quê

`privacidade.REGRAS_PII` é um catálogo declarativo aplicado em ordem
significativa (regras específicas antes das genéricas, para que um cartão de
crédito não seja parcialmente consumido pela regra de telefone).

| Regra | Detecta | Vira |
|---|---|---|
| `credencial` | `senha:`, `token=`, `api_key`, OTP, PIN | `[CREDENCIAL_MASCARADA]` |
| `linha_digitavel` | boleto (44–48 dígitos) | `[LINHA_DIGITAVEL_MASCARADA]` |
| `cartao_credito` | 13–19 dígitos **validados por Luhn** | `[CARTAO_MASCARADO]` |
| `cnpj` | CNPJ com dígitos verificadores válidos | `[CNPJ_MASCARADO]` |
| `cpf` | CPF formatado, ou 11 dígitos com DV válido | `[CPF_MASCARADO]` |
| `chave_pix` | UUID de chave aleatória | `[CHAVE_PIX_MASCARADA]` |
| `pix_copia_cola` | BR Code / EMV | `[PIX_COPIA_E_COLA_MASCARADO]` |
| `conta_bancaria` | "Agência X Conta Y" | `[DADOS_BANCARIOS_MASCARADOS]` |
| `email_pessoal` | parte local do e-mail | `[USUARIO_MASCARADO]@dominio` |
| `telefone` | fixo/celular BR com ou sem DDI | `[TELEFONE_MASCARADO]` |
| `cep` | CEP formatado | `[CEP_MASCARADO]` |
| `documento` | RG, CNH, passaporte, título | `[DOCUMENTO_MASCARADO]` |
| `data_nascimento` | data precedida de marcador | `[DATA_NASCIMENTO_MASCARADA]` |

### Decisões de projeto (ADRs)

**ADR-001 — Validar antes de mascarar.**
Cartões passam por Luhn; CPF e CNPJ, pelos dígitos verificadores. Mascarar por
formato puro destruiria números de pedido e protocolos, degradando a detecção
sem ganho de privacidade. A exceção é o CPF *formatado* (`000.000.000-00`), cuja
forma já é suficientemente distintiva para mascarar sempre.

**ADR-002 — Preservar o domínio, anonimizar a pessoa.**
`joao.silva@bradesco.com.br` vira `[USUARIO_MASCARADO]@bradesco.com.br`.
O domínio é o principal sinal antifraude (spoofing, domínios sósias): removê-lo
cegaria o produto. A identidade do titular, por outro lado, não contribui para a
detecção — é excedente, e o Art. 6º, III (necessidade) manda removê-la.

**ADR-003 — O endereço do remetente é preservado.**
Sob legítimo interesse para segurança da informação (Art. 7º, IX), combinado com
o princípio da necessidade: sem o remetente não há como avaliar spoofing. O que
é descartado é o *nome de exibição* (`mascarar_remetente`), que identifica uma
pessoa natural sem valor detectivo. No banco, guarda-se apenas o **domínio**.

**ADR-004 — URLs sobrevivem.**
Links são o artefato central do phishing. Mascará-los tornaria a Camada 2 inútil.

**ADR-005 — Falha fechada.**
Se qualquer regra lançar exceção, `mascarar_pii` devolve o texto inteiro
substituído por `[DADOS_CONFIDENCIAIS]`. Preferimos perder a análise a vazar o
original.

**ADR-006 — Teto de 20.000 caracteres.**
Protege a CPU contra textos patológicos. Um e-mail de phishing raramente
depende de conteúdo além disso.

---

## 4. Pseudonimização (Art. 13, §4º)

Contas e organizações são identificadas por `HMAC-SHA256(sal, escopo:valor)`
truncado em 16 hexadecimais.

* **Irreversível sem o sal.** O sal (`PHISHGUARD_SAL_PSEUDONIMO`) mora na
  infraestrutura, fora do alcance dos painéis. Sem ele não há como reverter nem
  enumerar o valor original.
* **Escopado.** `pseudonimizar("acme", escopo="conta")` difere de
  `escopo="tenant"`, impedindo correlacionar "usuário X" com "empresa X" a
  partir dos hashes.
* **Estável.** Normaliza caixa e espaços, então o mesmo titular gera sempre o
  mesmo hash — o que viabiliza métricas sem identificar ninguém.

> **Operacional:** se o sal não estiver configurado, um valor efêmero é gerado
> por processo. A API sobe e protege normalmente, mas os hashes deixam de ser
> estáveis entre reinícios. O `/health` reporta isso em
> `sal_pseudonimizacao_configurado`.

---

## 5. O que vai (e o que não vai) para o banco

Tabela `interacoes_hub`:

**Persistido** — `canal`, `data_hora`, `risco_detectado`, `score_risco`,
`nivel_alerta`, `tipo_conta`, `tenant_hash`, `usuario_hash`,
`dominio_remetente`, `dupla_checagem`, `pii_mascarado_qtd`, `pii_tipos`,
`latencia_ms`, `origem_veredito`.

**Nunca gravado** — corpo, assunto, mensagem do usuário, resposta da IA,
endereço completo do remetente ou destinatário, anexos, URLs completas.

### Bases legadas

Versões anteriores a 2.0 gravavam `mensagem_usuario` e `resposta_bot` em texto
puro. A versão 2.0 **para de escrever nessas colunas imediatamente**, mas não as
apaga sozinha: destruir dados de produção é decisão do operador, não efeito
colateral de um deploy.

```bash
# 1. Diagnóstico (não altera nada)
python scripts/migrar_lgpd_zero_retencao.py

# 2. Anonimiza o histórico (conteúdo → NULL, metadados preservados)
python scripts/migrar_lgpd_zero_retencao.py --executar

# 3. Opcional: remove as colunas de vez (irreversível, pede confirmação)
python scripts/migrar_lgpd_zero_retencao.py --executar --remover-colunas
```

Enquanto houver conteúdo residual, `GET /api/privacidade/auditoria` retorna
`"conforme": false` e aponta a ação necessária.

---

## 6. Direitos do titular (Art. 18)

| Direito | Como é atendido |
|---|---|
| Confirmação e acesso | `GET /api/metricas/pessoal?id_conta=...` |
| Transparência | `GET /api/privacidade` (manifesto público) |
| Anonimização | Aplicada por construção, antes do processamento |
| Eliminação | `DELETE /api/privacidade/meus-dados?id_conta=...` |
| Informação sobre compartilhamento | Seção `subprocessadores` do manifesto |

Como não há conteúdo armazenado, o direito à eliminação é atendido *por
construção*: o `DELETE` remove os metadados residuais, e não havia texto a
excluir.

---

## 7. Separação B2C / B2B e minimização

A mesma telemetria alimenta dois produtos, com recortes deliberadamente
diferentes:

* **B2C — `/api/metricas/pessoal`.** Filtrado pelo hash da própria conta. Um
  titular não consegue ver dados de outro, nem por manipulação de parâmetros:
  a consulta é sempre restrita ao `usuario_hash` derivado do `id_conta` enviado.
* **B2B — `/api/metricas/corporativo`.** Visão do gestor: domínios hostis,
  exposição por colaborador, distribuição por canal. Os colaboradores aparecem
  **apenas como pseudônimos**. O gestor vê que "o colaborador `ca9a3512…` foi
  alvo de 3 ataques" e pode agir sobre o risco agregado — sem que o painel se
  torne uma ferramenta de vigilância da correspondência da equipe.

Esse recorte é a razão de o Painel SOC não exibir nenhuma mensagem: a API não a
expõe porque o banco não a possui.

---

## 8. Verificação por terceiros

```bash
# Testes de conformidade (31 asserções sobre as garantias)
python tests/test_conformidade_lgpd.py
# ou, com pytest:
python -m pytest tests -v

# Autoauditoria em tempo de execução
curl -H "X-PhishGuard-Token: $PHISHGUARD_ADMIN_TOKEN" \
     http://localhost:8000/api/privacidade/auditoria

# Manifesto público
curl http://localhost:8000/api/privacidade
```

Toda resposta da API carrega o cabeçalho `X-PhishGuard-Data-Retention: none` e
um bloco `privacidade` com a contagem de dados anonimizados naquela requisição —
o selo de transparência exibido na extensão vem exatamente daí.
