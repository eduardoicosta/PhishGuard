# PhishGuard

Plataforma de deteccao de phishing multicanal (e-mail, WhatsApp e webchat), operando como uma solucao de Security as a Service (SECaaS) com arquitetura de privacidade Zero-Retention e conformidade nativa com a Lei Geral de Protecao de Dados (Lei 13.709/2018).

O sistema combina um motor de classificacao estatistica local (Ensemble Learning) com uma camada de analise contextual via Inteligencia Artificial Generativa (Google Gemini), aplicando um mecanismo obrigatorio de anonimizacao de dados pessoais antes de qualquer processamento externo.

---

## Indice

1. [Visao Geral do Projeto e Proposta de Valor](#1-visao-geral-do-projeto-e-proposta-de-valor)
2. [Arquitetura do Sistema e Componentes](#2-arquitetura-do-sistema-e-componentes)
3. [Privacidade e Conformidade (LGPD by Design)](#3-privacidade-e-conformidade-lgpd-by-design)
4. [Estrutura do Repositorio e Modulos](#4-estrutura-do-repositorio-e-modulos)
5. [Guia de Instalacao e Configuracao de Ambiente](#5-guia-de-instalacao-e-configuracao-de-ambiente)
6. [Documentacao de Endpoints da API](#6-documentacao-de-endpoints-da-api)
7. [Testes, Migracao e Validacao](#7-testes-migracao-e-validacao)
8. [Equipe](#8-equipe)

---

## 1. Visao Geral do Projeto e Proposta de Valor

O PhishGuard nasceu como um Produto Minimo Viavel academico (Enterprise Challenge - FIAP/CLARO) e evoluiu para uma arquitetura de produto corporativo (Enterprise SaaS), estruturada para suportar auditoria tecnica, conformidade legal rigorosa e expansao comercial simultanea em dois segmentos de mercado distintos, compartilhando o mesmo motor de deteccao e a mesma infraestrutura de dados.

### 1.1. Modelo de Negocio Dual

**PhishGuard Enterprise (B2B)**
Direcionado a Security Operations Centers (SOC), gestores de Tecnologia da Informacao e Chief Information Security Officers (CISO). Entrega governanca centralizada sobre a postura de seguranca da organizacao: ranking de dominios hostis, exposicao de colaboradores a ataques (identificados por pseudonimo criptografico, nunca pelo nome), distribuicao de ameacas por canal de comunicacao e trilha de auditoria integralmente anonimizada. O acesso aos endpoints de governanca e protegido por token de autenticacao dedicado.

**PhishGuard Personal (B2C)**
Direcionado ao usuario final e ao ambiente familiar. Entrega uma experiencia de protecao individual, com metricas pessoais de e-mails analisados, historico de ameacas bloqueadas e um painel dedicado que opera de forma isolada por identificador de conta, sem qualquer visibilidade cruzada entre titulares distintos.

### 1.2. Proposta de Valor Tecnica

- **Deteccao em duas camadas independentes**, permitindo que o sistema continue operando com precisao reduzida (porem funcional) mesmo na indisponibilidade total de servicos de Inteligencia Artificial de terceiros.
- **Privacidade estrutural, nao contratual**: a garantia de nao retencao de conteudo e imposta pelo proprio contrato de dados do codigo (schema de persistencia), nao apenas por uma clausula de politica de uso.
- **Operacao hibrida em tempo real** dentro do proprio webmail do usuario (Gmail e Outlook Web), sem exigir migracao de provedor de e-mail ou instalacao de agentes de sistema operacional.
- **Canal de resposta conversacional** replicado em WhatsApp e webchat, com o mesmo padrao de anonimizacao preventiva aplicado uniformemente em todos os canais.

---

## 2. Arquitetura do Sistema e Componentes

O sistema e composto por quatro subsistemas independentes que se comunicam exclusivamente via HTTP/JSON, permitindo substituicao e escalonamento isolado de cada camada.

```
+-------------------------+      +--------------------------+      +----------------------+
|  Extensao de Navegador  | ---> |    Backend (FastAPI)      | ---> |  Camada de IA (2 nv.) |
|  Gmail / Outlook Web    |      |  Orquestracao assincrona  |      |  Estatistica + Gemini |
+-------------------------+      +--------------------------+      +----------------------+
                                            |
                                            v
                                  +--------------------------+
                                  |  Persistencia (PostgreSQL)|
                                  |  Somente metadados        |
                                  |  agregados e anonimos     |
                                  +--------------------------+
                                            |
                        +-------------------+-------------------+
                        v                                       v
              +-------------------+                   +-------------------+
              |  Painel Enterprise |                   |  Painel Personal   |
              |  (B2B / SOC)       |                   |  (B2C)             |
              +-------------------+                   +-------------------+
```

### 2.1. Extensao de Navegador (Manifest V3)

Implementada em `extensao_chrome/`, compativel com Google Chrome e Microsoft Edge (baseado em Chromium), operando sobre os dominios `mail.google.com`, `outlook.office.com`, `outlook.office365.com` e `outlook.live.com`.

A extensao e dividida em tres processos com responsabilidades estritamente segregadas:

- **`content.js` (Content Script)**: executa no contexto da pagina do webmail. Realiza a extracao estrutural do assunto, corpo e remetente do e-mail diretamente do DOM, utilizando seletores especificos e resilientes por provedor. Tambem e responsavel pela injecao visual do banner de veredito e do modal de transparencia LGPD, preservando a identidade visual corporativa (fundo `#1e293b`, borda lateral de status colorida por nivel de risco e icone de escudo em SVG). Para o Outlook, o script utiliza uma estrategia de injecao na "zona cega" do DOM (dentro do corpo da mensagem) para evitar que o motor de reconciliacao React da Microsoft remova o elemento injetado.
- **`background.js` (Service Worker)**: motivo tecnico central da arquitetura MV3 deste projeto. O navegador aplica a politica de Private Network Access (PNA), que bloqueia requisicoes originadas de uma pagina publica (`https://outlook.live.com`) contra o espaco de enderecamento de loopback (`http://localhost:8000`), mesmo com CORS liberado no servidor. Como o Service Worker executa na origem privilegiada `chrome-extension://`, ele nao esta sujeito a essa restricao nem ao bloqueio de CORS, funcionando como um proxy de confianca entre o Content Script e a API. Tambem concentra a logica de resiliencia de rede (timeout de 20 segundos, retry com backoff exponencial) e o armazenamento local de configuracao e estatisticas agregadas via `chrome.storage.local`.
- **`popup.js` / `popup.html`**: interface de configuracao da extensao, exposta ao clicar no icone da extensao na barra do navegador. Contempla tres abas: Protecao (metricas locais do usuario), Privacidade (selo de transparencia e solicitacao de eliminacao de dados) e Conta (selecao de perfil B2B/B2C e endpoint da API).

### 2.2. Backend (FastAPI)

Implementado em `api.py`, o backend e construido sobre FastAPI com operacao integralmente assincrona (`async/await`), aproveitando o modelo de concorrencia baseado em event loop para atender multiplas requisicoes de analise sem bloqueio de thread durante chamadas de rede (Gemini) ou de banco de dados.

Caracteristicas de engenharia relevantes:

- **Injecao de estado via ciclo de vida (`lifespan`)**: os modelos de Machine Learning, o cliente do Gemini e o pool de conexoes do banco de dados sao inicializados uma unica vez na subida do processo e reutilizados por todas as requisicoes, eliminando custo de inicializacao por chamada.
- **Middleware de seguranca dedicado**: alem do CORS padrao, um middleware customizado responde explicitamente aos preflights de Private Network Access exigidos pelo Chrome quando a origem publica do webmail acessa o servidor local, e aplica cabecalhos de endurecimento (`X-Content-Type-Options`, `Cache-Control: no-store`, `X-PhishGuard-Data-Retention: none`) em toda resposta.
- **Resiliencia operacional dedicada** (`resiliencia.py`): toda chamada a Camada 2 (Gemini) e envolvida por um mecanismo de tres niveis:
  - **Timeout rigido por tentativa**, garantindo que nenhuma requisicao do usuario final fique bloqueada indefinidamente aguardando o provedor externo.
  - **Retry com backoff exponencial e jitter aleatorio**, absorvendo falhas transitorias (HTTP 429, 503, reset de conexao) sem gerar tempestade de requisicoes sincronizadas contra o provedor.
  - **Circuit Breaker por rota de uso** (um circuito para o canal de e-mail, outro para o hub conversacional): apos um numero configuravel de falhas consecutivas, o circuito abre e as chamadas subsequentes falham instantaneamente para o fallback local, sem consumir o timeout completo a cada usuario. O circuito fecha automaticamente apos um periodo de recuperacao, testando a dependencia com uma chamada de sondagem.
- **Injecao de dependencias do FastAPI** aplicada na protecao dos endpoints de governanca corporativa, via `Depends(exigir_token_admin)`, validando o cabecalho `X-PhishGuard-Token` contra a variavel de ambiente `PHISHGUARD_ADMIN_TOKEN`.

### 2.3. Camada de Inteligencia Artificial (Dupla Checagem)

O veredito de phishing e produzido por um pipeline de duas camadas independentes, com fallback automatico entre elas:

**Camada 1 - Motor Estatistico (local, sincrono, sem dependencia de rede)**
Ensemble de dois classificadores complementares, treinados sobre uma representacao vetorial TF-IDF do texto do e-mail:

- **Random Forest**: reduz variancia por meio de votacao entre multiplas arvores de decisao treinadas sobre subconjuntos aleatorios de dados.
- **XGBoost**: correcao sequencial de erro via gradient boosting, com maior sensibilidade a padroes lexicais sutis de engenharia social.

O score final e a media aritmetica das probabilidades de classe positiva (`phishing`) emitidas pelos dois modelos, ponderado com uma camada de reputacao previa (Camada 0) que zera o score quando o dominio do remetente pertence a uma whitelist de dominios corporativos e institucionais verificados.

**Camada 2 - Motor Contextual (Google Gemini, via `google-genai` SDK)**
Aciona o modelo Gemini com uma instrucao de sistema especializada em analise de engenharia social e verificacao de legitimidade de dominio, recebendo exclusivamente o texto ja processado pelo modulo de anonimizacao preventiva (`privacidade.py`). A resposta e validada estruturalmente contra um schema Pydantic (`VereditoGemini`), garantindo que o veredito (`is_phishing_real`) e a explicacao textual retornada sejam sempre consumiveis de forma previsivel pelo restante do sistema.

Quando a Camada 2 esta indisponivel (circuito aberto, timeout esgotado ou chave de API ausente), o sistema degrada de forma controlada para o veredito da Camada 1, sinalizando ao usuario o nivel de alerta `ATENCAO` (analise parcial) em vez de `CRITICO` ou `SEGURO`, preservando transparencia sobre a origem da decisao.

### 2.4. Camada de Persistencia (PostgreSQL / Azure)

Implementada em `persistencia.py`, e o unico modulo do sistema com permissao de escrita no banco de dados, hospedado em Azure Database for PostgreSQL. Essa centralizacao e uma decisao arquitetural deliberada: torna a garantia de retencao zero auditavel por inspecao de um unico arquivo, em vez de exigir varredura de todo o codigo-fonte.

Caracteristicas tecnicas:

- **Pool de conexoes** (`ThreadedConnectionPool`), eliminando o custo de estabelecer uma nova conexao TCP/TLS contra o Azure a cada requisicao.
- **Escrita assincrona fora do caminho critico**: o evento de telemetria e agendado como uma tarefa assincrona apos a resposta ja ter sido montada, garantindo que uma eventual lentidao do banco de dados jamais aumente a latencia percebida pelo usuario final.
- **Degradacao graciosa**: a indisponibilidade do banco de dados desativa a telemetria e os paineis de governanca, mas nunca interrompe a analise de seguranca do usuario.
- **Contrato de dados restritivo por construcao**: o dataclass `EventoTelemetria` define exaustivamente os campos que podem ser persistidos, todos eles metadados agregados (canal, veredito, score, dominio, hashes pseudonimizados, contadores). Nao existe, em nenhum ponto do codigo, um caminho de escrita que aceite texto livre proveniente do usuario.

---

## 3. Privacidade e Conformidade (LGPD by Design)

O principio central da arquitetura de dados do PhishGuard e enunciado da seguinte forma:

> O conteudo integral de uma mensagem processada pelo sistema jamais e persistido em qualquer camada de armazenamento permanente.

Essa garantia nao e uma politica declarada em documento juridico isolado; ela e imposta estruturalmente pelo codigo, atraves de tres mecanismos concretos, implementados no modulo `privacidade.py` e reforcados por `persistencia.py`.

### 3.1. Arquitetura de Retencao Zero (Zero-Retention)

O corpo do e-mail e as mensagens trocadas no hub conversacional existem exclusivamente na memoria volatil do processo do servidor, pelo tempo estrito de execucao da requisicao HTTP que os recebeu. Ao termino da resposta, a variavel que contem o texto sai de escopo e e reclamada pelo coletor de lixo do interpretador Python; nenhuma rotina do sistema grava esse conteudo em disco, em log ou em qualquer tabela do banco de dados.

A tabela `interacoes_hub`, unica tabela de telemetria do sistema, armazena apenas: canal de origem, data e hora do evento, veredito de risco, score numerico, nivel de alerta, tipo de conta (B2B/B2C), hashes pseudonimizados de conta e organizacao, dominio do remetente (metadado tecnico, nao dado pessoal isolado), indicador de uso da dupla checagem, contagem de dados sensiveis mascarados e latencia de processamento. Colunas legadas de versoes anteriores (`mensagem_usuario`, `resposta_bot`) sao mantidas apenas para compatibilidade de schema com bases ja provisionadas, porem o sistema atual nunca escreve nelas; o expurgo desse conteudo historico e tratado no script de migracao descrito na Secao 7.

### 3.2. Modulo de PII Masking (`privacidade.py`)

Antes de qualquer texto do usuario ser enviado ao modelo Gemini (Camada 2), o sistema executa obrigatoriamente a funcao `mascarar_pii()`, que aplica um catalogo declarativo de treze regras de deteccao e substituicao de Dados Pessoais Identificaveis (PII), avaliadas em ordem de especificidade decrescente para evitar que um padrao generico consuma parcialmente um padrao mais especifico:

| Regra | Dado detectado | Validacao aplicada | Substituicao |
|---|---|---|---|
| Credencial | Senhas, tokens, chaves de API, codigos de verificacao | Marcador textual precedente (`senha:`, `token=`) | `[CREDENCIAL_MASCARADA]` |
| Linha digitavel | Boletos bancarios (44 a 48 digitos) | Comprimento numerico | `[LINHA_DIGITAVEL_MASCARADA]` |
| Cartao de credito/debito | Numeros de 13 a 19 digitos | **Algoritmo de Luhn (ISO/IEC 7812)** | `[CARTAO_MASCARADO]` |
| CNPJ | Cadastro Nacional de Pessoa Juridica | Digitos verificadores oficiais | `[CNPJ_MASCARADO]` |
| CPF | Cadastro de Pessoa Fisica | Digitos verificadores da Receita Federal | `[CPF_MASCARADO]` |
| Chave Pix aleatoria | Identificador UUID v4 | Formato RFC 4122 | `[CHAVE_PIX_MASCARADA]` |
| Pix copia-e-cola | Codigo BR Code / EMV | Prefixo de payload EMV | `[PIX_COPIA_E_COLA_MASCARADO]` |
| Dados bancarios | Agencia e conta corrente | Marcadores contextuais | `[DADOS_BANCARIOS_MASCARADOS]` |
| E-mail pessoal | Parte local do endereco de e-mail | - | `[USUARIO_MASCARADO]@dominio-preservado` |
| Telefone | Numeros brasileiros fixos e moveis | Padrao de DDD/DDI | `[TELEFONE_MASCARADO]` |
| CEP | Codigo de Enderecamento Postal | Formato numerico | `[CEP_MASCARADO]` |
| Documentos | RG, CNH, passaporte, titulo de eleitor | Marcador textual precedente | `[DOCUMENTO_MASCARADO]` |
| Data de nascimento | Data precedida de marcador contextual | Marcador textual precedente | `[DATA_NASCIMENTO_MASCARADA]` |

**Decisao tecnica intencional - preservacao de dominios**: ao contrario do endereco de e-mail completo, o dominio do remetente (por exemplo, `bradesco-seguranca.xyz`) e deliberadamente preservado apos o mascaramento. Essa preservacao e o alicerce tecnico da deteccao de spoofing e de dominios sosias: sem o dominio intacto, a Camada 2 perderia a capacidade de comparar o remetente contra a marca legitima citada no corpo da mensagem. O mesmo raciocinio se aplica a URLs completas, que sobrevivem integralmente ao processo de mascaramento por serem o artefato tecnico central de identificacao de phishing.

**Validacao por algoritmo, nao apenas por formato**: numeros de cartao sao confirmados pelo algoritmo de Luhn e CPF/CNPJ pelos respectivos digitos verificadores oficiais antes de serem mascarados, reduzindo falsos positivos que destruiriam numeros de pedido, protocolos ou codigos de rastreio sem qualquer ganho real de privacidade.

**Falha fechada por padrao**: caso qualquer regra de mascaramento produza uma excecao nao tratada durante a execucao, o sistema descarta o texto original por completo e o substitui pela tag generica `[DADOS_CONFIDENCIAIS]`, privilegiando a perda de uma analise a exposicao acidental de um dado sensivel.

### 3.3. Pseudonimizacao com Sal Criptografico

Identificadores de conta (`id_conta`) e de organizacao (`organizacao`) jamais sao persistidos em texto claro. Antes de qualquer gravacao, sao convertidos pela funcao `pseudonimizar()` em um hash `HMAC-SHA256`, calculado com um sal secreto definido pela variavel de ambiente `PHISHGUARD_SAL_PSEUDONIMO` e escopado pelo contexto de uso (`conta` ou `tenant`), impedindo correlacao cruzada entre hashes de escopos distintos gerados a partir do mesmo valor original.

Sem a posse do sal, mantido exclusivamente na infraestrutura do servidor e fora do alcance de qualquer painel ou API publica, a reversao do hash para o identificador original e computacionalmente inviavel. Essa e a base tecnica que permite ao Painel Enterprise (B2B) exibir metricas de exposicao por colaborador sem jamais revelar a identidade da pessoa ao gestor que consulta o painel.

### 3.4. Trilha de Auditoria Anonimizada e Direitos do Titular

O endpoint `GET /api/privacidade/auditoria` executa uma autoauditoria em tempo de execucao, consultando o schema real do banco de dados e retornando se ha ou nao conteudo residual nas colunas legadas, permitindo que um auditor externo verifique a conformidade sem depender de acesso direto a infraestrutura. O endpoint `DELETE /api/privacidade/meus-dados` implementa o direito de eliminacao previsto no Artigo 18, VI, da LGPD; como nenhum conteudo e armazenado, a operacao ja satisfaz o direito por construcao, restando apenas a remocao dos metadados residuais associados ao hash do titular.

A documentacao tecnica completa desta arquitetura, incluindo as decisoes de projeto registradas como ADRs (Architecture Decision Records), esta disponivel em [`docs/ARQUITETURA_LGPD.md`](docs/ARQUITETURA_LGPD.md).

---

## 4. Estrutura do Repositorio e Modulos

```text
PhishGuard/
├── api.py                          Barramento FastAPI - orquestra as camadas 0, 1 e 2
├── privacidade.py                  PII Masking, pseudonimizacao e manifesto publico de LGPD
├── persistencia.py                 Unico ponto de escrita no banco de dados (somente metadados)
├── resiliencia.py                  Timeout, retry com backoff/jitter e circuit breaker
├── diagnostico.py                  Script utilitario de validacao de conexao IMAP
│
├── extensao_chrome/                Extensao de navegador Manifest V3
│   ├── manifest.json               Declaracao de permissoes, hosts e content scripts
│   ├── background.js               Service Worker - proxy de rede resiliente e configuracao
│   ├── content.js                  Extracao de DOM, banner de veredito e modal de privacidade
│   ├── popup.html / popup.js       Interface de configuracao (Protecao / Privacidade / Conta)
│
├── painel_soc/
│   └── index.html                  Painel Enterprise (B2B) - governanca e auditoria corporativa
│
├── painel_pessoal/
│   └── index.html                  Painel Personal (B2C) - metricas individuais do titular
│
├── hub_conversacional/
│   └── simulador_whatsapp.html     Simulador do canal WhatsApp para validacao do fluxo conversacional
│
├── site_comercial/
│   └── index.html                  Landing page institucional com webchat hibrido (vendas + analise)
│
├── models/                         Artefatos binarios (.pkl) dos modelos de Machine Learning treinados
│   ├── vetorizador.pkl             Vetorizador TF-IDF
│   ├── random_forest.pkl           Modelo Random Forest treinado
│   └── xgboost.pkl                 Modelo XGBoost treinado
│
├── data/                           Datasets utilizados no treinamento dos modelos
│
├── src/                            Ecossistema desktop legado e pipeline de treinamento de ML
│   ├── config.py                   Parametrizacao global
│   ├── email_client.py             Cliente de sessao IMAP/POP3
│   ├── gui.py                      Interface grafica da aplicacao desktop
│   ├── ml_engine.py                Pipeline de treinamento e exportacao dos modelos
│   └── main.py                     Ponto de entrada da aplicacao desktop
│
├── scripts/
│   ├── gerar_dataset_ptbr.py       Geracao do dataset em portugues brasileiro
│   └── migrar_lgpd_zero_retencao.py  Diagnostico e expurgo de conteudo legado no banco de dados
│
├── tests/
│   └── test_conformidade_lgpd.py   Suite de testes que valida as garantias de privacidade como codigo
│
├── docs/
│   └── ARQUITETURA_LGPD.md         Documento de referencia tecnica para auditoria de privacidade
│
├── .env.example                    Modelo de variaveis de ambiente, sem segredos reais
├── .env                            Variaveis de ambiente reais (nao versionado)
├── .gitignore                      Exclusoes de controle de versao
└── requirements.txt                Dependencias Python do projeto
```

### 4.1. Descricao Funcional dos Modulos Centrais

**`api.py`**
Ponto de entrada da aplicacao FastAPI. Define os contratos de entrada e saida via modelos Pydantic, orquestra a chamada sequencial das camadas de deteccao, aplica o middleware de seguranca de rede e expoe a totalidade dos endpoints REST consumidos pela extensao, pelos paineis e pelo hub conversacional.

**`privacidade.py`**
Modulo autocontido, sem dependencia de rede ou de banco de dados, responsavel por toda a logica de anonimizacao preventiva, validacao de dados sensiveis (Luhn, digitos verificadores de CPF/CNPJ) e pseudonimizacao criptografica. Tambem centraliza o manifesto publico de transparencia (`MANIFESTO_LGPD`), consumido pela extensao e pelos paineis.

**`persistencia.py`**
Camada de acesso a dados isolada, responsavel pelo pool de conexoes, pela definicao idempotente do schema e por todas as consultas agregadas consumidas pelos dois paineis (resumo estatistico, serie temporal, ranking de dominios sob risco, colaboradores em risco e distribuicao por canal).

**`resiliencia.py`**
Utilitario generico de resiliencia, desacoplado do dominio de negocio do PhishGuard, reaproveitavel para qualquer chamada assincrona a uma dependencia externa instavel.

---

## 5. Guia de Instalacao e Configuracao de Ambiente

### 5.1. Requisitos Previos

- Python 3.11 ou superior.
- Instancia de PostgreSQL acessivel (recomendado: Azure Database for PostgreSQL); a ausencia dessa dependencia nao impede a subida do servidor, apenas desativa a telemetria e os paineis de governanca.
- Chave de API valida do Google Gemini (Google AI Studio ou Google Cloud), para habilitar a Camada 2 de analise contextual.
- Navegador baseado em Chromium (Google Chrome ou Microsoft Edge) para instalacao da extensao.

### 5.2. Criacao do Ambiente Virtual

```bash
python -m venv venv
```

Ativacao no Windows (PowerShell):

```bash
.\venv\Scripts\Activate.ps1
```

Ativacao no Linux ou macOS:

```bash
source venv/bin/activate
```

### 5.3. Instalacao de Dependencias

```bash
pip install -r requirements.txt
```

### 5.4. Configuracao das Variaveis de Ambiente

O arquivo `.env.example` documenta a totalidade das variaveis suportadas pelo sistema. Copie-o para `.env` e preencha os valores reais:

```bash
cp .env.example .env
```

| Variavel | Obrigatoriedade | Efeito quando ausente |
|---|---|---|
| `GEMINI_API_KEY` | Recomendada | A Camada 2 e desativada; o sistema opera apenas com a Camada 1 |
| `DATABASE_URL` | Recomendada | Telemetria e paineis desativados; a analise de seguranca continua ativa |
| `PHISHGUARD_SAL_PSEUDONIMO` | Recomendada em producao | Um sal efemero e gerado por processo; os hashes de conta perdem estabilidade entre reinicios do servidor |
| `PHISHGUARD_DPO_CONTATO` | Opcional | Endereco de contato exibido no manifesto publico de privacidade |
| `PHISHGUARD_ADMIN_TOKEN` | Recomendada em producao | Os endpoints de governanca corporativa (B2B) ficam abertos sem autenticacao, aceitavel apenas em ambiente de desenvolvimento |
| `PHISHGUARD_LIMIAR_CAMADA_1` | Opcional | Assume o valor padrao `0.35` |
| `PHISHGUARD_GEMINI_MODEL` | Opcional | Assume o modelo padrao configurado no codigo |
| `PHISHGUARD_GEMINI_TIMEOUT` | Opcional | Assume `12` segundos |
| `PHISHGUARD_GEMINI_TENTATIVAS` | Opcional | Assume `2` tentativas |
| `PHISHGUARD_DB_POOL_MIN` / `PHISHGUARD_DB_POOL_MAX` | Opcional | Assumem `1` e `8`, respectivamente |
| `PHISHGUARD_CORS_ORIGENS` | Opcional | Origens adicionais liberadas no CORS, alem das ja aceitas por padrao |
| `PHISHGUARD_LOG_LEVEL` | Opcional | Assume `INFO` |

Geracao de um sal criptografico forte para producao:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5.5. Inicializacao do Servidor (Uvicorn)

```bash
python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```

A flag `--reload` deve ser omitida em ambiente de producao. Apos a subida do processo:

- Verificacao de prontidao e estado das camadas: `http://localhost:8000/health`
- Documentacao interativa (Swagger UI, gerada automaticamente pelo FastAPI): `http://localhost:8000/docs`

### 5.6. Instalacao da Extensao em Modo Desenvolvedor

1. No navegador, acesse `chrome://extensions` (Chrome) ou `edge://extensions` (Edge).
2. Ative a opcao **Modo do desenvolvedor**, localizada no canto superior direito da pagina.
3. Selecione **Carregar sem compactacao** (*Load unpacked*).
4. Aponte para o diretorio `extensao_chrome/` deste repositorio.
5. Abra o popup da extensao clicando em seu icone na barra de ferramentas, acesse a aba **Conta**, selecione o perfil desejado (Personal ou Enterprise) e confirme o endereco do endpoint da API.
6. Abra qualquer e-mail no Gmail ou no Outlook Web: o banner de veredito sera injetado automaticamente acima do corpo da mensagem.

### 5.7. Execucao dos Paineis Front-end

Os paineis realizam chamadas `fetch` a API e, por restricao de seguranca do navegador, nao podem ser abertos diretamente via protocolo `file://`. Sirva o diretorio raiz por HTTP:

```bash
python -m http.server 5500
```

- Painel Enterprise (B2B): `http://localhost:5500/painel_soc/index.html`
- Painel Personal (B2C): `http://localhost:5500/painel_pessoal/index.html`
- Simulador WhatsApp: `http://localhost:5500/hub_conversacional/simulador_whatsapp.html`
- Site comercial: `http://localhost:5500/site_comercial/index.html`

---

## 6. Documentacao de Endpoints da API

Todos os endpoints retornam JSON codificado em UTF-8 com preservacao integral de acentuacao (`ensure_ascii=False`) e carregam o cabecalho `X-PhishGuard-Data-Retention: none` em toda resposta.

### `POST /analisar-email`

Endpoint principal consumido pela extensao de navegador. Realiza a analise stateless de um e-mail: aplica a anonimizacao preventiva sobre o assunto e o corpo, calcula o score estatistico da Camada 1 e, quando disponivel, consulta a Camada 2 (Gemini) com o texto ja mascarado.

**Corpo da requisicao:**

```json
{
  "assunto": "Sua conta sera bloqueada em 24h",
  "corpo_texto": "Confirme seu CPF e senha em http://exemplo-suspeito.xyz",
  "remetente": "Seguranca <alerta@exemplo-suspeito.xyz>",
  "perfil": "B2C",
  "id_conta": "usuario@dominio.com",
  "organizacao": null
}
```

**Resposta:**

```json
{
  "score_risco": 0.81,
  "is_phishing": true,
  "nivel_alerta": "CRITICO",
  "explicacao": "O dominio do remetente nao pertence aos canais oficiais...",
  "veredito_gemini": true,
  "dupla_checagem": true,
  "origem_veredito": "camada_2",
  "latencia_ms": 1594,
  "privacidade": {
    "versao_politica": "2026.09",
    "retencao_conteudo": "nenhuma",
    "processamento": "memoria_volatil",
    "anonimizacao_antes_da_ia": true,
    "dados_sensiveis_mascarados": 2,
    "tipos_mascarados": ["cpf", "credencial"]
  }
}
```

O corpo do e-mail enviado nesta requisicao nunca e persistido; apenas os metadados agregados do resultado sao gravados de forma assincrona apos a resposta ser retornada ao cliente.

### `POST /webhook/whatsapp`

Endpoint do hub conversacional para o canal WhatsApp. Recebe uma mensagem de texto livre, aplica a mesma rotina de anonimizacao preventiva e retorna um veredito formatado para exibicao em interface de chat, incluindo emojis e marcacao de negrito compativel com o padrao do WhatsApp.

**Corpo da requisicao:**

```json
{
  "mensagem": "Voce foi sorteado! Envie seu CPF para resgatar o premio.",
  "perfil": "B2C",
  "id_conta": "usuario@dominio.com"
}
```

### `POST /webhook/webchat`

Endpoint do hub conversacional para o canal webchat, hospedado no site comercial. Opera em modo hibrido: responde tanto a perguntas comerciais sobre os planos do produto quanto a solicitacoes de analise de risco, alternando de forma dinamica entre os dois papeis conforme o conteudo da mensagem recebida. A classificacao de ameaca exige a presenca de um artefato tecnico analisavel (URL ou dominio) na mensagem original, evitando que perguntas hipoteticas sobre golpes ("isso e phishing?") sejam contabilizadas como ameacas efetivamente bloqueadas nas metricas de governanca.

### `GET /api/logs-soc`

Retorna a trilha de auditoria anonimizada mais recente, limitada por parametro de consulta (`limite`, padrao 50, maximo 500). Protegido por token de administracao quando `PHISHGUARD_ADMIN_TOKEN` esta definido. Nenhum campo de conteudo e retornado; a estrutura da resposta contem exclusivamente os metadados definidos no contrato `EventoTelemetria`.

### `GET /api/privacidade`

Endpoint publico, sem autenticacao, que expoe o manifesto de transparencia (`MANIFESTO_LGPD`): versao vigente da politica, garantias declaradas, bases legais aplicaveis, lista explicita de dados persistidos e de dados nunca persistidos, subprocessadores envolvidos (Google Gemini e Azure Database for PostgreSQL) e contato do encarregado de dados (DPO). Consumido pela extensao e pelos paineis para renderizacao do selo de transparencia.

### Endpoints complementares

| Metodo | Rota | Descricao |
|---|---|---|
| `GET` | `/api/metricas/pessoal` | Metricas agregadas do titular, filtradas pelo hash da propria conta (B2C) |
| `GET` | `/api/metricas/corporativo` | Governanca da organizacao: ranking de dominios, colaboradores em risco, series temporais (B2B, protegido) |
| `GET` | `/api/privacidade/auditoria` | Autoauditoria de retencao em tempo de execucao (protegido) |
| `DELETE` | `/api/privacidade/meus-dados` | Execucao do direito de eliminacao previsto no Artigo 18, VI, da LGPD |
| `GET` | `/health` | Prontidao do servico, estado das camadas de IA e diagnostico dos circuit breakers |

---

## 7. Testes, Migracao e Validacao

### 7.1. Suite de Testes de Conformidade LGPD

O arquivo `tests/test_conformidade_lgpd.py` implementa a conformidade de privacidade como codigo executavel: cada garantia declarada na Secao 3 deste documento corresponde a uma ou mais asserções automatizadas, cobrindo deteccao de PII por categoria, estabilidade e irreversibilidade da pseudonimizacao, e ausencia estrutural de campos de conteudo no contrato de persistencia.

Execucao via `pytest`:

```bash
python -m pytest tests -v
```

Execucao direta, sem dependencia de `pytest` instalado:

```bash
python tests/test_conformidade_lgpd.py
```

### 7.2. Migracao e Expurgo de Dados Legados

Instalacoes provisionadas a partir de versoes anteriores do PhishGuard podem conter registros historicos com conteudo de mensagem armazenado em texto puro nas colunas legadas `mensagem_usuario` e `resposta_bot`. O sistema atual interrompe imediatamente qualquer escrita nessas colunas, porem a remocao do historico existente e tratada como uma decisao explicita do operador da infraestrutura, nunca como efeito colateral automatico de uma atualizacao de versao.

O script `scripts/migrar_lgpd_zero_retencao.py` opera em tres modos progressivos:

**Modo de diagnostico (padrao, nao destrutivo):**

```bash
python scripts/migrar_lgpd_zero_retencao.py
```

Reporta a quantidade de registros totais, as colunas legadas presentes no schema e a quantidade de valores de conteudo ainda residentes no banco de dados.

**Modo de execucao (anonimizacao do historico):**

```bash
python scripts/migrar_lgpd_zero_retencao.py --executar
```

Sobrescreve com `NULL` o conteudo das colunas legadas, preservando integralmente os metadados historicos (canal, veredito, data e hora) para fins de continuidade estatistica dos paineis.

**Modo de execucao com remocao estrutural (irreversivel):**

```bash
python scripts/migrar_lgpd_zero_retencao.py --executar --remover-colunas
```

Apos a anonimizacao, executa a remocao definitiva (`DROP COLUMN`) das colunas legadas, tornando a garantia de retencao zero uma propriedade do proprio schema do banco de dados, impossivel de ser violada por um erro futuro de codigo. Esta operacao exige confirmacao explicita digitada pelo operador no momento da execucao.

### 7.3. Verificacao de Conformidade em Tempo de Execucao

Alem da suite de testes estatica, o sistema expoe uma rotina de autoauditoria acessivel via API, permitindo que um auditor externo, sem acesso direto a infraestrutura, confirme a ausencia de conteudo residual:

```bash
curl -H "X-PhishGuard-Token: SEU_TOKEN_DE_GOVERNANCA" \
     http://localhost:8000/api/privacidade/auditoria
```

---

## 8. Equipe

**Startup One**

* Arthur Dias da Silva Biancchi - RM 99162
* Eduardo Costa Nascimento dos Anjos - RM 552519
* Enzo Puerta Meschini - RM 550807

Curso de Sistemas de Informacao - FIAP (2026)

---

## Stack Tecnologica

| Camada | Tecnologia |
|---|---|
| Linguagem principal | Python 3.11 |
| Framework de API | FastAPI (assincrono) sobre Uvicorn |
| Machine Learning | Scikit-Learn (Random Forest), XGBoost, Pandas, NumPy |
| Inteligencia Artificial Generativa | Google Gemini, via SDK `google-genai` |
| Banco de dados | PostgreSQL (Azure Database for PostgreSQL) |
| Extensao de navegador | Chrome Manifest V3 (Service Worker e Content Script) |
| Front-end dos paineis | HTML, CSS e JavaScript nativos, sem dependencia de build ou framework |
