# PhishGuard

Plataforma de detecção de phishing multicanal (e-mail, WhatsApp e webchat), operando como uma solução de Security as a Service (SECaaS) com arquitetura de privacidade Zero-Retention e conformidade nativa com a Lei Geral de Proteção de Dados (Lei 13.709/2018).

O sistema combina um motor de classificação estatística local (Ensemble Learning) com uma camada de análise contextual via Inteligência Artificial Generativa (Google Gemini), aplicando um mecanismo obrigatório de anonimização de dados pessoais antes de qualquer processamento externo.

---

## Índice

1. [Visão Geral do Projeto e Proposta de Valor](#1-visão-geral-do-projeto-e-proposta-de-valor)
2. [Arquitetura do Sistema e Componentes](#2-arquitetura-do-sistema-e-componentes)
3. [Privacidade e Conformidade (LGPD by Design)](#3-privacidade-e-conformidade-lgpd-by-design)
4. [Estrutura do Repositório e Módulos](#4-estrutura-do-repositório-e-módulos)
5. [Guia de Instalação e Configuração de Ambiente](#5-guia-de-instalação-e-configuração-de-ambiente)
6. [Documentação de Endpoints da API](#6-documentação-de-endpoints-da-api)
7. [Testes, Migração e Validação](#7-testes-migração-e-validação)
8. [Equipe](#8-equipe)

---

## 1. Visão Geral do Projeto e Proposta de Valor

O PhishGuard nasceu como um Produto Mínimo Viável acadêmico (Enterprise Challenge - FIAP/CLARO) e evoluiu para uma arquitetura de produto corporativo (Enterprise SaaS), estruturada para suportar auditoria técnica, conformidade legal rigorosa e expansão comercial simultânea em dois segmentos de mercado distintos, compartilhando o mesmo motor de detecção e a mesma infraestrutura de dados.

### 1.1. Modelo de Negócio Dual

**PhishGuard Enterprise (B2B)**
Direcionado a Security Operations Centers (SOC), gestores de Tecnologia da Informação e Chief Information Security Officers (CISO). Entrega governança centralizada sobre a postura de segurança da organização: ranking de domínios hostis, exposição de colaboradores a ataques (identificados por pseudônimo criptográfico, nunca pelo nome), distribuição de ameaças por canal de comunicação e trilha de auditoria integralmente anonimizada. O acesso aos endpoints de governança é protegido por token de autenticação dedicado.

**PhishGuard Personal (B2C)**
Direcionado ao usuário final e ao ambiente familiar. Entrega uma experiência de proteção individual, com métricas pessoais de e-mails analisados, histórico de ameaças bloqueadas e um painel dedicado que opera de forma isolada por identificador de conta, sem qualquer visibilidade cruzada entre titulares distintos.

### 1.2. Proposta de Valor Técnica

- **Detecção em duas camadas independentes**, permitindo que o sistema continue operando com precisão reduzida (porém funcional) mesmo na indisponibilidade total de serviços de Inteligência Artificial de terceiros.
- **Privacidade estrutural, não contratual**: a garantia de não retenção de conteúdo é imposta pelo próprio contrato de dados do código (schema de persistência), não apenas por uma cláusula de política de uso.
- **Operação híbrida em tempo real** dentro do próprio webmail do usuário (Gmail e Outlook Web), sem exigir migração de provedor de e-mail ou instalação de agentes de sistema operacional.
- **Canal de resposta conversacional** replicado em WhatsApp e webchat, com o mesmo padrão de anonimização preventiva aplicado uniformemente em todos os canais.

---

## 2. Arquitetura do Sistema e Componentes

O sistema é composto por quatro subsistemas independentes que se comunicam exclusivamente via HTTP/JSON, permitindo substituição e escalonamento isolado de cada camada.

```
+-------------------------+      +--------------------------+      +----------------------+
|  Extensão de Navegador  | ---> |    Backend (FastAPI)      | ---> |  Camada de IA (2 nv.) |
|  Gmail / Outlook Web    |      |  Orquestração assíncrona  |      |  Estatística + Gemini |
+-------------------------+      +--------------------------+      +----------------------+
                                            |
                                            v
                                  +--------------------------+
                                  |  Persistência (PostgreSQL)|
                                  |  Somente metadados        |
                                  |  agregados e anônimos     |
                                  +--------------------------+
                                            |
                        +-------------------+-------------------+
                        v                                       v
              +-------------------+                   +-------------------+
              |  Painel Enterprise |                   |  Painel Personal   |
              |  (B2B / SOC)       |                   |  (B2C)             |
              +-------------------+                   +-------------------+
```

### 2.1. Extensão de Navegador (Manifest V3)

Implementada em `extensao_chrome/`, compatível com Google Chrome e Microsoft Edge (baseado em Chromium), operando sobre os domínios `mail.google.com`, `outlook.office.com`, `outlook.office365.com` e `outlook.live.com`.

A extensão é dividida em três processos com responsabilidades estritamente segregadas:

- **`content.js` (Content Script)**: executa no contexto da página do webmail. Realiza a extração estrutural do assunto, corpo e remetente do e-mail diretamente do DOM, utilizando seletores específicos e resilientes por provedor. Também é responsável pela injeção visual do banner de veredito e do modal de transparência LGPD, preservando a identidade visual corporativa (fundo `#1e293b`, borda lateral de status colorida por nível de risco e ícone de escudo em SVG). Para o Outlook, o script utiliza uma estratégia de injeção na "zona cega" do DOM (dentro do corpo da mensagem) para evitar que o motor de reconciliação React da Microsoft remova o elemento injetado.
- **`background.js` (Service Worker)**: motivo técnico central da arquitetura MV3 deste projeto. O navegador aplica a política de Private Network Access (PNA), que bloqueia requisições originadas de uma página pública (`https://outlook.live.com`) contra o espaço de endereçamento de loopback (`http://localhost:8000`), mesmo com CORS liberado no servidor. Como o Service Worker executa na origem privilegiada `chrome-extension://`, ele não está sujeito a essa restrição nem ao bloqueio de CORS, funcionando como um proxy de confiança entre o Content Script e a API. Também concentra a lógica de resiliência de rede (timeout de 20 segundos, retry com backoff exponencial) e o armazenamento local de configuração e estatísticas agregadas via `chrome.storage.local`.
- **`popup.js` / `popup.html`**: interface de configuração da extensão, exposta ao clicar no ícone da extensão na barra do navegador. Contempla três abas: Proteção (métricas locais do usuário), Privacidade (selo de transparência e solicitação de eliminação de dados) e Conta (seleção de perfil B2B/B2C e endpoint da API).

### 2.2. Backend (FastAPI)

Implementado em `api.py`, o backend é construído sobre FastAPI com operação integralmente assíncrona (`async/await`), aproveitando o modelo de concorrência baseado em event loop para atender múltiplas requisições de análise sem bloqueio de thread durante chamadas de rede (Gemini) ou de banco de dados.

Características de engenharia relevantes:

- **Injeção de estado via ciclo de vida (`lifespan`)**: os modelos de Machine Learning, o cliente do Gemini e o pool de conexões do banco de dados são inicializados uma única vez na subida do processo e reutilizados por todas as requisições, eliminando custo de inicialização por chamada.
- **Middleware de segurança dedicado**: além do CORS padrão, um middleware customizado responde explicitamente aos preflights de Private Network Access exigidos pelo Chrome quando a origem pública do webmail acessa o servidor local, e aplica cabeçalhos de endurecimento (`X-Content-Type-Options`, `Cache-Control: no-store`, `X-PhishGuard-Data-Retention: none`) em toda resposta.
- **Resiliência operacional dedicada** (`resiliencia.py`): toda chamada à Camada 2 (Gemini) é envolvida por um mecanismo de três níveis:
  - **Timeout rígido por tentativa**, garantindo que nenhuma requisição do usuário final fique bloqueada indefinidamente aguardando o provedor externo.
  - **Retry com backoff exponencial e jitter aleatório**, absorvendo falhas transitórias (HTTP 429, 503, reset de conexão) sem gerar tempestade de requisições sincronizadas contra o provedor.
  - **Circuit Breaker por rota de uso** (um circuito para o canal de e-mail, outro para o hub conversacional): após um número configurável de falhas consecutivas, o circuito abre e as chamadas subsequentes falham instantaneamente para o fallback local, sem consumir o timeout completo a cada usuário. O circuito fecha automaticamente após um período de recuperação, testando a dependência com uma chamada de sondagem.
- **Injeção de dependências do FastAPI** aplicada na proteção dos endpoints de governança corporativa, via `Depends(exigir_token_admin)`, validando o cabeçalho `X-PhishGuard-Token` contra a variável de ambiente `PHISHGUARD_ADMIN_TOKEN`.

### 2.3. Camada de Inteligência Artificial (Dupla Checagem)

O veredito de phishing é produzido por um pipeline de duas camadas independentes, com fallback automático entre elas:

**Camada 1 - Motor Estatístico (local, síncrono, sem dependência de rede)**
Ensemble de dois classificadores complementares, treinados sobre uma representação vetorial TF-IDF do texto do e-mail:

- **Random Forest**: reduz variância por meio de votação entre múltiplas árvores de decisão treinadas sobre subconjuntos aleatórios de dados.
- **XGBoost**: correção sequencial de erro via gradient boosting, com maior sensibilidade a padrões lexicais sutis de engenharia social.

O score final é a média aritmética das probabilidades de classe positiva (`phishing`) emitidas pelos dois modelos, ponderado com uma camada de reputação prévia (Camada 0) que zera o score quando o domínio do remetente pertence a uma whitelist de domínios corporativos e institucionais verificados.

**Camada 2 - Motor Contextual (Google Gemini, via `google-genai` SDK)**
Aciona o modelo Gemini com uma instrução de sistema especializada em análise de engenharia social e verificação de legitimidade de domínio, recebendo exclusivamente o texto já processado pelo módulo de anonimização preventiva (`privacidade.py`). A resposta é validada estruturalmente contra um schema Pydantic (`VereditoGemini`), garantindo que o veredito (`is_phishing_real`) e a explicação textual retornada sejam sempre consumíveis de forma previsível pelo restante do sistema.

Quando a Camada 2 está indisponível (circuito aberto, timeout esgotado ou chave de API ausente), o sistema degrada de forma controlada para o veredito da Camada 1, sinalizando ao usuário o nível de alerta `ATENÇÃO` (análise parcial) em vez de `CRÍTICO` ou `SEGURO`, preservando transparência sobre a origem da decisão.

### 2.4. Camada de Persistência (PostgreSQL / Azure)

Implementada em `persistencia.py`, é o único módulo do sistema com permissão de escrita no banco de dados, hospedado em Azure Database for PostgreSQL. Essa centralização é uma decisão arquitetural deliberada: torna a garantia de retenção zero auditável por inspeção de um único arquivo, em vez de exigir varredura de todo o código-fonte.

Características técnicas:

- **Pool de conexões** (`ThreadedConnectionPool`), eliminando o custo de estabelecer uma nova conexão TCP/TLS contra o Azure a cada requisição.
- **Escrita assíncrona fora do caminho crítico**: o evento de telemetria é agendado como uma tarefa assíncrona após a resposta já ter sido montada, garantindo que uma eventual lentidão do banco de dados jamais aumente a latência percebida pelo usuário final.
- **Degradação graciosa**: a indisponibilidade do banco de dados desativa a telemetria e os painéis de governança, mas nunca interrompe a análise de segurança do usuário.
- **Contrato de dados restritivo por construção**: o dataclass `EventoTelemetria` define exaustivamente os campos que podem ser persistidos, todos eles metadados agregados (canal, veredito, score, domínio, hashes pseudonimizados, contadores). Não existe, em nenhum ponto do código, um caminho de escrita que aceite texto livre proveniente do usuário.

---

## 3. Privacidade e Conformidade (LGPD by Design)

O princípio central da arquitetura de dados do PhishGuard é enunciado da seguinte forma:

> O conteúdo integral de uma mensagem processada pelo sistema jamais é persistido em qualquer camada de armazenamento permanente.

Essa garantia não é uma política declarada em documento jurídico isolado; ela é imposta estruturalmente pelo código, através de três mecanismos concretos, implementados no módulo `privacidade.py` e reforçados por `persistencia.py`.

### 3.1. Arquitetura de Retenção Zero (Zero-Retention)

O corpo do e-mail e as mensagens trocadas no hub conversacional existem exclusivamente na memória volátil do processo do servidor, pelo tempo estrito de execução da requisição HTTP que os recebeu. Ao término da resposta, a variável que contém o texto sai de escopo e é reclamada pelo coletor de lixo do interpretador Python; nenhuma rotina do sistema grava esse conteúdo em disco, em log ou em qualquer tabela do banco de dados.

A tabela `interacoes_hub`, única tabela de telemetria do sistema, armazena apenas: canal de origem, data e hora do evento, veredito de risco, score numérico, nível de alerta, tipo de conta (B2B/B2C), hashes pseudonimizados de conta e organização, domínio do remetente (metadado técnico, não dado pessoal isolado), indicador de uso da dupla checagem, contagem de dados sensíveis mascarados e latência de processamento. Colunas legadas de versões anteriores (`mensagem_usuario`, `resposta_bot`) são mantidas apenas para compatibilidade de schema com bases já provisionadas, porém o sistema atual nunca escreve nelas; o expurgo desse conteúdo histórico é tratado no script de migração descrito na Seção 7.

### 3.2. Módulo de PII Masking (`privacidade.py`)

Antes de qualquer texto do usuário ser enviado ao modelo Gemini (Camada 2), o sistema executa obrigatoriamente a função `mascarar_pii()`, que aplica um catálogo declarativo de treze regras de detecção e substituição de Dados Pessoais Identificáveis (PII), avaliadas em ordem de especificidade decrescente para evitar que um padrão genérico consuma parcialmente um padrão mais específico:

| Regra | Dado detectado | Validação aplicada | Substituição |
|---|---|---|---|
| Credencial | Senhas, tokens, chaves de API, códigos de verificação | Marcador textual precedente (`senha:`, `token=`) | `[CREDENCIAL_MASCARADA]` |
| Linha digitável | Boletos bancários (44 a 48 dígitos) | Comprimento numérico | `[LINHA_DIGITAVEL_MASCARADA]` |
| Cartão de crédito/débito | Números de 13 a 19 dígitos | **Algoritmo de Luhn (ISO/IEC 7812)** | `[CARTAO_MASCARADO]` |
| CNPJ | Cadastro Nacional de Pessoa Jurídica | Dígitos verificadores oficiais | `[CNPJ_MASCARADO]` |
| CPF | Cadastro de Pessoa Física | Dígitos verificadores da Receita Federal | `[CPF_MASCARADO]` |
| Chave Pix aleatória | Identificador UUID v4 | Formato RFC 4122 | `[CHAVE_PIX_MASCARADA]` |
| Pix copia-e-cola | Código BR Code / EMV | Prefixo de payload EMV | `[PIX_COPIA_E_COLA_MASCARADO]` |
| Dados bancários | Agência e conta corrente | Marcadores contextuais | `[DADOS_BANCARIOS_MASCARADOS]` |
| E-mail pessoal | Parte local do endereço de e-mail | - | `[USUARIO_MASCARADO]@dominio-preservado` |
| Telefone | Números brasileiros fixos e móveis | Padrão de DDD/DDI | `[TELEFONE_MASCARADO]` |
| CEP | Código de Endereçamento Postal | Formato numérico | `[CEP_MASCARADO]` |
| Documentos | RG, CNH, passaporte, título de eleitor | Marcador textual precedente | `[DOCUMENTO_MASCARADO]` |
| Data de nascimento | Data precedida de marcador contextual | Marcador textual precedente | `[DATA_NASCIMENTO_MASCARADA]` |

**Decisão técnica intencional - preservação de domínios**: ao contrário do endereço de e-mail completo, o domínio do remetente (por exemplo, `bradesco-seguranca.xyz`) é deliberadamente preservado após o mascaramento. Essa preservação é o alicerce técnico da detecção de spoofing e de domínios sósias: sem o domínio intacto, a Camada 2 perderia a capacidade de comparar o remetente contra a marca legítima citada no corpo da mensagem. O mesmo raciocínio se aplica a URLs completas, que sobrevivem integralmente ao processo de mascaramento por serem o artefato técnico central de identificação de phishing.

**Validação por algoritmo, não apenas por formato**: números de cartão são confirmados pelo algoritmo de Luhn e CPF/CNPJ pelos respectivos dígitos verificadores oficiais antes de serem mascarados, reduzindo falsos positivos que destruiriam números de pedido, protocolos ou códigos de rastreio sem qualquer ganho real de privacidade.

**Falha fechada por padrão**: caso qualquer regra de mascaramento produza uma exceção não tratada durante a execução, o sistema descarta o texto original por completo e o substitui pela tag genérica `[DADOS_CONFIDENCIAIS]`, privilegiando a perda de uma análise à exposição acidental de um dado sensível.

### 3.3. Pseudonimização com Sal Criptográfico

Identificadores de conta (`id_conta`) e de organização (`organizacao`) jamais são persistidos em texto claro. Antes de qualquer gravação, são convertidos pela função `pseudonimizar()` em um hash `HMAC-SHA256`, calculado com um sal secreto definido pela variável de ambiente `PHISHGUARD_SAL_PSEUDONIMO` e escopado pelo contexto de uso (`conta` ou `tenant`), impedindo correlação cruzada entre hashes de escopos distintos gerados a partir do mesmo valor original.

Sem a posse do sal, mantido exclusivamente na infraestrutura do servidor e fora do alcance de qualquer painel ou API pública, a reversão do hash para o identificador original é computacionalmente inviável. Essa é a base técnica que permite ao Painel Enterprise (B2B) exibir métricas de exposição por colaborador sem jamais revelar a identidade da pessoa ao gestor que consulta o painel.

### 3.4. Trilha de Auditoria Anonimizada e Direitos do Titular

O endpoint `GET /api/privacidade/auditoria` executa uma autoauditoria em tempo de execução, consultando o schema real do banco de dados e retornando se há ou não conteúdo residual nas colunas legadas, permitindo que um auditor externo verifique a conformidade sem depender de acesso direto à infraestrutura. O endpoint `DELETE /api/privacidade/meus-dados` implementa o direito de eliminação previsto no Artigo 18, VI, da LGPD; como nenhum conteúdo é armazenado, a operação já satisfaz o direito por construção, restando apenas a remoção dos metadados residuais associados ao hash do titular.

A documentação técnica completa desta arquitetura, incluindo as decisões de projeto registradas como ADRs (Architecture Decision Records), está disponível em [`docs/ARQUITETURA_LGPD.md`](docs/ARQUITETURA_LGPD.md).

---

## 4. Estrutura do Repositório e Módulos

```text
PhishGuard/
├── api.py                          Barramento FastAPI - orquestra as camadas 0, 1 e 2
├── privacidade.py                  PII Masking, pseudonimização e manifesto público de LGPD
├── persistencia.py                 Único ponto de escrita no banco de dados (somente metadados)
├── resiliencia.py                  Timeout, retry com backoff/jitter e circuit breaker
├── diagnostico.py                  Script utilitário de validação de conexão IMAP
│
├── extensao_chrome/                Extensão de navegador Manifest V3
│   ├── manifest.json               Declaração de permissões, hosts e content scripts
│   ├── background.js               Service Worker - proxy de rede resiliente e configuração
│   ├── content.js                  Extração de DOM, banner de veredito e modal de privacidade
│   ├── popup.html / popup.js       Interface de configuração (Proteção / Privacidade / Conta)
│
├── painel_soc/
│   └── index.html                  Painel Enterprise (B2B) - governança e auditoria corporativa
│
├── painel_pessoal/
│   └── index.html                  Painel Personal (B2C) - métricas individuais do titular
│
├── hub_conversacional/
│   └── simulador_whatsapp.html     Simulador do canal WhatsApp para validação do fluxo conversacional
│
├── site_comercial/
│   └── index.html                  Landing page institucional com webchat híbrido (vendas + análise)
│
├── models/                         Artefatos binários (.pkl) dos modelos de Machine Learning treinados
│   ├── vetorizador.pkl             Vetorizador TF-IDF
│   ├── random_forest.pkl           Modelo Random Forest treinado
│   └── xgboost.pkl                 Modelo XGBoost treinado
│
├── data/                           Datasets utilizados no treinamento dos modelos
│
├── src/                            Ecossistema desktop legado e pipeline de treinamento de ML
│   ├── config.py                   Parametrização global
│   ├── email_client.py             Cliente de sessão IMAP/POP3
│   ├── gui.py                      Interface gráfica da aplicação desktop
│   ├── ml_engine.py                Pipeline de treinamento e exportação dos modelos
│   └── main.py                     Ponto de entrada da aplicação desktop
│
├── scripts/
│   ├── gerar_dataset_ptbr.py       Geração do dataset em português brasileiro
│   └── migrar_lgpd_zero_retencao.py  Diagnóstico e expurgo de conteúdo legado no banco de dados
│
├── tests/
│   └── test_conformidade_lgpd.py   Suíte de testes que valida as garantias de privacidade como código
│
├── docs/
│   └── ARQUITETURA_LGPD.md         Documento de referência técnica para auditoria de privacidade
│
├── .env.example                    Modelo de variáveis de ambiente, sem segredos reais
├── .env                            Variáveis de ambiente reais (não versionado)
├── .gitignore                      Exclusões de controle de versão
└── requirements.txt                Dependências Python do projeto
```

### 4.1. Descrição Funcional dos Módulos Centrais

**`api.py`**
Ponto de entrada da aplicação FastAPI. Define os contratos de entrada e saída via modelos Pydantic, orquestra a chamada sequencial das camadas de detecção, aplica o middleware de segurança de rede e expõe a totalidade dos endpoints REST consumidos pela extensão, pelos painéis e pelo hub conversacional.

**`privacidade.py`**
Módulo autocontido, sem dependência de rede ou de banco de dados, responsável por toda a lógica de anonimização preventiva, validação de dados sensíveis (Luhn, dígitos verificadores de CPF/CNPJ) e pseudonimização criptográfica. Também centraliza o manifesto público de transparência (`MANIFESTO_LGPD`), consumido pela extensão e pelos painéis.

**`persistencia.py`**
Camada de acesso a dados isolada, responsável pelo pool de conexões, pela definição idempotente do schema e por todas as consultas agregadas consumidas pelos dois painéis (resumo estatístico, série temporal, ranking de domínios sob risco, colaboradores em risco e distribuição por canal).

**`resiliencia.py`**
Utilitário genérico de resiliência, desacoplado do domínio de negócio do PhishGuard, reaproveitável para qualquer chamada assíncrona a uma dependência externa instável.

---

## 5. Guia de Instalação e Configuração de Ambiente

### 5.1. Requisitos Prévios

- Python 3.11 ou superior.
- Instância de PostgreSQL acessível (recomendado: Azure Database for PostgreSQL); a ausência dessa dependência não impede a subida do servidor, apenas desativa a telemetria e os painéis de governança.
- Chave de API válida do Google Gemini (Google AI Studio ou Google Cloud), para habilitar a Camada 2 de análise contextual.
- Navegador baseado em Chromium (Google Chrome ou Microsoft Edge) para instalação da extensão.

### 5.2. Criação do Ambiente Virtual

```bash
python -m venv venv
```

Ativação no Windows (PowerShell):

```bash
.\venv\Scripts\Activate.ps1
```

Ativação no Linux ou macOS:

```bash
source venv/bin/activate
```

### 5.3. Instalação de Dependências

```bash
pip install -r requirements.txt
```

### 5.4. Configuração das Variáveis de Ambiente

O arquivo `.env.example` documenta a totalidade das variáveis suportadas pelo sistema. Copie-o para `.env` e preencha os valores reais:

```bash
cp .env.example .env
```

| Variável | Obrigatoriedade | Efeito quando ausente |
|---|---|---|
| `GEMINI_API_KEY` | Recomendada | A Camada 2 é desativada; o sistema opera apenas com a Camada 1 |
| `DATABASE_URL` | Recomendada | Telemetria e painéis desativados; a análise de segurança continua ativa |
| `PHISHGUARD_SAL_PSEUDONIMO` | Recomendada em produção | Um sal efêmero é gerado por processo; os hashes de conta perdem estabilidade entre reinícios do servidor |
| `PHISHGUARD_DPO_CONTATO` | Opcional | Endereço de contato exibido no manifesto público de privacidade |
| `PHISHGUARD_ADMIN_TOKEN` | Recomendada em produção | Os endpoints de governança corporativa (B2B) ficam abertos sem autenticação, aceitável apenas em ambiente de desenvolvimento |
| `PHISHGUARD_LIMIAR_CAMADA_1` | Opcional | Assume o valor padrão `0.35` |
| `PHISHGUARD_GEMINI_MODEL` | Opcional | Assume o modelo padrão configurado no código |
| `PHISHGUARD_GEMINI_TIMEOUT` | Opcional | Assume `12` segundos |
| `PHISHGUARD_GEMINI_TENTATIVAS` | Opcional | Assume `2` tentativas |
| `PHISHGUARD_DB_POOL_MIN` / `PHISHGUARD_DB_POOL_MAX` | Opcional | Assumem `1` e `8`, respectivamente |
| `PHISHGUARD_CORS_ORIGENS` | Opcional | Origens adicionais liberadas no CORS, além das já aceitas por padrão |
| `PHISHGUARD_LOG_LEVEL` | Opcional | Assume `INFO` |

Geração de um sal criptográfico forte para produção:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5.5. Inicialização do Servidor (Uvicorn)

```bash
python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```

A flag `--reload` deve ser omitida em ambiente de produção. Após a subida do processo:

- Verificação de prontidão e estado das camadas: `http://localhost:8000/health`
- Documentação interativa (Swagger UI, gerada automaticamente pelo FastAPI): `http://localhost:8000/docs`

### 5.6. Instalação da Extensão em Modo Desenvolvedor

1. No navegador, acesse `chrome://extensions` (Chrome) ou `edge://extensions` (Edge).
2. Ative a opção **Modo do desenvolvedor**, localizada no canto superior direito da página.
3. Selecione **Carregar sem compactação** (*Load unpacked*).
4. Aponte para o diretório `extensao_chrome/` deste repositório.
5. Abra o popup da extensão clicando em seu ícone na barra de ferramentas, acesse a aba **Conta**, selecione o perfil desejado (Personal ou Enterprise) e confirme o endereço do endpoint da API.
6. Abra qualquer e-mail no Gmail ou no Outlook Web: o banner de veredito será injetado automaticamente acima do corpo da mensagem.

### 5.7. Execução dos Painéis Front-end

Os painéis realizam chamadas `fetch` à API e, por restrição de segurança do navegador, não podem ser abertos diretamente via protocolo `file://`. Sirva o diretório raiz por HTTP:

```bash
python -m http.server 5500
```

- Painel Enterprise (B2B): `http://localhost:5500/painel_soc/index.html`
- Painel Personal (B2C): `http://localhost:5500/painel_pessoal/index.html`
- Simulador WhatsApp: `http://localhost:5500/hub_conversacional/simulador_whatsapp.html`
- Site comercial: `http://localhost:5500/site_comercial/index.html`

---

## 6. Documentação de Endpoints da API

Todos os endpoints retornam JSON codificado em UTF-8 com preservação integral de acentuação (`ensure_ascii=False`) e carregam o cabeçalho `X-PhishGuard-Data-Retention: none` em toda resposta.

### `POST /analisar-email`

Endpoint principal consumido pela extensão de navegador. Realiza a análise stateless de um e-mail: aplica a anonimização preventiva sobre o assunto e o corpo, calcula o score estatístico da Camada 1 e, quando disponível, consulta a Camada 2 (Gemini) com o texto já mascarado.

**Corpo da requisição:**

```json
{
  "assunto": "Sua conta será bloqueada em 24h",
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

O corpo do e-mail enviado nesta requisição nunca é persistido; apenas os metadados agregados do resultado são gravados de forma assíncrona após a resposta ser retornada ao cliente.

### `POST /webhook/whatsapp`

Endpoint do hub conversacional para o canal WhatsApp. Recebe uma mensagem de texto livre, aplica a mesma rotina de anonimização preventiva e retorna um veredito formatado para exibição em interface de chat, incluindo emojis e marcação de negrito compatível com o padrão do WhatsApp.

**Corpo da requisição:**

```json
{
  "mensagem": "Voce foi sorteado! Envie seu CPF para resgatar o premio.",
  "perfil": "B2C",
  "id_conta": "usuario@dominio.com"
}
```

### `POST /webhook/webchat`

Endpoint do hub conversacional para o canal webchat, hospedado no site comercial. Opera em modo híbrido: responde tanto a perguntas comerciais sobre os planos do produto quanto a solicitações de análise de risco, alternando de forma dinâmica entre os dois papéis conforme o conteúdo da mensagem recebida. A classificação de ameaça exige a presença de um artefato técnico analisável (URL ou domínio) na mensagem original, evitando que perguntas hipotéticas sobre golpes ("isso é phishing?") sejam contabilizadas como ameaças efetivamente bloqueadas nas métricas de governança.

### `GET /api/logs-soc`

Retorna a trilha de auditoria anonimizada mais recente, limitada por parâmetro de consulta (`limite`, padrão 50, máximo 500). Protegido por token de administração quando `PHISHGUARD_ADMIN_TOKEN` está definido. Nenhum campo de conteúdo é retornado; a estrutura da resposta contém exclusivamente os metadados definidos no contrato `EventoTelemetria`.

### `GET /api/privacidade`

Endpoint público, sem autenticação, que expõe o manifesto de transparência (`MANIFESTO_LGPD`): versão vigente da política, garantias declaradas, bases legais aplicáveis, lista explícita de dados persistidos e de dados nunca persistidos, subprocessadores envolvidos (Google Gemini e Azure Database for PostgreSQL) e contato do encarregado de dados (DPO). Consumido pela extensão e pelos painéis para renderização do selo de transparência.

### Endpoints complementares

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/metricas/pessoal` | Métricas agregadas do titular, filtradas pelo hash da própria conta (B2C) |
| `GET` | `/api/metricas/corporativo` | Governança da organização: ranking de domínios, colaboradores em risco, séries temporais (B2B, protegido) |
| `GET` | `/api/privacidade/auditoria` | Autoauditoria de retenção em tempo de execução (protegido) |
| `DELETE` | `/api/privacidade/meus-dados` | Execução do direito de eliminação previsto no Artigo 18, VI, da LGPD |
| `GET` | `/health` | Prontidão do serviço, estado das camadas de IA e diagnóstico dos circuit breakers |

---

## 7. Testes, Migração e Validação

### 7.1. Suíte de Testes de Conformidade LGPD

O arquivo `tests/test_conformidade_lgpd.py` implementa a conformidade de privacidade como código executável: cada garantia declarada na Seção 3 deste documento corresponde a uma ou mais asserções automatizadas, cobrindo detecção de PII por categoria, estabilidade e irreversibilidade da pseudonimização, e ausência estrutural de campos de conteúdo no contrato de persistência.

Execução via `pytest`:

```bash
python -m pytest tests -v
```

Execução direta, sem dependência de `pytest` instalado:

```bash
python tests/test_conformidade_lgpd.py
```

### 7.2. Migração e Expurgo de Dados Legados

Instalações provisionadas a partir de versões anteriores do PhishGuard podem conter registros históricos com conteúdo de mensagem armazenado em texto puro nas colunas legadas `mensagem_usuario` e `resposta_bot`. O sistema atual interrompe imediatamente qualquer escrita nessas colunas, porém a remoção do histórico existente é tratada como uma decisão explícita do operador da infraestrutura, nunca como efeito colateral automático de uma atualização de versão.

O script `scripts/migrar_lgpd_zero_retencao.py` opera em três modos progressivos:

**Modo de diagnóstico (padrão, não destrutivo):**

```bash
python scripts/migrar_lgpd_zero_retencao.py
```

Reporta a quantidade de registros totais, as colunas legadas presentes no schema e a quantidade de valores de conteúdo ainda residentes no banco de dados.

**Modo de execução (anonimização do histórico):**

```bash
python scripts/migrar_lgpd_zero_retencao.py --executar
```

Sobrescreve com `NULL` o conteúdo das colunas legadas, preservando integralmente os metadados históricos (canal, veredito, data e hora) para fins de continuidade estatística dos painéis.

**Modo de execução com remoção estrutural (irreversível):**

```bash
python scripts/migrar_lgpd_zero_retencao.py --executar --remover-colunas
```

Após a anonimização, executa a remoção definitiva (`DROP COLUMN`) das colunas legadas, tornando a garantia de retenção zero uma propriedade do próprio schema do banco de dados, impossível de ser violada por um erro futuro de código. Esta operação exige confirmação explícita digitada pelo operador no momento da execução.

### 7.3. Verificação de Conformidade em Tempo de Execução

Além da suíte de testes estática, o sistema expõe uma rotina de autoauditoria acessível via API, permitindo que um auditor externo, sem acesso direto à infraestrutura, confirme a ausência de conteúdo residual:

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

Curso de Sistemas de Informação - FIAP (2026)

---

## Stack Tecnológica

| Camada | Tecnologia |
|---|---|
| Linguagem principal | Python 3.11 |
| Framework de API | FastAPI (assíncrono) sobre Uvicorn |
| Machine Learning | Scikit-Learn (Random Forest), XGBoost, Pandas, NumPy |
| Inteligência Artificial Generativa | Google Gemini, via SDK `google-genai` |
| Banco de dados | PostgreSQL (Azure Database for PostgreSQL) |
| Extensão de navegador | Chrome Manifest V3 (Service Worker e Content Script) |
| Front-end dos painéis | HTML, CSS e JavaScript nativos, sem dependência de build ou framework |
