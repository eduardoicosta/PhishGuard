# PhishGuard - Detecção de Phishing com Ensemble Learning

Este repositório contém o Produto Mínimo Viável (MVP) do **PhishGuard**, uma solução de *Cybersecurity as a Service* (SECaaS) desenvolvida para o **Enterprise Challenge - CLARO**. O sistema utiliza Inteligência Artificial avançada para proteger estações de trabalho desktop contra e-mails e links fraudulentos (phishing) em tempo real.

---

## Integrantes (Startup One)
* **Arthur Dias da Silva Biancchi** – RM 99162
* **Eduardo Costa Nascimento dos Anjos** – RM 552519
* **Enzo Puerta Meschini** – RM 550807

**Curso:** Sistemas de Informação - FIAP (2026)

---

## Funcionalidades Principais
1. **Detecção Inteligente via Ensemble Learning:** Combinação híbrida dos algoritmos matemáticos **XGBoost** e **Random Forest** para classificar e prever e-mails maliciosos antes da interação do usuário.
2. **Caixa de Entrada Blindada:** Triagem visual com alertas cromáticos dinâmicos baseados no nível de risco gerado pela IA (Banners Verdes para e-mails seguros e Vermelhos para ameaças).
3. **Hub de Convergência Conversacional:** Interface integrada In-App e suporte planejado para validação ágil de URLs externas através da API do WhatsApp Business.
4. **Painel do SOC (Security Operations Center):** Governança ágil para controle do *Threshold* (sensibilidade) da IA e gerenciamento de *Whitelists* (domínios confiáveis).

---

## Stack Tecnológica
* **Linguagem Core:** Python
* **Inteligência Artificial:** Scikit-Learn, XGBoost, Pandas e NumPy
* **Barramento e APIs:** FastAPI
* **Banco de Dados & Cloud:** PostgreSQL, Google Cloud SQL e Google Cloud Platform (GCP)
* **Integrações de IA e Mensageria:** OpenAI API e WhatsApp Business API

---

## Estrutura de Diretórios
```text
PhishGuard/
├── assets/               # Identidade visual e logotipos do projeto
├── data/                 # Datasets de e-mails (phishing_email.csv)
├── models/               # Pesos binários dos modelos (.pkl)
├── src/                  # Código-fonte do ecossistema
│   ├── config.py         # Arquivos de parametrização global
│   ├── email_client.py   # Gerenciamento de sessões IMAP/POP3
│   ├── gui.py            # Telas do front-end da aplicação desktop
│   ├── ml_engine.py      # Pipeline de processamento e scores da IA
│   └── main.py           # Inicializador do software local
├── .env                  # Variáveis de ambiente e tokens privados
├── .gitignore            # Filtros de exclusão de arquivos pesados
├── diagnostico.py        # Script de validação e telemetria da caixa do Google
├── README.md             # Documentação técnica do repositório
└── requirements.txt      # Gerenciador de dependências e bibliotecas
```

---

## Configuração e Instalação Local

Como as pastas de ambientes virtuais (`venv/`), dados (`data/`) e modelos (`models/`) estão protegidas no `.gitignore`, siga as instruções abaixo para reconstruir o ambiente localmente:

### 1. Clonar o Repositório
```bash
git clone [https://github.com/eduardoicosta/PhishGuard.git](https://github.com/eduardoicosta/PhishGuard.git)
cd PhishGuard
```

### 2. Criar e Ativar o Ambiente Virtual
```bash
# Criar ambiente virtual
python -m venv venv

# Ativar no Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Ativar no Linux/macOS
source venv/bin/activate
```

### 3. Instalar as Dependências do Projeto
```bash
pip install -r requirements.txt
```

### 4. Configurar as Variáveis de Ambiente
Crie um arquivo chamado `.env` na raiz do seu projeto e configure suas credenciais de e-mail e chaves de API:
```text
IMAP_SERVER=imap.gmail.com
EMAIL_USER=seu_email@gmail.com
EMAIL_APP_PASSWORD=sua_senha_de_aplicativo_de_16_digitos
OPENAI_API_KEY=sua_chave_da_openai
```

---

## Executando o Script de Diagnóstico IMAP

O projeto acompanha um script utilitário (`diagnostico.py`) focado na checagem de integridade e varredura de requisições iniciais da caixa de entrada via protocolo IMAP seguro.

Para executar o teste de comunicação com o servidor e listagem de e-mails não lidos, certifique-se de que seu ambiente virtual esteja ativo e rode:

```bash
python diagnostico.py
```

### O que este script faz?
1. Inicializa o cliente através do módulo `src.email_client`.
2. Efetua a conexão segura com o servidor de e-mail configurado.
3. Acessa a pasta raiz da `INBOX`.
4. Executa um mapeamento estatístico coletando a quantidade total de mensagens e isolando mensagens sob a tag `UNSEEN` (não lidas).
5. Retorna o ID das requisições prontas para serem submetidas ao cérebro preditivo de IA do PhishGuard.
