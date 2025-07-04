# Shado-Report - Análise de Logs de Segurança com IA Local

O **Shado-Report** é uma aplicação web que analisa logs de segurança (ex.: LogRhythm, QRadar, Trend Micro ou texto genérico) usando um modelo de IA local (Ollama) e gera relatórios estruturados. O sistema inclui um frontend (HTML, JavaScript), um backend Node.js (`server.js`) e um backend Python (`main.py`). Este guia ensina como instalar e rodar o projeto passo a passo.

## Pré-requisitos

Antes de começar, instale o seguinte:

1. **Node.js** (v16 ou superior):
   - Baixe e instale: [nodejs.org](https://nodejs.org/)
   - Verifique: 
     node --version

2. **Python** (3.8 ou superior):
   - Baixe e instale: [python.org](https://www.python.org/)
   - Verifique:
     python --version

3. **Ollama**:
   - Baixe e instale: [ollama.ai](https://ollama.ai/)
   - Verifique:
     ollama --version

4. **Git** (opcional, para clonar o repositório):
   - Instale: [git-scm.com](https://git-scm.com/)
   - Verifique:
     git --version

## Instalação

### 1. Clonar o Repositório
Clone o projeto para sua máquina:

git clone <URL_DO_REPOSITORIO>
cd Shado-Report


### Instalando o Ollama no Linux
1. Baixar e Instalar o Ollama
    - O Ollama oferece um script de instalação automático para Linux.

Execute o Script de Instalação:
    - Abra o terminal e execute: curl -fsSL https://ollama.com/install.sh | sh
Isso baixa e instala o Ollama automaticamente.

Verificar a Instalação:
    - Confirme a versão instalada: ollama --version


Iniciar o Servidor Ollama:
    - Execute o servidor em segundo plano: ollama serve &
    - Ou em primeiro plano (para ver logs): ollama serve
    - Verifique se o servidor está ativo: curl http://localhost:11434/api/version
    - Puxar um Modelo: ollama pull llama3.1:8b ou ollama pull llama3

2. Configurar o Ollama como Serviço (Opcional)
    - Para garantir que o Ollama inicie automaticamente com o sistema:
    - Criar um Serviço Systemd:
    - Crie um arquivo de serviço: sudo nano /etc/systemd/system/ollama.service

Adicione o seguinte conteúdo:

[Unit]
Description=Ollama Service
After=network.target

[Service]
ExecStart=/usr/bin/ollama serve
Restart=always
User=$USER
Environment="OLLAMA_HOST=0.0.0.0:11434"

[Install]
WantedBy=multi-user.target

Habilitar e Iniciar o Serviço:
    - Atualize o systemd: sudo systemctl daemon-reload
    - Habilite o serviço para iniciar com o sistema: sudo systemctl enable ollama
    - Inicie o serviço: sudo systemctl start ollama
    - Verifique o status: sudo systemctl status ollama

### Instalando o Ollama no Windows
No Windows, o Ollama pode ser instalado via executável ou usando o Windows Subsystem for Linux (WSL), que é recomendado para integração com o projeto Shado-Report.

Opção 1: Instalação Nativa no Windows
    - Baixar o Ollama:
    - Acesse ollama.com e baixe o instalador para Windows (OllamaSetup.exe).
    - Execute o instalador como administrador:
    - Clique com o botão direito no arquivo e selecione "Executar como administrador".
    - Verificar a Instalação:
    - Abra o Prompt de Comando (cmd) ou PowerShell como administrador: ollama --version

Iniciar o Servidor Ollama:
    - O instalador configura o Ollama como um serviço que inicia automaticamente.
    - Para iniciar manualmente no cmd/PowerShell: ollama serve

Verifique se o servidor está ativo: curl http://localhost:11434/api/version


Puxar um Modelo: Use llama3.1:8b:
    - ollama pull llama3.1:8b
    - Alternativa: llama3: ollama pull llama3
    - Liste os modelos: ollama list

### 2. Configurar o Ollama
O Ollama executa o modelo de IA localmente para processar logs.

1. **Iniciar o Ollama**:
   - Execute:
     ollama serve

   - Isso inicia o servidor de IA na porta padrão `11434`.

2. **Puxar o Modelo**:
   - Use o modelo `llama3.1:8b` (recomendado por ser mais eficiente):
     ollama pull llama3.1:8b

   - Alternativa: Use `llama3` se necessário:
     ollama pull llama3

3. **Verificar o Ollama**:
   - Confirme que o servidor está ativo:
     curl http://localhost:11434/api/version

   - Saída esperada: Versão do Ollama (ex.: `0.1.x`).

### 3. Configurar o Backend Python (`main.py`)

1. **Instalar Dependências**:
   - Navegue até o diretório `backend/`:
     cd backend

   - Instale as dependências Python:
     pip install fastapi uvicorn langchain-ollama pydantic python-dotenv

2. **Configurar o Arquivo `.env`**:
   - Crie um arquivo `.env` em `backend/` com o seguinte conteúdo:

#porta
PORT=[Porta]

PYTHON_SERVICE_URL=http://localhost:[Porta]

# URL do servidor Ollama local
OLLAMA_URL=http://localhost:11434

OLLAMA_MODEL=llama3

# Faixas de IP permitidas (caso use firewall ou controle por IP)
ALLOWED_ORIGINS=http://localhost:[Porta],http://localhost:[Porta]http://127.0.0.1:[Porta]

# VPN desativada (pode ser usado no backend para validação futura)
ENABLE_VPN=false
ALLOWED_IP_RANGES=IP_DA_VPN

# Chaves de APIs externas (ABUSEIPDB e VIRUSTOTAL)
ABUSEIPDB_API_KEY=KEY
VIRUSTOTAL_API_KEY=KEY

4. **Iniciar o Backend Python**:
pip install -r requirements.txt
   - Execute:
    .\venv\Scripts\activate
     uvicorn main:app --host 0.0.0.0 --port 8000

**Iniciar o Backend Node.js**:
   - Execute: npm start
### 4. Configurar o Backend Node.js (`server.js`)

1. **Instalar Dependências**:
   - No diretório `backend/`:
     cd backend
     npm install express axios cors dotenv

## Licença
MIT