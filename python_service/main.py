import os
import logging
import asyncio
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain.schema.runnable import RunnableSequence
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

load_dotenv()

# Configuração de log
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("main")

# Definir endereço do Ollama
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
llm = None

# FastAPI app
app = FastAPI()

# Middleware de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:30000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conectar ao Ollama
@app.on_event("startup")
async def startup_event():
    global llm
    logger.info("Iniciando conexão com o Ollama...")
    for tentativa in range(1, 4):
        try:
            logger.info(f"Tentativa {tentativa} de conexão com Ollama ({OLLAMA_BASE_URL})...")
            llm = OllamaLLM(
                model="llama3.1:8b",
                base_url=OLLAMA_BASE_URL,
                temperature=0.7,
                num_ctx=4096,
                num_gpu=40,
                timeout=60.0
            )
            start_time = datetime.now()
            response = await llm.ainvoke("Teste SOC")
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"✅ Conectado ao Ollama: {response} (tempo: {duration:.2f}s)")
            return
        except Exception as e:
            logger.error(f"❌ Tentativa {tentativa} falhou: {e}")
            if tentativa < 3:
                await asyncio.sleep(2)
    logger.error("❌ Não foi possível conectar ao Ollama.")
    raise Exception("Falha ao conectar ao Ollama após 3 tentativas.")

# Modelos de dados
class LogRequest(BaseModel):
    log: str
    iocs: list[str] = []
    categories: list[str] = []
    report_type: str = "base"
    alertName: str = "Não disponível"
    ruleName: str = "Não disponível"

class RespondRequest(BaseModel):
    log: str

class PatternsRequest(BaseModel):
    logs: list[str]

# Função para saudação (ajustada para 15:30 -03)
def get_saudacao():
    hora = 15  # Horário atual: 03:30 PM -03
    return "Bom dia" if hora < 12 else "Boa tarde" if hora < 18 else "Boa noite"

# Extração mínima de campos
def extract_log_fields(log: str, alertName: str, ruleName: str):
    if not log or not log.strip():
        logger.error("Log vazio recebido.")
        raise ValueError("Log não pode ser vazio.")
    logger.info(f"Log recebido (tamanho: {len(log)} caracteres)")
    return {
        "log": log[:5000],
        "saudacao": get_saudacao(),
        "alertName": alertName,
        "ruleName": ruleName
    }

# Template do relatório padrão
report_prompt = PromptTemplate(
    input_variables=["saudacao", "log", "iocs", "categories", "alertName", "ruleName"],
    template="""Você é um analista de segurança cibernética especializado em uma equipe de monitoramento. Sua tarefa é analisar o log fornecido, identificar os evento ocorrido e gerar um relatório claro, conciso e profissional para o cliente, solicitando validações. O relatório deve seguir rigorosamente o modelo abaixo, preenchendo todos os campos com base no log. Se uma informação não estiver disponível, não precisa preecher o campo. Use linguagem profissional, objetiva e acessível, evitando jargões técnicos excessivos, mas mantendo precisão.

*Instruções*:
- *Caso de uso*: Descreva o evento (ex.: falha de login, acesso não autorizado) com base no log.
- *Análise*: Forneça uma análise técnica detalhada, incluindo contexto (tipo de evento), impacto potencial (ex.: interrupção de serviço) e implicações.
- *Objetivo do caso de uso*: Especifique o objetivo da análise (ex.: detectar intrusões, identificar falhas de autenticação).
- *Fonte de dados*: Use "Windows Event Log" para logs XML ou "Syslog" para logs Syslog. Se não identificável, use não preechar.
- *Justificativa*: Explique por que o evento justifica investigação, considerando gravidade, tipo de evento, número de tentativas (se aplicável) e impacto potencial (ex.: comprometimento de credenciais).
- *Recomendações*: Liste 3 ações práticas e acionáveis para mitigar o evento e prevenir recorrências, alinhadas com padrões como NIST ou CIS Controls. Considere as categorias: {categories}.
- *Resultado*: Derive do campo 'message' (ex.: "Failed" para "Login failed") ou não preechar se não aplicável e não leva no resultado final .
- *Status*: Use não preechar a menos que o log forneça um campo 'status' explícito.
- *Campos ausentes*: Não sera necessario preecher caso o campos sem informação no log.
- *Formatação*: Siga exatamente o modelo abaixo, incluindo quebras de linha e emojis. Retorne o relatório em texto puro, sem formatação adicional (ex.: markdown, HTML).

*Modelo do Relatório*:

Prezados(as), {saudacao}.

Nossa equipe identificou uma atividade suspeita em seu ambiente. Seguem abaixo mais detalhes para validação:

Caso de uso: [Descreva o caso de uso com base no log]

🕵 Análise: [Análise técnica detalhada]

Objetivo do caso de uso: [Objetivo da análise]

📊 Fonte de dados utilizada na análise: [Fonte do log]

🚨Severidade: [Severidade, ex.: uma brevia descrição doque possar acontece no ambiente e classifique o nivel]

🧾 Evidências
Data do Log: [Data e hora do evento]
Fonte do Log: [Sistema ou componente que gerou o log]
Usuário de Origem: [Usuário que iniciou a atividade, se aplicável]
Usuário Afetado: [Usuário impactado, se aplicável]
IP/Host de Origem: [IP ou host que iniciou a atividade]
IP/Host Afetado: [IP ou host impactado]
Localização (Origem/Impactado): [Localização geográfica ou lógica, se disponível]
Tipo do Evento: [Tipo de evento, ex.: acesso não autorizado]
Grupo: [Categoria do evento, ex.: segurança web, autenticação]
Objeto: [Recurso alvo, ex.: diretório, arquivo]
Nome do Objeto: [Nome específico do recurso]
Tipo do Objeto: [Tipo de recurso, ex.: diretório web, banco de dados]
Assunto: [Resumo do evento, ex.: tentativa de acesso a diretório restrito]
Política: [Política de segurança violada, se aplicável]
Nome da Ameaça: [Nome da ameaça, ex.: sondagem automatizada]
Nome do Processo: [Processo envolvido, se aplicável]
Nome da Regra MPE: [Regra de monitoramento que disparou o alerta]
Mensagem do Fornecedor: [Mensagem ou código de erro do sistema]
ID do Fornecedor: [Identificador único do evento, se disponível]
Identificador de Navegador: [User-agent ou identificador, se aplicável]
Ação: [Ação realizada, ex.: tentativa de acesso]
Status: [Status da ação, ex.: sucesso, falha]
Resultado: [Resultado final, ex.: bloqueado, permitido]
Sessão: [Sessão, ex.: Sessão caso venha no log]
Aplicação: [Aplicação, ex.: Aplicação que foi executada ou rodada]

Detalhes dos IOCs: {iocs}

🕵 Justificativa para abertura do caso: [Justificativa clara]

📌 Recomendações:
[Recomendação 1]
[Recomendação 2]
[Recomendação 3]

*Log fornecido*: {log}
"""
)

# Template do relatório de refino de regra
refine_rule_prompt = PromptTemplate(
    input_variables=["saudacao", "log", "alertName", "ruleName"],
    template="""Você é um analista de segurança cibernética especializado em análise de monitoramento e refino de regras. Sua tarefa é analisar o log fornecido, identificar o evento ocorrido, determinar se o alerta gerado é um falso positivo e redigir uma solicitação clara, concisa e profissional para a equipe de sustentação, solicitando a validação de um possível refino da regra.

O relatório deve seguir rigorosamente o modelo abaixo, preenchendo todos os campos com base no log. Se uma informação não estiver disponível, use "Não disponível". Use linguagem técnica, porém clara, adequada para a equipe de sustentação.

*Instruções*:
- *Cabeçalho*: Inclua o nome da regra no título. Use "N/A" se não disponível no log.
- *Saudação e Introdução*: Use uma saudação profissional (ex.: "Prezados, bom dia") e explique brevemente o contexto do alerta, destacando a possibilidade de falsos positivos.
- *Justificativa*:
- *Exemplo de evento relevante*: Descreva o evento detectado (ex.: data, IP, ação, sistema afetado) com base no log.
- *Motivo do falso positivo*: Explique por que o alerta é considerado um falso positivo (ex.: atividade legítima, comportamento esperado de uma aplicação).
- *Solicitação*: Formule uma solicitação clara para a equipe de sustentação, sugerindo ações específicas (ex.: exclusão de IPs, ajuste de parâmetros, revisão de assinaturas).
- *Campos ausentes*: Use "Não disponível" para campos sem informação no log.
- *Formatação*: Siga exatamente o modelo abaixo, incluindo quebras de linha e emojis. Retorne o relatório em texto puro, sem formatação adicional (ex.: markdown, HTML).

**Modelo do Relatório**:

Prezados(as), {saudacao}. Identificamos um alerta gerado pela regra {ruleName} no SIEM, que pode estar gerando falsos positivos, impactando a eficiência do monitoramento. [Explique brevemente o que está acontecendo com base no evento do log].

📝 Solicitação:  
[Solicitação clara para a equipe de sustentação, ex.: "Solicitamos a validação da regra {ruleName} para verificar se ajustes são necessários, como exclusão de IPs específicos, ajuste de parâmetros ou revisão de assinaturas."]

🎯 Justificativa:  
- Exemplo de evento relevante: [Descrição do evento detectado, incluindo detalhes como data, IP, ação ou sistema afetado]

🔎 Exemplo de Evento Relevante:  
[Inserir exemplo do evento considerado válido ou suspeito, com os principais campos: IP, usuário, hostname, etc.]

📌 Motivo do Falso Positivo:  
[Explicação sobre por que o alerta gerado foi considerado um falso positivo. Ex: tarefa agendada legítima, scanner interno autorizado, etc.]

Ação: [Ação realizada, ex.: tentativa de acesso]  
Nome da Regra MPE: {ruleName}

📌 Considerações Finais:  
[Observações adicionais que devem ser levadas em conta no refino – Ex: ajustar horários de sensibilidade, whitelisting de host, correlação com outros eventos, etc.]

📄 Nome da Regra: {ruleName}  
📄 Nome do Alerta: {alertName}  
📄 Amostra do ID: [ID do alerta gerado]  
📄 Amostra do Log Recebido: {log}  
📂 Caso no SIEM: [Número do chamado criado no SIEM]
"""
)

# Template do relatório de saúde do SIEM
siem_health_prompt = PromptTemplate(
    input_variables=["saudacao", "log"],
    template="""Você é um analista de segurança cibernética especializado em monitoramento e manutenção da saúde de sistemas SIEM. Sua tarefa é analisar o log fornecido, identificar possíveis problemas relacionados à saúde do SIEM (ex.: falhas na coleta de logs, atrasos, falsos positivos, regras mal configuradas, integrações inativas) e redigir um relatório claro, conciso e profissional para a equipe de manutenção do SIEM, solicitando validação ou ações corretivas. O relatório deve seguir rigorosamente o modelo abaixo, preenchendo todos os campos com base no log. Se uma informação não estiver disponível, use "Não disponível". Use linguagem técnica, mas acessível, adequada para a equipe de manutenção.

*Instruções*:
- *Caso de uso*: Descreva o problema identificado (ex.: falha na coleta de logs, atraso na ingestão) com base no log.
- *Justificativa*: Explique por que o evento indica um problema na saúde do SIEM, considerando impacto (ex.: lacunas no monitoramento) e gravidade.
- *Objetivo do caso de uso**: Especifique o objetivo da análise (ex.: garantir coleta em tempo real, corrigir regras mal configuradas).
- *Fonte de dados*: Use "Windows Event Log" para logs XML, "Syslog" para logs Syslog, ou "N/A" se não identificável.
- *Campos ausentes*: Use "Não disponível" para campos sem informação no log.
- *Resultado*: Derive do campo 'message' (ex.: "Failed" para "Log collection failed") ou use "N/A" se não aplicável.
- *Status*: Use "N/A" a menos que o log forneça um campo 'status' explícito.
- *Formatação*: Siga exatamente o modelo abaixo, incluindo quebras de linha e emojis. Retorne o relatório em texto puro, sem formatação adicional (ex.: markdown, HTML).

*Modelo do Relatório*:

Prezados(as), {saudacao}.

Nossa equipe identificou uma possível questão relacionada à saúde do SIEM que requer validação. Seguem abaixo mais detalhes para análise:

Caso de uso: [Descrição do caso de uso, ex.: "Verificar a integridade da coleta de logs para identificar falhas ou atrasos na ingestão de dados."]

🕵 Justificativa para abertura do caso: [Explicação do motivo pelo qual o log indica um problema, ex.: "O log mostra um atraso significativo na ingestão de dados, sugerindo problemas na integração com a fonte de dados."]

Objetivo do caso de uso: [Objetivo da análise, ex.: "Garantir que os logs sejam coletados em tempo real para evitar lacunas no monitoramento de segurança."]

📊 Fonte de dados utilizada na análise: [Fonte dos dados, ex.: "Windows Event Log", "Syslog", "N/A"]

🧾 Evidências:
- Data do Log: [Data e hora do evento]
- Fonte do Log: [Sistema ou componente que gerou o log, ex.: agente SIEM]
- Usuário de Origem: [Usuário associado, se aplicável]
- Usuário Afetado: [Usuário impactado, se aplicável]
- IP/Host de Origem: [IP ou host que gerou o evento]
- IP/Host Afetado: [IP ou host impactado]
- Localização (Origem/Impactado): [Localização geográfica ou lógica, se disponível]
- Tipo do Evento: [Tipo de evento, ex.: falha de integração]
- Grupo: [Categoria do evento, ex.: saúde do SIEM]
- Objeto: [Recurso alvo, ex.: conector]
- Nome do Objeto: [Nome específico do recurso, ex.: Conector_Firewall_X]
- Tipo do Objeto: [Tipo de recurso, ex.: conector]
- Assunto: [Resumo do evento, ex.: falha na coleta de logs]
- Política: [Política ou configuração relevante, se aplicável]
- Nome da Ameaça: [Nome do problema, ex.: atraso na ingestão]
- Nome do Processo: [Processo envolvido, ex.: ingestão de logs]
- Nome da Regra MPE: [Regra que disparou o alerta, se aplicável]
- Mensagem do Fornecedor: [Mensagem ou código de erro do sistema]
- ID do Fornecedor: [Identificador único do evento, se disponível]
- Identificador de Navegador: [User-agent, se aplicável, ou "Não disponível"]
- Ação: [Ação relacionada, ex.: tentativa de coleta]
- Status: [Status da ação, ex.: falha]
- Resultado: [Resultado final, ex.: log não coletado]

*Log fornecido*: {log}
"""
)

# Rota principal
@app.get("/")
async def root():
    return {"message": "🚀 Serviço SOC"}

# Rota para análise de logs
@app.post("/analyze")
async def analyze(request: LogRequest):
    logger.info(f"Solicitação recebida: log='{request.log[:50]}...' iocs={request.iocs} categories={request.categories} report_type='{request.report_type}' alertName='{request.alertName}' ruleName='{request.ruleName}'")
    
    try:
        # Extrair campos mínimos
        fields = extract_log_fields(request.log, request.alertName, request.ruleName)
        fields["iocs"] = ", ".join(request.iocs) if request.iocs else "Nenhum"
        fields["categories"] = ", ".join(request.categories) if request.categories else "gerenciamento de acesso"

        # Escolher o prompt com base no tipo de relatório
        if request.report_type == "refine":
            report_chain = RunnableSequence(refine_rule_prompt | llm)
        elif request.report_type == "siem-health":
            report_chain = RunnableSequence(siem_health_prompt | llm)
        else:
            report_chain = RunnableSequence(report_prompt | llm)

        # Gerar relatório com a IA
        logger.info("Iniciando geração do relatório com Ollama...")
        start_time = datetime.now()
        report = await asyncio.wait_for(
            report_chain.ainvoke(fields),
            timeout=60.0
        )
        # Garantir que as quebras de linha sejam preservadas
        report = report.strip().replace("\n\n", "\n")  # Normalizar quebras de linha
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Relatório gerado em {duration:.2f}s")
        return {
            "input_log": request.log,
            "resposta": report
        }
    except Exception as e:
        logger.error(f"Erro ao gerar relatório: {e}")
        return {
            "input_log": request.log,
            "resposta": f"Erro ao processar o log: {str(e)}. Verifique o log ou a conexão com o Ollama."
        }

# Rota para resposta a incidentes
@app.post("/respond")
async def respond(request: RespondRequest):
    try:
        fields = extract_log_fields(request.log, "Não disponível", "Não disponível")
        logger.info("Iniciando geração de ações de mitigação...")
        start_time = datetime.now()
        actions = await asyncio.wait_for(
            llm.ainvoke(f"Sugira 3 ações para mitigar o evento no log: {request.log[:500]}. Baseie-se em NIST SP 800-53 ou CIS Controls."),
            timeout=60.0
        )
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Ações geradas em {duration:.2f}s")
        return {"resposta": actions.strip(), "input_log": request.log}
    except Exception as e:
        logger.error(f"Erro ao responder: {e}")
        return {
            "input_log": request.log,
            "resposta": f"Erro ao processar o log: {str(e)}. Verifique o log ou a conexão com o Ollama."
        }

# Rota para análise de padrões
@app.post("/patterns")
async def patterns(request: PatternsRequest):
    try:
        if not request.logs or not any(log.strip() for log in request.logs):
            logger.error("❌ Lista de logs vazia.")
            return {
                "input_logs": request.logs,
                "resposta": "Erro: Forneça pelo menos um log válido."
            }
        
        logger.info("Iniciando análise de padrões...")
        start_time = datetime.now()
        patterns = await asyncio.wait_for(
            llm.ainvoke(f"Identifique padrões nos logs: {', '.join([log[:250] for log in request.logs if log.strip()])}. Descreva os padrões e implicações de segurança."),
            timeout=60.0
        )
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Padrões analisados em {duration:.2f}s")
        return {"resposta": patterns.strip(), "input_logs": request.logs}
    except Exception as e:
        logger.error(f"Erro ao analisar padrões: {e}")
        return {
            "input_logs": request.logs,
            "resposta": f"Erro ao processar os logs: {str(e)}. Verifique os logs ou a conexão com o Ollama."
        }