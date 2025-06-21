const express = require('express');
const axios = require('axios');
const cors = require('cors');
const xml2js = require('xml2js');

require('dotenv').config({ path: __dirname + '/.env' });

const app = express();

// Configurar para servir arquivos estáticos (ex.: index.html, styles.css, script.js)
app.use(express.static(__dirname + '/public'));

app.use(cors());
app.use(express.json());

// Funções de validação
function isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    return ip.split('.').every(num => {
        const n = parseInt(num);
        return n >= 0 && n <= 255 && num === n.toString();
    });
}

function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        try {
            new URL(`http://${url}`);
            return true;
        } catch {
            return false;
        }
    }
}

function isValidHash(hash) {
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    return hashRegex.test(hash);
}

// Função para consultar AbuseIPDB
async function checkAbuseIPDB(ip) {
    try {
        const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' }
        });
        return {
            confidenceScore: response.data.data.abuseConfidenceScore,
            reports: response.data.data.totalReports,
            country: response.data.data.countryCode || 'N/A',
            lastReported: response.data.data.lastReportedAt || 'N/A'
        };
    } catch (error) {
        console.error(`Erro ao consultar AbuseIPDB para ${ip}:`, error.message);
        return { error: 'Falha ao consultar AbuseIPDB' };
    }
}

// Função para consultar VirusTotal
async function checkVirusTotal(ioc, type) {
    try {
        let endpoint = '';
        if (type === 'ip') endpoint = `ip_addresses/${ioc}`;
        else if (type === 'url') endpoint = `urls`;
        else if (type === 'hash') endpoint = `files/${encodeURIComponent(ioc)}`;

        if (type === 'url') {
            console.log(`Submetendo URL para VirusTotal: ${ioc}, Corpo: { url: "${ioc}" }`);
            const submitResponse = await axios.post(
                `https://www.virustotal.com/api/v3/${endpoint}`,
                { url: ioc },
                {
                    headers: {
                        'x-apikey': process.env.VIRUSTOTAL_API_KEY,
                        'Content-Type': 'application/json'
                    }
                }
            );
            console.log('Resposta de submissão:', submitResponse.data);
            const analysisId = submitResponse.data.data.id;

            let analysisResult;
            for (let i = 0; i < 5; i++) {
                await new Promise(resolve => setTimeout(resolve, 2000));
                const resultResponse = await axios.get(
                    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                    { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } }
                );
                analysisResult = resultResponse.data.data.attributes;
                console.log(`Status da análise da URL (${i + 1}/5):`, analysisResult.status);
                if (analysisResult.status === 'completed') break;
            }

            if (!analysisResult || analysisResult.status !== 'completed') {
                throw new Error('Análise da URL não concluída no prazo');
            }
            const analysis = analysisResult.stats || analysisResult.last_analysis_stats;
            const malicious = analysis.malicious || 0;
            const total = Object.values(analysis).reduce((a, b) => a + b, 0);
            return { score: total > 0 ? (malicious / total) * 100 : 0, isReported: malicious > 0 };
        } else {
            console.log(`Consultando VirusTotal para ${type}: ${ioc}`);
            const response = await axios.get(`https://www.virustotal.com/api/v3/${endpoint}`, {
                headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
            });
            const analysis = response.data.data.attributes.last_analysis_stats;
            const malicious = analysis.malicious || 0;
            const total = Object.values(analysis).reduce((a, b) => a + b, 0);
            return { score: total > 0 ? (malicious / total) * 100 : 0, isReported: malicious > 0 };
        }
    } catch (error) {
        console.error(`Erro ao consultar VirusTotal para ${ioc} (tipo: ${type}):`, error.message, error.response?.data);
        return { error: error.response?.data?.error?.message || 'Falha ao consultar VirusTotal', score: -1, isReported: false };
    }
}

// Função para verificar IOCs
async function checkIOC(ioc) {
    console.log(`Validando IOC: ${ioc}`);
    let type = 'unknown';
    if (isValidIP(ioc)) type = 'ip';
    else if (isValidURL(ioc)) type = 'url';
    else if (isValidHash(ioc)) type = 'hash';
    console.log(`Verificando IOC: ${ioc}, Tipo detectado: ${type}`);

    try {
        let result;
        if (type === 'ip') {
            console.log(`Chamando AbuseIPDB para IP: ${ioc}`);
            const abuseResponse = await axios.get('https://api.abuseipdb.com/api/v2/check', {
                params: { ipAddress: ioc, maxAgeInDays: 90 },
                headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' }
            });
            result = {
                ioc: ioc,
                type: type,
                score: abuseResponse.data.data.abuseConfidenceScore,
                isReported: abuseResponse.data.data.abuseConfidenceScore > 0
            };
        } else {
            console.log(`Chamando VirusTotal para ${type}: ${ioc}`);
            const vtResult = await checkVirusTotal(ioc, type);
            if (vtResult.error) throw new Error(vtResult.error);
            result = {
                ioc: ioc,
                type: type,
                score: vtResult.score,
                isReported: vtResult.isReported
            };
        }
        return result;
    } catch (error) {
        console.error(`Erro ao verificar ${ioc}:`, error.message, error.response?.data);
        return {
            ioc: ioc,
            type: type,
            score: -1,
            isReported: false,
            error: error.message
        };
    }
}

// Rota para analisar IOCs
app.post('/api/analyze-iocs', async (req, res) => {
    const { iocs } = req.body;
    if (!iocs || !Array.isArray(iocs) || iocs.length === 0) {
        return res.status(400).json({ error: 'Por favor, forneça uma lista de IOCs.' });
    }

    try {
        const results = await Promise.all(iocs.map(ioc => checkIOC(ioc)));
        const reportedIOCs = results.filter(result => result.score > 0 && result.score !== -1);
        const unreportedIOCs = results.filter(result => result.score === 0 || result.score === -1);

        res.json({
            reported: reportedIOCs,
            unreported: unreportedIOCs,
            stats: {
                reportedCount: reportedIOCs.length,
                unreportedCount: unreportedIOCs.length
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao analisar IOCs: ' + error.message });
    }
});

// Função para parsear log
async function parseLogText(logText) {
    const logObj = {};

    try {
        const syslogRegex = /^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/;
        if (syslogRegex.test(logText)) {
            const content = logText.replace(syslogRegex, '');
            const pairs = content.split(/\s+(?=\w+=)/).reduce((acc, pair) => {
                const [key, ...valueParts] = pair.split('=');
                if (key && valueParts.length) {
                    let value = valueParts.join('=').trim();
                    if (value.startsWith('"') && value.endsWith('"')) {
                        value = value.slice(1, -1);
                    }
                    acc[key.toLowerCase().replace(/\s+/g, '_')] = value;
                }
                return acc;
            }, {});

            logObj.eventid = pairs.eventid || 'N/A';
            logObj.time = pairs.timegenerated || pairs.timewritten || 'N/A';
            logObj.event_type = pairs.task || `EventID ${logObj.eventid}`;
            logObj.message = pairs.message || 'N/A';
            logObj.username = pairs.user || 'N/A';
            logObj.destination_host = pairs.computer || 'N/A';
            logObj.source_ip = pairs.originatingcomputer || 'N/A';
            logObj.level = pairs.level || 'N/A';
            logObj.event_category = pairs.eventcategory || 'N/A';

            Object.keys(pairs).forEach(key => {
                if (!logObj[key]) {
                    logObj[key] = pairs[key];
                }
            });

            return logObj;
        }
    } catch (syslogError) {
        console.log('Não é Syslog, tentando outros formatos:', syslogError.message);
    }

    try {
        const parser = new xml2js.Parser({ explicitArray: false });
        const result = await parser.parseStringPromise(logText);
        const event = result.Event;
        const system = event.System || {};
        const eventData = event.EventData || {};

        logObj.eventid = system.EventID || 'N/A';
        logObj.time = system.TimeCreated?._?.SystemTime || 'N/A';
        logObj.event_type = system.Task || `EventID ${logObj.eventid}`;
        logObj.destination_host = system.Computer || 'N/A';
        logObj.level = system.Level || 'N/A';

        if (eventData.Data) {
            const data = Array.isArray(eventData.Data) ? eventData.Data : [eventData.Data];
            data.forEach(item => {
                const key = item.$.Name.toLowerCase().replace(/\s+/g, '_');
                logObj[key] = item._ || item || 'N/A';
            });
        }

        logObj.message = logObj.message || `User ${logObj.subject_user_name || 'N/A'} performed action on ${logObj.target_user_name || 'N/A'} at ${logObj.destination_host || 'N/A'}.`;
        return logObj;
    } catch (xmlError) {
        console.log('Não é XML, tentando parsear como chave-valor:', xmlError.message);
    }

    const lines = logText.split('\n').filter(line => line.trim());
    for (const line of lines) {
        const [key, ...valueParts] = line.split(':').map(part => part.trim());
        const value = valueParts.join(':').trim();
        if (key && value) {
            logObj[key.toLowerCase().replace(/\s+/g, '_')] = value;
        }
    }

    return logObj;
}

// Rota POST para gerar relatório
app.post('/api/report', async (req, res) => {
    console.log('Requisição recebida:', req.body);
    const { log, iocs, categories, reportType } = req.body;

    if (!log || typeof log !== 'string') {
        console.error('Erro: Log inválido');
        return res.status(400).json({ error: 'Log é obrigatório e deve ser uma string' });
    }

    if (!reportType || !['base', 'refine', 'siem-health'].includes(reportType)) {
        console.error('Erro: Tipo de relatório inválido');
        return res.status(400).json({ error: 'Selecione um tipo de relatório válido' });
    }

    const safeIocs = Array.isArray(iocs) ? iocs : [];
    const safeCategories = Array.isArray(categories) ? categories : [];

    try {
        const logObj = await parseLogText(log);
        console.log('Log parseado:', logObj);

        let iocDetails = 'N/A';
        if (safeIocs.length > 0) {
            const iocResults = await Promise.all(safeIocs.map(ioc => checkIOC(ioc)));
            iocDetails = iocResults.map(result => {
                const errorStr = result.error ? `Erro: ${result.error}` : '';
                return `Type: ${result.type}, Value: ${result.ioc}, Score: ${result.score}, Reported: ${result.isReported} ${errorStr}`;
            }).join('\n---\n');
        }

        // Determinar saudação baseada no horário atual
        const hour = new Date().getHours();
        let saudacao = 'boa tarde';
        if (hour < 12) saudacao = 'bom dia';
        else if (hour >= 18) saudacao = 'boa noite';

        const relatorioPrompt = `
Você é um analista de segurança cibernética especializado em uma equipe de monitoramento. Sua tarefa é analisar o log fornecido, identificar os evento ocorrido e gerar um relatório claro, conciso e profissional para o cliente, solicitando validações. O relatório deve seguir rigorosamente o modelo abaixo, preenchendo todos os campos com base no log. Se uma informação não estiver disponível, use "N/A". Use linguagem profissional, objetiva e acessível, evitando jargões técnicos excessivos, mas mantendo precisão.

**Instruções**:
- **Caso de uso**: Descreva o evento (ex.: falha de login, acesso não autorizado) com base no log.
- **Análise**: Forneça uma análise técnica detalhada, incluindo contexto (tipo de evento), impacto potencial (ex.: interrupção de serviço) e implicações.
- **Objetivo do caso de uso**: Especifique o objetivo da análise (ex.: detectar intrusões, identificar falhas de autenticação).
- **Fonte de dados**: Use "Windows Event Log" para logs XML ou "Syslog" para logs Syslog. Se não identificável, use "N/A".
- **Justificativa**: Explique por que o evento justifica investigação, considerando gravidade, tipo de evento, número de tentativas (se aplicável) e impacto potencial (ex.: comprometimento de credenciais).
- **Recomendações**: Liste 3-5 ações práticas e acionáveis para mitigar o evento e prevenir recorrências, alinhadas com padrões como NIST ou CIS Controls. Considere as categorias: ${safeCategories.join(', ')}.
- **Resultado**: Derive do campo 'message' (ex.: "Failed" para "Login failed") ou use "N/A" se não aplicável.
- **Status**: Use "N/A" a menos que o log forneça um campo 'status' explícito.
- **Campos ausentes**: Use "N/A" para campos sem informação no log.
- **Formatação**: Siga exatamente o modelo abaixo, incluindo quebras de linha e emojis. Retorne o relatório em texto puro, sem formatação adicional (ex.: markdown, HTML).

**Modelo do Relatório**:

Prezados(as), ${saudacao}.

Nossa equipe identificou uma atividade suspeita em seu ambiente. Seguem abaixo mais detalhes para validação:

Caso de uso: [Descreva o caso de uso com base no log]
🕵 Análise: [Análise técnica detalhada]

Objetivo do caso de uso: [Objetivo da análise]

📊 Fonte de dados utilizada na análise: [Fonte do log]

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
Detalhes dos IOCs: ${iocDetails}

🕵 Justificativa para abertura do caso: [Justificativa clara]

📌 Recomendações:
1. [Recomendação 1]
2. [Recomendação 2]
3. [Recomendação 3]
4. [Recomendação 4, se aplicável]
5. [Recomendação 5, se aplicável]

**Log fornecido**: ${log}

Gere o relatório EXATAMENTE no formato especificado, preenchendo todos os campos com base no log fornecido.
`;
        const refinePrompt = `
Você é um analista de segurança cibernética especializado em análise de monitoramento e refino de regras. Sua tarefa é analisar o log fornecido, identificar o evento ocorrido, determinar se o alerta gerado é um falso positivo e redigir uma solicitação clara, concisa e profissional para a equipe de sustentação, solicitando a validação de um possível refino da regra. O relatório deve seguir rigorosamente o modelo abaixo, preenchendo todos os campos com base no log. Se uma informação não estiver disponível, use "Não disponível". Use linguagem técnica, mas clara, adequada para a equipe de sustentação.

**Instruções**:
- **Cabeçalho**: Inclua o nome da regra no título. Use "N/A" se não disponível no log.
- **Saudação e Introdução**: Use uma saudação profissional (ex.: "Prezados, bom dia") e explique brevemente o contexto do alerta, destacando a possibilidade de falsos positivos.
- **Justificativa**:
  - **Exemplo de evento relevante**: Descreva o evento detectado (ex.: data, IP, ação, sistema afetado) com base no log.
  - **Motivo do falso positivo**: Explique por que o alerta é considerado um falso positivo (ex.: atividade legítima, comportamento esperado de uma aplicação).
- **Solicitação**: Formule uma solicitação clara para a equipe de sustentação, sugerindo ações específicas (ex.: exclusão de IPs, ajuste de parâmetros, revisão de assinaturas).
- **Campos ausentes**: Use "Não disponível" para campos sem informação no log.
- **Formatação**: Siga exatamente o modelo abaixo, incluindo quebras de linha e emojis. Retorne o relatório em texto puro, sem formatação adicional (ex.: markdown, HTML).

**Modelo do Relatório**:

Solicitação de Refino de Regra no SIEM - [Nome da Regra]

[Prezados, ${saudacao}. Identificamos um alerta gerado pela regra [Nome da Regra] no SIEM, que pode estar gerando falsos positivos, impactando a eficiência do monitoramento.]

🔍 Justificativa:
- Exemplo de evento relevante: [Descrição do evento detectado, incluindo detalhes como data, IP, ação ou sistema afetado]
- Motivo do falso positivo: [Explicação do porquê o alerta é considerado um falso positivo]

📌 Solicitação:
[Solicitação clara para a equipe de sustentação, ex.: "Solicitamos a validação da regra [Nome da Regra] para verificar se ajustes são necessários, como exclusão de IPs específicos, ajuste de parâmetros ou revisão de assinaturas."]

🛡️ Considerações Finais:
📋 Nome do Alerta: [Nome do alerta no SIEM]
📋 Sub-ID do Evento: [Identificador único do evento, se disponível]
📋 Assinatura: [Assinatura da regra que gerou o alerta, se aplicável]
📋 Amostra de Evidência: [Trecho do log ou evidência específica que ilustra o evento]
📂 Caso no SIEM: [Número do caso ou chamado no SIEM, se disponível]

**Log fornecido**: ${log}

Gere o relatório EXATAMENTE no formato especificado, preenchendo todos os campos com base no log fornecido.`;

        const siemHealthPrompt = `
Você é um analista de segurança cibernética especializado em monitoramento e manutenção da saúde de sistemas SIEM. Sua tarefa é analisar o log fornecido, identificar possíveis problemas relacionados à saúde do SIEM (ex.: falhas na coleta de logs, atrasos, falsos positivos, regras mal configuradas, integrações inativas) e redigir um relatório claro, conciso e profissional para a equipe de manutenção do SIEM, solicitando validação ou ações corretivas. O relatório deve seguir rigorosamente o modelo abaixo, preenchendo todos os campos com base no log. Se uma informação não estiver disponível, use "Não disponível". Use linguagem técnica, mas acessível, adequada para a equipe de manutenção.

**Instruções**:
- **Caso de uso**: Descreva o problema identificado (ex.: falha na coleta de logs, atraso na ingestão) com base no log.
- **Justificativa**: Explique por que o evento indica um problema na saúde do SIEM, considerando impacto (ex.: lacunas no monitoramento) e gravidade.
- **Objetivo do caso de uso**: Especifique o objetivo da análise (ex.: garantir coleta em tempo real, corrigir regras mal configuradas).
- **Fonte de dados**: Use "Windows Event Log" para logs XML, "Syslog" para logs Syslog, ou "N/A" se não identificável.
- **Campos ausentes**: Use "Não disponível" para campos sem informação no log.
- **Resultado**: Derive do campo 'message' (ex.: "Failed" para "Log collection failed") ou use "N/A" se não aplicável.
- **Status**: Use "N/A" a menos que o log forneça um campo 'status' explícito.
- **Formatação**: Siga exatamente o modelo abaixo, incluindo quebras de linha e emojis. Retorne o relatório em texto puro, sem formatação adicional (ex.: markdown, HTML).

**Modelo do Relatório**:

Prezados(as), ${saudacao}.

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

**Log fornecido**: ${log}

Gere o relatório EXATAMENTE no formato especificado, preenchendo todos os campos com base no log fornecido.

`;

        const prompt = reportType === 'base' ? relatorioPrompt : reportType === 'refine' ? refinePrompt : siemHealthPrompt;
        console.log('Prompt enviado à IA:', prompt); // Depuração

        const response = await axios.post(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent',
            { contents: [{ parts: [{ text: prompt }] }] },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'x-goog-api-key': process.env.GEMINI_API_KEY,
                },
            }
        );

        let report = response.data.candidates[0].content.parts[0].text;
        console.log('Resposta da IA:', report); // Depuração
        report = report.replace(/\*\*|#|\*|_|\[.*?\]\(.*?\)/g, '');
        res.json({ report });
    } catch (error) {
        console.error('Erro na requisição:', error.message, error.response?.data);
        // Usar alternativa fixa apenas se a API falhar
        const hour = new Date().getHours();
        let saudacao = 'boa tarde';
        if (hour < 12) saudacao = 'bom dia';
        else if (hour >= 18) saudacao = 'boa noite';
        res.json({ report });
    }
});

// Função para iniciar o servidor
function createServer() {
    const server = app.listen(process.env.PORT || 30000, () => {
        console.log(`Servidor rodando em http://localhost:${process.env.PORT || 30000}`);
    });
    return server;
}

// Exporta a função createServer
module.exports = { createServer };