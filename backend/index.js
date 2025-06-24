const express = require('express');
const axios = require('axios');
const cors = require('cors');
const xml2js = require('xml2js');
const crypto = require('crypto');
const ipRangeCheck = require('ip-range-check');
const querystring = require('querystring');
const url = require('url');
const path = require('path');

require('dotenv').config({ path: __dirname + '/.env' });

const app = express();

// Configuração de arquivos estáticos
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Verificação de variáveis de ambiente essenciais
const requiredEnvVars = ['GEMINI_API_KEY', 'ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY'];
const missingEnvVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingEnvVars.length > 0) {
    console.error(`Erro: Variáveis de ambiente ausentes: ${missingEnvVars.join(', ')}`);
    process.exit(1);
}

// Configuração do CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:30000', 'http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:8080'];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        try {
            const originUrl = new URL(origin);
            const isAllowed = allowedOrigins.some(allowed => {
                try {
                    const allowedUrl = new URL(allowed);
                    return originUrl.hostname === allowedUrl.hostname &&
                        originUrl.protocol === allowedUrl.protocol;
                } catch {
                    return false;
                }
            });
            if (isAllowed) return callback(null, true);
        } catch (e) {
            console.warn(`Erro ao validar origem CORS: ${origin}`, e.message);
        }
        console.warn(`Acesso CORS negado para origem: ${origin}`);
        callback(new Error(`Origem ${origin} não permitida pelo CORS`));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());

// Middleware de VPN
function restrictToVPN(req, res, next) {
    const vpnEnabled = process.env.ENABLE_VPN === 'true';
    const allowedRanges = process.env.ALLOWED_IP_RANGES ? process.env.ALLOWED_IP_RANGES.split(',') : [];

    if (!vpnEnabled) return next();
    if (allowedRanges.length === 0) {
        return res.status(403).json({ error: 'Acesso negado: configure ALLOWED_IP_RANGES no .env' });
    }

    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    if (!clientIp || !isValidIP(clientIp)) {
        return res.status(403).json({ error: 'Acesso negado: IP inválido' });
    }

    if (!ipRangeCheck(clientIp, allowedRanges)) {
        return res.status(403).json({ error: 'Acesso negado: requisição fora da VPN.' });
    }
    next();
}

app.use(restrictToVPN);

// Funções de ofuscação
function obfuscateForPrompt(data) {
    if (!data || data === 'N/A') return 'N/A';

    if (isValidIP(data)) {
        const parts = data.split('.');
        return `[REDACTED_IP].${parts[3]}`;
    }

    if (typeof data === 'string' && data.includes('.')) {
        const parts = data.split('.');
        if (parts.length > 1) {
            return `[REDACTED_HOST].${parts.slice(-1).join('.')}`;
        }
    }

    if (typeof data === 'string') {
        if (data.length <= 3) return '[REDACTED_USER]';
        return `${data.charAt(0)}[REDACTED]${data.length > 1 ? data.slice(-1) : ''}`;
    }

    return '[REDACTED_DATA]';
}

function obfuscateSensitiveData(data) {
    if (!data || data === 'N/A') return 'N/A';
    if (isValidIP(data)) {
        const parts = data.split('.');
        return `***.***.${parts[2]}.${parts[3]}`;
    }
    if (typeof data === 'string') {
        if (data.length <= 6) return '***';
        return `${data.slice(0, 3)}...${data.slice(-3)}`;
    }
    return '***';
}

// Funções de validação
function isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    return ip.split('.').every(num => {
        const n = parseInt(num, 10);
        return !isNaN(n) && n.toString() === num && n >= 0 && n <= 255;
    });
}

function isValidURL(inputUrl) {
    try {
        new URL(inputUrl);
        return true;
    } catch {
        try {
            new URL(`http://${inputUrl}`);
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

// Funções de API
async function checkAbuseIPDB(ip) {
    if (!isValidIP(ip)) return { error: 'Endereço IP inválido' };
    try {
        const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: {
                Key: process.env.ABUSEIPDB_API_KEY.trim(),
                Accept: 'application/json'
            },
            timeout: 5000
        });

        if (!response.data || !response.data.data) {
            throw new Error('Resposta inválida do AbuseIPDB');
        }

        return {
            confidenceScore: response.data.data.abuseConfidenceScore || 0,
            reports: response.data.data.totalReports || 0,
            country: response.data.data.countryCode || 'N/A',
            lastReported: response.data.data.lastReportedAt || 'N/A'
        };
    } catch (error) {
        console.error(`Erro ao consultar AbuseIPDB para ${ip}:`, error.message);
        return {
            error: error.response?.data?.message || 'Falha ao consultar AbuseIPDB',
            details: error.response?.data || {}
        };
    }
}

async function checkVirusTotal(ioc, type) {
    if (!ioc || !type) {
        console.error('Parâmetros inválidos para VirusTotal:', { ioc, type });
        return { error: 'Parâmetros inválidos', score: -1, isReported: false };
    }

    if (!process.env.VIRUSTOTAL_API_KEY) {
        console.error('Erro: VIRUSTOTAL_API_KEY não definida no ambiente');
        return { error: 'Chave de API do VirusTotal não configurada', score: -1, isReported: false };
    }

    try {
        let endpoint = '';
        if (type === 'ip') endpoint = `ip_addresses/${ioc}`;
        else if (type === 'url') endpoint = `urls`;
        else if (type === 'hash') endpoint = `files/${encodeURIComponent(ioc)}`;
        else {
            console.error('Tipo de IOC não suportado:', type);
            return { error: 'Tipo de IOC não suportado', score: -1, isReported: false };
        }

        console.log(`Iniciando consulta ao VirusTotal para IOC: ${ioc} (tipo: ${type})`);

        if (type === 'url') {
            const submitResponse = await axios.post(
                `https://www.virustotal.com/api/v3/${endpoint}`,
                querystring.stringify({ url: ioc }),
                {
                    headers: {
                        'x-apikey': process.env.VIRUSTOTAL_API_KEY.trim(),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 10000
                }
            );

            if (!submitResponse.data || !submitResponse.data.data || !submitResponse.data.data.id) {
                throw new Error('Resposta inválida do VirusTotal ao submeter URL');
            }

            console.log('URL submetida com sucesso:', submitResponse.data.data);
            const analysisId = submitResponse.data.data.id;
            const parsedUrl = new URL(ioc);
            const domain = parsedUrl.hostname;

            let analysisResult;
            for (let i = 0; i < 5; i++) {
                await new Promise(resolve => setTimeout(resolve, 2000));
                console.log(`Verificando status da análise: ${analysisId} (tentativa ${i + 1}/5)`);

                const resultResponse = await axios.get(
                    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                    {
                        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY.trim() },
                        timeout: 5000
                    }
                );

                if (!resultResponse.data || !resultResponse.data.data || !resultResponse.data.data.attributes) {
                    continue;
                }

                analysisResult = resultResponse.data.data.attributes;
                if (analysisResult.status === 'completed') break;
            }

            if (!analysisResult || analysisResult.status !== 'completed') {
                console.warn(`Análise incompleta para ${ioc}:`, analysisResult);
                return {
                    error: 'Análise não concluída a tempo',
                    score: -1,
                    isReported: false,
                    domain
                };
            }

            const analysis = analysisResult.stats || analysisResult.last_analysis_stats || {};
            const malicious = analysis.malicious || 0;
            const suspicious = analysis.suspicious || 0;
            const total = Object.values(analysis).reduce((a, b) => a + b, 0);

            console.log(`Resultado da análise para ${ioc}:`, { malicious, suspicious, total });
            return {
                score: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
                isReported: (malicious + suspicious) > 0,
                domain
            };

        } else {
            const response = await axios.get(
                `https://www.virustotal.com/api/v3/${endpoint}`,
                {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY.trim() },
                    timeout: 5000
                }
            );

            if (!response.data || !response.data.data || !response.data.data.attributes) {
                throw new Error('Resposta inválida do VirusTotal');
            }

            console.log(`Consulta direta concluída para ${ioc}`);
            const analysis = response.data.data.attributes.last_analysis_stats || {};
            const malicious = analysis.malicious || 0;
            const suspicious = analysis.suspicious || 0;
            const total = Object.values(analysis).reduce((a, b) => a + b, 0);

            console.log(`Resultado da análise para ${ioc}:`, { malicious, suspicious, total });
            return {
                score: total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0,
                isReported: (malicious + suspicious) > 0
            };
        }
    } catch (error) {
        console.error(`Erro ao consultar VirusTotal para ${ioc} (tipo: ${type}):`, {
            message: error.message,
            status: error.response?.status,
            data: error.response?.data,
            headersSent: error.config?.headers
        });

        try {
            const parsedUrl = new URL(ioc);
            return {
                error: error.response?.data?.error?.message || 'Falha ao consultar VirusTotal',
                score: -1,
                isReported: false,
                domain: type === 'url' ? parsedUrl.hostname : undefined
            };
        } catch {
            return {
                error: error.response?.data?.error?.message || 'Falha ao consultar VirusTotal',
                score: -1,
                isReported: false
            };
        }
    }
}

async function checkIOC(ioc, selectedType) {
    if (!ioc || typeof ioc !== 'string') {
        return { ioc, type: 'invalid', score: -1, isReported: false, error: 'IOC inválido' };
    }

    // Limpar o IOC
    ioc = ioc.trim();

    let type = 'unknown';
    if (isValidIP(ioc)) type = 'ip';
    else if (isValidURL(ioc)) type = 'url';
    else if (isValidHash(ioc)) type = 'hash';

    console.log(`Validando IOC: ${ioc}, Tipo: ${type}, Modo selecionado: ${selectedType}`);

    if (selectedType === 'ip' && type !== 'ip') {
        return {
            ioc,
            type: 'invalid',
            score: -1,
            isReported: false,
            error: 'Apenas IPs são permitidos neste modo'
        };
    } else if (selectedType === 'url_hash' && !['url', 'hash'].includes(type)) {
        return {
            ioc,
            type: 'invalid',
            score: -1,
            isReported: false,
            error: 'Apenas URLs ou Hashes são permitidos neste modo'
        };
    }

    try {
        if (type === 'ip') {
            const abuseResult = await checkAbuseIPDB(ioc);
            if (abuseResult.error) throw new Error(abuseResult.error);
            return {
                ioc,
                type,
                score: abuseResult.confidenceScore,
                isReported: abuseResult.confidenceScore > 0,
                details: {
                    reports: abuseResult.reports,
                    country: abuseResult.country,
                    lastReported: abuseResult.lastReported
                }
            };
        } else if (type === 'url' || type === 'hash') {
            const vtResult = await checkVirusTotal(ioc, type);
            if (vtResult.error) throw new Error(vtResult.error);
            return {
                ioc,
                type,
                score: vtResult.score,
                isReported: vtResult.isReported,
                domain: vtResult.domain
            };
        } else {
            return {
                ioc,
                type,
                score: -1,
                isReported: false,
                error: 'Tipo de IOC não reconhecido'
            };
        }
    } catch (error) {
        console.error(`Erro ao processar IOC ${ioc}:`, error.message);
        return {
            ioc,
            type,
            score: -1,
            isReported: false,
            error: error.message
        };
    }
}

// Rota para analisar IOCs
app.post('/api/analyze-iocs', async (req, res) => {
    try {
        const { iocs, type } = req.body;
        console.log('Requisição recebida para /api/analyze-iocs:', { iocs, type });

        if (!iocs || !Array.isArray(iocs) || iocs.length === 0 || iocs.length > 20) {
            return res.status(400).json({
                error: 'Forneça uma lista de 1 a 20 IOCs.'
            });
        }

        if (!type || !['ip', 'url_hash'].includes(type)) {
            return res.status(400).json({
                error: 'Tipo de IOC inválido. Use "ip" ou "url_hash".'
            });
        }

        // Limpar e filtrar IOCs
        const cleanedIocs = iocs
            .map(ioc => typeof ioc === 'string' ? ioc.trim() : '')
            .filter(ioc => ioc.length > 0);

        if (cleanedIocs.length === 0) {
            return res.status(400).json({
                error: 'Nenhum IOC válido fornecido.'
            });
        }

        const results = await Promise.all(cleanedIocs.map(ioc => checkIOC(ioc, type)));
        const reportedIOCs = results.filter(result => result.isReported && result.score !== -1);
        const unreportedIOCs = results.filter(result => !result.isReported || result.score === -1);

        const response = {
            reported: reportedIOCs,
            unreported: unreportedIOCs,
            stats: {
                reportedCount: reportedIOCs.length,
                unreportedCount: unreportedIOCs.length,
                total: results.length
            }
        };

        console.log('Resposta enviada para /api/analyze-iocs:', response);
        res.json(response);
    } catch (error) {
        console.error('Erro ao analisar IOCs:', error.message);
        res.status(500).json({
            error: 'Erro ao analisar IOCs: ' + error.message
        });
    }
});

// Função para parsear log
async function parseLogText(logText) {
    if (!logText || typeof logText !== 'string') return { error: 'Log inválido' };
    const logObj = {};
    const trimmedLog = logText.trim();

    try {
        const syslogRegex = /^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/;
        if (syslogRegex.test(trimmedLog)) {
            const content = trimmedLog.replace(syslogRegex, '');
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
                if (!logObj[key]) logObj[key] = pairs[key];
            });

            return logObj;
        }
    } catch (syslogError) {
        console.error('Erro ao parsear como Syslog:', syslogError.message);
    }

    try {
        if (trimmedLog.startsWith('<')) {
            const parser = new xml2js.Parser({ explicitArray: false, trim: true, mergeAttrs: true });
            const result = await parser.parseStringPromise(trimmedLog);
            const event = result.Event || {};
            const system = event.System || {};
            const eventData = event.EventData || {};

            logObj.eventid = system.EventID || 'N/A';
            logObj.time = system.TimeCreated?.$.SystemTime || 'N/A';
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

            logObj.message = logObj.message ||
                `User ${logObj.subject_user_name || 'N/A'} performed action on ${logObj.target_user_name || 'N/A'} at ${logObj.destination_host || 'N/A'}.`;

            return logObj;
        }
    } catch (xmlError) {
        console.error('Erro ao parsear como XML:', xmlError.message);
    }

    try {
        const lines = trimmedLog.split('\n').filter(line => line.trim());
        for (const line of lines) {
            const [key, ...valueParts] = line.split(':').map(part => part.trim());
            const value = valueParts.join(':').trim();
            if (key && value) logObj[key.toLowerCase().replace(/\s+/g, '_')] = value;
        }
        if (Object.keys(logObj).length === 0) logObj.raw_log = trimmedLog;
        return logObj;
    } catch (kvError) {
        console.error('Erro ao parsear como chave-valor:', kvError.message);
        return { error: 'Falha ao parsear o log', raw_log: trimmedLog };
    }
}

// Função para ofuscar dados dentro da mensagem
function obfuscateSensitiveInMessage(message) {
    if (!message || typeof message !== 'string') return 'N/A';

    // Ofuscar usuários no formato 'DOMAIN\username'
    message = message.replace(/(\\+)([^\\\s]+)/g, (match, slash, user) => {
        return slash + obfuscateForPrompt(user);
    });

    // Ofuscar IPs
    message = message.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (ip) => {
        return isValidIP(ip) ? obfuscateForPrompt(ip) : ip;
    });

    // Ofuscar hosts/domínios
    message = message.replace(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g, (host) => {
        return host.includes('.') ? obfuscateForPrompt(host) : host;
    });

    return message;
}

// Rota para gerar relatório com ofuscação
app.post('/api/report', async (req, res) => {
    try {
        const { log, iocs, categories, reportType } = req.body;

        // Validações
        if (!log || typeof log !== 'string') {
            return res.status(400).json({ error: 'Log é obrigatório e deve ser uma string' });
        }

        if (!reportType || !['base', 'refine', 'siem-health'].includes(reportType)) {
            return res.status(400).json({ error: 'Selecione um tipo de relatório válido' });
        }

        const safeIocs = Array.isArray(iocs) ? iocs.filter(ioc => typeof ioc === 'string' && ioc.trim()) : [];
        const safeCategories = Array.isArray(categories) ? categories.filter(cat => typeof cat === 'string' && cat.trim()) : [];

        // Parsear e ofuscar o log
        const logObj = await parseLogText(log);
        const obfuscatedLogObj = {
            ...logObj,
            username: obfuscateForPrompt(logObj.username),
            user: obfuscateForPrompt(logObj.user),
            subject_user_name: obfuscateForPrompt(logObj.subject_user_name),
            target_user_name: obfuscateForPrompt(logObj.target_user_name),
            computer: obfuscateForPrompt(logObj.computer),
            destination_host: obfuscateForPrompt(logObj.destination_host),
            source_ip: obfuscateForPrompt(logObj.source_ip),
            originatingcomputer: obfuscateForPrompt(logObj.originatingcomputer),
            ip_address: obfuscateForPrompt(logObj.ip_address),
            client_ip: obfuscateForPrompt(logObj.client_ip),
            message: obfuscateSensitiveInMessage(logObj.message)
        };

        // Processar IOCs com ofuscação
        let iocDetails = 'N/A';
        if (safeIocs.length > 0) {
            const iocResults = await Promise.all(safeIocs.map(ioc => checkIOC(ioc.trim())));
            iocDetails = iocResults.map(result => {
                const obfuscatedIoc = obfuscateForPrompt(result.ioc);
                return `Tipo: ${result.type}, Valor: ${obfuscatedIoc}, Score: ${result.score}, Reported: ${result.isReported}`;
            }).join('\n---\n');
        }

        // Determinar saudação
        const hour = new Date().getHours();
        let saudacao = 'boa tarde';
        if (hour < 12) saudacao = 'bom dia';
        else if (hour >= 18) saudacao = 'boa noite';

        // Construir o prompt com o formato exato solicitado
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

**Log fornecido**: ${JSON.stringify(obfuscatedLogObj, null, 2)}

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

**Log fornecido**: ${JSON.stringify(obfuscatedLogObj, null, 2)}

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

**Log fornecido**: ${JSON.stringify(obfuscatedLogObj, null, 2)}

Gere o relatório EXATAMENTE no formato especificado, preenchendo todos os campos com base no log fornecido.
`;

        const prompt = reportType === 'base' ? relatorioPrompt :
            reportType === 'refine' ? refinePrompt :
                siemHealthPrompt;

        console.log('Prompt enviado à IA:', prompt);

        const response = await axios.post(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent',
            {
                contents: [{
                    parts: [{
                        text: prompt
                    }]
                }]
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'x-goog-api-key': process.env.GEMINI_API_KEY.trim(),
                },
                timeout: 15000
            }
        );

        if (!response.data || !response.data.candidates || !response.data.candidates[0] || !response.data.candidates[0].content) {
            throw new Error('Resposta inválida da API Gemini');
        }

        let report = response.data.candidates[0].content.parts[0]?.text || 'Nenhum conteúdo retornado pela IA';
        console.log('Resposta da IA:', report);

        // Limpar formatação markdown
        report = report.replace(/\*\*|#|\*|_|\[.*?\]\(.*?\)/g, '');

        res.json({
            success: true,
            report,
            obfuscatedLog: obfuscatedLogObj
        });
    } catch (error) {
        console.error('Erro na requisição:', {
            message: error.message,
            stack: error.stack,
            response: error.response?.data
        });

        res.status(500).json({
            error: 'Erro ao gerar relatório: ' + error.message,
            details: error.response?.data || {}
        });
    }
});

// Inicialização do servidor
const PORT = process.env.PORT || 30000;
const server = app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});

// Tratamento de erros
process.on('unhandledRejection', (err) => {
    console.error('Erro não tratado:', err);
    server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
    console.error('Exceção não capturada:', err);
    server.close(() => process.exit(1));
});

module.exports = { app, server };