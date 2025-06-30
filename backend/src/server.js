const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const { parseLogText } = require('./parseLog');
const { checkIOC } = require('./iocAnalysis');

require('dotenv').config({ path: path.join(__dirname, '../.env') });

const app = express();

// Configuração de arquivos estáticos
app.use(express.static(path.join(__dirname, '../../frontend')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../../frontend/index.html'));
});

// Configuração do CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:30000', 'http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:8080'];

app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());

// Middleware para logar todas as requisições
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Rota para analisar IOCs
app.post('/api/analyze-iocs', async (req, res) => {
    try {
        const { iocs, type } = req.body;
        console.log('Requisição recebida para /api/analyze-iocs:', { iocs, type });

        if (!iocs || !Array.isArray(iocs) || iocs.length === 0) {
            return res.status(400).json({ error: 'Forneça uma lista de pelo menos 1 IOC.' });
        }

        if (!type || !['ip', 'url_hash'].includes(type)) {
            return res.status(400).json({ error: 'Tipo de IOC inválido. Use "ip" ou "url_hash".' });
        }

        const cleanedIocs = iocs.map(ioc => typeof ioc === 'string' ? ioc.trim() : '').filter(ioc => ioc.length > 0);
        if (cleanedIocs.length === 0) {
            return res.status(400).json({ error: 'Nenhum IOC válido fornecido.' });
        }

        // Processar IOCs em lotes de 20
        const batchSize = 20;
        const results = [];
        const startTime = Date.now();

        for (let i = 0; i < cleanedIocs.length; i += batchSize) {
            const batch = cleanedIocs.slice(i, i + batchSize);
            console.log(`Processando lote de ${batch.length} IOCs (${i + 1} a ${Math.min(i + batchSize, cleanedIocs.length)} de ${cleanedIocs.length})`);

            const batchResults = await Promise.all(batch.map(ioc => checkIOC(ioc, type)));
            results.push(...batchResults);

            // Pausa de 2 segundos entre lotes para respeitar limites de taxa das APIs
            if (i + batchSize < cleanedIocs.length) {
                console.log('Aguardando 2 segundos antes do próximo lote...');
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }

        const duration = Date.now() - startTime;
        console.log(`Análise de IOCs concluída em ${duration}ms`);

        const reportedIOCs = results.filter(result => result.isReported && result.score !== -1);
        const unreportedIOCs = results.filter(result => !result.isReported || result.score === -1);

        res.json({
            reported: reportedIOCs,
            unreported: unreportedIOCs,
            stats: {
                reportedCount: reportedIOCs.length,
                unreportedCount: unreportedIOCs.length,
                total: results.length
            }
        });
    } catch (error) {
        console.error('Erro ao analisar IOCs:', error.message, error.stack);
        res.status(500).json({ error: 'Erro ao analisar IOCs: ' + error.message });
    }
});

// Rota para gerar relatório
app.post('/api/report', async (req, res) => {
    console.log('[%s] POST /api/report', new Date().toISOString());
    console.log('Requisição recebida:', req.body);

    if (!req.body.log || !req.body.log.trim()) {
        console.error('Erro: Log vazio na requisição');
        return res.status(400).json({ error: 'Log vazio', details: 'O campo log é obrigatório e não pode estar vazio.' });
    }

    const requestBody = {
        log: req.body.log || '',
        iocs: req.body.iocs || [],
        categories: req.body.categories && req.body.categories[0] ? req.body.categories : ['autenticação'],
        report_type: req.body.reportType || 'base',
        // Novo: Incluir alertName e ruleName
        alertName: req.body.alertName || 'Não disponível',
        ruleName: req.body.ruleName || 'Não disponível'
    };
    console.log('Enviando para Python:', {
        log: requestBody.log.slice(0, 50) + '...',
        iocs: requestBody.iocs,
        categories: requestBody.categories,
        report_type: requestBody.report_type,
        alertName: requestBody.alertName,
        ruleName: requestBody.ruleName
    });

    try {
        const startTime = Date.now();
        const pythonServiceUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
        const response = await axios.post(`${pythonServiceUrl}/analyze`, requestBody, {
            timeout: 60000
        });
        const duration = Date.now() - startTime;
        console.log('Resposta Python:', response.data, `Tempo: ${duration}ms`);
        res.json(response.data);
    } catch (error) {
        console.error('Erro ao gerar relatório:', error.message, error.stack);
        if (error.code === 'ECONNABORTED') {
            res.status(504).json({
                error: 'Timeout ao gerar relatório',
                details: 'O servidor demorou para responder. Tente novamente ou verifique a conexão com o Ollama.'
            });
        } else {
            res.status(500).json({
                error: 'Erro ao gerar relatório',
                details: error.message
            });
        }
    }
});

// Rota para responder a incidentes
app.post('/api/respond-incident', async (req, res) => {
    try {
        const { log } = req.body;
        console.log('Requisição recebida para /api/respond-incident:', { log: log.slice(0, 50) + '...' });

        if (!log || typeof log !== 'string') {
            return res.status(400).json({ error: 'Log é obrigatório e deve ser uma string' });
        }

        const startTime = Date.now();
        const pythonServiceUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
        const response = await axios.post(`${pythonServiceUrl}/respond`, {
            log
        }, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 60000
        });
        const duration = Date.now() - startTime;
        console.log(`Resposta do serviço Python (respond) recebida em ${duration}ms`);

        if (!response.data || !response.data.resposta) {
            throw new Error('Resposta inválida do serviço de resposta a incidentes');
        }

        res.json({
            success: true,
            actions: response.data.resposta
        });
    } catch (error) {
        console.error('Erro ao responder a incidente:', error.message, error.stack);
        if (error.code === 'ECONNABORTED') {
            res.status(504).json({
                error: 'Timeout ao responder a incidente',
                details: 'O servidor demorou para responder. Tente novamente ou verifique a conexão com o Ollama.'
            });
        } else {
            res.status(500).json({
                error: 'Erro ao responder a incidente: ' + error.message,
                details: error.response?.data || {}
            });
        }
    }
});

// Rota para análise de padrões
app.post('/api/analyze-patterns', async (req, res) => {
    try {
        const { logs } = req.body;
        console.log('Requisição recebida para /api/analyze-patterns:', { logs: logs.map(l => l.slice(0, 50) + '...') });

        if (!logs || !Array.isArray(logs) || logs.length === 0) {
            return res.status(400).json({ error: 'Forneça uma lista de logs válida' });
        }

        const startTime = Date.now();
        const pythonServiceUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
        const response = await axios.post(`${pythonServiceUrl}/patterns`, {
            logs
        }, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 60000
        });
        const duration = Date.now() - startTime;
        console.log(`Resposta do serviço Python (patterns) recebida em ${duration}ms`);

        if (!response.data || !response.data.resposta) {
            throw new Error('Resposta inválida do serviço de análise de padrões');
        }

        res.json({
            success: true,
            patterns: response.data.resposta
        });
    } catch (error) {
        console.error('Erro ao analisar padrões:', error.message, error.stack);
        if (error.code === 'ECONNABORTED') {
            res.status(504).json({
                error: 'Timeout ao analisar padrões',
                details: 'O servidor demorou para responder. Tente novamente ou verifique a conexão com o Ollama.'
            });
        } else {
            res.status(500).json({
                error: 'Erro ao analisar padrões: ' + error.message,
                details: error.response?.data || {}
            });
        }
    }
});

// Inicialização do servidor
const PORT = process.env.PORT || 30000;
const server = app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});

process.on('unhandledRejection', (err) => {
    console.error('Erro não tratado:', err.message, err.stack);
    server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
    console.error('Exceção não capturada:', err.message, err.stack);
    server.close(() => process.exit(1));
});

module.exports = { app, server };