const axios = require('axios');
require('dotenv').config();

const checkIOC = async (ioc, type) => {
    try {
        console.log(`Verificando IOC: ${ioc} (tipo: ${type})`);
        console.log(`ABUSEIPDB_API_KEY: ${process.env.ABUSEIPDB_API_KEY ? 'presente' : 'ausente'}`);
        console.log(`VIRUSTOTAL_API_KEY: ${process.env.VIRUSTOTAL_API_KEY ? 'presente' : 'ausente'}`);

        if (type === 'ip') {
            if (!process.env.ABUSEIPDB_API_KEY) {
                throw new Error('Chave de API do AbuseIPDB não configurada');
            }

            const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
                params: {
                    ipAddress: ioc,
                    maxAgeInDays: 90
                },
                headers: {
                    'Key': process.env.ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                },
                timeout: 10000
            });

            console.log(`Resposta do AbuseIPDB para ${ioc}:`, response.data);

            const data = response.data.data;
            return {
                ioc,
                isReported: data.totalReports > 0,
                score: data.abuseConfidenceScore || -1,
                country: data.countryCode || 'N/A',
                referenceLink: `https://www.abuseipdb.com/check/${ioc}`
            };
        } else if (type === 'url_hash') {
            if (!process.env.VIRUSTOTAL_API_KEY) {
                throw new Error('Chave de API do VirusTotal não configurada');
            }

            const isHash = /^[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}$/.test(ioc);
            
            if (isHash) {
                const response = await axios.get(`https://www.virustotal.com/api/v3/files/${ioc}`, {
                    headers: {
                        'x-apikey': process.env.VIRUSTOTAL_API_KEY
                    },
                    timeout: 10000
                });

                console.log(`Resposta do VirusTotal para hash ${ioc}:`, response.data);

                const data = response.data.data.attributes;
                return {
                    ioc,
                    isReported: data.last_analysis_stats?.malicious > 0,
                    score: data.last_analysis_stats?.malicious || -1,
                    country: data.country || 'N/A',
                    referenceLink: `https://www.virustotal.com/gui/file/${ioc}`
                };
            } else {
                const response = await axios.post(
                    'https://www.virustotal.com/api/v3/urls',
                    new URLSearchParams({ url: ioc }).toString(),
                    {
                        headers: {
                            'x-apikey': process.env.VIRUSTOTAL_API_KEY,
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        timeout: 10000
                    }
                );

                console.log(`Resposta da análise de URL ${ioc}:`, response.data);

                const analysisId = response.data.data.id;

                let attempts = 0;
                const maxAttempts = 10;
                let analysisResult;
                while (attempts < maxAttempts) {
                    const resultResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                        headers: {
                            'x-apikey': process.env.VIRUSTOTAL_API_KEY
                        },
                        timeout: 10000
                    });

                    console.log(`Resposta dos resultados da análise para ${ioc} (tentativa ${attempts + 1}):`, resultResponse.data);

                    analysisResult = resultResponse.data.data.attributes;
                    if (analysisResult.status === 'completed') {
                        break;
                    }
                    attempts++;
                    await new Promise(resolve => setTimeout(resolve, 3000));
                }

                if (analysisResult.status !== 'completed') {
                    throw new Error('Análise da URL não foi concluída a tempo');
                }

                const urlId = response.data.data.id.split('-')[1];
                const urlDetailsResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                    headers: {
                        'x-apikey': process.env.VIRUSTOTAL_API_KEY
                    },
                    timeout: 10000
                });

                console.log(`Detalhes da URL ${ioc}:`, urlDetailsResponse.data);

                const data = urlDetailsResponse.data.data.attributes;
                return {
                    ioc,
                    isReported: data.last_analysis_stats?.malicious > 0,
                    score: data.last_analysis_stats?.malicious || -1,
                    country: data.country || 'N/A',
                    referenceLink: `https://www.virustotal.com/gui/url/${urlId}`
                };
            }
        } else {
            throw new Error('Tipo de IOC inválido. Use "ip" ou "url_hash".');
        }
    } catch (error) {
        console.error(`Erro ao verificar IOC ${ioc}:`, error.response ? error.response.data : error.message);
        return {
            ioc,
            isReported: false,
            score: -1,
            country: 'N/A',
            referenceLink: '#',
            error: error.message
        };
    }
};

module.exports = { checkIOC };