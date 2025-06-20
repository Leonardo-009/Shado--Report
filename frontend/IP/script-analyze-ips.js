function generateProfessionalBarChart(iocData, container) {
    container.innerHTML = ''; // Limpa o contêiner

    const ipData = iocData.filter(item => item.type === 'ip' && item.score >= 0); // Filtra apenas IPs com score válido

    if (ipData.length === 0) {
        container.innerHTML = '<p style="color: #ffffff80; text-align: center; font-style: italic;">Nenhum IP reportado para exibir.</p>';
        return;
    }

    // Cria o cabeçalho
    const header = document.createElement('div');
    header.className = 'chart-header';
    header.innerHTML = `
        <span>IP</span>
        <span>Score</span>
        <span>Status</span>
    `;
    container.appendChild(header);

    // Cria uma barra para cada IP
    ipData.forEach(item => {
        const score = item.score;
        const barContainer = document.createElement('div');
        barContainer.className = 'bar-item';
        barContainer.dataset.tooltip = `Score: ${score}%\nÚltimo reporte: N/A`; // Placeholder para tooltip
        barContainer.style.marginBottom = '1rem';

        const ipLabel = document.createElement('span');
        ipLabel.className = 'ip-label';
        ipLabel.textContent = item.ioc;

        const barWrapper = document.createElement('div');
        barWrapper.className = 'bar-wrapper';

        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.width = '0'; // Inicia com largura 0 para animação
        const barColor = score >= 75 ? '#ff4d4d' : score >= 50 ? '#ffca3a' : '#52b788'; // Vermelho, Amarelo, Verde
        bar.style.background = `linear-gradient(90deg, ${barColor}, ${barColor}d9)`;
        bar.style.boxShadow = 'inset 0 2px 6px rgba(0, 0, 0, 0.2)';

        const scoreLabel = document.createElement('span');
        scoreLabel.className = 'score-label';
        scoreLabel.textContent = `${score}%`;

        const statusIcon = document.createElement('span');
        statusIcon.className = 'status-icon';
        statusIcon.innerHTML = score >= 75 ? '⚠️' : score >= 50 ? '🔔' : '✅';

        barWrapper.appendChild(bar);
        barContainer.appendChild(ipLabel);
        barContainer.appendChild(barWrapper);
        barContainer.appendChild(scoreLabel);
        barContainer.appendChild(statusIcon);
        container.appendChild(barContainer);

        // Animação ao carregar
        requestAnimationFrame(() => {
            bar.style.width = `${score}%`;
        });

        // Efeito hover
        barContainer.addEventListener('mouseenter', () => {
            barContainer.style.transform = 'translateY(-3px)';
            barContainer.style.boxShadow = `0 6px 18px rgba(${hexToRgb(barColor).join(', ')}, 0.4)`;
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = barContainer.dataset.tooltip;
            document.body.appendChild(tooltip);
            const rect = barContainer.getBoundingClientRect();
            tooltip.style.left = `${rect.left + rect.width / 2}px`;
            tooltip.style.top = `${rect.top - 40}px`;
        });

        barContainer.addEventListener('mouseleave', () => {
            barContainer.style.transform = 'translateY(0)';
            barContainer.style.boxShadow = 'none';
            const tooltip = document.querySelector('.tooltip');
            if (tooltip) tooltip.remove();
        });
    });
}

// Função auxiliar para converter hex para RGB
function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? [
        parseInt(result[1], 16),
        parseInt(result[2], 16),
        parseInt(result[3], 16)
    ] : [0, 0, 0];
}

function isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    return ip.split('.').every(num => parseInt(num) >= 0 && parseInt(num) <= 255);
}

function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function isValidHash(hash) {
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    return hashRegex.test(hash);
}

function encodeForUrl(ioc) {
    return encodeURIComponent(ioc).replace(/'/g, "%27").replace(/"/g, "%22");
}

async function analyzeIocs() {
    const iocList = document.getElementById('iocList').value.split('\n').filter(ioc => ioc.trim() !== '');
    const iocResults = document.getElementById('iocResults');
    const distributionChartContainer = document.getElementById('distributionChartContainer');
    const statusDiv = document.getElementById('status');

    if (iocList.length === 0) {
        iocResults.innerHTML = '<p>Por favor, insira pelo menos um IOC (IP, URL ou Hash).</p>';
        updateStatus('ERRO: Nenhum IOC fornecido', 'status-error');
        return;
    }

    updateStatus('PROCESSANDO: Analisando IOCs...', 'status-processing');

    try {
        const response = await fetch('http://localhost:30000/api/analyze-iocs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ iocs: iocList })
        });
        const data = await response.json();
        console.log('Resposta da API:', data);

        if (response.ok) {
            let resultsHtml = '<h3 class="section-title">IOCs Reportados</h3><div class="results-table"><table>';
            resultsHtml += `
                <thead>
                    <tr>
                        <th>IOC</th>
                        <th>Score</th>
                        <th>AbuseIPDB</th>
                    </tr>
                </thead>
                <tbody>
            `;
            data.reported.forEach(result => {
                const abuseUrl = result.type === 'ip' ? `https://www.abuseipdb.com/check/${encodeForUrl(result.ioc)}` : '';
                resultsHtml += `
                    <tr>
                        <td>${result.ioc}</td>
                        <td>${result.type === 'ip' ? `${result.score}%` : '-'}</td>
                        <td>${result.type === 'ip' ? abuseUrl : '-'}</td>
                    </tr>
                `;
            });
            resultsHtml += '</tbody></table></div>';

            resultsHtml += '<h3 class="section-title">IOCs Não Reportados</h3><div class="results-table"><table>';
            resultsHtml += `
                <thead>
                    <tr>
                        <th>IOC</th>
                        <th>Tipo</th>
                        <th>AbuseIPDB</th>
                    </tr>
                </thead>
                <tbody>
            `;
            data.unreported.forEach(result => {
                const abuseUrl = result.type === 'ip' ? `https://www.abuseipdb.com/check/${encodeForUrl(result.ioc)}` : '';
                resultsHtml += `
                    <tr>
                        <td>${result.ioc}</td>
                        <td>${result.type}</td>
                        <td>${result.type === 'ip' ? abuseUrl : '-'}</td>
                    </tr>
                `;
            });
            resultsHtml += '</tbody></table></div>';

            iocResults.innerHTML = resultsHtml;

            // Gerar gráfico de distribuição para IPs
            const allIocs = [...data.reported, ...data.unreported];
            generateProfessionalBarChart(allIocs, distributionChartContainer);
            updateStatus('SUCESSO: Análise concluída!', 'status-success');
        } else {
            iocResults.innerHTML = `<p>Erro: ${data.error}</p>`;
            updateStatus(`ERRO: ${data.error}`, 'status-error');
        }
    } catch (error) {
        iocResults.innerHTML = `<p>Erro ao conectar: ${error.message}</p>`;
        updateStatus(`ERRO: ${error.message}`, 'status-error');
        console.error('Erro detalhado:', error);
    }
}

function updateStatus(message, statusClass) {
    const statusDiv = document.getElementById('status');
    statusDiv.textContent = message;
    statusDiv.className = 'status ' + statusClass;
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
}