function generateProfessionalBarChart(iocData, container) {
    console.log('generateProfessionalBarChart chamado com:', iocData);
    container.innerHTML = ''; // Limpa o contêiner

    const ipData = iocData.filter(item => item.type === 'ip' && item.score >= 0);
    if (ipData.length === 0) {
        container.innerHTML = '<p style="color: #ffffff80; text-align: center; font-style: italic;">Nenhum IP reportado para exibir.</p>';
        return;
    }

    const header = document.createElement('div');
    header.className = 'chart-header';
    header.innerHTML = `
        <span>IP</span>
        <span>Score</span>
        <span>Status</span>
    `;
    container.appendChild(header);

    ipData.forEach(item => {
        const score = item.score;
        const barContainer = document.createElement('div');
        barContainer.className = 'bar-item';
        barContainer.dataset.tooltip = `Score: ${score}%\nÚltimo reporte: N/A`;
        barContainer.style.marginBottom = '1rem';

        const ipLabel = document.createElement('span');
        ipLabel.className = 'ip-label';
        ipLabel.textContent = item.ioc;

        const barWrapper = document.createElement('div');
        barWrapper.className = 'bar-wrapper';

        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.width = '0';
        const barColor = score >= 75 ? '#ff4d4d' : score >= 50 ? '#ffca3a' : '#52b788';
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

        requestAnimationFrame(() => {
            bar.style.width = `${score}%`;
        });

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

        barContainer.addEventListener('mouseout', () => {
            barContainer.style.transform = 'translateY(0)';
            barContainer.style.boxShadow = 'none';
            const tooltip = document.querySelector('.tooltip');
            if (tooltip) tooltip.remove();
        });
    });
}

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
    return ip.split('.').every(num => parseInt(num) >= 0 && num <= 255);
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
    return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash);
}

function isValidInput(ioc) {
    return isValidIP(ioc) || isValidURL(ioc) || isValidHash(ioc);
}

function encodeForUrl(ioc) {
    return encodeURIComponent(ioc).replace(/'/g, "%27").replace(/"/g, "%22");
}

function generateReferenceUrl(ioc, type, domain) {
    console.log('generateReferenceUrl chamado:', { ioc, type, domain });
    if (type === 'ip') {
        return `https://www.abuseipdb.com/check/${encodeForUrl(ioc)}`;
    } else if (type === 'url') {
        return domain ? `https://www.virustotal.com/gui/domain/${encodeForUrl(domain)}` : '#';
    } else if (type === 'hash') {
        return `https://www.virustotal.com/gui/file/${encodeForUrl(ioc)}`;
    }
    return '#';
}

function updatePlaceholder() {
    console.log('updatePlaceholder chamada');
    const iocType = document.getElementById('iocType');
    const iocList = document.getElementById('iocList');
    if (!iocType || !iocList) {
        console.error('Elementos iocType ou iocList não encontrados');
        return;
    }
    iocList.placeholder = iocType.value === 'ip'
        ? 'Insira IPs, um por linha\nExemplo:\n8.8.8.8\n192.168.1.1'
        : 'Insira URLs ou Hashes, um por linha\nExemplo:\nhttps://example.com\n5d41402abc4b2a76b9719d911017c592';
}

function validateIocList() {
    const iocListElement = document.getElementById('iocList');
    const iocType = document.getElementById('iocType').value;
    if (!iocListElement) return;

    const lines = iocListElement.value.split('\n').map(line => line.trim()).filter(line => line);
    const invalidLines = lines.filter(ioc => {
        if (iocType === 'ip') return !isValidIP(ioc);
        return !isValidURL(ioc) && !isValidHash(ioc);
    });

    if (invalidLines.length > 0) {
        iocListElement.classList.add('invalid');
        iocListElement.title = `IOCs inválidos:\n${invalidLines.join('\n')}`;
    } else {
        iocListElement.classList.remove('invalid');
        iocListElement.title = '';
    }
}

async function analyzeIocs() {
    console.log('analyzeIocs chamado');
    const iocTypeElement = document.getElementById('iocType');
    const iocListElement = document.getElementById('iocList');
    const iocResults = document.getElementById('iocResults');
    const distributionChartContainer = document.getElementById('distributionChartContainer');
    const statusDiv = document.getElementById('status');

    if (!iocTypeElement || !iocListElement || !iocResults || !distributionChartContainer || !statusDiv) {
        console.error('Elementos não encontrados:', {
            iocTypeElement, iocListElement, iocResults, distributionChartContainer, statusDiv
        });
        updateStatus('ERRO: Elementos da página não encontrados', 'status-error');
        return;
    }

    const iocList = iocListElement.value.split('\n').map(ioc => ioc.trim()).filter(ioc => ioc);
    const iocType = iocTypeElement.value;

    console.log('Dados capturados:', { iocList, iocType });

    if (!iocList.length) {
        console.log('Nenhum IOC fornecido');
        iocResults.innerHTML = '<p>Por favor, insira pelo menos um IOC (IP, URL ou Hash).</p>';
        updateStatus('ERRO: Nenhum IOC fornecido', 'status-error');
        return;
    }

    if (!iocType) {
        console.log('Tipo de IOC não selecionado');
        iocResults.innerHTML = '<p>Por favor, selecione um tipo de IOC (IP ou URL/Hash).</p>';
        updateStatus('ERRO: Tipo de IOC não selecionado', 'status-error');
        return;
    }

    const invalidIocs = iocList.filter(ioc => !isValidInput(ioc));
    if (invalidIocs.length) {
        console.log('IOCs inválidos detectados:', invalidIocs);
        iocResults.innerHTML = `<p>IOCs inválidos: ${invalidIocs.join(', ')}</p>`;
        updateStatus('ERRO: IOCs inválidos detectados', 'status-error');
        return;
    }

    updateStatus('PROCESSANDO: Analisando IOCs...', 'status-processing');
    iocResults.innerHTML = '<p>Carregando resultados...</p>';

    try {
        console.log('Enviando requisição:', { iocs: iocList, type: iocType });
        const response = await fetch('http://localhost:30000/api/analyze-iocs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ iocs: iocList, type: iocType })
        });

        console.log('Resposta recebida:', { status: response.status, ok: response.ok });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Erro na resposta:', errorData);
            throw new Error(errorData.error || `Erro ${response.status}`);
        }

        const data = await response.json();
        console.log('Dados recebidos:', data);

        let resultsHtml = '<h3 class="section-title">Resultados da Análise</h3><div class="results-table"><table>';
        resultsHtml += `
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Score</th>
                    <th>Link de Referência</th>
                </tr>
            </thead>
            <tbody>
        `;
        const allIocs = [...(data.reported || []), ...(data.unreported || [])];
        allIocs.forEach(result => {
            const referenceUrl = generateReferenceUrl(result.ioc, result.type, result.domain);
            resultsHtml += `
                <tr>
                    <td>${result.ioc || '-'}</td>
                    <td>${result.score !== undefined && result.score !== -1 ? `${result.score}%` : '-'}</td>
                    <td><a href="${referenceUrl}" target="_blank">${referenceUrl}</a></td>
                </tr>
            `;
        });
        resultsHtml += '</tbody></table></div>';

        iocResults.innerHTML = resultsHtml;
        generateProfessionalBarChart(allIocs, distributionChartContainer);
        updateStatus('SUCESSO: Análise concluída!', 'status-success');
    } catch (error) {
        console.error('Erro ao analisar IOCs:', error.message, error.stack);
        iocResults.innerHTML = `<p>Erro ao conectar: ${error.message}</p>`;
        updateStatus(`ERRO: ${error.message}`, 'status-error');
    }
}

function updateStatus(message, statusClass) {
    console.log('updateStatus chamado:', { message, statusClass });
    const statusDiv = document.getElementById('status');
    if (statusDiv) {
        statusDiv.textContent = message;
        statusDiv.className = `status ${statusClass}`;
    } else {
        console.error('Elemento status não encontrado');
    }
}

function closeModal() {
    console.log('closeModal chamado');
    const modal = document.getElementById('modal');
    if (modal) {
        modal.classList.remove('active');
    } else {
        console.error('Elemento modal não encontrado');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM carregado, inicializando eventos');
    const analyzeButton = document.getElementById('analyzeButton');
    const iocListElement = document.getElementById('iocList');
    const iocTypeElement = document.getElementById('iocType');

    if (analyzeButton) {
        analyzeButton.addEventListener('click', () => {
            console.log('Botão Analisar IOCs clicado');
            analyzeIocs();
        });
    } else {
        console.error('Botão analyzeButton não encontrado');
    }

    if (iocListElement && iocTypeElement) {
        iocListElement.addEventListener('input', validateIocList);
        iocTypeElement.addEventListener('change', validateIocList);
        updatePlaceholder();
        validateIocList();
    }
});