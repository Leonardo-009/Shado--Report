let iocChartInstance = null;

function updateStatus(message, statusClass) {
    const statusDiv = document.getElementById('status');
    if (statusDiv) {
        statusDiv.textContent = message;
        statusDiv.className = 'status-message';
        statusDiv.classList.add(statusClass);
    }
}

function showModal(title, message) {
    const modal = document.getElementById('modal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');

    if (modal && modalTitle && modalMessage) {
        modalTitle.textContent = title;
        modalMessage.textContent = message;
        modal.style.display = 'block';
    } else {
        console.error('Elementos do modal não encontrados');
    }
}

function closeModal() {
    const modal = document.getElementById('modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

async function analyzeIocs() {
    const iocListElement = document.getElementById('iocList');
    const iocTypeElement = document.getElementById('iocType');
    const iocResults = document.getElementById('iocResults');
    const statusDiv = document.getElementById('status');

    if (!iocListElement || !iocTypeElement || !iocResults || !statusDiv) {
        updateStatus('ERRO: Elementos da página não encontrados', 'error');
        showModal('Erro', 'Elementos da página não encontrados.');
        return;
    }

    const iocs = iocListElement.value.split('\n').map(ioc => ioc.trim()).filter(ioc => ioc);
    const type = iocTypeElement.value;

    if (!iocs.length) {
        iocResults.innerHTML = '<p>Por favor, insira pelo menos um IOC.</p>';
        updateStatus('ERRO: Nenhum IOC fornecido', 'error');
        showModal('Erro', 'Por favor, insira pelo menos um IOC.');
        return;
    }

    if (iocs.length > 100) {
        updateStatus(`PROCESSANDO: Analisando ${iocs.length} IOCs, isso pode levar alguns minutos...`, 'processing');
        showModal('Aviso', `Você está analisando ${iocs.length} IOCs. Isso pode levar alguns minutos devido aos limites das APIs externas.`);
    } else {
        updateStatus('PROCESSANDO: Analisando IOCs...', 'processing');
    }
    iocResults.innerHTML = '<p>Carregando resultados...</p>';

    try {
        console.log('Enviando requisição para /api/analyze-iocs:', { iocs, type });
        const response = await fetch('http://localhost:30000/api/analyze-iocs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ iocs, type })
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Erro na resposta:', errorData);
            throw new Error(errorData.error || `Erro ${response.status}`);
        }

        const data = await response.json();
        let resultsHtml = '<h3 class="section-title">IOCs Reportados</h3><div class="results-table"><table>';
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
        data.reported.forEach(result => {
            resultsHtml += `
                <tr>
                    <td>${result.ioc}</td>
                    <td>${result.score}%</td>
                    <td><a href="${result.referenceLink || '#'}" target="_blank" rel="noopener noreferrer">${result.referenceLink || 'N/A'}</a></td>
                </tr>
            `;
        });
        resultsHtml += '</tbody></table></div>';

        resultsHtml += '<h3 class="section-title">IOCs Não Reportados</h3><div class="results-table"><table>';
        resultsHtml += `
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Status</th>
                    <th>Link de Referência</th>
                </tr>
            </thead>
            <tbody>
        `;
        data.unreported.forEach(result => {
            resultsHtml += `
                <tr>
                    <td>${result.ioc}</td>
                    <td>${result.error || 'Não reportado'}</td>
                    <td><a href="${result.referenceLink || '#'}" target="_blank" rel="noopener noreferrer">${result.referenceLink || 'N/A'}</a></td>
                </tr>
            `;
        });
        resultsHtml += '</tbody></table></div>';

        iocResults.innerHTML = resultsHtml;
        updateStatus(`SUCESSO: Análise concluída! ${data.stats.reportedCount} IOCs reportados, ${data.stats.unreportedCount} não reportados.`, 'success');

        renderIOCChart(data);
    } catch (error) {
        console.error('Erro detalhado:', error);
        iocResults.innerHTML = `<p>Erro ao conectar: ${error.message}</p>`;
        updateStatus(`ERRO: ${error.message}`, 'error');
        showModal('Erro no Servidor', `Detalhes: ${error.message}`);
    }
}

function renderIOCChart(data) {
    const ctx = document.getElementById('iocChart');
    if (!ctx) return;

    if (iocChartInstance) {
        iocChartInstance.destroy();
        iocChartInstance = null;
    }

    const maxChartItems = 50;
    const labels = [...data.reported, ...data.unreported].slice(0, maxChartItems).map(result => result.ioc);
    const scores = [...data.reported, ...data.unreported].slice(0, maxChartItems).map(result => result.score !== -1 ? result.score : 0);

    iocChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Score de Ameaça',
                data: scores,
                backgroundColor: scores.map(score => score > 0 ? '#ff4d4d' : '#4CAF50')
            }]
        },
        options: {
            scales: {
                y: { beginAtZero: true }
            },
            plugins: {
                title: {
                    display: true,
                    text: `Score de Ameaça (mostrando até ${maxChartItems} IOCs)`
                }
            }
        }
    });
}

function updatePlaceholder() {
    const iocType = document.getElementById('iocType').value;
    const iocList = document.getElementById('iocList');
    if (iocType === 'ip') {
        iocList.placeholder = 'Cole IPs aqui (um por linha, ex.: 8.8.8.8)';
    } else {
        iocList.placeholder = 'Cole URLs ou hashes aqui (um por linha)';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const analyzeButton = document.getElementById('analyzeButton');
    if (analyzeButton) {
        analyzeButton.addEventListener('click', analyzeIocs);
    }
    updateStatus('AGUARDANDO ENTRADA...', 'waiting');

    const closeButton = document.querySelector('.close-button');
    if (closeButton) {
        closeButton.addEventListener('click', closeModal);
    }
});