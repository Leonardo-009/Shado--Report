async function analyzePatterns() {
    const logListElement = document.getElementById('logList');
    const patternResults = document.getElementById('patternResults');
    const statusDiv = document.getElementById('status');

    if (!logListElement || !patternResults || !statusDiv) {
        updateStatus('ERRO: Elementos da página não encontrados', 'error');
        showModal('Erro', 'Elementos da página não encontrados.');
        return;
    }

    const logs = logListElement.value.split('\n').map(log => log.trim()).filter(log => log);
    if (!logs.length) {
        patternResults.innerHTML = '<p>Por favor, insira pelo menos um log.</p>';
        updateStatus('ERRO: Nenhum log fornecido', 'error');
        showModal('Erro', 'Por favor, insira pelo menos um log.');
        return;
    }

    updateStatus('PROCESSANDO: Analisando padrões...', 'processing');
    patternResults.innerHTML = '<p>Carregando resultados...</p>';

    try {
        const response = await fetch('http://localhost:30000/api/analyze-patterns', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logs })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `Erro ${response.status}`);
        }

        const data = await response.json();
        let resultsHtml = '<h3 class="section-title">Padrões Identificados</h3><div class="results-table"><table>';
        resultsHtml += `
            <thead>
                <tr>
                    <th>Padrão</th>
                </tr>
            </thead>
            <tbody>
        `;
        data.patterns.forEach(pattern => {
            resultsHtml += `
                <tr>
                    <td>${pattern}</td>
                </tr>
            `;
        });
        resultsHtml += '</tbody></table></div>';

        patternResults.innerHTML = resultsHtml;
        updateStatus('SUCESSO: Análise concluída!', 'success');
    } catch (error) {
        console.error('Erro detalhado:', error);
        patternResults.innerHTML = `<p>Erro ao conectar: ${error.message}</p>`;
        updateStatus(`ERRO: ${error.message}`, 'error');
        showModal('Erro no Servidor', `Detalhes: ${error.message}`);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const analyzeButton = document.getElementById('analyzeButton');
    if (analyzeButton) {
        analyzeButton.addEventListener('click', analyzePatterns);
    }
    updateStatus('AGUARDANDO ENTRADA...', 'waiting');
});