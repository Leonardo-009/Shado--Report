function updateStatus(message, type) {
    const statusEl = document.getElementById('status');
    if (statusEl) {
        statusEl.innerHTML = `<i class="fas fa-${getStatusIcon(type)}"></i> ${message}`;
        statusEl.className = `status status-${type}`;
    }
}

function getStatusIcon(type) {
    switch (type) {
        case 'waiting': return 'clock';
        case 'processing': return 'spinner fa-spin';
        case 'success': return 'check-circle';
        case 'error': return 'exclamation-circle';
        default: return 'info-circle';
    }
}

function showModal(title, message) {
    const modal = document.getElementById('modal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');
    if (modal && modalTitle && modalMessage) {
        modalTitle.textContent = title;
        modalMessage.textContent = message;
        modal.classList.add('active');
    }
}

function closeModal() {
    const modal = document.getElementById('modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

function setupReportTypeOptions() {
    const reportOptions = document.querySelectorAll('.report-type-option');
    reportOptions.forEach(option => {
        const radio = option.querySelector('input[type="radio"]');
        if (radio) {
            if (radio.checked) {
                option.classList.add('selected');
                toggleRefineFields(radio.value);
            }
            option.addEventListener('click', function (e) {
                if (e.target.tagName === 'LABEL' || e.target.tagName === 'I') return;
                selectReportOption(this);
            });
            const label = option.querySelector('label');
            if (label) {
                label.addEventListener('click', function (e) {
                    selectReportOption(this.closest('.report-type-option'));
                    e.stopPropagation();
                });
            }
            radio.addEventListener('change', function () {
                if (this.checked) {
                    selectReportOption(this.closest('.report-type-option'));
                }
            });
        }
    });
}

function selectReportOption(selectedOption) {
    const reportOptions = document.querySelectorAll('.report-type-option');
    reportOptions.forEach(option => option.classList.remove('selected'));
    selectedOption.classList.add('selected');
    const radio = selectedOption.querySelector('input[type="radio"]');
    if (radio) {
        toggleRefineFields(radio.value);
    }
}

function toggleRefineFields(reportType) {
    const refineFields = document.getElementById('refineRuleFields');
    if (refineFields) {
        if (reportType === 'refine') {
            refineFields.classList.add('visible');
            refineFields.style.display = 'block';
        } else {
            refineFields.classList.remove('visible');
            setTimeout(() => {
                if (!refineFields.classList.contains('visible')) {
                    refineFields.style.display = 'none';
                }
            }, 300);
        }
    }
}

async function gerarRelatorio() {
    try {
        const logInputElement = document.getElementById('log');
        if (!logInputElement) {
            showModal('Erro', 'Elemento log não encontrado no HTML.');
            updateStatus('Erro de configuração.', 'error');
            return;
        }
        const logInput = logInputElement.value || '';
        console.log('Valor de logInput capturado:', logInput.slice(0, 50) + '...');
        if (!logInput.trim()) {
            showModal('Erro', 'Por favor, insira um log válido antes de gerar o relatório.');
            updateStatus('Log vazio.', 'error');
            return;
        }

        const reportType = document.querySelector('input[name="report-type"]:checked')?.value || 'base';
        const alertName = document.getElementById('alertName')?.value.trim() || 'Não disponível';
        const ruleName = document.getElementById('ruleName')?.value.trim() || 'Não disponível';

        updateStatus('Processando relatório...', 'processing');

        const requestBody = {
            log: logInput,
            categories: ['autenticação'],
            report_type: reportType,
            alertName: alertName,
            ruleName: ruleName
        };

        const response = await fetch('/api/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody),
            signal: AbortSignal.timeout(60000)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`${errorData.error}: ${errorData.details}`);
        }

        const data = await response.json();
        if (!data || !data.resposta || typeof data.resposta !== 'string') {
            throw new Error('Resposta inválida do servidor');
        }

        const outputElement = document.getElementById('reportOutput');
        if (outputElement) {
            if (data.resposta.includes('Análise') || data.resposta.includes('Solicitação')) {
                outputElement.innerText = data.resposta;
                updateStatus('Relatório gerado com sucesso!', 'success');
            } else {
                outputElement.innerText = 'Relatório inválido ou sem análise.';
                updateStatus('Relatório inválido.', 'error');
            }
        } else {
            throw new Error('Elemento reportOutput não encontrado');
        }
    } catch (error) {
        console.error('Erro detalhado:', error);
        let errorMessage = error.message;
        if (error.message.includes('Timeout')) {
            errorMessage = 'Timeout: O servidor demorou para responder. Tente novamente ou verifique a conexão com o Ollama.';
        }
        const outputElement = document.getElementById('reportOutput');
        if (outputElement) {
            outputElement.innerText = `Erro no Servidor\nDetalhes: ${errorMessage}`;
        }
        updateStatus(`Erro: ${errorMessage}`, 'error');
        showModal('Erro', errorMessage);
    }
}

function copyReport() {
    const reportOutput = document.getElementById('reportOutput');
    if (!reportOutput || reportOutput.textContent === 'Seu relatório será exibido aqui.') {
        showModal('Aviso', 'Nenhum relatório para copiar.');
        return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = reportOutput.textContent;
    textarea.style.position = 'fixed';
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showModal('Sucesso', 'Relatório copiado para a área de transferência!');
            setTimeout(closeModal, 2000);
        } else {
            throw new Error('Falha ao copiar');
        }
    } catch (err) {
        showModal('Erro', `Falha ao copiar o relatório: ${err.message}`);
        console.error('Erro ao copiar:', err);
    } finally {
        document.body.removeChild(textarea);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const reportButton = document.getElementById('reportButton');
    if (reportButton) {
        reportButton.addEventListener('click', gerarRelatorio);
    } else {
        console.error('Botão reportButton não encontrado no HTML.');
    }

    updateStatus('AGUARDANDO ENTRADA...', 'waiting');
    setupReportTypeOptions();
});