// Atualiza o status da interface
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

// Funções para gerenciar severidade
function getSeverityLevel(alertType) {
    const severityMap = {
        'critical': 90,
        'high': 70,
        'medium': 50,
        'low': 30,
        'info': 10
    };
    
    const patterns = {
        'critical': /ataque|exploit|vulnerabilidade crítica|critical|exploit/i,
        'high': /malware|phishing|invasão|high/i,
        'medium': /suspeito|anomalia|tentativa|medium/i,
        'low': /aviso|alerta menor|low/i,
        'info': /informação|log|info/i
    };
    
    if (severityMap.hasOwnProperty(alertType.toLowerCase())) {
        return severityMap[alertType.toLowerCase()];
    }
    
    for (const [level, pattern] of Object.entries(patterns)) {
        if (pattern.test(alertType)) {
            return severityMap[level];
        }
    }
    
    return 20;
}

function getSeverityEmoji(severity) {
    if (severity >= 80) return '🔴';
    if (severity >= 60) return '🟠';
    if (severity >= 40) return '🟡';
    if (severity >= 20) return '🔵';
    return '🟢';
}

function formatSeverity(alertType) {
    const severity = getSeverityLevel(alertType);
    const emoji = getSeverityEmoji(severity);
    return `${emoji} <span class="severity-${getSeverityClass(severity)}">${severity}%</span>`;
}

function getSeverityClass(severity) {
    if (severity >= 80) return 'critical';
    if (severity >= 60) return 'high';
    if (severity >= 40) return 'medium';
    if (severity >= 20) return 'low';
    return 'info';
}

// Exibe o modal com mensagem
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

// Fecha o modal
function closeModal() {
    const modal = document.getElementById('modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

// Valida IOC (IP ou URL básica)
function isValidIoc(ioc) {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const urlRegex = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/;
    return ipRegex.test(ioc) || urlRegex.test(ioc);
}

// Adiciona um IOC à lista
function addIocFromMainField() {
    const iocInput = document.getElementById('main-ioc-field');
    if (iocInput) {
        const iocValue = iocInput.value.trim();
        if (!iocValue || !isValidIoc(iocValue)) {
            showModal('Erro', 'Por favor, insira um IOC válido (IP ou URL).');
            return;
        }
        addIoc(iocValue);
        iocInput.value = '';
    }
}

function addIoc(value) {
    const iocList = document.getElementById('ioc-list');
    if (iocList) {
        const iocItem = document.createElement('div');
        iocItem.className = 'ioc-item';
        iocItem.innerHTML = `
            <input type="text" value="${value}" readonly>
            <button onclick="removeIoc(this)"><i class="fas fa-trash"></i></button>
        `;
        iocList.appendChild(iocItem);
    }
}

// Remove um IOC da lista
function removeIoc(button) {
    if (button && button.parentElement) {
        button.parentElement.remove();
    }
}

// Configura os tipos de relatório
function setupReportTypeOptions() {
    const reportOptions = document.querySelectorAll('.report-type-option');

    reportOptions.forEach(option => {
        const radio = option.querySelector('input[type="radio"]');
        if (radio && radio.checked) {
            option.classList.add('selected');
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
    });
}

function selectReportOption(selectedOption) {
    const reportOptions = document.querySelectorAll('.report-type-option');

    reportOptions.forEach(opt => {
        opt.classList.remove('selected');
        const radio = opt.querySelector('input[type="radio"]');
        if (radio) radio.checked = false;
    });

    selectedOption.classList.add('selected');
    const radio = selectedOption.querySelector('input[type="radio"]');
    if (radio) {
        radio.checked = true;
        radio.dispatchEvent(new Event('change'));
    }

    const errorElement = document.getElementById('reportTypeError');
    if (errorElement) errorElement.style.display = 'none';
}

// Gera o relatório
async function gerarRelatorio() {
    const log = document.getElementById('log')?.value.trim();
    const reportOutput = document.getElementById('reportOutput');
    const selectedReportType = document.querySelector('input[name="report-type"]:checked');
    const reportTypeError = document.getElementById('reportTypeError');

    if (!log || log.length < 10) {
        showModal('Erro', 'Por favor, insira um log válido (mínimo 10 caracteres).');
        updateStatus('ERRO: Log inválido', 'error');
        return;
    }

    if (!selectedReportType) {
        if (reportTypeError) reportTypeError.style.display = 'block';
        updateStatus('ERRO: Selecione um tipo de relatório', 'error');
        return;
    }

    updateStatus('PROCESSANDO: Analisando log...', 'processing');

    try {
        const iocs = Array.from(document.querySelectorAll('#ioc-list .ioc-item input'))
            .map(input => input.value.trim())
            .filter(ioc => ioc.length > 0);

        const response = await fetch('http://localhost:30000/api/report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                log,
                iocs,
                reportType: selectedReportType.value
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `Erro ${response.status}: ${response.statusText}`);
        }

        if (reportOutput) {
            let reportContent = data.report;
            
            // Adiciona severidade ao relatório
            let alertType = 'info';
            const alertPattern = /Tipo de Alerta:\s*(.*)/i;
            const match = reportContent.match(alertPattern);
            if (match && match[1]) {
                alertType = match[1].trim();
            }
            
            const severity = formatSeverity(alertType);
            reportContent = reportContent.replace(
                /(Tipo de Alerta:\s*.*)/i,
                `$1\nSeveridade: ${severity}`
            );
            
            reportOutput.innerHTML = reportContent.replace(/\n/g, '<br>');
            reportOutput.style.display = 'block';
            updateStatus('SUCESSO: Relatório gerado', 'success');
        }

    } catch (error) {
        console.error('Erro detalhado:', error);
        const errorMsg = error.message.includes('Failed to fetch')
            ? 'Falha na conexão com o servidor'
            : error.message;

        showModal('Erro no Servidor', `Detalhes: ${errorMsg}`);
        updateStatus(`ERRO: ${errorMsg}`, 'error');
    }
}

// Copia o relatório para a área de transferência
function copyReport() {
    const reportOutput = document.getElementById('reportOutput');
    if (!reportOutput || reportOutput.textContent === 'Seu relatório será exibido aqui.') {
        showModal('Aviso', 'Nenhum relatório para copiar.');
        return;
    }

    // Remove tags HTML ao copiar
    const textToCopy = reportOutput.textContent || reportOutput.innerText;
    
    navigator.clipboard.writeText(textToCopy).then(() => {
        showModal('Sucesso', 'Relatório copiado para a área de transferência!');
        setTimeout(closeModal, 2000);
    }).catch(err => {
        showModal('Erro', `Falha ao copiar o relatório: ${err.message}`);
        console.error('Erro ao copiar:', err);
    });
}

// Navegação
function handleNavigation() {
    const screens = document.querySelectorAll('.screen');
    const navLinks = document.querySelectorAll('.nav-link');
    const hash = window.location.hash || '#home';
    const targetScreenId = hash.replace('#', '') + '-screen';

    if (screens && navLinks) {
        screens.forEach(screen => screen.classList.remove('active-screen'));
        navLinks.forEach(link => link.classList.remove('active'));

        const targetScreen = document.getElementById(targetScreenId);
        if (targetScreen) {
            targetScreen.classList.add('active-screen');
            const activeLink = document.querySelector(`.nav-link[data-screen="${targetScreenId}"]`);
            if (activeLink) activeLink.classList.add('active');
        }
    }
}

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
    updateStatus('AGUARDANDO ENTRADA...', 'waiting');
    handleNavigation();
    window.addEventListener('hashchange', handleNavigation);

    const reportOutput = document.getElementById('reportOutput');
    if (reportOutput) {
        reportOutput.textContent = 'Seu relatório será exibido aqui.';
        reportOutput.style.display = 'block';
    }

    const addIocButton = document.getElementById('addIocButton');
    if (addIocButton) {
        addIocButton.addEventListener('click', addIocFromMainField);
    }

    setupReportTypeOptions();
});