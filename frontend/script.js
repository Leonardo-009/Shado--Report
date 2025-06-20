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

// Alterna visibilidade do grupo de categorias
function toggleTypeGroup(titleElement) {
    const group = titleElement ? titleElement.parentElement : null;
    if (group) {
        const isCollapsed = group.classList.contains('collapsed');
        group.classList.toggle('collapsed', !isCollapsed);
        const chevron = titleElement.querySelector('.fa-chevron-down');
        if (chevron) {
            chevron.classList.toggle('fa-chevron-up', isCollapsed);
        }
    }
}

// Atualiza as categorias selecionadas
function updateCategories() {
    const selectedCategories = Array.from(document.querySelectorAll('#incidentCategoriesContainer input[type="checkbox"]:checked'))
        .filter(cb => cb.id !== 'refine-rule' && cb.id !== 'siem-health')
        .map(cb => cb.value);
    console.log('Categorias selecionadas:', selectedCategories);
}

// Alterna visibilidade do grupo de monitoramento
function toggleMonitoringCategory() {
    const checkbox = document.getElementById('monitoring-toggle');
    const options = document.querySelector('.category-options');
    if (checkbox && options) {
        options.style.display = checkbox.checked ? 'block' : 'none';
    }
}

// Configura os tipos de relatório
function setupReportTypeOptions() {
    const reportOptions = document.querySelectorAll('.report-type-option');

    reportOptions.forEach(option => {
        // Verifica seleção prévia
        const radio = option.querySelector('input[type="radio"]');
        if (radio && radio.checked) {
            option.classList.add('selected');
        }

        // Click na opção
        option.addEventListener('click', function (e) {
            if (e.target.tagName === 'LABEL' || e.target.tagName === 'I') return;

            selectReportOption(this);
        });

        // Click no label
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

    // Remove seleção anterior
    reportOptions.forEach(opt => {
        opt.classList.remove('selected');
        const radio = opt.querySelector('input[type="radio"]');
        if (radio) radio.checked = false;
    });

    // Adiciona nova seleção
    selectedOption.classList.add('selected');
    const radio = selectedOption.querySelector('input[type="radio"]');
    if (radio) {
        radio.checked = true;
        radio.dispatchEvent(new Event('change'));
    }

    // Esconde mensagem de erro
    const errorElement = document.getElementById('reportTypeError');
    if (errorElement) errorElement.style.display = 'none';
}

// Gera o relatório usando sua API real
async function gerarRelatorio() {
    const log = document.getElementById('log')?.value.trim();
    const reportOutput = document.getElementById('reportOutput');
    const selectedReportType = document.querySelector('input[name="report-type"]:checked');
    const reportTypeError = document.getElementById('reportTypeError');

    if (!log) {
        showModal('Erro', 'Por favor, insira um log válido.');
        updateStatus('ERRO: Log não fornecido', 'error');
        return;
    }

    if (!selectedReportType) {
        if (reportTypeError) reportTypeError.style.display = 'block';
        updateStatus('ERRO: Selecione um tipo de relatório.', 'error');
        return;
    }

    if (reportTypeError) reportTypeError.style.display = 'none';

    const reportType = selectedReportType.value;
    const iocItems = document.querySelectorAll('#ioc-list .ioc-item input');
    const iocs = Array.from(iocItems).map(input => input.value);
    const selectedCategories = Array.from(document.querySelectorAll('#incidentCategoriesContainer input[type="checkbox"]:checked'))
        .filter(cb => cb.name !== 'report-type')
        .map(cb => cb.value);

    const payload = {
        log,
        iocs,
        categories: selectedCategories,
        reportType
    };

    updateStatus('PROCESSANDO: Enviando log e IOCs para análise...', 'processing');

    try {
        const response = await fetch('http://localhost:30000/api/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`Erro HTTP! status: ${response.status}`);
        }

        const data = await response.json();

        if (reportOutput && data.report) {
            reportOutput.textContent = data.report;
            const reportContainer = document.getElementById('reportContainer');
            if (reportContainer) {
                reportContainer.innerHTML = '';
                reportContainer.appendChild(reportOutput);
                // Remova esta linha: reportOutput.style.display = 'block';
            }
            updateStatus('SUCESSO: Relatório gerado com sucesso!', 'success');
        }
    } catch (error) {
        console.error('Erro ao gerar relatório:', error);
        showModal('Erro', `Erro ao conectar com o servidor: ${error.message}`);
        updateStatus(`ERRO: ${error.message}`, 'error');
    }
}

// Copia o relatório para a área de transferência
function copyReport() {
    const reportOutput = document.getElementById('reportOutput')?.textContent;
    if (!reportOutput || reportOutput === 'Seu relatório será exibido aqui.') {
        showModal('Aviso', 'Nenhum relatório para copiar.');
        return;
    }

    navigator.clipboard.writeText(reportOutput).then(() => {
        showModal('Sucesso', 'Relatório copiado para a área de transferência!');
        setTimeout(closeModal, 2000);
    }).catch(err => {
        showModal('Erro', `Falha ao copiar o relatório: ${err.message}`);
        console.error('Erro ao copiar:', err);
    });
}

// Navega para uma tela
function navigateTo(hash) {
    if (hash) {
        window.location.hash = hash;
        handleNavigation();
    }
}

// Gerencia navegação entre telas
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

// Modifique o evento DOMContentLoaded para inicializar com mensagem visível
document.addEventListener('DOMContentLoaded', () => {
    updateStatus('AGUARDANDO ENTRADA...', 'waiting');
    handleNavigation();
    window.addEventListener('hashchange', handleNavigation);

    const reportOutput = document.getElementById('reportOutput');
    if (reportOutput) {
        reportOutput.textContent = 'Seu relatório será exibido aqui.';
        // Garanta que está visível
        reportOutput.style.display = 'block';
    }

    // Configura os tipos de relatório
    setupReportTypeOptions();
})