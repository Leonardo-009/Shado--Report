document.getElementById('ticketForm').addEventListener('submit', async function (event) {
    event.preventDefault(); // Impede o recarregamento da página

    const report = document.getElementById('report').value;
    const classification = document.getElementById('classification').value;
    const client = document.getElementById('client').value;
    const statusElement = document.getElementById('status');

    // Validação básica
    if (!report || !classification || !client) {
        statusElement.textContent = 'Por favor, preencha todos os campos.';
        statusElement.classList.add('text-red-500');
        return;
    }

    statusElement.textContent = 'Criando ticket...';
    statusElement.classList.remove('text-red-500', 'text-green-500');
    statusElement.classList.add('text-gray-600');

    try {
        const response = await fetch('http://localhost:30000/api/create-ticket', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                report,
                classification,
                client
            }),
            signal: AbortSignal.timeout(30000) // Timeout de 30 segundos
        });

        const data = await response.json();

        if (response.ok) {
            statusElement.textContent = `Ticket criado com sucesso! ID: ${data.ticketId}`;
            statusElement.classList.add('text-green-500');
            document.getElementById('ticketForm').reset();
        } else {
            throw new Error(data.error || 'Erro ao criar o ticket');
        }
    } catch (error) {
        statusElement.textContent = `Erro: ${error.message}`;
        statusElement.classList.add('text-red-500');
    }
});