const xml2js = require('xml2js');

async function parseLogText(logText) {
    if (!logText || typeof logText !== 'string') return { error: 'Log inválido' };
    const logObj = {};
    const trimmedLog = logText.trim();

    try {
        const syslogRegex = /^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/;
        if (syslogRegex.test(trimmedLog)) {
            const content = trimmedLog.replace(syslogRegex, '');
            const pairs = content.split(/\s+(?=\w+=)/).reduce((acc, pair) => {
                const [key, ...valueParts] = pair.split('=');
                if (key && valueParts.length) {
                    let value = valueParts.join('=').trim();
                    if (value.startsWith('"') && value.endsWith('"')) {
                        value = value.slice(1, -1);
                    }
                    acc[key.toLowerCase().replace(/\s+/g, '_')] = value;
                }
                return acc;
            }, {});

            logObj.eventid = pairs.eventid || 'N/A';
            logObj.time = pairs.timegenerated || pairs.timewritten || 'N/A';
            logObj.event_type = pairs.task || `EventID ${logObj.eventid}`;
            logObj.message = pairs.message || 'N/A';
            logObj.username = pairs.user || 'N/A';
            logObj.destination_host = pairs.computer || 'N/A';
            logObj.source_ip = pairs.originatingcomputer || 'N/A';
            logObj.level = pairs.level || 'N/A';
            logObj.event_category = pairs.eventcategory || 'N/A';

            Object.keys(pairs).forEach(key => {
                if (!logObj[key]) logObj[key] = pairs[key];
            });

            return logObj;
        }
    } catch (syslogError) {
        console.error('Erro ao parsear como Syslog:', syslogError.message);
    }

    try {
        if (trimmedLog.startsWith('<')) {
            const parser = new xml2js.Parser({ explicitArray: false, trim: true, mergeAttrs: true });
            const result = await parser.parseStringPromise(trimmedLog);
            const event = result.Event || {};
            const system = event.System || {};
            const eventData = event.EventData || {};

            logObj.eventid = system.EventID || 'N/A';
            logObj.time = system.TimeCreated?.SystemTime || 'N/A';
            logObj.event_type = system.Task || `EventID ${logObj.eventid}`;
            logObj.destination_host = system.Computer || 'N/A';
            logObj.level = system.Level || 'N/A';

            if (eventData.Data) {
                const data = Array.isArray(eventData.Data) ? eventData.Data : [eventData.Data];
                data.forEach(item => {
                    const key = item.Name.toLowerCase().replace(/\s+/g, '_');
                    logObj[key] = item._ || item || 'N/A';
                });
            }

            logObj.message = logObj.message ||
                `User ${logObj.subject_user_name || 'N/A'} performed action on ${logObj.target_user_name || 'N/A'} at ${logObj.destination_host || 'N/A'}.`;

            return logObj;
        }
    } catch (xmlError) {
        console.error('Erro ao parsear como XML:', xmlError.message);
    }

    try {
        const lines = trimmedLog.split('\n').filter(line => line.trim());
        for (const line of lines) {
            const [key, ...valueParts] = line.split(':').map(part => part.trim());
            const value = valueParts.join(':').trim();
            if (key && value) logObj[key.toLowerCase().replace(/\s+/g, '_')] = value;
        }
        if (Object.keys(logObj).length === 0) logObj.raw_log = trimmedLog;
        return logObj;
    } catch (kvError) {
        console.error('Erro ao parsear como chave-valor:', kvError.message);
        return { error: 'Falha ao parsear o log', raw_log: trimmedLog };
    }
}

module.exports = { parseLogText };