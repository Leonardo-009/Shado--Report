const { app, BrowserWindow } = require('electron');
const path = require('path');
const { createServer } = require('./backend/index');

require('dotenv').config({ path: path.join(__dirname, 'backend', '.env') });

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        // width: 1200,
        // height: 800,
        frame: true,
        maximizable: true,
        icon: path.join(__dirname, './shadow.ico'), // Adiciona o ícone aqui
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            enableRemoteModule: true
        }
    });

    mainWindow.maximize();
    mainWindow.setMenu(null);

    mainWindow.loadFile(path.join(__dirname, './frontend', 'index.html'));

    // Opcional: Adicione para depuração
    // mainWindow.webContents.openDevTools();

    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    mainWindow.webContents.on('before-input-event', (event, input) => {
        if ((input.control && input.key.toLowerCase() === 'q') || input.alt && input.key.toLowerCase() === 'f4') {
            app.quit();
        }
    });
}

app.on('ready', () => {
    try {
        const server = createServer();
        createWindow();
    } catch (error) {
        console.error('Erro ao iniciar o servidor:', error);
        app.quit();
    }
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});

process.on('uncaughtException', (error) => {
    console.error('Exceção não tratada:', error);
    if (mainWindow) {
        mainWindow.webContents.send('error', error.message);
    }
    app.quit();
});