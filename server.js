// server.js
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;

// --- Server-side Data Storage (Simple JSON files for demo) ---
const DATA_DIR = path.join(__dirname, 'data');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.json');
const OFFLINE_MESSAGES_FILE = path.join(DATA_DIR, 'offline_messages.json');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

let vaults = {};
let offlineMessages = {};
let connectedClients = {};

function loadData(filePath, defaultData) {
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error(`Error loading data from ${filePath}:`, error.message);
    }
    return defaultData;
}

function saveData(filePath, data) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
        console.error(`Error saving data to ${filePath}:`, error.message);
    }
}

vaults = loadData(VAULTS_FILE, {});
for (const vaultId in vaults) {
    if (vaults[vaultId].members) {
        vaults[vaultId].members = new Set(vaults[vaultId].members);
    } else {
        vaults[vaultId].members = new Set();
    }
}
offlineMessages = loadData(OFFLINE_MESSAGES_FILE, {});

// --- Cryptography on Server (for vault key encryption/decryption) ---
async function deriveKeyFromHashServer(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey);
        });
    });
}

function encryptDataServer(data, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([encrypted, tag]);
}

function decryptDataServer(encryptedDataWithTag, key, iv) {
    const tagLength = 16;
    const encryptedData = encryptedDataWithTag.slice(0, encryptedDataWithTag.length - tagLength);
    const tag = encryptedDataWithTag.slice(encryptedDataWithTag.length - tagLength);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    return decrypted;
}

// --- WebSocket Server Logic ---
wss.on('connection', (ws) => {
    let currentUserId = null;
    ws.on('message', async (message) => {
        let data;
        try {
             data = JSON.parse(message.toString());
        } catch (e) {
            console.error("Failed to parse incoming WebSocket message:", e, message.toString());
            ws.send(JSON.stringify({ type: 'error', message: 'Malformed message received.' }));
            return;
        }
        console.log('Received from client:', data.type, data.userId || '');

        if (data.type === 'register') {
            currentUserId = data.userId;
            connectedClients[currentUserId] = ws;
            console.log(`User ${currentUserId} connected.`);
            if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                ws.send(JSON.stringify({ type: 'offline_messages', messages: offlineMessages[currentUserId] }));
                delete offlineMessages[currentUserId];
                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                console.log(`Sent ${offlineMessages[currentUserId]?.length || 0} offline messages to ${currentUserId}`);
            }
        } else if (!currentUserId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Please register your user ID first.' }));
            return;
        }

        switch (data.type) {
            case 'create_vault':
                const vaultId = crypto.randomUUID();
                const vaultHash = crypto.randomBytes(16).toString('hex');
                const rawVaultKey = Buffer.from(data.rawVaultKeyB64, 'base64');
                const salt = Buffer.from(data.saltB64, 'base64');

                const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
                const ivForVaultKey = crypto.randomBytes(16);
                const encryptedVaultKey = encryptDataServer(rawVaultKey, derivedKeyForVaultKey, ivForVaultKey);

                vaults[vaultId] = {
                    name: data.vaultName,
                    type: data.vaultType,
                    expiration: data.expiration,
                    adminId: currentUserId,
                    encryptedKeyB64: encryptedVaultKey.toString('base64'),
                    ivB64: ivForVaultKey.toString('base64'),
                    saltB64: salt.toString('base64'),
                    used: data.vaultType === 'private' ? false : true,
                    members: new Set([currentUserId]),
                    createdAt: Date.now()
                };

                // Serialize and save vaults
                const vaultsToSave_create = {};
                for (const [id, v] of Object.entries(vaults)) {
                    vaultsToSave_create[id] = { ...v, members: Array.from(v.members) };
                }
                saveData(VAULTS_FILE, vaultsToSave_create);

                ws.send(JSON.stringify({
                    type: 'vault_created',
                    vaultId: vaultId,
                    vaultHash: vaultHash,
                    vaultName: data.vaultName,
                    vaultType: data.vaultType,
                    expiration: data.expiration,
                    encryptedKeyB64: encryptedVaultKey.toString('base64'),
                    ivB64: ivForVaultKey.toString('base64'),
                    saltB64: salt.toString('base64')
                }));

                console.log(`Vault ${vaultId} created by ${currentUserId}. Hash: ${vaultHash}`);
                break;

            case 'join_vault':
                const { vaultHash: joinHash, vaultName: userVaultName } = data;
                let foundVaultId = null;

                for (const id in vaults) {
                    const vault = vaults[id];
                    const tempSalt = Buffer.from(vault.saltB64, 'base64');
                    const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                    try {
                        const tempDecryptedKey = decryptDataServer(
                            Buffer.from(vault.encryptedKeyB64, 'base64'),
                            tempDerivedKey,
                            Buffer.from(vault.ivB64, 'base64')
                        );
                        foundVaultId = id;
                        break;
                    } catch (e) {
                        continue;
                    }
                }

                if (foundVaultId) {
                    const vault = vaults[foundVaultId];
                    if (vault.type === 'private' && vault.used) {
                        ws.send(JSON.stringify({ type: 'error', message: 'This private vault hash has already been used.' }));
                        return;
                    }

                    vault.members.add(currentUserId);
                    if (vault.type === 'private') {
                        vault.used = true;
                    }

                    // Serialize and save vaults
                    const vaultsToSave_join = {};
                    for (const [id, v] of Object.entries(vaults)) {
                        vaultsToSave_join[id] = { ...v, members: Array.from(v.members) };
                    }
                    saveData(VAULTS_FILE, vaultsToSave_join);

                    ws.send(JSON.stringify({
                        type: 'vault_joined',
                        joinedVaultId: foundVaultId,
                        joinedVaultName: userVaultName,
                        joinedVaultType: vault.type,
                        joinedExpiration: vault.expiration,
                        encryptedKeyB64: vault.encryptedKeyB64,
                        ivB64: vault.ivB64,
                        saltB64: vault.saltB64,
                        vaultHash: joinHash
                    }));

                    console.log(`User ${currentUserId} joined vault ${foundVaultId}.`);

                    if (offlineMessages[currentUserId]) {
                        const relevantMessages = offlineMessages[currentUserId].filter(msg => msg.vaultId === foundVaultId);
                        if (relevantMessages.length > 0) {
                            ws.send(JSON.stringify({ type: 'offline_messages', messages: relevantMessages }));
                            offlineMessages[currentUserId] = offlineMessages[currentUserId].filter(msg => msg.vaultId !== foundVaultId);
                            if (offlineMessages[currentUserId].length === 0) {
                                delete offlineMessages[currentUserId];
                            }
                            saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                        }
                    }
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or hash is incorrect/expired.' }));
                }
                break;

            case 'send_message':
                const { vaultId: msgVaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType } = data;
                const vault = vaults[msgVaultId];
                if (vault && vault.members.has(senderId)) {
                    const messageToSend = {
                        type: 'new_message',
                        vaultId: msgVaultId,
                        senderId: senderId,
                        encryptedMessage: encryptedMessage,
                        iv: iv,
                        timestamp: timestamp,
                        isFile: isFile,
                        fileName: fileName,
                        fileMimeType: fileMimeType
                    };
                    vault.members.forEach(memberId => {
                        if (memberId !== senderId) {
                            const recipientWs = connectedClients[memberId];
                            if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                                recipientWs.send(JSON.stringify(messageToSend));
                            } else {
                                if (!offlineMessages[memberId]) {
                                    offlineMessages[memberId] = [];
                                }
                                offlineMessages[memberId].push(messageToSend);
                                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                                console.log(`Stored offline message for ${memberId} in vault ${msgVaultId}`);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member.' }));
                }
                break;

            case 'nuke':
                const nukeUserId = data.userId;
                console.log(`Nuke request received for user: ${nukeUserId}`);
                for (const id in vaults) {
                    if (vaults[id].members.has(nukeUserId)) {
                        vaults[id].members.delete(nukeUserId);
                        if (vaults[id].type === 'private' && vaults[id].members.size === 0) {
                            console.log(`Private vault ${id} is now empty after nuke.`);
                        }
                    }
                }

                // Serialize and save vaults after nuke
                const vaultsToSave_nuke = {};
                for (const [id, v] of Object.entries(vaults)) {
                     vaultsToSave_nuke[id] = { ...v, members: Array.from(v.members) };
                }
                saveData(VAULTS_FILE, vaultsToSave_nuke);

                if (offlineMessages[nukeUserId]) {
                    delete offlineMessages[nukeUserId];
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                }
                if (connectedClients[nukeUserId]) {
                    connectedClients[nukeUserId].close();
                    delete connectedClients[nukeUserId];
                }
                console.log(`User ${nukeUserId} data nuked from server.`);
                break;

            default:
                ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
                break;
        }
    });

    ws.on('close', () => {
        if (currentUserId) {
            delete connectedClients[currentUserId];
            console.log(`User ${currentUserId} disconnected.`);
        }
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

// --- Vault Expiration Logic ---
function checkVaultExpirations() {
    const now = Date.now();
    let changed = false;
    for (const vaultId in vaults) {
        const vault = vaults[vaultId];
        if (vault.expiration === 'never') continue;
        let expirationTimeMs;
        const match = vault.expiration.match(/(\d+)([hmyd])/);
        if (!match) continue;
        const [_, value, unit] = match;
        const numValue = parseInt(value);
        switch (unit) {
            case 'h': expirationTimeMs = numValue * 60 * 60 * 1000; break;
            case 'd': expirationTimeMs = numValue * 24 * 60 * 60 * 1000; break;
            case 'm': expirationTimeMs = numValue * 30 * 24 * 60 * 60 * 1000; break;
            case 'y': expirationTimeMs = numValue * 365 * 24 * 60 * 60 * 1000; break;
            default: expirationTimeMs = 0;
        }
        if (vault.createdAt + expirationTimeMs < now) {
            console.log(`Vault ${vault.name} (${vaultId}) has expired. Deleting.`);
            vault.members.forEach(memberId => {
                const memberWs = connectedClients[memberId];
                if (memberWs && memberWs.readyState === WebSocket.OPEN) {
                    memberWs.send(JSON.stringify({
                        type: 'vault_expired_notification',
                        expiredVaultId: vaultId,
                        expiredVaultName: vault.name
                    }));
                }
                if (offlineMessages[memberId]) {
                    offlineMessages[memberId] = offlineMessages[memberId].filter(msg => msg.vaultId !== vaultId);
                    if (offlineMessages[memberId].length === 0) {
                        delete offlineMessages[memberId];
                    }
                }
            });
            delete vaults[vaultId];
            changed = true;
        }
    }
    if (changed) {
        // Serialize and save vaults and offline messages after expiration check
        const vaultsToSave_expire = {};
        for (const [id, v] of Object.entries(vaults)) {
            vaultsToSave_expire[id] = { ...v, members: Array.from(v.members) };
        }
        saveData(VAULTS_FILE, vaultsToSave_expire);
        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
    }
}

setInterval(checkVaultExpirations, 60 * 1000);

// --- Basic HTTP Server for Health Check ---
app.get('/', (req, res) => {
    res.send('The Platform Relay Server is running.');
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
