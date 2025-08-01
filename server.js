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

// --- Server-side Data Storage ---
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

// --- Cryptography on Server ---
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
            console.error("Failed to parse message:", e, message.toString());
            return;
        }
        
        if (data.type === 'register') {
            currentUserId = data.userId;
            connectedClients[currentUserId] = ws;
            
            // Send offline messages if any
            if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                ws.send(JSON.stringify({ 
                    type: 'offline_messages', 
                    messages: offlineMessages[currentUserId] 
                }));
                delete offlineMessages[currentUserId];
                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
            }
            return;
        }
        
        if (!currentUserId) {
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Please register first with a user ID.' 
            }));
            return;
        }

        switch (data.type) {
            case 'create_vault':
                try {
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

                    // Save vaults with proper serialization
                    const serializableVaults = {};
                    for (const [id, v] of Object.entries(vaults)) {
                        serializableVaults[id] = { 
                            ...v, 
                            members: Array.from(v.members) 
                        };
                    }
                    saveData(VAULTS_FILE, serializableVaults);

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
                } catch (e) {
                    console.error("Error creating vault:", e);
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        message: 'Failed to create vault: ' + e.message 
                    }));
                }
                break;

            case 'join_vault':
                try {
                    const { vaultHash: joinHash, vaultName: userVaultName } = data;
                    let foundVaultId = null;
                    
                    for (const id in vaults) {
                        const vault = vaults[id];
                        if (vault.used && vault.type === 'private') continue;
                        
                        const tempSalt = Buffer.from(vault.saltB64, 'base64');
                        const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                        
                        try {
                            decryptDataServer(
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
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'This private vault hash has already been used.' 
                            }));
                            return;
                        }
                        
                        vault.members.add(currentUserId);
                        if (vault.type === 'private') {
                            vault.used = true;
                        }
                        
                        // Save vaults with proper serialization
                        const serializableVaults = {};
                        for (const [id, v] of Object.entries(vaults)) {
                            serializableVaults[id] = { 
                                ...v, 
                                members: Array.from(v.members) 
                            };
                        }
                        saveData(VAULTS_FILE, serializableVaults);
                        
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
                        
                        // Send offline messages for this vault if any
                        if (offlineMessages[currentUserId]) {
                            const relevantMessages = offlineMessages[currentUserId].filter(
                                msg => msg.vaultId === foundVaultId
                            );
                            
                            if (relevantMessages.length > 0) {
                                ws.send(JSON.stringify({ 
                                    type: 'offline_messages', 
                                    messages: relevantMessages 
                                }));
                                
                                offlineMessages[currentUserId] = offlineMessages[currentUserId].filter(
                                    msg => msg.vaultId !== foundVaultId
                                );
                                
                                if (offlineMessages[currentUserId].length === 0) {
                                    delete offlineMessages[currentUserId];
                                }
                                
                                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                            }
                        }
                    } else {
                        ws.send(JSON.stringify({ 
                            type: 'error', 
                            message: 'Vault not found or hash is incorrect/expired.' 
                        }));
                    }
                } catch (e) {
                    console.error("Error joining vault:", e);
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        message: 'Failed to join vault: ' + e.message 
                    }));
                }
                break;

            case 'send_message':
                try {
                    const { vaultId, senderId, encryptedMessage, iv, timestamp, 
                            isFile, fileName, fileMimeType } = data;
                    const vault = vaults[vaultId];
                    
                    if (vault && vault.members.has(senderId)) {
                        const messageToSend = {
                            type: 'new_message',
                            vaultId: vaultId,
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
                                }
                            }
                        });
                    } else {
                        ws.send(JSON.stringify({ 
                            type: 'error', 
                            message: 'Vault not found or you are not a member.' 
                        }));
                    }
                } catch (e) {
                    console.error("Error sending message:", e);
                }
                break;

            case 'nuke':
                try {
                    const nukeUserId = data.userId;
                    console.log(`Nuke request received for user: ${nukeUserId}`);
                    
                    // Remove user from all vaults
                    for (const id in vaults) {
                        if (vaults[id].members.has(nukeUserId)) {
                            vaults[id].members.delete(nukeUserId);
                            if (vaults[id].members.size === 0 && vaults[id].type === 'private') {
                                delete vaults[id];
                            }
                        }
                    }
                    
                    // Save updated vaults
                    const serializableVaults = {};
                    for (const [id, v] of Object.entries(vaults)) {
                        serializableVaults[id] = { 
                            ...v, 
                            members: Array.from(v.members) 
                        };
                    }
                    saveData(VAULTS_FILE, serializableVaults);
                    
                    // Clear offline messages
                    if (offlineMessages[nukeUserId]) {
                        delete offlineMessages[nukeUserId];
                        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                    }
                    
                    // Disconnect client
                    if (connectedClients[nukeUserId]) {
                        connectedClients[nukeUserId].close();
                        delete connectedClients[nukeUserId];
                    }
                } catch (e) {
                    console.error("Error processing nuke:", e);
                }
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
        
        let expirationTimeMs = 0;
        const match = vault.expiration.match(/(\d+)([hmyd])/);
        
        if (match) {
            const value = parseInt(match[1]);
            const unit = match[2];
            
            switch (unit) {
                case 'h': expirationTimeMs = value * 60 * 60 * 1000; break;
                case 'd': expirationTimeMs = value * 24 * 60 * 60 * 1000; break;
                case 'm': expirationTimeMs = value * 30 * 24 * 60 * 60 * 1000; break;
                case 'y': expirationTimeMs = value * 365 * 24 * 60 * 60 * 1000; break;
            }
        }
        
        if (vault.createdAt + expirationTimeMs < now) {
            console.log(`Vault ${vault.name} (${vaultId}) has expired. Deleting.`);
            
            // Notify members
            vault.members.forEach(memberId => {
                const memberWs = connectedClients[memberId];
                if (memberWs && memberWs.readyState === WebSocket.OPEN) {
                    memberWs.send(JSON.stringify({
                        type: 'vault_expired_notification',
                        expiredVaultId: vaultId,
                        expiredVaultName: vault.name
                    }));
                }
                
                // Clean up offline messages
                if (offlineMessages[memberId]) {
                    offlineMessages[memberId] = offlineMessages[memberId].filter(
                        msg => msg.vaultId !== vaultId
                    );
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
        // Save updated vaults
        const serializableVaults = {};
        for (const [id, v] of Object.entries(vaults)) {
            serializableVaults[id] = { 
                ...v, 
                members: Array.from(v.members) 
            };
        }
        saveData(VAULTS_FILE, serializableVaults);
        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
    }
}

setInterval(checkVaultExpirations, 60 * 1000);

// --- Basic HTTP Server ---
app.get('/', (req, res) => {
    res.send('The Platform Relay Server is running.');
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
