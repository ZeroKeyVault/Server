 const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const kyber = require('kyber-crystals');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

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
            const parsedData = JSON.parse(data);
            if (filePath === VAULTS_FILE) {
                for (const vaultId in parsedData) {
                    if (parsedData[vaultId].members && Array.isArray(parsedData[vaultId].members)) {
                        parsedData[vaultId].members = new Set(parsedData[vaultId].members);
                    } else {
                        parsedData[vaultId].members = new Set();
                    }
                }
            }
            return parsedData;
        }
    } catch (error) {
        console.error(`Error loading data from ${filePath}:`, error.message);
    }
    return defaultData;
}

function saveData(filePath, data) {
    try {
        const serializableData = JSON.parse(JSON.stringify(data, (key, value) => {
            if (value instanceof Set) {
                return Array.from(value);
            }
            return value;
        }));
        fs.writeFileSync(filePath, JSON.stringify(serializableData, null, 2), 'utf8');
    } catch (error) {
        console.error(`Error saving data to ${filePath}:`, error.message);
    }
}

vaults = loadData(VAULTS_FILE, {});
offlineMessages = loadData(OFFLINE_MESSAGES_FILE, {});

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

wss.on('connection', (ws) => {
    let currentUserId = null;

    ws.on('message', async (message) => {
        let data;
        try {
            data = JSON.parse(message.toString());
        } catch (e) {
            console.error("Server: Failed to parse incoming WebSocket message:", e, message.toString());
            ws.send(JSON.stringify({ type: 'error', message: 'Malformed message received.' }));
            return;
        }
        console.log('Received from client:', data.type, data.userId || '');

        if (data.type === 'register') {
            currentUserId = data.userId;
            connectedClients[currentUserId] = ws;
            console.log(`User ${currentUserId} connected.`);

            if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                const uniqueOfflineMessages = offlineMessages[currentUserId].filter((msg, index, self) =>
                    index === self.findIndex((m) => (
                        m.vaultId === msg.vaultId &&
                        m.senderId === msg.senderId &&
                        m.timestamp === msg.timestamp &&
                        m.type === msg.type &&
                        m.fileId === msg.fileId &&
                        m.chunkIndex === msg.chunkIndex
                    ))
                );

                if (uniqueOfflineMessages.length > 0) {
                    ws.send(JSON.stringify({ type: 'offline_messages', messages: uniqueOfflineMessages }));
                    delete offlineMessages[currentUserId];
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                    console.log(`Sent ${uniqueOfflineMessages.length} offline messages to ${currentUserId}`);
                }
            }
        } else if (!currentUserId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Please register your user ID first.' }));
            return;
        }

        switch (data.type) {
            case 'create_vault':
                const vaultId = crypto.randomUUID();
                const vaultHash = crypto.randomBytes(16).toString('hex');
                const encryptedKeyB64FromClient = data.encryptedKeyB64;
                const ivB64FromClient = data.ivB64;
                const saltB64FromClient = data.saltB64;

                if (!encryptedKeyB64FromClient || !ivB64FromClient || !saltB64FromClient) {
                    console.error("Server: Missing encrypted key components from client for create_vault.");
                    ws.send(JSON.stringify({ type: 'error', message: 'Missing key components for vault creation.' }));
                    return;
                }

                vaults[vaultId] = {
                    name: data.vaultName,
                    type: data.vaultType,
                    expiration: data.expiration,
                    adminId: currentUserId,
                    encryptedKeyB64: encryptedKeyB64FromClient,
                    ivB64: ivB64FromClient,
                    saltB64: saltB64FromClient,
                    kyberPublicKey: data.kyberPublicKey,
                    kyberPrivateKey: data.kyberPrivateKey,
                    used: data.vaultType === 'private' ? false : true,
                    members: new Set([currentUserId]),
                    createdAt: Date.now()
                };
                saveData(VAULTS_FILE, vaults);
                console.log(`Server: Vault ${vaultId} saved to file.`);

                ws.send(JSON.stringify({
                    type: 'vault_created',
                    vaultId: vaultId,
                    vaultHash: vaultHash,
                    vaultName: data.vaultName,
                    vaultType: data.vaultType,
                    expiration: data.expiration,
                    encryptedKeyB64: encryptedKeyB64FromClient,
                    ivB64: ivB64FromClient,
                    saltB64: saltB64FromClient
                }));
                console.log(`Server: Vault ${vaultId} created by ${currentUserId}. Hash: ${vaultHash}. Response sent to client.`);
                break;

            case 'get_vault_public_key':
                let foundVault = null;
                for (const id in vaults) {
                    const vault = vaults[id];
                    if (!vault.saltB64 || !vault.encryptedKeyB64 || !vault.ivB64) {
                        continue;
                    }
                    try {
                        const tempSalt = Buffer.from(vault.saltB64, 'base64');
                        const tempDerivedKey = await deriveKeyFromHashServer(data.vaultHash, tempSalt);
                        const tempDecryptedKey = decryptDataServer(
                            Buffer.from(vault.encryptedKeyB64, 'base64'),
                            tempDerivedKey,
                            Buffer.from(vault.ivB64, 'base64')
                        );
                        foundVault = vault;
                        break;
                    } catch (e) {
                        continue;
                    }
                }

                if (foundVault && foundVault.kyberPublicKey) {
                    ws.send(JSON.stringify({
                        type: 'vault_public_key',
                        vaultHash: data.vaultHash,
                        publicKey: foundVault.kyberPublicKey
                    }));
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or does not support Kyber encryption.' }));
                }
                break;

            case 'join_vault':
                const { vaultHash: joinHash, kyberCiphertext, vaultName: userVaultName } = data;
                let foundVaultId = null;
                let kyberPrivateKey = null;

                for (const id in vaults) {
                    const vault = vaults[id];
                    if (!vault.saltB64 || !vault.encryptedKeyB64 || !vault.ivB64) {
                        continue;
                    }
                    try {
                        const tempSalt = Buffer.from(vault.saltB64, 'base64');
                        const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                        const tempDecryptedKey = decryptDataServer(
                            Buffer.from(vault.encryptedKeyB64, 'base64'),
                            tempDerivedKey,
                            Buffer.from(vault.ivB64, 'base64')
                        );
                        foundVaultId = id;
                        kyberPrivateKey = Uint8Array.from(Buffer.from(vault.kyberPrivateKey, 'base64'));
                        break;
                    } catch (e) {
                        continue;
                    }
                }

                if (foundVaultId && kyberPrivateKey) {
                    const vault = vaults[foundVaultId];
                    if (vault.type === 'private' && vault.used) {
                        ws.send(JSON.stringify({ type: 'error', message: 'This private vault hash has already been used.' }));
                        return;
                    }

                    const ciphertext = Uint8Array.from(Buffer.from(kyberCiphertext, 'base64'));
                    const sharedSecret = kyber.decapsulate(ciphertext, kyberPrivateKey, 2);

                    const salt = crypto.randomValues(new Uint8Array(16));
                    const derivedKeyForVaultKey = await deriveKeyFromHashServer(joinHash, salt);
                    const decryptedVaultKeyRaw = await decryptDataServer(
                        Buffer.from(vault.encryptedKeyB64, 'base64'),
                        derivedKeyForVaultKey,
                        Buffer.from(vault.ivB64, 'base64')
                    );

                    const sharedSecretKey = crypto.createCipheriv('aes-256-gcm', Buffer.from(sharedSecret), Buffer.alloc(16));
                    const encryptedKey = Buffer.concat([sharedSecretKey.update(decryptedVaultKeyRaw), sharedSecretKey.final(), sharedSecretKey.getAuthTag()]);

                    vault.members.add(currentUserId);
                    if (vault.type === 'private') {
                        vault.used = true;
                    }
                    saveData(VAULTS_FILE, vaults);

                    ws.send(JSON.stringify({
                        type: 'vault_joined',
                        joinedVaultId: foundVaultId,
                        joinedVaultName: userVaultName,
                        joinedVaultType: vault.type,
                        joinedExpiration: vault.expiration,
                        encryptedKeyB64: encryptedKey.toString('base64'),
                        ivB64: Buffer.from(sharedSecretKey.getIV()).toString('base64'),
                        saltB64: Buffer.from(salt).toString('base64'),
                        vaultHash: joinHash
                    }));
                    console.log(`Server: User ${currentUserId} joined vault ${foundVaultId} with Kyber.`);

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
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or Kyber keys missing.' }));
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
                                console.log(`Server: Stored offline text message for ${memberId} in vault ${msgVaultId}`);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member.' }));
                }
                break;

            case 'send_file_metadata':
                const {
                    vaultId: fileMetaVaultId,
                    senderId: fileMetaSenderId,
                    fileId,
                    fileName: fileMetaName,
                    fileMimeType: fileMetaMimeType,
                    fileSize,
                    totalChunks,
                    timestamp: fileMetaTimestamp
                } = data;

                const fileMetaVault = vaults[fileMetaVaultId];

                if (fileMetaVault && fileMetaVault.members.has(fileMetaSenderId)) {
                    const fileMetadataToSend = {
                        type: 'send_file_metadata',
                        vaultId: fileMetaVaultId,
                        senderId: fileMetaSenderId,
                        fileId: fileId,
                        fileName: fileMetaName,
                        fileMimeType: fileMetaMimeType,
                        fileSize: fileSize,
                        totalChunks: totalChunks,
                        timestamp: fileMetaTimestamp
                    };

                    fileMetaVault.members.forEach(memberId => {
                        if (memberId !== fileMetaSenderId) {
                            const recipientWs = connectedClients[memberId];
                            if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                                recipientWs.send(JSON.stringify(fileMetadataToSend));
                            } else {
                                if (!offlineMessages[memberId]) {
                                    offlineMessages[memberId] = [];
                                }
                                offlineMessages[memberId].push(fileMetadataToSend);
                                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member for file metadata.' }));
                }
                break;

            case 'send_file_chunk':
                const {
                    vaultId: fileChunkVaultId,
                    senderId: fileChunkSenderId,
                    fileId: chunkFileId,
                    chunkIndex,
                    encryptedChunk,
                    timestamp: fileChunkTimestamp,
                    fileName: fileChunkName,
                    fileMimeType: fileChunkMimeType
                } = data;

                const fileChunkVault = vaults[fileChunkVaultId];

                if (fileChunkVault && fileChunkVault.members.has(fileChunkSenderId)) {
                    const fileChunkToSend = {
                        type: 'send_file_chunk',
                        vaultId: fileChunkVaultId,
                        senderId: fileChunkSenderId,
                        fileId: chunkFileId,
                        chunkIndex: chunkIndex,
                        encryptedChunk: encryptedChunk,
                        timestamp: fileChunkTimestamp,
                        fileName: fileChunkName,
                        fileMimeType: fileChunkMimeType
                    };

                    fileChunkVault.members.forEach(memberId => {
                        if (memberId !== fileChunkSenderId) {
                            const recipientWs = connectedClients[memberId];
                            if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                                recipientWs.send(JSON.stringify(fileChunkToSend));
                            } else {
                                if (!offlineMessages[memberId]) {
                                    offlineMessages[memberId] = [];
                                }
                                offlineMessages[memberId].push(fileChunkToSend);
                                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member for file chunk.' }));
                }
                break;

            case 'nuke':
                const nukeUserId = data.userId;
                console.log(`Server: Nuke request received for user: ${nukeUserId}`);

                for (const id in vaults) {
                    if (vaults[id].members.has(nukeUserId)) {
                        vaults[id].members.delete(nukeUserId);
                        if (vaults[id].type === 'private' && vaults[id].members.size === 0) {
                            console.log(`Server: Private vault ${id} is now empty after nuke, marking for deletion.`);
                        }
                    }
                }
                saveData(VAULTS_FILE, vaults);

                if (offlineMessages[nukeUserId]) {
                    delete offlineMessages[nukeUserId];
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                }

                if (connectedClients[nukeUserId]) {
                    connectedClients[nukeUserId].close();
                    delete connectedClients[nukeUserId];
                }
                console.log(`Server: User ${nukeUserId} data nuked from server.`);
                break;

            default:
                ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
                break;
        }
    });

    ws.on('close', () => {
        if (currentUserId) {
            delete connectedClients[currentUserId];
            console.log(`Server: User ${currentUserId} disconnected.`);
        }
    });

    ws.on('error', (error) => {
        console.error('Server: WebSocket error:', error);
    });
});

function checkVaultExpirations() {
    const now = Date.now();
    let changed = false;
    for (const vaultId in vaults) {
        const vault = vaults[vaultId];
        if (vault.expiration === 'never') continue;

        let expirationTimeMs;
        const [value, unit] = vault.expiration.match(/(\d+)([hmy])/).slice(1);
        const numValue = parseInt(value);

        switch (unit) {
            case 'h': expirationTimeMs = numValue * 60 * 60 * 1000; break;
            case 'd': expirationTimeMs = numValue * 24 * 60 * 60 * 1000; break;
            case 'm': expirationTimeMs = numValue * 30 * 24 * 60 * 60 * 1000; break;
            case 'y': expirationTimeMs = numValue * 365 * 24 * 60 * 60 * 1000; break;
            default: expirationTimeMs = 0;
        }

        if (vault.createdAt + expirationTimeMs < now) {
            console.log(`Server: Vault ${vault.name} (${vaultId}) has expired. Deleting.`);
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
        saveData(VAULTS_FILE, vaults);
        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
    }
}

setInterval(checkVaultExpirations, 60 * 1000);

app.get('/', (req, res) => {
    res.send('The Platform Relay Server is running with enhanced Kyber encryption.');
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT} with Kyber post-quantum security`);
});
