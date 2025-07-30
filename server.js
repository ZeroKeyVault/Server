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
                
                vaults[vaultId] = {
                    name: data.vaultName,
                    type: data.vaultType,
                    expiration: data.expiration,
                    adminId: currentUserId,
                    encryptedKeyB64: data.encryptedKeyB64,
                    ivB64: data.ivB64,
                    saltB64: data.saltB64,
                    kyberPublicKey: data.kyberPublicKey,
                    kyberPrivateKey: data.kyberPrivateKey,
                    used: data.vaultType === 'private' ? false : true,
                    members: new Set([currentUserId]),
                    createdAt: Date.now(),
                    vaultHash: vaultHash
                };
                saveData(VAULTS_FILE, vaults);

                ws.send(JSON.stringify({
                    type: 'vault_created',
                    vaultId: vaultId,
                    vaultHash: vaultHash,
                    vaultName: data.vaultName,
                    vaultType: data.vaultType,
                    expiration: data.expiration
                }));
                console.log(`Vault ${vaultId} created by ${currentUserId}. Hash: ${vaultHash}`);
                break;
                
            case 'get_vault_public_key':
                let foundVault = null;
                for (const id in vaults) {
                    const vault = vaults[id];
                    if (vault.vaultHash === data.vaultHash) {
                        foundVault = vault;
                        break;
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
                    if (vault.vaultHash === joinHash) {
                        foundVaultId = id;
                        kyberPrivateKey = Uint8Array.from(Buffer.from(vault.kyberPrivateKey, 'base64'));
                        break;
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

                    // Prepare response
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
                    
                    // Update vault membership
                    vault.members.add(currentUserId);
                    if (vault.type === 'private') {
                        vault.used = true;
                    }
                    saveData(VAULTS_FILE, vaults);
                    
                    console.log(`User ${currentUserId} joined vault ${foundVaultId}`);
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or Kyber keys missing.' }));
                }
                break;
                
            // Other cases (send_message, send_file_metadata, etc.) remain the same
            // ...
            
            default:
                ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
        }
    });

    ws.on('close', () => {
        if (currentUserId) {
            delete connectedClients[currentUserId];
            console.log(`User ${currentUserId} disconnected.`);
        }
    });

    ws.on('error', (error) => {
        console.error('Server: WebSocket error:', error);
    });
});

// Start server
app.get('/', (req, res) => {
    res.send('The Platform Relay Server is running with enhanced Kyber encryption.');
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT} with Kyber post-quantum security`);
});
