// server.js
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// --- Import Kyber ---
const { Kyber768 } = require('@noble/post-quantum/kyber');

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
// Standard PBKDF2 logic remains for Public Vaults
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
                const vaultType = data.vaultType; // Get vault type

                let vaultDataToStore = {
                    name: data.vaultName,
                    type: vaultType,
                    expiration: data.expiration,
                    adminId: currentUserId,
                    members: new Set([currentUserId]),
                    createdAt: Date.now()
                };

                if (vaultType === 'public') {
                    // --- Public Vault Logic (Unchanged) ---
                    const salt = Buffer.from(data.saltB64, 'base64');
                    const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
                    const ivForVaultKey = crypto.randomBytes(16);
                    const encryptedVaultKey = encryptDataServer(rawVaultKey, derivedKeyForVaultKey, ivForVaultKey);
                    vaultDataToStore.encryptedKeyB64 = encryptedVaultKey.toString('base64');
                    vaultDataToStore.ivB64 = ivForVaultKey.toString('base64');
                    vaultDataToStore.saltB64 = salt.toString('base64');
                    vaultDataToStore.used = true; // Public hashes are not single-use like private ones implicitly were

                    // Response for public vault (Unchanged)
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

                } else if (vaultType === 'private') {
                    // --- Private Vault Logic (Kyber PQC) ---
                    // 1. Validate seed length (rawVaultKey must be 32 bytes for Kyber768 seed)
                    if (rawVaultKey.length !== 32) {
                         ws.send(JSON.stringify({ type: 'error', message: 'Invalid key size for private vault creation.' }));
                         console.error(`User ${currentUserId} attempted to create private vault with invalid key size: ${rawVaultKey.length} bytes.`);
                         break;
                    }

                    // 2. Generate Kyber768 keypair using the rawVaultKey as the seed
                    const seed = new Uint8Array(rawVaultKey); // Use the raw AES key as the seed
                    const { publicKey: pk_enc, secretKey: sk_enc } = Kyber768.keygen(seed);

                    // 3. Server performs encapsulation using the same seed
                    //    The ciphertext is deterministic if the seed and pk are the same.
                    const { ciphertext, sharedSecret } = Kyber768.encapsulate(pk_enc, seed);

                    // 4. Store only the public key and ciphertext on the server
                    vaultDataToStore.pk_enc_b64 = Buffer.from(pk_enc).toString('base64');
                    vaultDataToStore.ciphertext_b64 = Buffer.from(ciphertext).toString('base64');
                    vaultDataToStore.used = false; // Private hash used once

                    // 5. Send back the vault details, pk_enc, and ciphertext to the creator
                    ws.send(JSON.stringify({
                        type: 'vault_created',
                        vaultId: vaultId,
                        vaultHash: vaultHash,
                        vaultName: data.vaultName,
                        vaultType: data.vaultType,
                        expiration: data.expiration,
                        pk_enc_b64: Buffer.from(pk_enc).toString('base64'), // Send pk_enc
                        ciphertext_b64: Buffer.from(ciphertext).toString('base64'), // Send ciphertext
                        // No encryptedKeyB64, ivB64, saltB64 for private vaults anymore
                    }));
                } else {
                     ws.send(JSON.stringify({ type: 'error', message: 'Invalid vault type.' }));
                     break;
                }

                // Store the vault data in memory and save to file
                vaults[vaultId] = vaultDataToStore;
                // Convert Set to Array for JSON serialization
                const serializableVaults = {};
                for (const [id, v] of Object.entries(vaults)) {
                    serializableVaults[id] = { ...v, members: Array.from(v.members) };
                }
                saveData(VAULTS_FILE, serializableVaults);

                console.log(`Vault ${vaultId} (${vaultType}) created by ${currentUserId}. Hash: ${vaultHash}`);
                break;

            case 'join_vault':
                const { vaultHash: joinHash, vaultName: userVaultName } = data;
                let foundVaultId = null;
                let foundVault = null;

                // Find the vault by hash
                for (const id in vaults) {
                    const vault = vaults[id];
                    if (vault.type === 'public') {
                        // --- Public Vault Join Logic (Unchanged) ---
                        const tempSalt = Buffer.from(vault.saltB64, 'base64');
                        const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                        try {
                            const tempDecryptedKey = decryptDataServer(
                                Buffer.from(vault.encryptedKeyB64, 'base64'),
                                tempDerivedKey,
                                Buffer.from(vault.ivB64, 'base64')
                            );
                            foundVaultId = id;
                            foundVault = vault;
                            break;
                        } catch (e) {
                            continue;
                        }
                    } else if (vault.type === 'private' && !vault.used) {
                         // --- Private Vault Join Logic (Kyber PQC) ---
                         // For private vaults, we just need to match the hash (assuming hash uniqueness)
                         // A more robust system might use a separate lookup table.
                         // For simplicity here, we iterate. In production, index by hash.
                         if (joinHash === vaultHash) { // This check relies on hash uniqueness
                             foundVaultId = id;
                             foundVault = vault;
                             break;
                         }
                    }
                }

                if (foundVaultId && foundVault) {
                    if (foundVault.type === 'private' && foundVault.used) {
                        ws.send(JSON.stringify({ type: 'error', message: 'This private vault hash has already been used.' }));
                        return;
                    }

                    foundVault.members.add(currentUserId);
                    if (foundVault.type === 'private') {
                        foundVault.used = true;
                    }

                    // Save updated vault data
                    const serializableVaults = {};
                    for (const [id, v] of Object.entries(vaults)) {
                        serializableVaults[id] = { ...v, members: Array.from(v.members) };
                    }
                    saveData(VAULTS_FILE, serializableVaults);

                    if (foundVault.type === 'public') {
                        // --- Response for Public Vault Join (Unchanged) ---
                        ws.send(JSON.stringify({
                            type: 'vault_joined',
                            joinedVaultId: foundVaultId,
                            joinedVaultName: userVaultName,
                            joinedVaultType: foundVault.type,
                            joinedExpiration: foundVault.expiration,
                            encryptedKeyB64: foundVault.encryptedKeyB64,
                            ivB64: foundVault.ivB64,
                            saltB64: foundVault.saltB64,
                            vaultHash: joinHash
                        }));
                    } else if (foundVault.type === 'private') {
                        // --- Response for Private Vault Join (Kyber PQC) ---
                        ws.send(JSON.stringify({
                            type: 'vault_joined',
                            joinedVaultId: foundVaultId,
                            joinedVaultName: userVaultName,
                            joinedVaultType: foundVault.type,
                            joinedExpiration: foundVault.expiration,
                            pk_enc_b64: foundVault.pk_enc_b64, // Send pk_enc
                            ciphertext_b64: foundVault.ciphertext_b64, // Send ciphertext
                            vaultHash: joinHash
                        }));
                    }

                    console.log(`User ${currentUserId} joined vault ${foundVaultId} (${foundVault.type}).`);

                    // Send offline messages
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
                const serializableVaults = {};
                for (const [id, v] of Object.entries(vaults)) {
                     serializableVaults[id] = { ...v, members: Array.from(v.members) };
                }
                saveData(VAULTS_FILE, serializableVaults);

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
        const match = vault.expiration.match(/(\d+)([hmyd])/); // Added 'd' for day support if needed
        if (!match) continue; // Skip if format is unexpected
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
        const serializableVaults = {};
        for (const [id, v] of Object.entries(vaults)) {
            serializableVaults[id] = { ...v, members: Array.from(v.members) };
        }
        saveData(VAULTS_FILE, serializableVaults);
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
