// server.js
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // Node.js crypto module for key derivation

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

// --- Server-side Data Storage (Simple JSON files for demo) ---
// In a production environment, use a robust database (e.g., PostgreSQL, MongoDB)
// and proper authentication/authorization.
const DATA_DIR = path.join(__dirname, 'data');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.json');
const OFFLINE_MESSAGES_FILE = path.join(DATA_DIR, 'offline_messages.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

let vaults = {}; // vaultId -> { name, type, expiration, adminId, encryptedKeyB64, ivB64, saltB64, used (for private), members: Set<userId> }
let offlineMessages = {}; // userId -> [{ vaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType }]
let connectedClients = {}; // userId -> WebSocket

/**
 * Loads data from a JSON file.
 * @param {string} filePath - Path to the JSON file.
 * @param {object} defaultData - Default data if file doesn't exist or is empty.
 * @returns {object} Parsed data.
 */
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

/**
 * Saves data to a JSON file.
 * @param {string} filePath - Path to the JSON file.
 * @param {object} data - Data to save.
 */
function saveData(filePath, data) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
        console.error(`Error saving data to ${filePath}:`, error.message);
    }
}

// Load initial data
vaults = loadData(VAULTS_FILE, {});
// Convert members arrays back to Sets if loaded from JSON
for (const vaultId in vaults) {
    if (vaults[vaultId].members) {
        vaults[vaultId].members = new Set(vaults[vaultId].members);
    } else {
        vaults[vaultId].members = new Set();
    }
}
offlineMessages = loadData(OFFLINE_MESSAGES_FILE, {});

// --- Cryptography on Server (for vault key encryption/decryption) ---
// This part is crucial for "The Laughing Buddha Protocol" to ensure the server
// never sees the plaintext vault keys or messages.

/**
 * Derives a cryptographic key from a given password (hash) using PBKDF2.
 * This is used to encrypt/decrypt the vault's main AES key.
 * Server-side equivalent of client's deriveKeyFromHash.
 * @param {string} password - The vault hash (password).
 * @param {Buffer} salt - A unique salt for key derivation.
 * @returns {Promise<Buffer>} The derived key.
 */
async function deriveKeyFromHashServer(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey);
        });
    });
}

/**
 * Encrypts data using AES-256-GCM.
 * @param {Buffer} data - The data to encrypt.
 * @param {Buffer} key - The AES key (32 bytes).
 * @param {Buffer} iv - The IV (16 bytes).
 * @returns {Buffer} Encrypted data.
 */
function encryptDataServer(data, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([encrypted, tag]); // Append auth tag
}

/**
 * Decrypts data using AES-256-GCM.
 * @param {Buffer} encryptedDataWithTag - The encrypted data with auth tag.
 * @param {Buffer} key - The AES key (32 bytes).
 * @param {Buffer} iv - The IV (16 bytes).
 * @returns {Buffer} Decrypted data.
 */
function decryptDataServer(encryptedDataWithTag, key, iv) {
    const tagLength = 16; // AES-GCM default tag length
    const encryptedData = encryptedDataWithTag.slice(0, encryptedDataWithTag.length - tagLength);
    const tag = encryptedDataWithTag.slice(encryptedDataWithTag.length - tagLength);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    return decrypted;
}


// --- WebSocket Server Logic ---

wss.on('connection', (ws) => {
    let currentUserId = null; // Will be set after 'register' message

    ws.on('message', async (message) => {
        const data = JSON.parse(message.toString());
        console.log('Received from client:', data.type, data.userId || '');

        if (data.type === 'register') {
            currentUserId = data.userId;
            connectedClients[currentUserId] = ws;
            console.log(`User ${currentUserId} connected.`);

            // Send any pending offline messages to the newly connected user
            if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                ws.send(JSON.stringify({ type: 'offline_messages', messages: offlineMessages[currentUserId] }));
                delete offlineMessages[currentUserId]; // Clear after sending
                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                console.log(`Sent ${offlineMessages[currentUserId]?.length || 0} offline messages to ${currentUserId}`);
            }
        } else if (!currentUserId) {
            // Reject messages if user is not registered yet
            ws.send(JSON.stringify({ type: 'error', message: 'Please register your user ID first.' }));
            return;
        }

        switch (data.type) {
            case 'create_vault':
                const vaultId = crypto.randomUUID();
                const vaultHash = crypto.randomBytes(16).toString('hex'); // Unique hash for joining
                const rawVaultKey = Buffer.from(data.rawVaultKeyB64, 'base64'); // Raw AES key from client
                const salt = Buffer.from(data.saltB64, 'base64'); // Salt from client

                // Server encrypts the raw vault key using a key derived from the vaultHash
                const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
                const ivForVaultKey = crypto.randomBytes(16); // IV for encrypting the vault key
                const encryptedVaultKey = encryptDataServer(rawVaultKey, derivedKeyForVaultKey, ivForVaultKey);

                vaults[vaultId] = {
                    name: data.vaultName,
                    type: data.vaultType,
                    expiration: data.expiration,
                    adminId: currentUserId, // Admin for public vaults
                    encryptedKeyB64: encryptedVaultKey.toString('base64'), // Store encrypted key
                    ivB64: ivForVaultKey.toString('base64'), // Store IV for key encryption
                    saltB64: salt.toString('base64'), // Store salt for key derivation
                    used: data.vaultType === 'private' ? false : true, // Private hash used once
                    members: new Set([currentUserId]),
                    createdAt: Date.now() // For expiration
                };
                saveData(VAULTS_FILE, vaults);

                // Send back the vault details and the encrypted key to the creator
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

                // Find the vault by hash
                for (const id in vaults) {
                    const vault = vaults[id];
                    // Re-derive the hash to compare (this is inefficient, but ensures hash is not stored directly)
                    // A better way would be to store a hash of the hash, or have a separate lookup table.
                    // For this demo, we'll iterate and check.
                    const tempSalt = Buffer.from(vault.saltB64, 'base64');
                    const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                    try {
                        // Attempt to decrypt the vault key with the provided hash
                        const tempDecryptedKey = decryptDataServer(
                            Buffer.from(vault.encryptedKeyB64, 'base64'),
                            tempDerivedKey,
                            Buffer.from(vault.ivB64, 'base64')
                        );
                        // If decryption succeeds, it means the hash is correct
                        foundVaultId = id;
                        break;
                    } catch (e) {
                        // Decryption failed, not the correct hash or key
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
                        vault.used = true; // Mark hash as used for private vaults
                    }
                    saveData(VAULTS_FILE, vaults);

                    // Send the encrypted vault key and IV to the joiner
                    ws.send(JSON.stringify({
                        type: 'vault_joined',
                        joinedVaultId: foundVaultId,
                        joinedVaultName: userVaultName, // Use the name given by the joiner
                        joinedVaultType: vault.type,
                        joinedExpiration: vault.expiration,
                        encryptedKeyB64: vault.encryptedKeyB64, // Send the encrypted key
                        ivB64: vault.ivB64, // Send the IV for key encryption
                        saltB64: vault.saltB64, // Send the salt for key derivation
                        vaultHash: joinHash // Send the hash back so client can derive key
                    }));
                    console.log(`User ${currentUserId} joined vault ${foundVaultId}.`);

                    // Send any pending offline messages for this vault to the new member
                    if (offlineMessages[currentUserId]) {
                        const relevantMessages = offlineMessages[currentUserId].filter(msg => msg.vaultId === foundVaultId);
                        if (relevantMessages.length > 0) {
                            ws.send(JSON.stringify({ type: 'offline_messages', messages: relevantMessages }));
                            // Remove only the sent messages from offline store
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
                        encryptedMessage: encryptedMessage, // Server only relays encrypted content
                        iv: iv,
                        timestamp: timestamp,
                        isFile: isFile,
                        fileName: fileName,
                        fileMimeType: fileMimeType
                    };

                    vault.members.forEach(memberId => {
                        if (memberId !== senderId) { // Don't send back to sender
                            const recipientWs = connectedClients[memberId];
                            if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                                recipientWs.send(JSON.stringify(messageToSend));
                            } else {
                                // Store for offline delivery
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

                // Remove user from all vaults
                for (const id in vaults) {
                    if (vaults[id].members.has(nukeUserId)) {
                        vaults[id].members.delete(nukeUserId);
                        // If a private vault becomes empty, consider deleting it or marking it for deletion
                        if (vaults[id].type === 'private' && vaults[id].members.size === 0) {
                            console.log(`Private vault ${id} is now empty after nuke, marking for deletion.`);
                            // We can set a flag or short expiration to clean up empty private vaults
                            // For this demo, we'll just leave it empty until its natural expiration
                        }
                    }
                }
                saveData(VAULTS_FILE, vaults);

                // Clear offline messages for this user
                if (offlineMessages[nukeUserId]) {
                    delete offlineMessages[nukeUserId];
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                }

                // Disconnect the client
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
        const [value, unit] = vault.expiration.match(/(\d+)([hmy])/).slice(1);
        const numValue = parseInt(value);

        switch (unit) {
            case 'h': expirationTimeMs = numValue * 60 * 60 * 1000; break;
            case 'd': expirationTimeMs = numValue * 24 * 60 * 60 * 1000; break; // 'd' for days, though client uses '24h'
            case 'm': expirationTimeMs = numValue * 30 * 24 * 60 * 60 * 1000; break; // Approx month
            case 'y': expirationTimeMs = numValue * 365 * 24 * 60 * 60 * 1000; break; // Approx year
            default: expirationTimeMs = 0; // Should not happen with client validation
        }

        if (vault.createdAt + expirationTimeMs < now) {
            console.log(`Vault ${vault.name} (${vaultId}) has expired. Deleting.`);
            // Notify members before deleting
            vault.members.forEach(memberId => {
                const memberWs = connectedClients[memberId];
                if (memberWs && memberWs.readyState === WebSocket.OPEN) {
                    memberWs.send(JSON.stringify({
                        type: 'vault_expired_notification',
                        expiredVaultId: vaultId,
                        expiredVaultName: vault.name
                    }));
                }
                // Also remove any offline messages for this vault
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
        saveData(OFFLINE_MESSAGES_FILE, offlineMessages); // Save updated offline messages
    }
}

// Check expirations every minute
setInterval(checkVaultExpirations, 60 * 1000);

// --- Basic HTTP Server for Health Check (for Render) ---
app.get('/', (req, res) => {
    res.send('The Platform Relay Server is running.');
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});

