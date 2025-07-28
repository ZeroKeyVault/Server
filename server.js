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
            const parsedData = JSON.parse(data);
            // Convert members arrays back to Sets if loaded from JSON
            if (filePath === VAULTS_FILE) {
                for (const vaultId in parsedData) {
                    if (parsedData[vaultId].members && Array.isArray(parsedData[vaultId].members)) {
                        parsedData[vaultId].members = new Set(parsedData[vaultId].members);
                    } else {
                        parsedData[vaultId].members = new Set(); // Ensure it's always a Set
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

/**
 * Saves data to a JSON file.
 * @param {string} filePath - Path to the JSON file.
 * @param {object} data - Data to save.
 */
function saveData(filePath, data) {
    try {
        // Convert Sets to Arrays for JSON serialization before saving
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

// Load initial data
vaults = loadData(VAULTS_FILE, {});
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

            // Send any pending offline messages to the newly connected user
            if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                // Filter out any potential duplicate messages if a client reconnects quickly
                const uniqueOfflineMessages = offlineMessages[currentUserId].filter((msg, index, self) =>
                    index === self.findIndex((m) => (
                        m.vaultId === msg.vaultId &&
                        m.senderId === msg.senderId &&
                        m.timestamp === msg.timestamp &&
                        m.type === msg.type && // Important for distinguishing metadata/chunks
                        m.fileId === msg.fileId && // Important for distinguishing file parts
                        m.chunkIndex === msg.chunkIndex // Important for distinguishing file parts
                    ))
                );

                if (uniqueOfflineMessages.length > 0) {
                    ws.send(JSON.stringify({ type: 'offline_messages', messages: uniqueOfflineMessages }));
                    // Clear after sending - only remove the messages that were actually sent
                    // For simplicity in this demo, we clear all for the user.
                    // In production, you'd track which messages were successfully delivered.
                    delete offlineMessages[currentUserId];
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                    console.log(`Sent ${uniqueOfflineMessages.length} offline messages to ${currentUserId}`);
                }
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

                // These are already encrypted by the client using a key derived from a temporary hash.
                // The server's role is to store these encrypted components and the salt,
                // and provide the server-generated vaultHash for future decryption by joiners.
                const encryptedKeyB64FromClient = data.encryptedKeyB64;
                const ivB64FromClient = data.ivB64;
                const saltB64FromClient = data.saltB64; // This salt is used with the vaultHash to derive the key for decryption

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
                    encryptedKeyB64: encryptedKeyB64FromClient, // Store as received
                    ivB64: ivB64FromClient, // Store as received
                    saltB64: saltB64FromClient, // Store as received
                    used: data.vaultType === 'private' ? false : true,
                    members: new Set([currentUserId]),
                    createdAt: Date.now()
                };
                saveData(VAULTS_FILE, vaults);
                console.log(`Server: Vault ${vaultId} saved to file.`);


                // Send back the vault details and the *same* encrypted key to the creator.
                // The creator will use the server-generated vaultHash to decrypt their own vault key.
                ws.send(JSON.stringify({
                    type: 'vault_created',
                    vaultId: vaultId,
                    vaultHash: vaultHash, // This is the server-generated hash
                    vaultName: data.vaultName,
                    vaultType: data.vaultType,
                    expiration: data.expiration,
                    encryptedKeyB64: encryptedKeyB64FromClient, // Send back what was received
                    ivB64: ivB64FromClient, // Send back what was received
                    saltB64: saltB64FromClient // Send back what was received
                }));
                console.log(`Server: Vault ${vaultId} created by ${currentUserId}. Hash: ${vaultHash}. Response sent to client.`);
                break;

            case 'join_vault':
                const { vaultHash: joinHash, vaultName: userVaultName } = data;
                let foundVaultId = null;

                // Find the vault by hash
                for (const id in vaults) {
                    const vault = vaults[id];
                    // Re-derive the hash to compare (this is inefficient, but ensures hash is not stored directly)
                    // Ensure saltB64, encryptedKeyB64, ivB64 exist before attempting decryption
                    if (!vault.saltB64 || !vault.encryptedKeyB64 || !vault.ivB64) {
                        console.warn(`Server: Skipping vault ${id} due to missing key components.`);
                        continue;
                    }

                    const tempSalt = Buffer.from(vault.saltB64, 'base64');
                    try {
                        const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
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
                        console.log(`Server: Decryption failed for vault ${id} with provided hash.`, e.message);
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
                    console.log(`Server: Vault ${foundVaultId} members updated to file.`);

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
                    console.log(`Server: User ${currentUserId} joined vault ${foundVaultId}. Response sent.`);

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
                            console.log(`Server: Sent ${relevantMessages.length} offline messages to ${currentUserId} for vault ${foundVaultId}.`);
                        }
                    }

                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or hash is incorrect/expired.' }));
                    console.log(`Server: Join vault failed for ${currentUserId}. Hash: ${joinHash}.`);
                }
                break;

            case 'send_message': // Handles text messages
                const { vaultId: msgVaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType } = data;
                const vault = vaults[msgVaultId];

                if (vault && vault.members.has(senderId)) {
                    const messageToSend = {
                        type: 'new_message', // This type is for text messages
                        vaultId: msgVaultId,
                        senderId: senderId,
                        encryptedMessage: encryptedMessage, // Server only relays encrypted content
                        iv: iv,
                        timestamp: timestamp,
                        isFile: isFile, // Should be false for this type
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
                                console.log(`Server: Stored offline text message for ${memberId} in vault ${msgVaultId}`);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member.' }));
                    console.log(`Server: Message send failed for ${senderId} in vault ${msgVaultId}.`);
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
                        type: 'send_file_metadata', // Relay this specific type
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
                                console.log(`Server: Stored offline file metadata for ${memberId} (file: ${fileId})`);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member for file metadata.' }));
                    console.log(`Server: File metadata send failed for ${fileMetaSenderId} in vault ${fileMetaVaultId}.`);
                }
                break;

            case 'send_file_chunk':
                const {
                    vaultId: fileChunkVaultId,
                    senderId: fileChunkSenderId,
                    fileId: chunkFileId,
                    chunkIndex,
                    encryptedChunk, // This contains the combined header+IV+ciphertext
                    timestamp: fileChunkTimestamp,
                    fileName: fileChunkName, // Included for offline message clarity
                    fileMimeType: fileChunkMimeType // Included for offline message clarity
                } = data;

                const fileChunkVault = vaults[fileChunkVaultId];

                if (fileChunkVault && fileChunkVault.members.has(fileChunkSenderId)) {
                    const fileChunkToSend = {
                        type: 'send_file_chunk', // Relay this specific type
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
                                console.log(`Server: Stored offline file chunk ${chunkIndex} for ${memberId} (file: ${chunkFileId})`);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member for file chunk.' }));
                    console.log(`Server: File chunk send failed for ${fileChunkSenderId} in vault ${fileChunkVaultId}.`);
                }
                break;

            case 'nuke':
                const nukeUserId = data.userId;
                console.log(`Server: Nuke request received for user: ${nukeUserId}`);

                // Remove user from all vaults
                for (const id in vaults) {
                    if (vaults[id].members.has(nukeUserId)) {
                        vaults[id].members.delete(nukeUserId);
                        // If a private vault becomes empty, consider deleting it or marking it for deletion
                        if (vaults[id].type === 'private' && vaults[id].members.size === 0) {
                            console.log(`Server: Private vault ${id} is now empty after nuke, marking for deletion.`);
                            // We can set a flag or short expiration to clean up empty private vaults
                            // For this demo, we'll just leave it empty until its natural expiration
                        }
                    }
                }
                saveData(VAULTS_FILE, vaults);
                console.log(`Server: Vaults updated after nuke for ${nukeUserId}.`);

                // Clear offline messages for this user
                if (offlineMessages[nukeUserId]) {
                    delete offlineMessages[nukeUserId];
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                    console.log(`Server: Offline messages cleared for ${nukeUserId}.`);
                }

                // Disconnect the client
                if (connectedClients[nukeUserId]) {
                    connectedClients[nukeUserId].close();
                    delete connectedClients[nukeUserId];
                    console.log(`Server: User ${nukeUserId} disconnected by nuke request.`);
                }
                console.log(`Server: User ${nukeUserId} data nuked from server.`);
                break;

            default:
                ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
                console.log(`Server: Unknown message type received: ${data.type}`);
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
            console.log(`Server: Vault ${vault.name} (${vaultId}) has expired. Deleting.`);
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
        console.log("Server: Expired vaults and associated offline messages cleaned up.");
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
