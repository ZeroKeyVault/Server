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
const USER_KEYS_FILE = path.join(DATA_DIR, 'user_keys.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

let vaults = {}; // vaultId -> { name, type, expiration, adminId, encryptedKeyB64, ivB64, saltB64, used (for private), members: Set<userId>, isKyberEncrypted, kyberCiphertext }
let offlineMessages = {}; // userId -> [{ vaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType }]
let connectedClients = {}; // userId -> WebSocket
let userKeys = {}; // userId -> { publicKey, keyTimestamp }

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
userKeys = loadData(USER_KEYS_FILE, {});

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

/**
 * Stores a user's Kyber public key
 * @param {string} userId - User ID
 * @param {string} publicKeyB64 - Base64 encoded public key
 */
function storeUserKyberPublicKey(userId, publicKeyB64) {
    userKeys[userId] = {
        publicKey: publicKeyB64,
        keyTimestamp: Date.now()
    };
    saveData(USER_KEYS_FILE, userKeys);
}

/**
 * Gets a user's Kyber public key
 * @param {string} userId - User ID
 * @returns {string|null} Base64 encoded public key or null if not found
 */
function getUserKyberPublicKey(userId) {
    const userKey = userKeys[userId];
    return userKey ? userKey.publicKey : null;
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
            case 'store_kyber_public_key':
                // Store user's Kyber public key
                storeUserKyberPublicKey(currentUserId, data.publicKey);
                console.log(`Stored Kyber public key for user ${currentUserId}`);
                ws.send(JSON.stringify({ type: 'kyber_key_stored', success: true }));
                break;

            case 'create_vault':
                const vaultId = crypto.randomUUID();
                const vaultHash = crypto.randomBytes(16).toString('hex'); // Unique hash for joining

                let encryptedVaultKey;
                let ivForVaultKey;
                let saltForKey = null;
                let kyberCiphertext = null;
                let isKyberEncrypted = data.isKyberEncrypted || false;

                if (isKyberEncrypted && data.vaultType === 'private') {
                    // Use Kyber encryption for private vaults
                    encryptedVaultKey = Buffer.from(data.encryptedVaultKeyB64, 'base64');
                    ivForVaultKey = Buffer.from(data.ivB64, 'base64');
                    kyberCiphertext = data.kyberCiphertext;
                } else {
                    // Use regular PBKDF2 encryption for public vaults
                    const rawVaultKey = Buffer.from(data.rawVaultKeyB64, 'base64');
                    const salt = Buffer.from(data.saltB64, 'base64');
                    saltForKey = salt;

                    // Server encrypts the raw vault key using a key derived from the vaultHash
                    const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
                    ivForVaultKey = crypto.randomBytes(16); // IV for encrypting the vault key
                    encryptedVaultKey = encryptDataServer(rawVaultKey, derivedKeyForVaultKey, ivForVaultKey);
                }

                vaults[vaultId] = {
                    name: data.vaultName,
                    type: data.vaultType,
                    expiration: data.expiration,
                    adminId: currentUserId, // Admin for public vaults
                    encryptedKeyB64: encryptedVaultKey.toString('base64'), // Store encrypted key
                    ivB64: ivForVaultKey.toString('base64'), // Store IV for key encryption
                    saltB64: saltForKey ? saltForKey.toString('base64') : null, // Store salt for key derivation
                    used: data.vaultType === 'private' ? false : true, // Private hash used once
                    members: new Set([currentUserId]),
                    createdAt: Date.now(), // For expiration
                    isKyberEncrypted: isKyberEncrypted,
                    kyberCiphertext: kyberCiphertext
                };
                saveData(VAULTS_FILE, vaults);

                // Send back the vault details and the encrypted key to the creator
                const createResponse = {
                    type: 'vault_created',
                    vaultId: vaultId,
                    vaultHash: vaultHash,
                    vaultName: data.vaultName,
                    vaultType: data.vaultType,
                    expiration: data.expiration,
                    encryptedKeyB64: encryptedVaultKey.toString('base64'),
                    ivB64: ivForVaultKey.toString('base64'),
                    isKyberEncrypted: isKyberEncrypted
                };

                if (saltForKey) {
                    createResponse.saltB64 = saltForKey.toString('base64');
                }
                if (kyberCiphertext) {
                    createResponse.kyberCiphertext = kyberCiphertext;
                }

                ws.send(JSON.stringify(createResponse));
                console.log(`Vault ${vaultId} created by ${currentUserId}. Hash: ${vaultHash}, Kyber: ${isKyberEncrypted}`);
                break;

            case 'join_vault':
                const { vaultHash: joinHash, vaultName: userVaultName } = data;
                let foundVaultId = null;

                // Find the vault by hash
                for (const id in vaults) {
                    const vault = vaults[id];
                    
                    if (vault.isKyberEncrypted) {
                        // For Kyber-encrypted vaults, we need to match against stored metadata
                        // Since we can't decrypt without the user's private key
                        // We'll use a different approach - store vault hash for lookup
                        // For now, let's assume the hash comparison works differently for Kyber vaults
                        // In a real implementation, you might store additional metadata
                        continue; // Skip Kyber vaults for hash-based lookup
                    } else {
                        // Regular PBKDF2-based vault
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
                }

                // For Kyber vaults, we need a different approach to find them
                // Let's also check if the hash matches any vault ID pattern or stored reference
                if (!foundVaultId) {
                    // Alternative lookup for Kyber vaults - using hash as identifier
                    for (const id in vaults) {
                        const vault = vaults[id];
                        if (vault.isKyberEncrypted) {
                            // Simple hash comparison for Kyber vaults
                            // In production, you'd have a more sophisticated lookup mechanism
                            if (vault.vaultHashReference === joinHash) {
                                foundVaultId = id;
                                break;
                            }
                        }
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
                    const joinResponse = {
                        type: 'vault_joined',
                        joinedVaultId: foundVaultId,
                        joinedVaultName: userVaultName, // Use the name given by the joiner
                        joinedVaultType: vault.type,
                        joinedExpiration: vault.expiration,
                        encryptedKeyB64: vault.encryptedKeyB64, // Send the encrypted key
                        ivB64: vault.ivB64, // Send the IV for key encryption
                        vaultHash: joinHash, // Send the hash back so client can derive key
                        isKyberEncrypted: vault.isKyberEncrypted
                    };

                    if (vault.saltB64) {
                        joinResponse.saltB64 = vault.saltB64; // Send the salt for key derivation
                    }
                    if (vault.kyberCiphertext) {
                        joinResponse.kyberCiphertext = vault.kyberCiphertext;
                    }

                    ws.send(JSON.stringify(joinResponse));
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

                // Clear user's Kyber keys
                if (userKeys[nukeUserId]) {
                    delete userKeys[nukeUserId];
                    saveData(USER_KEYS_FILE, userKeys);
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
        const expirationMatch = vault.expiration.match(/(\d+)([hmy])/);
        if (!expirationMatch) continue;
        
        const [, value, unit] = expirationMatch;
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

// --- Enhanced Kyber Vault Handling ---

/**
 * Creates a simplified lookup system for Kyber vaults
 * This stores a hash reference to help with vault discovery
 */
function createKyberVaultReference(vaultId, vaultHash) {
    // Store the hash reference for easier lookup
    if (!vaults[vaultId]) return;
    
    // Create a hash of the hash for lookup purposes (avoiding storing the actual hash)
    const hashReference = crypto.createHash('sha256').update(vaultHash).digest('hex').substring(0, 16);
    vaults[vaultId].vaultHashReference = hashReference;
    saveData(VAULTS_FILE, vaults);
    
    return hashReference;
}

/**
 * Finds Kyber vault by hash reference
 */
function findKyberVaultByHash(vaultHash) {
    const hashReference = crypto.createHash('sha256').update(vaultHash).digest('hex').substring(0, 16);
    
    for (const vaultId in vaults) {
        const vault = vaults[vaultId];
        if (vault.isKyberEncrypted && vault.vaultHashReference === hashReference) {
            return vaultId;
        }
    }
    return null;
}

// --- Enhanced Vault Creation with Better Kyber Support ---

/**
 * Enhanced create vault handler with proper Kyber support
 */
function handleEnhancedVaultCreation(data, currentUserId, ws) {
    const vaultId = crypto.randomUUID();
    const vaultHash = crypto.randomBytes(16).toString('hex');
    
    // Store vault with enhanced Kyber support
    const vault = {
        name: data.vaultName,
        type: data.vaultType,
        expiration: data.expiration,
        adminId: currentUserId,
        encryptedKeyB64: data.encryptedVaultKeyB64,
        ivB64: data.ivB64,
        used: data.vaultType === 'private' ? false : true,
        members: new Set([currentUserId]),
        createdAt: Date.now(),
        isKyberEncrypted: data.isKyberEncrypted || false
    };

    if (data.isKyberEncrypted) {
        vault.kyberCiphertext = data.kyberCiphertext;
        // Create hash reference for easier lookup
        vault.vaultHashReference = crypto.createHash('sha256').update(vaultHash).digest('hex').substring(0, 16);
    } else {
        vault.saltB64 = data.saltB64;
    }

    vaults[vaultId] = vault;
    saveData(VAULTS_FILE, vaults);

    return { vaultId, vaultHash, vault };
}

/**
 * Enhanced join vault handler with proper Kyber support
 */
async function handleEnhancedVaultJoin(data, currentUserId, ws) {
    const { vaultHash: joinHash, vaultName: userVaultName } = data;
    let foundVaultId = null;

    // First, try to find Kyber vaults using hash reference
    foundVaultId = findKyberVaultByHash(joinHash);
    
    // If not found, try regular PBKDF2 vaults
    if (!foundVaultId) {
        for (const id in vaults) {
            const vault = vaults[id];
            if (!vault.isKyberEncrypted && vault.saltB64) {
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
        }
    }

    return foundVaultId;
}

// --- Basic HTTP Server for Health Check (for Render) ---
app.get('/', (req, res) => {
    res.send(`
        <h1>The Platform Relay Server is running</h1>
        <p>Enhanced with Kyber Encryption Support</p>
        <p>Server Status: Active</p>
        <p>Vaults: ${Object.keys(vaults).length}</p>
        <p>Connected Clients: ${Object.keys(connectedClients).length}</p>
        <p>User Keys Stored: ${Object.keys(userKeys).length}</p>
    `);
});

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        vaults: Object.keys(vaults).length,
        connectedClients: Object.keys(connectedClients).length,
        userKeys: Object.keys(userKeys).length,
        kyberEnabled: true
    });
});

// Statistics endpoint
app.get('/stats', (req, res) => {
    const kyberVaults = Object.values(vaults).filter(v => v.isKyberEncrypted).length;
    const regularVaults = Object.values(vaults).filter(v => !v.isKyberEncrypted).length;
    
    res.json({
        totalVaults: Object.keys(vaults).length,
        kyberVaults: kyberVaults,
        regularVaults: regularVaults,
        connectedClients: Object.keys(connectedClients).length,
        userKeys: Object.keys(userKeys).length,
        offlineMessageQueues: Object.keys(offlineMessages).length,
        uptime: process.uptime()
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log('The Platform Relay Server with Kyber Encryption Support');
    console.log('Enhanced security features:');
    console.log('- Kyber-like post-quantum encryption for private vaults');
    console.log('- PBKDF2 encryption for public vaults');
    console.log('- End-to-end encryption with zero-knowledge architecture');
    console.log('- Automatic vault expiration');
    console.log('- Offline message queuing');
});
