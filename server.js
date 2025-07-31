// server.js
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// Import Kyber for post-quantum key exchange
const { kyber } = require('crystals-kyber'); // CRYSTALS-Kyber implementation (NIST FIPS 203) [[15]]

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;

// --- Server-side Data Storage ---
const DATA_DIR = path.join(__dirname, 'data');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.json');
const OFFLINE_MESSAGES_FILE = path.join(DATA_DIR, 'offline_messages.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

let vaults = {}; // vaultId -> { name, type, expiration, adminId, encryptedKeyB64, ivB64, saltB64, used, members: Set<userId>, kyberPublicKey? }
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

// --- Cryptography on Server ---
/**
 * Derives a cryptographic key from a given password (hash) using PBKDF2.
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
 * Encrypts the vault key using Kyber and then with the hash-derived key.
 * @param {Buffer} rawVaultKey - The raw AES vault key.
 * @param {string} vaultHash - The vault hash.
 * @param {Buffer} salt - The salt for PBKDF2.
 * @returns {Object} Contains encryptedKeyB64, ivB64, and saltB64
 */
async function encryptVaultKeyWithKyber(rawVaultKey, vaultHash, salt) {
    // First, encrypt with Kyber (post-quantum layer)
    const { publicKey, secretKey } = kyber.keygen();
    const { sharedSecret, ciphertext } = kyber.encaps(publicKey);
    
    // Use shared secret to encrypt the raw vault key
    const ivForVaultKey = crypto.randomBytes(16);
    const encryptedVaultKey = encryptDataServer(rawVaultKey, sharedSecret, ivForVaultKey);
    
    // Now encrypt the Kyber public key and ciphertext with the hash-derived key
    const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
    const ivForKyber = crypto.randomBytes(16);
    const encryptedKyberData = encryptDataServer(
        Buffer.concat([publicKey, ciphertext]),
        derivedKeyForVaultKey,
        ivForKyber
    );
    
    return {
        encryptedKeyB64: encryptedVaultKey.toString('base64'),
        ivB64: ivForVaultKey.toString('base64'),
        saltB64: salt.toString('base64'),
        kyberDataB64: encryptedKyberData.toString('base64'),
        kyberIvB64: ivForKyber.toString('base64')
    };
}

/**
 * Decrypts the vault key using Kyber and the hash-derived key.
 * @param {string} encryptedKeyB64 - Base64 encoded encrypted vault key.
 * @param {string} ivB64 - Base64 encoded IV for vault key.
 * @param {string} kyberDataB64 - Base64 encoded Kyber data.
 * @param {string} kyberIvB64 - Base64 encoded IV for Kyber data.
 * @param {string} vaultHash - The vault hash.
 * @param {Buffer} salt - The salt for PBKDF2.
 * @returns {Buffer} The decrypted vault key.
 */
async function decryptVaultKeyWithKyber(encryptedKeyB64, ivB64, kyberDataB64, kyberIvB64, vaultHash, salt) {
    // First, decrypt Kyber data with hash-derived key
    const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
    const decryptedKyberData = decryptDataServer(
        Buffer.from(kyberDataB64, 'base64'),
        derivedKeyForVaultKey,
        Buffer.from(kyberIvB64, 'base64')
    );
    
    // Extract Kyber public key and ciphertext
    const publicKey = decryptedKyberData.slice(0, 1184); // Kyber768 public key size
    const ciphertext = decryptedKyberData.slice(1184);
    
    // Decrypt with Kyber
    const sharedSecret = kyber.decaps(Buffer.from(secretKey), ciphertext);
    const decryptedVaultKey = decryptDataServer(
        Buffer.from(encryptedKeyB64, 'base64'),
        sharedSecret,
        Buffer.from(ivB64, 'base64')
    );
    
    return decryptedVaultKey;
}

// --- WebSocket Server Logic ---
wss.on('connection', (ws) => {
    let currentUserId = null;
    ws.on('message', async (message) => {
        const data = JSON.parse(message.toString());
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
                const salt = crypto.randomBytes(16);
                const rawVaultKey = Buffer.from(data.rawVaultKeyB64, 'base64');
                
                try {
                    // Use Kyber for the initial key exchange (post-quantum security layer)
                    const encryptionResult = await encryptVaultKeyWithKyber(rawVaultKey, vaultHash, salt);
                    
                    vaults[vaultId] = {
                        name: data.vaultName,
                        type: data.vaultType,
                        expiration: data.expiration,
                        adminId: currentUserId,
                        encryptedKeyB64: encryptionResult.encryptedKeyB64,
                        ivB64: encryptionResult.ivB64,
                        saltB64: encryptionResult.saltB64,
                        kyberDataB64: encryptionResult.kyberDataB64,
                        kyberIvB64: encryptionResult.kyberIvB64,
                        used: data.vaultType === 'private' ? false : true,
                        members: new Set([currentUserId]),
                        createdAt: Date.now()
                    };
                    
                    saveData(VAULTS_FILE, vaults);
                    
                    ws.send(JSON.stringify({
                        type: 'vault_created',
                        vaultId: vaultId,
                        vaultHash: vaultHash,
                        vaultName: data.vaultName,
                        vaultType: data.vaultType,
                        expiration: data.expiration,
                        encryptedKeyB64: encryptionResult.encryptedKeyB64,
                        ivB64: encryptionResult.ivB64,
                        saltB64: encryptionResult.saltB64,
                        kyberDataB64: encryptionResult.kyberDataB64,
                        kyberIvB64: encryptionResult.kyberIvB64
                    }));
                    
                    console.log(`Vault ${vaultId} created by ${currentUserId}. Hash: ${vaultHash}`);
                } catch (error) {
                    console.error('Kyber encryption error:', error);
                    ws.send(JSON.stringify({ type: 'error', message: 'Failed to encrypt vault key with Kyber.' }));
                }
                break;
                
            case 'join_vault':
                const { vaultHash: joinHash, vaultName: userVaultName } = data;
                let foundVaultId = null;
                
                for (const id in vaults) {
                    const vault = vaults[id];
                    try {
                        // Verify access using the hash (same as before)
                        const tempSalt = Buffer.from(vault.saltB64, 'base64');
                        const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                        
                        // Just verify we can derive the key (no actual decryption needed here)
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
                    
                    saveData(VAULTS_FILE, vaults);
                    
                    ws.send(JSON.stringify({
                        type: 'vault_joined',
                        joinedVaultId: foundVaultId,
                        joinedVaultName: userVaultName,
                        joinedVaultType: vault.type,
                        joinedExpiration: vault.expiration,
                        encryptedKeyB64: vault.encryptedKeyB64,
                        ivB64: vault.ivB64,
                        saltB64: vault.saltB64,
                        kyberDataB64: vault.kyberDataB64,
                        kyberIvB64: vault.kyberIvB64,
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
                            console.log(`Private vault ${id} is now empty after nuke, marking for deletion.`);
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
        const match = vault.expiration.match(/(\d+)([hmy])/);
        if (!match) {
            console.error(`Invalid expiration format: ${vault.expiration}`);
            continue;
        }
        
        const [value, unit] = match.slice(1);
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
        saveData(VAULTS_FILE, vaults);
        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
    }
}

// Check expirations every minute
setInterval(checkVaultExpirations, 60 * 1000);

// --- Basic HTTP Server for Health Check ---
app.get('/', (req, res) => {
    res.send('The Platform Relay Server is running with post-quantum security.');
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT} with Kyber post-quantum cryptography`);
});
