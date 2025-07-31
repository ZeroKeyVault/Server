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
        let data;
        try {
            data = JSON.parse(message.toString());
        } catch (e) {
            console.error("Failed to parse incoming WebSocket message:", e, message.toString());
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'error', message: 'Malformed message format' }));
            }
            return;
        }
        
        console.log('Received from client:', data.type, data.userId || '');
        
        if (data.type === 'register') {
            if (!data.userId || typeof data.userId !== 'string') {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid user ID format' }));
                }
                return;
            }
            
            currentUserId = data.userId;
            connectedClients[currentUserId] = ws;
            console.log(`User ${currentUserId} connected.`);
            
            // Send any pending offline messages to the newly connected user
            if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'offline_messages', messages: offlineMessages[currentUserId] }));
                }
                delete offlineMessages[currentUserId]; // Clear after sending
                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                console.log(`Sent ${offlineMessages[currentUserId]?.length || 0} offline messages to ${currentUserId}`);
            }
        } else if (!currentUserId) {
            // Reject messages if user is not registered yet
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'error', message: 'Please register your user ID first.' }));
            }
            return;
        }
        
        try {
            switch (data.type) {
                case 'create_private_vault':
                    // Validate input
                    if (!data.vaultName || !data.expiration || !data.vaultHash || !data.publicKey) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing required parameters for private vault creation' 
                            }));
                        }
                        return;
                    }
                    
                    const vaultId = crypto.randomUUID();
                    const publicKey = Buffer.from(data.publicKey, 'base64');
                    
                    vaults[vaultId] = {
                        name: data.vaultName,
                        type: 'private',
                        expiration: data.expiration,
                        adminId: currentUserId,
                        vaultHash: data.vaultHash,
                        publicKey: publicKey.toString('base64'),
                        used: false,
                        members: new Set([currentUserId]),
                        createdAt: Date.now()
                    };
                    
                    saveData(VAULTS_FILE, vaults);
                    
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'private_vault_created',
                            vaultId: vaultId,
                            vaultHash: data.vaultHash,
                            vaultName: data.vaultName,
                            expiration: data.expiration
                        }));
                    }
                    
                    console.log(`Private vault ${vaultId} created by ${currentUserId}. Hash: ${data.vaultHash}`);
                    break;
                    
                case 'request_join_private_vault':
                    // Validate input
                    if (!data.vaultHash || !data.vaultName) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing required parameters for joining private vault' 
                            }));
                        }
                        return;
                    }
                    
                    let foundVaultId = null;
                    
                    // Find the vault by hash
                    for (const id in vaults) {
                        const vault = vaults[id];
                        if (vault.vaultHash === data.vaultHash) {
                            foundVaultId = id;
                            break;
                        }
                    }
                    
                    if (foundVaultId) {
                        const vault = vaults[foundVaultId];
                        
                        if (vault.type === 'private' && vault.used) {
                            if (ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({ 
                                    type: 'error', 
                                    message: 'This private vault hash has already been used.' 
                                }));
                            }
                            return;
                        }
                        
                        vault.members.add(currentUserId);
                        if (vault.type === 'private') {
                            vault.used = true;
                        }
                        
                        saveData(VAULTS_FILE, vaults);
                        
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                type: 'private_vault_public_key',
                                vaultId: foundVaultId,
                                vaultName: data.vaultName,
                                expiration: vault.expiration,
                                publicKey: vault.publicKey
                            }));
                        }
                        
                        console.log(`User ${currentUserId} requested to join private vault ${foundVaultId}.`);
                    } else {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Vault not found or hash is incorrect/expired.' 
                            }));
                        }
                    }
                    break;
                    
                case 'submit_private_vault_key':
                    // Validate input
                    if (!data.vaultId || !data.ciphertext || !data.encryptedVaultKey || !data.iv) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing required parameters for private vault key submission' 
                            }));
                        }
                        return;
                    }
                    
                    const targetVault = vaults[data.vaultId];
                    if (targetVault && targetVault.type === 'private') {
                        // Forward the data to the creator
                        const creatorWs = connectedClients[targetVault.adminId];
                        if (creatorWs && creatorWs.readyState === WebSocket.OPEN) {
                            creatorWs.send(JSON.stringify({
                                type: 'private_vault_key',
                                vaultId: data.vaultId,
                                ciphertext: data.ciphertext,
                                encryptedVaultKey: data.encryptedVaultKey,
                                iv: data.iv
                            }));
                        } else {
                            // Store for offline delivery
                            if (!offlineMessages[targetVault.adminId]) {
                                offlineMessages[targetVault.adminId] = [];
                            }
                            offlineMessages[targetVault.adminId].push({
                                type: 'private_vault_key',
                                vaultId: data.vaultId,
                                ciphertext: data.ciphertext,
                                encryptedVaultKey: data.encryptedVaultKey,
                                iv: data.iv
                            });
                            saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                        }
                    }
                    break;
                    
                case 'create_vault':
                    // Validate input
                    if (!data.vaultName || !data.vaultType || !data.expiration || 
                        !data.rawVaultKeyB64 || !data.saltB64) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing required parameters for vault creation' 
                            }));
                        }
                        return;
                    }
                    
                    const publicVaultId = crypto.randomUUID();
                    const vaultHash = crypto.randomBytes(16).toString('hex');
                    const rawVaultKey = Buffer.from(data.rawVaultKeyB64, 'base64');
                    const salt = Buffer.from(data.saltB64, 'base64');
                    
                    // Server encrypts the raw vault key using a key derived from the vaultHash
                    const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, salt);
                    const ivForVaultKey = crypto.randomBytes(16);
                    const encryptedVaultKey = encryptDataServer(rawVaultKey, derivedKeyForVaultKey, ivForVaultKey);
                    
                    vaults[publicVaultId] = {
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
                    saveData(VAULTS_FILE, vaults);
                    
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'vault_created',
                            vaultId: publicVaultId,
                            vaultHash: vaultHash,
                            vaultName: data.vaultName,
                            vaultType: data.vaultType,
                            expiration: data.expiration,
                            encryptedKeyB64: encryptedVaultKey.toString('base64'),
                            ivB64: ivForVaultKey.toString('base64'),
                            saltB64: salt.toString('base64')
                        }));
                    }
                    
                    console.log(`Vault ${publicVaultId} created by ${currentUserId}. Hash: ${vaultHash}`);
                    break;
                    
                case 'join_vault':
                    // Validate input
                    if (!data.vaultHash || !data.vaultName) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing required parameters for joining vault' 
                            }));
                        }
                        return;
                    }
                    
                    let foundPublicVaultId = null;
                    
                    // Find the vault by hash
                    for (const id in vaults) {
                        const vault = vaults[id];
                        const tempSalt = Buffer.from(vault.saltB64, 'base64');
                        const tempDerivedKey = await deriveKeyFromHashServer(data.vaultHash, tempSalt);
                        try {
                            decryptDataServer(
                                Buffer.from(vault.encryptedKeyB64, 'base64'),
                                tempDerivedKey,
                                Buffer.from(vault.ivB64, 'base64')
                            );
                            foundPublicVaultId = id;
                            break;
                        } catch (e) {
                            continue;
                        }
                    }
                    
                    if (foundPublicVaultId) {
                        const vault = vaults[foundPublicVaultId];
                        if (vault.type === 'private' && vault.used) {
                            if (ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({ 
                                    type: 'error', 
                                    message: 'This private vault hash has already been used.' 
                                }));
                            }
                            return;
                        }
                        vault.members.add(currentUserId);
                        if (vault.type === 'private') {
                            vault.used = true;
                        }
                        saveData(VAULTS_FILE, vaults);
                        
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                type: 'vault_joined',
                                joinedVaultId: foundPublicVaultId,
                                joinedVaultName: data.vaultName,
                                joinedVaultType: vault.type,
                                joinedExpiration: vault.expiration,
                                encryptedKeyB64: vault.encryptedKeyB64,
                                ivB64: vault.ivB64,
                                saltB64: vault.saltB64,
                                vaultHash: data.vaultHash
                            }));
                        }
                        
                        console.log(`User ${currentUserId} joined vault ${foundPublicVaultId}.`);
                        
                        // Send any pending offline messages for this vault to the new member
                        if (offlineMessages[currentUserId]) {
                            const relevantMessages = offlineMessages[currentUserId].filter(
                                msg => msg.vaultId === foundPublicVaultId
                            );
                            if (relevantMessages.length > 0 && ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({ 
                                    type: 'offline_messages', 
                                    messages: relevantMessages 
                                }));
                                offlineMessages[currentUserId] = offlineMessages[currentUserId].filter(
                                    msg => msg.vaultId !== foundPublicVaultId
                                );
                                if (offlineMessages[currentUserId].length === 0) {
                                    delete offlineMessages[currentUserId];
                                }
                                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                            }
                        }
                    } else {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Vault not found or hash is incorrect/expired.' 
                            }));
                        }
                    }
                    break;
                    
                case 'send_message':
                    // Validate input
                    if (!data.vaultId || !data.senderId || !data.encryptedMessage || 
                        !data.iv || !data.timestamp) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing required parameters for sending message' 
                            }));
                        }
                        return;
                    }
                    
                    const messageVault = vaults[data.vaultId];
                    if (messageVault && messageVault.members.has(data.senderId)) {
                        const messageToSend = {
                            type: 'new_message',
                            vaultId: data.vaultId,
                            senderId: data.senderId,
                            encryptedMessage: data.encryptedMessage,
                            iv: data.iv,
                            timestamp: data.timestamp,
                            isFile: data.isFile || false,
                            fileName: data.fileName || null,
                            fileMimeType: data.fileMimeType || null
                        };
                        messageVault.members.forEach(memberId => {
                            if (memberId !== data.senderId) {
                                const recipientWs = connectedClients[memberId];
                                if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
                                    recipientWs.send(JSON.stringify(messageToSend));
                                } else {
                                    if (!offlineMessages[memberId]) {
                                        offlineMessages[memberId] = [];
                                    }
                                    offlineMessages[memberId].push(messageToSend);
                                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                                    console.log(`Stored offline message for ${memberId} in vault ${data.vaultId}`);
                                }
                            }
                        });
                    } else {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Vault not found or you are not a member.' 
                            }));
                        }
                    }
                    break;
                    
                case 'nuke':
                    if (!data.userId) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Missing user ID for nuke request' 
                            }));
                        }
                        return;
                    }
                    
                    console.log(`Nuke request received for user: ${data.userId}`);
                    
                    // Remove user from all vaults
                    for (const id in vaults) {
                        if (vaults[id].members.has(data.userId)) {
                            vaults[id].members.delete(data.userId);
                            if (vaults[id].type === 'private' && vaults[id].members.size === 0) {
                                console.log(`Private vault ${id} is now empty after nuke, marking for deletion.`);
                            }
                        }
                    }
                    saveData(VAULTS_FILE, vaults);
                    
                    // Clear offline messages for this user
                    if (offlineMessages[data.userId]) {
                        delete offlineMessages[data.userId];
                        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                    }
                    
                    // Disconnect the client
                    if (connectedClients[data.userId] && connectedClients[data.userId] !== ws) {
                        connectedClients[data.userId].close();
                        delete connectedClients[data.userId];
                    }
                    console.log(`User ${data.userId} data nuked from server.`);
                    break;
                    
                default:
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ 
                            type: 'error', 
                            message: 'Unknown message type.' 
                        }));
                    }
                    break;
            }
        } catch (error) {
            console.error(`Error processing message type ${data.type}:`, error);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ 
                    type: 'error', 
                    message: 'Internal server error. Please try again.' 
                }));
            }
        }
    });
    
    ws.on('close', (code, reason) => {
        if (currentUserId) {
            delete connectedClients[currentUserId];
            console.log(`User ${currentUserId} disconnected (code: ${code}, reason: ${reason}).`);
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
    const vaultIdsToDelete = [];
    
    for (const vaultId in vaults) {
        const vault = vaults[vaultId];
        if (vault.expiration === 'never') continue;
        
        let expirationTimeMs;
        const match = vault.expiration.match(/(\d+)([hmy])/);
        if (!match) {
            console.warn(`Invalid expiration format for vault ${vaultId}: ${vault.expiration}`);
            continue;
        }
        
        const [value, unit] = match.slice(1);
        const numValue = parseInt(value);
        
        switch (unit) {
            case 'h': expirationTimeMs = numValue * 60 * 60 * 1000; break;
            case 'd': expirationTimeMs = numValue * 24 * 60 * 60 * 1000; break;
            case 'm': expirationTimeMs = numValue * 30 * 24 * 60 * 60 * 1000; break;
            case 'y': expirationTimeMs = numValue * 365 * 24 * 60 * 60 * 1000; break;
            default: 
                console.warn(`Unknown expiration unit for vault ${vaultId}: ${unit}`);
                continue;
        }
        
        if (vault.createdAt + expirationTimeMs < now) {
            console.log(`Vault ${vault.name} (${vaultId}) has expired. Deleting.`);
            vaultIdsToDelete.push(vaultId);
        }
    }
    
    // Process deletions in batch
    if (vaultIdsToDelete.length > 0) {
        vaultIdsToDelete.forEach(vaultId => {
            const vault = vaults[vaultId];
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
                    offlineMessages[memberId] = offlineMessages[memberId].filter(
                        msg => msg.vaultId !== vaultId
                    );
                    if (offlineMessages[memberId].length === 0) {
                        delete offlineMessages[memberId];
                    }
                }
            });
            delete vaults[vaultId];
        });
        
        saveData(VAULTS_FILE, vaults);
        saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
        changed = true;
    }
    
    if (changed) {
        console.log(`Cleaned up ${vaultIdsToDelete.length} expired vaults.`);
    }
}

// Check expirations every minute
setInterval(checkVaultExpirations, 60 * 1000);

// --- Basic HTTP Server for Health Check (for Render) ---
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>The Platform Server</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
                .info { margin: 20px 0; padding: 15px; background-color: #f9f9f9; border-left: 4px solid #4CAF50; }
                .footer { margin-top: 40px; text-align: center; color: #777; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>The Platform Server</h1>
                <p>Secure messaging relay server</p>
            </div>
            
            <div class="info">
                <h2>Server Status</h2>
                <p>This is a secure relay server for The Platform messaging application.</p>
                <p>For client connection, please use the WebSocket endpoint at <code>wss://${req.headers.host}</code></p>
                <p>Health check: <a href="/health">/health</a></p>
            </div>
            
            <div class="footer">
                <p>Encrypted by The Laughing Buddha Protocol</p>
                <p>a Prakhar Solanki creation</p>
                <p>&copy;2025-The Platform. All rights reserved.</p>
            </div>
        </body>
        </html>
    `);
});

// Health check endpoint
app.get('/health', (req, res) => {
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        activeConnections: Object.keys(connectedClients).length,
        vaultCount: Object.keys(vaults).length
    };
    
    res.status(200).json(health);
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log("The Platform Server is running");
    
    // Initial expiration check on startup
    checkVaultExpirations();
});
