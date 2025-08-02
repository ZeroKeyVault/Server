const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const oqs = require('oqs');

// --- Configuration ---
const SERVER_PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, 'encrypted_data.bin');
const SERVER_AES_KEY_HEX = process.env.SERVER_AES_KEY || crypto.randomBytes(32).toString('hex');
const SERVER_AES_KEY = Buffer.from(SERVER_AES_KEY_HEX, 'hex');

// Validate key length
if (SERVER_AES_KEY.length !== 32) {
    console.error("SERVER_AES_KEY must be a 32-byte (64 hex character) hex string.");
    process.exit(1);
}

console.log(`Server running on port ${SERVER_PORT}`);
console.log(`Server AES Key Length: ${SERVER_AES_KEY.length} bytes`);

// --- Data Structures ---
let serverData = {
    users: {},
    vaults: {},
    messages: {}
};

// --- Data Persistence (Encrypted at Rest) ---
function encryptData(data) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', SERVER_AES_KEY, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return iv.toString('hex') + ':' + encrypted + ':' + tag;
}

function decryptData(encryptedDataWithTag) {
    const parts = encryptedDataWithTag.split(':');
    if (parts.length !== 3) throw new Error('Invalid encrypted data format');
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const tag = Buffer.from(parts[2], 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', SERVER_AES_KEY, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

function loadData() {
    if (fs.existsSync(DATA_FILE)) {
        try {
            const encrypted = fs.readFileSync(DATA_FILE, 'utf8');
            const data = decryptData(encrypted);
            
            // Reconstruct Sets from arrays
            for (const vaultId in data.vaults) {
                if (data.vaults[vaultId].members && Array.isArray(data.vaults[vaultId].members)) {
                    data.vaults[vaultId].members = new Set(data.vaults[vaultId].members);
                }
            }
            console.log("Data loaded from disk.");
            return data;
        } catch (err) {
            console.error("Error loading data:", err);
            return { users: {}, vaults: {}, messages: {} };
        }
    }
    return { users: {}, vaults: {}, messages: {} };
}

function saveData() {
    try {
        // Convert Sets to arrays for JSON serialization
        const dataToSave = JSON.parse(JSON.stringify(serverData));
        for (const vaultId in dataToSave.vaults) {
            if (dataToSave.vaults[vaultId].members instanceof Set) {
                dataToSave.vaults[vaultId].members = Array.from(dataToSave.vaults[vaultId].members);
            }
        }
        
        const encrypted = encryptData(dataToSave);
        fs.writeFileSync(DATA_FILE, encrypted, 'utf8');
    } catch (err) {
        console.error("Error saving data:", err);
    }
}

// --- Helper Functions ---
function generateVaultHash() {
    return crypto.randomBytes(32).toString('hex');
}

function deriveKeyFromHash(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function encryptWithDerivedKey(data, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return { encrypted, tag };
}

function decryptWithDerivedKey(encrypted, key, iv, tag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function getExpirationTimestamp(expirationTime) {
    const now = new Date();
    switch (expirationTime) {
        case '1h': return new Date(now.getTime() + 60 * 60 * 1000);
        case '5h': return new Date(now.getTime() + 5 * 60 * 60 * 1000);
        case '24h': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
        case '1mo': return new Date(now.setMonth(now.getMonth() + 1));
        case '3mo': return new Date(now.setMonth(now.getMonth() + 3));
        case '6mo': return new Date(now.setMonth(now.getMonth() + 6));
        case '1yr': return new Date(now.setFullYear(now.getFullYear() + 1));
        case 'never': return null;
        default: return null;
    }
}

function checkVaultExpiration() {
    const now = new Date();
    for (const vaultId in serverData.vaults) {
        const vault = serverData.vaults[vaultId];
        if (vault.expiration && new Date(vault.expiration) < now) {
            console.log(`Vault ${vault.name} (${vaultId}) expired`);
            delete serverData.vaults[vaultId];
            delete serverData.messages[vaultId];
            
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.userId) {
                    client.send(JSON.stringify({
                        type: 'vault_expired_notification',
                        expiredVaultId: vaultId,
                        expiredVaultName: vault.name
                    }));
                }
            });
        }
    }
    saveData();
}

// --- WebSocket Server ---
const wss = new WebSocket.Server({ port: SERVER_PORT });
serverData = loadData();

wss.on('connection', (ws) => {
    console.log('Client connected');

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            const userId = ws.userId;

            // Handle registration first
            if (data.type === 'register') {
                if (!data.userId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Missing user ID' }));
                    return;
                }
                ws.userId = data.userId;
                serverData.users[data.userId] = { lastSeen: new Date().toISOString() };
                saveData();
                return;
            }

            // All other actions require registration
            if (!userId || !serverData.users[userId]) {
                ws.send(JSON.stringify({ type: 'error', message: 'Register first' }));
                return;
            }

            switch (data.type) {
                case 'create_vault':
                    const { vaultName, vaultType, expiration, rawVaultKeyB64, saltB64, clientPublicKeyB64 } = data;
                    const vaultId = crypto.randomUUID();
                    const vaultHash = vaultType === 'private' ? `private_${vaultId}` : generateVaultHash();
                    const expirationDate = getExpirationTimestamp(expiration);

                    if (vaultType === 'private' && clientPublicKeyB64) {
                        try {
                            const kem = new oqs.KeyEncapsulation('Kyber512');
                            const { publicKey: serverPublicKey, secretKey: serverSecretKey } = kem.generateKeyPair();
                            const clientPublicKey = Buffer.from(clientPublicKeyB64, 'base64');
                            const ciphertext = kem.encapSecret(clientPublicKey);
                            const serverSharedSecret = kem.getSharedSecret();

                            const salt = crypto.randomBytes(16);
                            const keyMaterial = crypto.pbkdf2Sync(serverSharedSecret, salt, 100000, 32, 'sha256');
                            
                            // Store vault data
                            serverData.vaults[vaultId] = {
                                id: vaultId,
                                name: vaultName,
                                type: vaultType,
                                expiration: expirationDate ? expirationDate.toISOString() : null,
                                creator: userId,
                                members: new Set([userId]),
                                encryptedKey: ciphertext.toString('base64'),
                                salt: salt.toString('base64'),
                                kemSecretKey: serverSecretKey.toString('base64')
                            };
                            serverData.messages[vaultId] = [];
                            saveData();

                            ws.send(JSON.stringify({
                                type: 'vault_created',
                                vaultId,
                                vaultHash,
                                vaultName,
                                vaultType,
                                expiration,
                                serverPublicKeyB64: serverPublicKey.toString('base64'),
                                saltB64: salt.toString('base64')
                            }));
                        } catch (e) {
                            console.error("Kyber error:", e);
                            ws.send(JSON.stringify({ type: 'error', message: 'Kyber exchange failed' }));
                        }
                    } else if (vaultType === 'public' && rawVaultKeyB64 && saltB64) {
                        const salt = Buffer.from(saltB64, 'base64');
                        const iv = crypto.randomBytes(12);
                        const key = deriveKeyFromHash(vaultHash, salt);
                        const { encrypted, tag } = encryptWithDerivedKey(
                            Buffer.from(rawVaultKeyB64, 'base64').toString('binary'),
                            key,
                            iv
                        );

                        serverData.vaults[vaultId] = {
                            id: vaultId,
                            name: vaultName,
                            type: vaultType,
                            expiration: expirationDate ? expirationDate.toISOString() : null,
                            creator: userId,
                            members: new Set([userId]),
                            encryptedKey: encrypted,
                            iv: iv.toString('hex'),
                            tag: tag,
                            salt: salt.toString('base64'),
                            hash: vaultHash
                        };
                        serverData.messages[vaultId] = [];
                        saveData();

                        ws.send(JSON.stringify({
                            type: 'vault_created',
                            vaultId,
                            vaultHash,
                            vaultName,
                            vaultType,
                            expiration,
                            encryptedKeyB64: Buffer.from(encrypted, 'hex').toString('base64'),
                            ivB64: iv.toString('base64'),
                            saltB64: saltB64
                        }));
                    } else {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid create params' }));
                    }
                    break;

                case 'join_vault':
                    const { vaultHash: joinHash, vaultName: joinName, clientPublicKeyB64: joinPubKey } = data;
                    let foundVault = null;
                    
                    // Find vault by hash
                    for (const vaultId in serverData.vaults) {
                        const vault = serverData.vaults[vaultId];
                        if (vault.type === 'private' && joinHash === `private_${vaultId}`) {
                            foundVault = vault;
                            break;
                        } else if (vault.type === 'public' && vault.hash === joinHash) {
                            foundVault = vault;
                            break;
                        }
                    }

                    if (!foundVault) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Vault not found' }));
                        return;
                    }

                    foundVault.members.add(userId);
                    saveData();

                    if (foundVault.type === 'private' && joinPubKey && foundVault.kemSecretKey) {
                        try {
                            const kem = new oqs.KeyEncapsulation('Kyber512');
                            kem.secretKey = Buffer.from(foundVault.kemSecretKey, 'base64');
                            const clientPublicKey = Buffer.from(joinPubKey, 'base64');
                            const ciphertext = kem.encapSecret(clientPublicKey);
                            const salt = Buffer.from(foundVault.salt, 'base64');

                            ws.send(JSON.stringify({
                                type: 'vault_joined',
                                joinedVaultId: foundVault.id,
                                joinedVaultName: joinName,
                                joinedVaultType: foundVault.type,
                                joinedExpiration: foundVault.expiration || 'never',
                                encryptedKeyB64: ciphertext.toString('base64'),
                                saltB64: salt.toString('base64'),
                                vaultHash: joinHash,
                                serverPublicKeyB64: kem.publicKey.toString('base64')
                            }));

                            // Send offline messages
                            if (serverData.messages[foundVault.id]?.length > 0) {
                                ws.send(JSON.stringify({
                                    type: 'offline_messages',
                                    messages: serverData.messages[foundVault.id]
                                }));
                            }
                        } catch (e) {
                            console.error("Kyber join error:", e);
                            ws.send(JSON.stringify({ type: 'error', message: 'Kyber join failed' }));
                        }
                    } else if (foundVault.type === 'public') {
                        const salt = Buffer.from(foundVault.salt, 'base64');
                        const iv = Buffer.from(foundVault.iv, 'hex');
                        const key = deriveKeyFromHash(foundVault.hash, salt);
                        const decrypted = decryptWithDerivedKey(
                            foundVault.encryptedKey,
                            key,
                            iv,
                            Buffer.from(foundVault.tag, 'hex')
                        );

                        ws.send(JSON.stringify({
                            type: 'vault_joined',
                            joinedVaultId: foundVault.id,
                            joinedVaultName: joinName,
                            joinedVaultType: foundVault.type,
                            joinedExpiration: foundVault.expiration || 'never',
                            encryptedKeyB64: Buffer.from(decrypted, 'binary').toString('base64'),
                            ivB64: iv.toString('base64'),
                            saltB64: foundVault.salt,
                            vaultHash: joinHash
                        }));

                        // Send offline messages
                        if (serverData.messages[foundVault.id]?.length > 0) {
                            ws.send(JSON.stringify({
                                type: 'offline_messages',
                                messages: serverData.messages[foundVault.id]
                            }));
                        }
                    }
                    break;

                case 'send_message':
                    const { vaultId, encryptedMessage, iv, isFile, fileName, fileMimeType } = data;
                    
                    if (!serverData.vaults[vaultId] || !serverData.vaults[vaultId].members.has(userId)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid vault or access' }));
                        return;
                    }

                    const msg = {
                        vaultId,
                        senderId: userId,
                        encryptedMessage,
                        iv,
                        timestamp: new Date().toISOString(),
                        isFile: !!isFile,
                        fileName: fileName || null,
                        fileMimeType: fileMimeType || null
                    };

                    if (!serverData.messages[vaultId]) serverData.messages[vaultId] = [];
                    serverData.messages[vaultId].push(msg);
                    saveData();

                    // Broadcast to all vault members
                    wss.clients.forEach(client => {
                        if (
                            client.readyState === WebSocket.OPEN &&
                            client.userId &&
                            serverData.vaults[vaultId].members.has(client.userId)
                        ) {
                            client.send(JSON.stringify({
                                ...msg,
                                type: 'new_message'
                            }));
                        }
                    });
                    break;

                case 'nuke':
                    // Remove user from all vaults
                    for (const vaultId in serverData.vaults) {
                        serverData.vaults[vaultId].members.delete(userId);
                    }
                    delete serverData.users[userId];
                    saveData();
                    ws.send(JSON.stringify({ type: 'nuke_complete' }));
                    break;

                default:
                    ws.send(JSON.stringify({ type: 'error', message: 'Unknown command' }));
            }
        } catch (err) {
            console.error('Message error:', err);
            ws.send(JSON.stringify({ type: 'error', message: 'Processing error' }));
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected');
        if (ws.userId && serverData.users[ws.userId]) {
            serverData.users[ws.userId].lastSeen = new Date().toISOString();
            saveData();
        }
    });
});

// Periodically check for expired vaults
setInterval(checkVaultExpiration, 60 * 1000);
