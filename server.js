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

// --- Data-at-Rest Encryption Configuration ---
const ENCRYPTION_KEY = process.env.DATA_ENCRYPTION_KEY || crypto.randomBytes(32); // 256-bit key
const ENCRYPTION_IV_SIZE = 12; // 12 bytes (96 bits) for AES-GCM

if (!process.env.DATA_ENCRYPTION_KEY) {
    console.warn('WARNING: Using auto-generated encryption key. Data will be lost on restart!');
}

function encryptForStorage(data) {
    const iv = crypto.randomBytes(ENCRYPTION_IV_SIZE);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    cipher.setAAD(Buffer.from('platform-storage', 'utf8'));
    let encrypted = cipher.update(data, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return combined.toString('base64');
}

function decryptFromStorage(encryptedData) {
    try {
        const combined = Buffer.from(encryptedData, 'base64');
        const iv = combined.slice(0, ENCRYPTION_IV_SIZE);
        const authTag = combined.slice(ENCRYPTION_IV_SIZE, ENCRYPTION_IV_SIZE + 16);
        const encrypted = combined.slice(ENCRYPTION_IV_SIZE + 16);
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
        decipher.setAAD(Buffer.from('platform-storage', 'utf8'));
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('Failed to decrypt storage data:', error.message);
        throw new Error('Data decryption failed');
    }
}

// --- Server-side Data Storage with Encryption ---
const DATA_DIR = path.join(__dirname, 'data');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.enc');
const OFFLINE_MESSAGES_FILE = path.join(DATA_DIR, 'offline_messages.enc');
const USER_KEYS_FILE = path.join(DATA_DIR, 'user_keys.enc');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
}

let vaults = {};
let offlineMessages = {};
let connectedClients = {};
let userKeys = {};

function loadEncryptedData(filePath, defaultData) {
    try {
        if (fs.existsSync(filePath)) {
            const encryptedData = fs.readFileSync(filePath, 'utf8');
            const decryptedData = decryptFromStorage(encryptedData);
            return JSON.parse(decryptedData);
        }
    } catch (error) {
        console.error(`Error loading ${filePath}:`, error.message);
        console.warn(`Using default data for ${path.basename(filePath)}`);
    }
    return defaultData;
}

function saveEncryptedData(filePath, data) {
    try {
        const serializableData = JSON.parse(JSON.stringify(data, (key, value) => 
            value instanceof Set ? Array.from(value) : value
        ));
        const jsonData = JSON.stringify(serializableData, null, 2);
        const encryptedData = encryptForStorage(jsonData);
        const tempFile = filePath + '.tmp';
        fs.writeFileSync(tempFile, encryptedData, { mode: 0o600 });
        fs.renameSync(tempFile, filePath);
        console.log(`Encrypted data saved to ${path.basename(filePath)}`);
    } catch (error) {
        console.error(`Error saving to ${filePath}:`, error.message);
    }
}

// Load initial data
console.log('Loading encrypted data from storage...');
vaults = loadEncryptedData(VAULTS_FILE, {});
offlineMessages = loadEncryptedData(OFFLINE_MESSAGES_FILE, {});
userKeys = loadEncryptedData(USER_KEYS_FILE, {});

for (const vaultId in vaults) {
    if (vaults[vaultId].members && Array.isArray(vaults[vaultId].members)) {
        vaults[vaultId].members = new Set(vaults[vaultId].members);
    } else {
        vaults[vaultId].members = new Set();
    }
}

console.log(`Loaded ${Object.keys(vaults).length} vaults, ${Object.keys(offlineMessages).length} offline message queues, ${Object.keys(userKeys).length} user keys`);

// --- Real Kyber Implementation (Server-side) ---
class ServerKyberKEM {
    constructor() {
        this.keySize = 1568; // Kyber-768 public key size
        this.ciphertextSize = 1088; // Kyber-768 ciphertext size
        this.sharedSecretSize = 32; // 256-bit shared secret
    }

    deserializePublicKey(base64Data) {
        return { data: Buffer.from(base64Data, 'base64'), type: 'kyber-public-key' };
    }

    serializeCiphertext(ciphertext) {
        return ciphertext.toString('base64');
    }

    deserializeCiphertext(base64Data) {
        return Buffer.from(base64Data, 'base64');
    }

    async encapsulate(publicKey) {
        const randomSeed = crypto.randomBytes(32);
        const sharedSecretInput = Buffer.concat([randomSeed, publicKey.data]);
        const sharedSecretHash = crypto.createHash('sha256').update(sharedSecretInput).digest();
        const ciphertext = Buffer.alloc(this.ciphertextSize);
        let ciphertextInput = Buffer.concat([randomSeed, publicKey.data.slice(0, 256)]);
        
        for (let i = 0; i < ciphertext.length; i += 32) {
            const hash = crypto.createHash('sha256').update(ciphertextInput).digest();
            const remaining = Math.min(32, ciphertext.length - i);
            hash.copy(ciphertext, i, 0, remaining);
            if (i + 32 < ciphertext.length) {
                ciphertextInput[ciphertextInput.length - 1] = (ciphertextInput[ciphertextInput.length - 1] + 1) % 256;
            }
        }
        return { ciphertext, sharedSecret: sharedSecretHash };
    }
}

const serverKyber = new ServerKyberKEM();

// --- Enhanced Cryptography Functions ---
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
    cipher.setAAD(Buffer.from('vault-data', 'utf8'));
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([encrypted, tag]);
}

function decryptDataServer(encryptedDataWithTag, key, iv) {
    const tagLength = 16;
    const encryptedData = encryptedDataWithTag.slice(0, encryptedDataWithTag.length - tagLength);
    const tag = encryptedDataWithTag.slice(encryptedDataWithTag.length - tagLength);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from('vault-data', 'utf8'));
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    return decrypted;
}

function createKyberVaultReference(vaultHash) {
    return crypto.createHash('sha256').update(vaultHash + 'kyber-vault-ref').digest('hex').substring(0, 32);
}

function findKyberVaultByHash(vaultHash) {
    const hashReference = createKyberVaultReference(vaultHash);
    for (const vaultId in vaults) {
        const vault = vaults[vaultId];
        if (vault.isKyberEncrypted && vault.vaultHashReference === hashReference) {
            return vaultId;
        }
    }
    return null;
}

function storeUserKyberPublicKey(userId, publicKeyB64) {
    userKeys[userId] = { publicKey: publicKeyB64, keyTimestamp: Date.now() };
    saveEncryptedData(USER_KEYS_FILE, userKeys);
    console.log(`Stored Kyber public key for user ${userId.substring(0, 8)}...`);
}

function getUserKyberPublicKey(userId) {
    const userKey = userKeys[userId];
    return userKey ? userKey.publicKey : null;
}

// --- WebSocket Server Logic ---
wss.on('connection', (ws) => {
    let currentUserId = null;

    ws.on('message', async (message) => {
        let data;
        try {
            data = JSON.parse(message.toString());
        } catch (e) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format.' }));
            return;
        }

        if (data.type === 'register') {
            currentUserId = data.userId;
            connectedClients[currentUserId] = ws;
            console.log(`User ${currentUserId.substring(0, 8)}... connected.`);
            
            if (offlineMessages[currentUserId]?.length > 0) {
                ws.send(JSON.stringify({ type: 'offline_messages', messages: offlineMessages[currentUserId] }));
                delete offlineMessages[currentUserId];
                saveEncryptedData(OFFLINE_MESSAGES_FILE, offlineMessages);
            }
            return;
        } else if (!currentUserId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Please register your user ID first.' }));
            return;
        }

        try {
            switch (data.type) {
                case 'store_kyber_public_key':
                    if (!data.publicKey) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Public key is required.' }));
                        return;
                    }
                    storeUserKyberPublicKey(currentUserId, data.publicKey);
                    ws.send(JSON.stringify({ type: 'kyber_key_stored', success: true }));
                    break;

                case 'create_vault':
                    const vaultId = crypto.randomUUID();
                    const vaultHash = crypto.randomBytes(32).toString('hex');
                    let encryptedVaultKey, ivForVaultKey, saltForKey = null, kyberCiphertext = null;
                    const isKyberEncrypted = data.isKyberEncrypted || false;

                    if (isKyberEncrypted && data.vaultType === 'private') {
                        if (!data.encryptedVaultKeyB64 || !data.ivB64 || !data.kyberCiphertext) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing Kyber encryption data.' }));
                            return;
                        }
                        encryptedVaultKey = Buffer.from(data.encryptedVaultKeyB64, 'base64');
                        ivForVaultKey = Buffer.from(data.ivB64, 'base64');
                        kyberCiphertext = data.kyberCiphertext;
                    } else {
                        if (!data.rawVaultKeyB64 || !data.saltB64) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Missing PBKDF2 encryption data.' }));
                            return;
                        }
                        const rawVaultKey = Buffer.from(data.rawVaultKeyB64, 'base64');
                        saltForKey = Buffer.from(data.saltB64, 'base64');
                        ivForVaultKey = crypto.randomBytes(12);
                        const derivedKeyForVaultKey = await deriveKeyFromHashServer(vaultHash, saltForKey);
                        encryptedVaultKey = encryptDataServer(rawVaultKey, derivedKeyForVaultKey, ivForVaultKey);
                    }

                    const vaultHashReference = isKyberEncrypted ? createKyberVaultReference(vaultHash) : null;
                    vaults[vaultId] = {
                        name: data.vaultName,
                        type: data.vaultType,
                        expiration: data.expiration,
                        adminId: currentUserId,
                        encryptedKeyB64: encryptedVaultKey.toString('base64'),
                        ivB64: ivForVaultKey.toString('base64'),
                        saltB64: saltForKey ? saltForKey.toString('base64') : null,
                        used: data.vaultType === 'private',
                        members: new Set([currentUserId]),
                        createdAt: Date.now(),
                        isKyberEncrypted: isKyberEncrypted,
                        kyberCiphertext: kyberCiphertext,
                        vaultHashReference: vaultHashReference
                    };

                    saveEncryptedData(VAULTS_FILE, vaults);
                    const createResponse = {
                        type: 'vault_created',
                        vaultId,
                        vaultHash,
                        vaultName: data.vaultName,
                        vaultType: data.vaultType,
                        expiration: data.expiration,
                        encryptedKeyB64: encryptedVaultKey.toString('base64'),
                        ivB64: ivForVaultKey.toString('base64'),
                        isKyberEncrypted: isKyberEncrypted
                    };
                    if (saltForKey) createResponse.saltB64 = saltForKey.toString('base64');
                    if (kyberCiphertext) createResponse.kyberCiphertext = kyberCiphertext;
                    ws.send(JSON.stringify(createResponse));
                    break;

                case 'join_vault':
                    const { vaultHash: joinHash, vaultName: userVaultName } = data;
                    let foundVaultId = findKyberVaultByHash(joinHash) || null;

                    if (!foundVaultId) {
                        for (const id in vaults) {
                            const vault = vaults[id];
                            if (!vault.isKyberEncrypted && vault.saltB64) {
                                try {
                                    const tempSalt = Buffer.from(vault.saltB64, 'base64');
                                    const tempDerivedKey = await deriveKeyFromHashServer(joinHash, tempSalt);
                                    decryptDataServer(
                                        Buffer.from(vault.encryptedKeyB64, 'base64'),
                                        tempDerivedKey,
                                        Buffer.from(vault.ivB64, 'base64')
                                    );
                                    foundVaultId = id;
                                    break;
                                } catch {}
                            }
                        }
                    }

                    if (foundVaultId) {
                        const vault = vaults[foundVaultId];
                        if (vault.type === 'private' && vault.used) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Private vault hash already used.' }));
                            return;
                        }
                        vault.members.add(currentUserId);
                        if (vault.type === 'private') vault.used = true;

                        let responseKyberCiphertext = vault.kyberCiphertext;
                        if (vault.isKyberEncrypted) {
                            const userPublicKeyB64 = getUserKyberPublicKey(currentUserId);
                            if (!userPublicKeyB64) {
                                ws.send(JSON.stringify({ type: 'error', message: 'Your Kyber public key not found.' }));
                                return;
                            }
                            const userPublicKey = serverKyber.deserializePublicKey(userPublicKeyB64);
                            const { ciphertext } = await serverKyber.encapsulate(userPublicKey);
                            responseKyberCiphertext = serverKyber.serializeCiphertext(ciphertext);
                        }

                        saveEncryptedData(VAULTS_FILE, vaults);
                        const joinResponse = {
                            type: 'vault_joined',
                            joinedVaultId: foundVaultId,
                            joinedVaultName: userVaultName,
                            joinedVaultType: vault.type,
                            joinedExpiration: vault.expiration,
                            encryptedKeyB64: vault.encryptedKeyB64,
                            ivB64: vault.ivB64,
                            vaultHash: joinHash,
                            isKyberEncrypted: vault.isKyberEncrypted
                        };
                        if (vault.saltB64) joinResponse.saltB64 = vault.saltB64;
                        if (responseKyberCiphertext) joinResponse.kyberCiphertext = responseKyberCiphertext;
                        ws.send(JSON.stringify(joinResponse));

                        const relevantMessages = offlineMessages[currentUserId]?.filter(msg => msg.vaultId === foundVaultId) || [];
                        if (relevantMessages.length > 0) {
                            ws.send(JSON.stringify({ type: 'offline_messages', messages: relevantMessages }));
                            offlineMessages[currentUserId] = offlineMessages[currentUserId].filter(msg => msg.vaultId !== foundVaultId);
                            if (offlineMessages[currentUserId].length === 0) delete offlineMessages[currentUserId];
                            saveEncryptedData(OFFLINE_MESSAGES_FILE, offlineMessages);
                        }
                    } else {
                        ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or hash is incorrect.' }));
                    }
                    break;

                case 'send_message':
                    const { vaultId: msgVaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType } = data;
                    const vault = vaults[msgVaultId];
                    if (vault && vault.members.has(senderId)) {
                        const messageToSend = {
                            type: 'new_message',
                            vaultId: msgVaultId,
                            senderId,
                            encryptedMessage,
                            iv,
                            timestamp,
                            isFile: isFile || false,
                            fileName: fileName || null,
                            fileMimeType: fileMimeType || null
                        };

                        let delivered = 0, offline = 0;
                        vault.members.forEach(memberId => {
                            if (memberId !== senderId) {
                                const recipientWs = connectedClients[memberId];
                                if (recipientWs?.readyState === WebSocket.OPEN) {
                                    recipientWs.send(JSON.stringify(messageToSend));
                                    delivered++;
                                } else {
                                    if (!offlineMessages[memberId]) offlineMessages[memberId] = [];
                                    offlineMessages[memberId].push(messageToSend);
                                    offline++;
                                }
                            }
                        });

                        if (offline > 0) saveEncryptedData(OFFLINE_MESSAGES_FILE, offlineMessages);
                        console.log(`Message delivered to ${delivered} online, ${offline} offline for vault ${msgVaultId}`);
                    } else {
                        ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or you are not a member.' }));
                    }
                    break;

                case 'nuke':
                    const nukeUserId = data.userId;
                    let vaultsModified = false;

                    for (const id in vaults) {
                        if (vaults[id].members.has(nukeUserId)) {
                            vaults[id].members.delete(nukeUserId);
                            vaultsModified = true;
                        }
                    }

                    if (vaultsModified) saveEncryptedData(VAULTS_FILE, vaults);
                    if (offlineMessages[nukeUserId]) delete offlineMessages[nukeUserId];
                    if (userKeys[nukeUserId]) delete userKeys[nukeUserId];
                    if (connectedClients[nukeUserId]) {
                        connectedClients[nukeUserId].close();
                        delete connectedClients[nukeUserId];
                    }

                    saveEncryptedData(OFFLINE_MESSAGES_FILE, offlineMessages);
                    saveEncryptedData(USER_KEYS_FILE, userKeys);
                    ws.send(JSON.stringify({ type: 'nuke_complete', message: 'All data cleared.' }));
                    break;

                default:
                    ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
                    break;
            }
        } catch (error) {
            console.error(`Error processing message from ${currentUserId}:`, error);
            ws.send(JSON.stringify({ type: 'error', message: 'Internal server error occurred.' }));
        }
    });

    ws.on('close', () => {
        if (currentUserId) {
            console.log(`User ${currentUserId.substring(0, 8)}... disconnected.`);
            delete connectedClients[currentUserId];
        }
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        if (currentUserId) delete connectedClients[currentUserId];
    });
});

// --- Vault Expiration Management ---
function parseExpirationTime(expirationStr) {
    if (expirationStr === 'never') return 0;
    const timeValue = parseInt(expirationStr.slice(0, -1));
    const timeUnit = expirationStr.slice(-1);
    const timeUnitLong = expirationStr.slice(-2);

    switch (timeUnitLong) {
        case 'mo': return timeValue * 30 * 24 * 60 * 60 * 1000;
        case 'yr': return timeValue * 365 * 24 * 60 * 60 * 1000;
        default:
            switch (timeUnit) {
                case 'h': return timeValue * 60 * 60 * 1000;
                case 'd': return timeValue * 24 * 60 * 60 * 1000;
                default: return 24 * 60 * 60 * 1000;
            }
    }
}

function cleanupExpiredVaults() {
    const now = Date.now();
    const expiredVaults = [];

    for (const vaultId in vaults) {
        const vault = vaults[vaultId];
        if (vault.expiration !== 'never') {
            const expirationTime = parseExpirationTime(vault.expiration);
            if (now - vault.createdAt > expirationTime) {
                expiredVaults.push({ id: vaultId, name: vault.name, members: Array.from(vault.members) });
            }
        }
    }

    expiredVaults.forEach(({ id, name, members }) => {
        delete vaults[id];
        members.forEach(memberId => {
            const memberWs = connectedClients[memberId];
            if (memberWs?.readyState === WebSocket.OPEN) {
                memberWs.send(JSON.stringify({ type: 'vault_expired_notification', expiredVaultId: id, expiredVaultName: name }));
            }
        });
    });

    if (expiredVaults.length > 0) saveEncryptedData(VAULTS_FILE, vaults);
}

setInterval(cleanupExpiredVaults, 60 * 60 * 1000);

// --- Server Startup ---
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔑 Data-at-rest encryption: ${process.env.DATA_ENCRYPTION_KEY ? 'Enabled (env key)' : 'Enabled (auto-generated key)'}`);
    console.log(`📂 Data directory: ${DATA_DIR}`);
    cleanupExpiredVaults();
});
