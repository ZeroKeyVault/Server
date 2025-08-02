const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const oqs = require('oqs'); // For Kyber

// --- Configuration ---
const SERVER_PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, 'encrypted_data.bin');
// Use a 32-byte (256-bit) key for AES-256-GCM
const SERVER_AES_KEY_HEX = process.env.SERVER_AES_KEY || crypto.randomBytes(32).toString('hex');
const SERVER_AES_KEY = Buffer.from(SERVER_AES_KEY_HEX, 'hex');

// Validate key length
if (SERVER_AES_KEY.length !== 32) {
    console.error("SERVER_AES_KEY must be a 32-byte (64 hex character) hex string.");
    process.exit(1);
}

console.log(`Server AES Key Length: ${SERVER_AES_KEY.length} bytes`);

// --- Data Structures ---
let serverData = {
    users: {}, // userId -> { lastSeen: timestamp }
    vaults: {}, // vaultId -> { id, name, type, expiration, creator, members: Set, encryptedKey, iv, salt, kemSecretKey (for private) }
    messages: {} // vaultId -> [messages]
};

// --- Data Persistence (Encrypted at Rest) ---
function encryptData(data) {
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipher('aes-256-gcm', SERVER_AES_KEY);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return iv.toString('hex') + ':' + encrypted + ':' + tag;
}

function decryptData(encryptedDataWithTag) {
    const parts = encryptedDataWithTag.split(':');
    if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format');
    }
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const tag = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipher('aes-256-gcm', SERVER_AES_KEY);
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
            console.error("Error loading data from disk:", err);
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
        console.log("Data saved to disk.");
    } catch (err) {
        console.error("Error saving data to disk:", err);
    }
}

// --- Helper Functions ---
function generateVaultHash() {
    return crypto.randomBytes(32).toString('hex'); // 256-bit random hex string
}

function deriveKeyFromHash(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256'); // 256-bit key
}

function encryptWithDerivedKey(data, password, salt) {
    const key = deriveKeyFromHash(password, salt);
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipher('aes-256-gcm', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return { encryptedData: encrypted, iv: iv.toString('hex'), tag: tag };
}

function decryptWithDerivedKey(encryptedDataWithTag, password, salt) {
    const key = deriveKeyFromHash(password, salt);
    const parts = encryptedDataWithTag.split(':');
    if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format for derived key decryption');
    }
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const tag = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipher('aes-256-gcm', key);
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
    let expiredVaults = [];
    for (const vaultId in serverData.vaults) {
        const vault = serverData.vaults[vaultId];
        if (vault.expiration && new Date(vault.expiration) < now) {
            expiredVaults.push({ id: vaultId, name: vault.name });
        }
    }
    expiredVaults.forEach(({ id, name }) => {
        delete serverData.vaults[id];
        delete serverData.messages[id];
        console.log(`Vault ${name} (${id}) has expired and been removed.`);
        // Notify online members (if any)
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && serverData.users[client.userId]) {
                client.send(JSON.stringify({
                    type: 'vault_expired_notification',
                    expiredVaultId: id,
                    expiredVaultName: name
                }));
            }
        });
    });
    if (expiredVaults.length > 0) {
        saveData();
    }
}

// --- WebSocket Server ---
const wss = new WebSocket.Server({ port: SERVER_PORT });

wss.on('connection', (ws) => {
    console.log('New client connected');

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            const userId = ws.userId; // Set during 'register'

            switch (data.type) {
                case 'register':
                    if (data.userId) {
                        ws.userId = data.userId;
                        serverData.users[ws.userId] = { lastSeen: new Date().toISOString() };
                        console.log(`User registered: ${ws.userId}`);
                        saveData();
                    }
                    break;

                case 'create_vault':
                    if (!userId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'User not registered.' }));
                        break;
                    }
                    const { vaultName, vaultType, expiration, rawVaultKeyB64, saltB64, clientPublicKeyB64, tempVaultId } = data;
                    const vaultId = crypto.randomUUID();
                    const vaultHash = vaultType === 'private' ? `private_${vaultId}` : generateVaultHash();
                    const expirationDate = getExpirationTimestamp(expiration);

                    if (vaultType === 'private' && clientPublicKeyB64) {
                        try {
                            // 1. Server generates its own Kyber key pair
                            const kem = new oqs.KeyEncapsulation('Kyber512');
                            const { publicKey: serverPublicKey, secretKey: serverSecretKey } = kem.generateKeyPair();

                            // 2. Server encapsulates a shared secret using the client's public key
                            const clientPublicKey = Uint8Array.from(atob(clientPublicKeyB64), c => c.charCodeAt(0));
                            const ciphertext = kem.encapSecret(clientPublicKey); // This is sent to the client

                            // 3. Server derives the actual vault key from its own shared secret
                            const serverSharedSecret = kem.getSharedSecret();
                            const salt = crypto.getRandomValues(new Uint8Array(16)); // Salt for key derivation
                            const keyMaterial = crypto.pbkdf2Sync(serverSharedSecret, salt, 100000, 32, 'sha256');
                            const vaultAesKey = crypto.createSecretKey(keyMaterial, { name: 'AES-GCM' });

                            // 4. Export the vault key to raw bytes for storage
                            const rawVaultKey = await new Promise((resolve, reject) => {
                                crypto.subtle.exportKey('raw', vaultAesKey)
                                    .then(resolve)
                                    .catch(reject);
                            });

                            // 5. Encrypt the raw vault key with the server's master key for storage
                            const { encryptedData, iv, tag } = encryptWithDerivedKey(
                                Buffer.from(rawVaultKey).toString('binary'),
                                SERVER_AES_KEY_HEX, // Use server's key as "password"
                                salt // Use the same salt for consistency
                            );

                            // 6. Store vault data on the server
                            serverData.vaults[vaultId] = {
                                id: vaultId,
                                name: vaultName,
                                type: vaultType,
                                expiration: expirationDate ? expirationDate.toISOString() : null,
                                creator: userId,
                                members: new Set([userId]),
                                encryptedKey: encryptedData,
                                iv: iv,
                                tag: tag,
                                salt: salt.toString('hex'),
                                kemSecretKey: serverSecretKey.toString('base64') // Store server's secret key
                            };
                            serverData.messages[vaultId] = [];

                            saveData();

                            // 7. Send response to client with server's public key and salt
                            ws.send(JSON.stringify({
                                type: 'vault_created',
                                vaultId,
                                vaultHash,
                                vaultName,
                                vaultType,
                                expiration,
                                serverPublicKeyB64: btoa(String.fromCharCode(...new Uint8Array(serverPublicKey))),
                                saltB64: btoa(String.fromCharCode(...salt))
                            }));

                            // Send offline messages if any exist
                            if (serverData.messages[vaultId] && serverData.messages[vaultId].length > 0) {
                                ws.send(JSON.stringify({
                                    type: 'offline_messages',
                                    messages: serverData.messages[vaultId]
                                }));
                            }
                        } catch (e) {
                            console.error("Kyber key exchange failed during vault creation:", e);
                            ws.send(JSON.stringify({ type: 'error', message: 'Failed to perform Kyber key exchange for vault creation.' }));
                        }
                    } else if (vaultType === 'public' && rawVaultKeyB64 && saltB64) {
                        // Standard PBKDF2 encryption for public vaults
                        const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
                        const rawVaultKey = Uint8Array.from(atob(rawVaultKeyB64), c => c.charCodeAt(0));
                        const { encryptedData, iv, tag } = encryptWithDerivedKey(
                            Buffer.from(rawVaultKey).toString('binary'),
                            vaultHash,
                            salt
                        );

                        serverData.vaults[vaultId] = {
                            id: vaultId,
                            name: vaultName,
                            type: vaultType,
                            expiration: expirationDate ? expirationDate.toISOString() : null,
                            creator: userId,
                            members: new Set([userId]),
                            encryptedKey: encryptedData,
                            iv: iv,
                            tag: tag,
                            salt: salt.toString('hex')
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
                            encryptedKeyB64: btoa(String.fromCharCode(...new Uint8Array(Buffer.from(encryptedData, 'hex')))),
                            ivB64: btoa(String.fromCharCode(...new Uint8Array(Buffer.from(iv, 'hex')))),
                            saltB64: saltB64
                        }));

                        // Send offline messages if any exist
                        if (serverData.messages[vaultId] && serverData.messages[vaultId].length > 0) {
                            ws.send(JSON.stringify({
                                type: 'offline_messages',
                                messages: serverData.messages[vaultId]
                            }));
                        }
                    } else {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid vault creation parameters.' }));
                    }
                    break;

                case 'join_vault':
                    if (!userId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'User not registered.' }));
                        break;
                    }
                    const { vaultHash: joinHash, vaultName: joinName, clientPublicKeyB64: joinClientPublicKeyB64 } = data;
                    let foundVaultId = null;
                    for (const id in serverData.vaults) {
                        if (serverData.vaults[id].type === 'private' && joinHash === `private_${id}`) {
                            foundVaultId = id;
                            break;
                        } else if (serverData.vaults[id].type === 'public' && serverData.vaults[id].hash === joinHash) {
                            foundVaultId = id;
                            break;
                        }
                    }

                    if (!foundVaultId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid vault hash.' }));
                        break;
                    }

                    const vaultToJoin = serverData.vaults[foundVaultId];
                    vaultToJoin.members.add(userId);

                    if (vaultToJoin.type === 'private' && joinClientPublicKeyB64 && vaultToJoin.kemSecretKey) {
                        try {
                            // 1. Server retrieves its stored secret key
                            const kem = new oqs.KeyEncapsulation('Kyber512');
                            kem.secretKey = Uint8Array.from(atob(vaultToJoin.kemSecretKey), c => c.charCodeAt(0));

                            // 2. Server encapsulates a shared secret using the joining client's public key
                            const clientPublicKey = Uint8Array.from(atob(joinClientPublicKeyB64), c => c.charCodeAt(0));
                            const ciphertext = kem.encapSecret(clientPublicKey); // This is sent to the client

                            // 3. Server uses the same salt it stored during creation for key derivation
                            const salt = Buffer.from(vaultToJoin.salt, 'hex');

                            saveData();

                            // 4. Send response to client with ciphertext and salt
                            ws.send(JSON.stringify({
                                type: 'vault_joined',
                                joinedVaultId: foundVaultId,
                                joinedVaultName: joinName,
                                joinedVaultType: vaultToJoin.type,
                                joinedExpiration: vaultToJoin.expiration ? new Date(vaultToJoin.expiration).toISOString() : 'never',
                                encryptedKeyB64: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
                                saltB64: btoa(String.fromCharCode(...salt)),
                                vaultHash: joinHash,
                                serverPublicKeyB64: kem.publicKey.toString('base64')
                            }));

                            // Send offline messages if any exist
                            if (serverData.messages[foundVaultId] && serverData.messages[foundVaultId].length > 0) {
                                ws.send(JSON.stringify({
                                    type: 'offline_messages',
                                    messages: serverData.messages[foundVaultId]
                                }));
                            }
                        } catch (e) {
                            console.error("Kyber key exchange failed during vault join:", e);
                            ws.send(JSON.stringify({ type: 'error', message: 'Failed to perform Kyber key exchange for vault join.' }));
                        }
                    } else if (vaultToJoin.type === 'public') {
                        // Standard PBKDF2 decryption for public vaults (re-encrypt for joiner)
                        const joinSalt = Buffer.from(vaultToJoin.salt, 'hex');
                        const decryptedVaultKeyBinary = decryptWithDerivedKey(
                            `${vaultToJoin.iv}:${vaultToJoin.encryptedKey}:${vaultToJoin.tag}`,
                            joinHash,
                            joinSalt
                        );
                        const { encryptedData, iv, tag } = encryptWithDerivedKey(
                            decryptedVaultKeyBinary,
                            joinHash,
                            joinSalt
                        );

                        saveData();

                        ws.send(JSON.stringify({
                            type: 'vault_joined',
                            joinedVaultId: foundVaultId,
                            joinedVaultName: joinName,
                            joinedVaultType: vaultToJoin.type,
                            joinedExpiration: vaultToJoin.expiration ? new Date(vaultToJoin.expiration).toISOString() : 'never',
                            encryptedKeyB64: btoa(String.fromCharCode(...new Uint8Array(Buffer.from(encryptedData, 'hex')))),
                            ivB64: btoa(String.fromCharCode(...new Uint8Array(Buffer.from(iv, 'hex')))),
                            saltB64: joinSalt.toString('base64'),
                            vaultHash: joinHash
                        }));

                        // Send offline messages if any exist
                        if (serverData.messages[foundVaultId] && serverData.messages[foundVaultId].length > 0) {
                            ws.send(JSON.stringify({
                                type: 'offline_messages',
                                messages: serverData.messages[foundVaultId]
                            }));
                        }
                    } else {
                        ws.send(JSON.stringify({ type: 'error', message: 'Vault type mismatch or missing data for join.' }));
                        break;
                    }
                    break;

                case 'send_message':
                    if (!userId || !data.vaultId || !data.encryptedMessage || !data.iv) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Missing message data.' }));
                        break;
                    }
                    const targetVault = serverData.vaults[data.vaultId];
                    if (!targetVault || !targetVault.members.has(userId)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Not a member of this vault.' }));
                        break;
                    }

                    const messageObj = {
                        vaultId: data.vaultId,
                        senderId: userId,
                        encryptedMessage: data.encryptedMessage,
                        iv: data.iv,
                        timestamp: data.timestamp || new Date().toISOString(),
                        isFile: data.isFile || false,
                        fileName: data.fileName || null,
                        fileMimeType: data.fileMimeType || null
                    };

                    if (!serverData.messages[data.vaultId]) {
                        serverData.messages[data.vaultId] = [];
                    }
                    serverData.messages[data.vaultId].push(messageObj);
                    saveData();

                    // Broadcast message to all members of the vault
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.userId && targetVault.members.has(client.userId)) {
                            client.send(JSON.stringify(messageObj));
                        }
                    });
                    break;

                case 'nuke':
                    if (!userId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'User not registered.' }));
                        break;
                    }
                    // Remove user from all vaults
                    for (const vaultId in serverData.vaults) {
                        serverData.vaults[vaultId].members.delete(userId);
                        // If vault becomes empty, optionally remove it
                        // if (serverData.vaults[vaultId].members.size === 0) {
                        //     delete serverData.vaults[vaultId];
                        //     delete serverData.messages[vaultId];
                        // }
                    }
                    // Remove user data
                    delete serverData.users[userId];
                    saveData();
                    console.log(`User data nuked for: ${userId}`);
                    break;

                default:
                    ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
            }
        } catch (err) {
            console.error('Error processing message:', err, message);
            ws.send(JSON.stringify({ type: 'error', message: 'Internal server error.' }));
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected');
        // Optionally update lastSeen timestamp for the user
        if (ws.userId && serverData.users[ws.userId]) {
             serverData.users[ws.userId].lastSeen = new Date().toISOString();
             saveData();
        }
    });
});

// --- Server Initialization ---
serverData = loadData();
setInterval(checkVaultExpiration, 60 * 1000); // Check every minute
console.log(`Server running on port ${SERVER_PORT}`);
