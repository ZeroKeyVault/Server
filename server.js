// server.js
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid'); // Import uuid for generating unique IDs

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 8080; // Use PORT env variable for Render deployment

console.log('WebSocket server starting...');

// --- Server Data Storage ---
const DATA_DIR = path.join(__dirname, 'data');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.json');
const OFFLINE_MESSAGES_FILE = path.join(DATA_DIR, 'offline_messages.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

// Global data structures (loaded from/saved to files)
// Stored vaultId -> { vaultName, vaultType, vaultHash, encryptedAesKeyB64, saltB64, ivB64, expiration, participants: [] }
let vaults = {};
// Stored userId -> [{ messageData }]
let offlineMessages = {};

// Active WebSocket connections: userId -> WebSocket object
const connectedClients = new Map();

// Helper to load data from JSON files
function loadData(filePath, defaultData) {
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error(`Error loading ${filePath}:`, error.message);
    }
    return defaultData;
}

// Helper to save data to JSON files
function saveData(filePath, data) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
        console.error(`Error saving ${filePath}:`, error.message);
    }
}

// Load initial data on server start
vaults = loadData(VAULTS_FILE, {});
// Convert participants arrays back to Sets if needed for internal logic (though arrays are fine for JSON)
for (const vaultId in vaults) {
    if (vaults[vaultId].participants && !Array.isArray(vaults[vaultId].participants)) {
        // This handles older formats if necessary, ensuring 'participants' is an array.
        // In this specific implementation, it should always be an array.
        vaults[vaultId].participants = Array.from(vaults[vaultId].participants);
    }
}
offlineMessages = loadData(OFFLINE_MESSAGES_FILE, {});

// Helper to convert expiration string (e.g., "1h", "1mo") to a Date object
function parseExpiration(expirationStr) {
    const now = new Date();
    switch (expirationStr) {
        case '1h': return new Date(now.getTime() + 60 * 60 * 1000);
        case '5h': return new Date(now.getTime() + 5 * 60 * 60 * 1000);
        case '24h': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
        case '1mo': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // Approximate month
        case '3mo': return new Date(now.getTime() + 3 * 30 * 24 * 60 * 60 * 1000);
        case '6mo': return new Date(now.getTime() + 6 * 30 * 24 * 60 * 60 * 1000);
        case '1yr': return new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
        case 'never': return new Date(8640000000000000); // Max possible Date, effectively never
        default: return new Date(now.getTime() + 24 * 60 * 60 * 1000); // Default 24 hours
    }
}

// --- WebSocket Server ---
wss.on('connection', ws => {
    let currentUserId = null; // Store userId for this connection

    console.log('Client connected');

    ws.on('message', message => {
        let parsedMessage;
        try {
            parsedMessage = JSON.parse(message);
        } catch (e) {
            console.error('Failed to parse message:', message, e);
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON format.' }));
            return;
        }

        console.log('Received:', parsedMessage.type, 'from', parsedMessage.userId ? parsedMessage.userId.substring(0,8) + '...' : 'unknown');

        switch (parsedMessage.type) {
            case 'register':
                currentUserId = parsedMessage.userId;
                connectedClients.set(currentUserId, ws);
                console.log(`User ${currentUserId.substring(0,8)}... registered.`);

                // Send any pending offline messages
                if (offlineMessages[currentUserId] && offlineMessages[currentUserId].length > 0) {
                    ws.send(JSON.stringify({
                        type: 'offline_messages',
                        messages: offlineMessages[currentUserId]
                    }));
                    delete offlineMessages[currentUserId]; // Clear after sending
                    saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                }
                break;

            case 'create_vault':
                // Ensure currentUserId is set before creating vaults
                if (!currentUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'User not registered. Please refresh.' }));
                    return;
                }

                const vaultId = uuidv4();
                const expirationDate = parseExpiration(parsedMessage.expiration);

                const newVault = {
                    id: vaultId,
                    name: parsedMessage.vaultName,
                    type: parsedMessage.vaultType,
                    vaultHash: parsedMessage.vaultHash,
                    encryptedAesKeyB64: parsedMessage.encryptedAesKeyB64,
                    saltB64: parsedMessage.saltB64,
                    ivB64: parsedMessage.ivB64,
                    expiration: expirationDate.toISOString(),
                    participants: [currentUserId] // Creator is the first participant
                };
                vaults[vaultId] = newVault; // Store in object
                saveData(VAULTS_FILE, vaults); // Persist

                ws.send(JSON.stringify({
                    type: 'vault_created',
                    vaultId: vaultId,
                    vaultName: parsedMessage.vaultName,
                    vaultType: parsedMessage.vaultType,
                    vaultHash: parsedMessage.vaultHash,
                    encryptedAesKeyB64: parsedMessage.encryptedAesKeyB64,
                    saltB64: parsedMessage.saltB64,
                    ivB64: parsedMessage.ivB64,
                    expiration: newVault.expiration,
                    participants: newVault.participants
                }));
                console.log(`Vault ${vaultId.substring(0,8)}... created by ${currentUserId.substring(0,8)}...`);
                break;

            case 'join_vault':
                // Ensure currentUserId is set
                if (!currentUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'User not registered. Please refresh.' }));
                    return;
                }

                let targetVault = null;
                for (const id in vaults) {
                    if (vaults[id].vaultHash === parsedMessage.vaultHash) {
                        targetVault = vaults[id];
                        break;
                    }
                }

                if (targetVault) {
                    if (!targetVault.participants.includes(currentUserId)) {
                        targetVault.participants.push(currentUserId);
                        saveData(VAULTS_FILE, vaults); // Persist change
                        console.log(`User ${currentUserId.substring(0,8)}... joined vault ${targetVault.id.substring(0,8)}...`);
                    } else {
                        console.log(`User ${currentUserId.substring(0,8)}... already in vault ${targetVault.id.substring(0,8)}...`);
                    }

                    // Send vault_joined to the joining client
                    ws.send(JSON.stringify({
                        type: 'vault_joined',
                        vaultId: targetVault.id,
                        vaultName: parsedMessage.vaultName, // Client's preferred name for display
                        vaultType: targetVault.type,
                        vaultHash: targetVault.vaultHash,
                        encryptedAesKeyB64: targetVault.encryptedAesKeyB64,
                        saltB64: targetVault.saltB64,
                        ivB64: targetVault.ivB64,
                        expiration: targetVault.expiration,
                        participants: targetVault.participants
                    }));

                    // Notify other active participants in the vault about the new join
                    targetVault.participants.forEach(participantId => {
                        if (participantId !== currentUserId && connectedClients.has(participantId)) {
                            const otherClientWs = connectedClients.get(participantId);
                            otherClientWs.send(JSON.stringify({
                                type: 'vault_joined', // Use vault_joined to trigger participant update on client
                                vaultId: targetVault.id,
                                vaultName: targetVault.name, // Server's original name
                                vaultType: targetVault.type,
                                vaultHash: targetVault.vaultHash,
                                encryptedAesKeyB64: targetVault.encryptedAesKeyB64,
                                saltB64: targetVault.saltB64,
                                ivB64: targetVault.ivB64,
                                expiration: targetVault.expiration,
                                participants: targetVault.participants // Send updated participants list
                            }));
                            console.log(`Notified ${participantId.substring(0,8)}... about vault ${targetVault.id.substring(0,8)}... participant change.`);
                        }
                    });

                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found with that hash.' }));
                    console.warn(`Join attempt failed: Vault not found for hash ${parsedMessage.vaultHash}.`);
                }
                break;

            case 'reconnect_vault':
                // Ensure currentUserId is set
                if (!currentUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'User not registered. Please refresh.' }));
                    return;
                }

                const reconVault = vaults[parsedMessage.vaultId];
                if (reconVault) {
                    if (!reconVault.participants.includes(currentUserId)) {
                        reconVault.participants.push(currentUserId);
                        saveData(VAULTS_FILE, vaults); // Persist change
                        console.log(`User ${currentUserId.substring(0,8)}... re-registered in vault ${reconVault.id.substring(0,8)}...`);
                    }
                    // Inform other active participants that this user is now online/active in the vault
                    reconVault.participants.forEach(participantId => {
                        if (participantId !== currentUserId && connectedClients.has(participantId)) {
                            const otherClientWs = connectedClients.get(participantId);
                            otherClientWs.send(JSON.stringify({
                                type: 'vault_joined', // Use vault_joined to update client's participants list
                                vaultId: reconVault.id,
                                vaultName: reconVault.name,
                                vaultType: reconVault.type,
                                vaultHash: reconVault.vaultHash,
                                encryptedAesKeyB64: reconVault.encryptedAesKeyB64,
                                saltB64: reconVault.saltB64,
                                ivB64: reconVault.ivB64,
                                expiration: reconVault.expiration,
                                participants: reconVault.participants
                            }));
                             console.log(`Notified ${participantId.substring(0,8)}... about ${currentUserId.substring(0,8)}... rejoining vault ${reconVault.id.substring(0,8)}...`);
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: `Vault ${parsedMessage.vaultId.substring(0,8)}... is no longer known to the server. Please create or re-join.` }));
                    console.warn(`Reconnect failed: Vault ${parsedMessage.vaultId.substring(0,8)}... not found on server.`);
                }
                break;

            case 'send_message': // This covers text messages and file chunks that fall back to server
            case 'file_chunk': // This type is primarily for P2P but handled by server if P2P fails
            case 'chat_message': // This type is primarily for P2P but handled by server if P2P fails
                // Ensure currentUserId is set
                if (!currentUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'User not registered. Please refresh.' }));
                    return;
                }

                const { vaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType, fileId, chunkIndex, totalChunks } = parsedMessage;
                const vaultToSend = vaults[vaultId];

                if (vaultToSend) {
                    // Check for expired vaults
                    if (new Date(vaultToSend.expiration) < new Date()) {
                        delete vaults[vaultId];
                        saveData(VAULTS_FILE, vaults);
                        console.log(`Vault ${vaultId.substring(0,8)}... expired and removed.`);
                        ws.send(JSON.stringify({ type: 'error', message: `Vault "${vaultToSend.name}" has expired and is no longer active.` }));
                        return;
                    }

                    // Iterate over participants and send message
                    vaultToSend.participants.forEach(participantId => {
                        if (participantId !== senderId) { // Don't send back to sender
                            const clientWs = connectedClients.get(participantId);
                            const messageToSend = {
                                type: 'new_message', // General type for client to process server-relayed messages
                                vaultId: vaultId,
                                senderId: senderId,
                                encryptedMessage: encryptedMessage,
                                iv: iv,
                                timestamp: timestamp,
                                isFile: isFile,
                                fileName: fileName,
                                fileMimeType: fileMimeType,
                                fileId: fileId,
                                chunkIndex: chunkIndex,
                                totalChunks: totalChunks
                            };

                            if (clientWs && clientWs.readyState === WebSocket.OPEN) {
                                clientWs.send(JSON.stringify(messageToSend));
                                // console.log(`Relayed message from ${senderId.substring(0,8)}... to ${participantId.substring(0,8)}... in vault ${vaultId.substring(0,8)}...`);
                            } else {
                                // Store for offline delivery
                                if (!offlineMessages[participantId]) {
                                    offlineMessages[participantId] = [];
                                }
                                offlineMessages[participantId].push(messageToSend);
                                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);
                                console.log(`Stored message for offline user ${participantId.substring(0,8)}... in vault ${vaultId.substring(0,8)}...`);
                            }
                        }
                    });
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found or expired.' }));
                    console.warn(`Message send failed: Vault ${vaultId.substring(0,8)}... not found or expired.`);
                }
                break;

            case 'webrtc_signal': // Signaling messages from client
                // Ensure currentUserId is set
                if (!currentUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'User not registered. Please refresh.' }));
                    return;
                }
                const { fromUserId, toUserId, signalData, vaultId: signalVaultId } = parsedMessage; // Renamed vaultId to signalVaultId to avoid conflict
                const targetClientWs = connectedClients.get(toUserId);

                if (targetClientWs && targetClientWs.readyState === WebSocket.OPEN) {
                    targetClientWs.send(JSON.stringify({
                        type: 'webrtc_signal',
                        fromUserId: fromUserId,
                        toUserId: toUserId,
                        signalData: signalData,
                        vaultId: signalVaultId // Pass vaultId back to client
                    }));
                    // console.log(`Relayed WebRTC signal from ${fromUserId.substring(0,8)}... to ${toUserId.substring(0,8)}... for vault ${signalVaultId.substring(0,8)}...`);
                } else {
                    // This scenario is expected: if target user is offline, P2P won't work, and client will fall back to server.
                    // No error needs to be sent back to the client unless signaling is critical for server logic.
                    // console.warn(`Target client ${toUserId.substring(0,8)}... for WebRTC signal is offline or not found.`);
                }
                break;

            case 'nuke':
                // Ensure currentUserId is set
                if (!currentUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'User not registered. Cannot nuke.' }));
                    return;
                }
                const nukeUserId = currentUserId; // Nuke only the current user's data

                // Remove user from all vaults they participated in
                for (const vaultId in vaults) {
                    const vault = vaults[vaultId];
                    if (vault.participants) {
                        const index = vault.participants.indexOf(nukeUserId);
                        if (index > -1) {
                            vault.participants.splice(index, 1);
                            console.log(`User ${nukeUserId.substring(0,8)}... removed from vault ${vaultId.substring(0,8)}...`);
                        }
                    }
                    // If a vault becomes empty after nuke, delete it
                    if (vault.participants.length === 0) {
                        delete vaults[vaultId];
                        console.log(`Vault ${vaultId.substring(0,8)}... is now empty and removed.`);
                    }
                }
                saveData(VAULTS_FILE, vaults); // Persist changes to vaults

                // Clear any offline messages for this user
                delete offlineMessages[nukeUserId];
                saveData(OFFLINE_MESSAGES_FILE, offlineMessages);

                console.log(`All server data for user ${nukeUserId.substring(0,8)}... nuked.`);
                break;

            default:
                ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type.' }));
                console.warn('Unknown message type received:', parsedMessage.type);
        }
    });

    ws.on('close', () => {
        if (currentUserId) {
            connectedClients.delete(currentUserId);
            console.log(`Client ${currentUserId.substring(0,8)}... disconnected.`);
        } else {
            console.log('An unregistered client disconnected.');
        }
    });

    ws.on('error', error => {
        console.error('WebSocket error:', error);
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log(`WebSocket server is running on ws://localhost:${PORT}`);
    console.log(`Remember to update the SERVER_URL in Voltas.html to your Render URL.`);
});
