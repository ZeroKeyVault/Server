const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware to parse JSON bodies for vault creation
app.use(express.json());

// In-memory storage for vaults
const vaults = new Map(); // key: hash, value: { creationTime, expirationTime }

// Encryption configuration
const algorithm = 'aes-256-cbc';
const key = Buffer.from(process.env.SECRET_KEY, 'hex'); // Set this in Render environment variables

// Encrypt function
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Decrypt function
function decrypt(text) {
  const [ivHex, encryptedHex] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString('utf8');
}

// Calculate expiration time based on client input
function calculateExpirationTime(expiration) {
  const now = Date.now();
  switch (expiration) {
    case '1 Hour': return now + 3600000;
    case '5 Hours': return now + 18000000;
    case '24 Hours': return now + 86400000;
    case '1 Month': return now + 2592000000;
    case '3 Months': return now + 7776000000;
    case '6 Months': return now + 15552000000;
    case '1 Year': return now + 31536000000;
    case 'Never': return null;
    default: return now + 3600000; // Default to 1 hour
  }
}

// Create a new vault
app.post('/create-vault', (req, res) => {
  const hash = crypto.randomBytes(16).toString('hex');
  const creationTime = Date.now();
  const expirationTime = calculateExpirationTime(req.body.expiration);
  vaults.set(hash, { creationTime, expirationTime });
  res.json({ hash });
});

// Handle Socket.IO connections
io.on('connection', (socket) => {
  socket.on('join', (vaultHash) => {
    if (vaults.has(vaultHash)) {
      const vault = vaults.get(vaultHash);
      if (!vault.expirationTime || Date.now() < vault.expirationTime) {
        socket.join(vaultHash);
      } else {
        socket.emit('error', 'Vault has expired');
      }
    } else {
      socket.emit('error', 'Vault not found');
    }
  });

  socket.on('message', (data) => {
    const { vaultHash, content } = data;
    if (vaults.has(vaultHash)) {
      const vault = vaults.get(vaultHash);
      if (!vault.expirationTime || Date.now() < vault.expirationTime) {
        const encrypted = encrypt(content); // Encrypt the message
        const decrypted = decrypt(encrypted); // Decrypt just before relay
        io.to(vaultHash).emit('message', decrypted); // Relay to all in vault
      } else {
        socket.emit('error', 'Vault has expired');
      }
    } else {
      socket.emit('error', 'Vault not found');
    }
  });
});

// Clean up expired vaults every minute
setInterval(() => {
  const now = Date.now();
  for (const [hash, vault] of vaults) {
    if (vault.expirationTime && now > vault.expirationTime) {
      vaults.delete(hash);
    }
  }
}, 60000);

// Start server on Render-assigned port
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
