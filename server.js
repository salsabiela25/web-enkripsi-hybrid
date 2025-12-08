// server.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '100mb' })); // sesuaikan limit jika file lebih besar

// ----- paths -----
const DATA_DIR = path.join(__dirname, 'data');
const MASTER_KEY_PATH = path.join(DATA_DIR, 'master.key');
const USERS_PATH = path.join(DATA_DIR, 'users.json');

// pastikan folder data ada
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ----- MASTER KEY: persist ke file (32 bytes) -----
let SERVER_MASTER_KEY;
if (fs.existsSync(MASTER_KEY_PATH)) {
  SERVER_MASTER_KEY = fs.readFileSync(MASTER_KEY_PATH);
  if (SERVER_MASTER_KEY.length !== 32) {
    console.warn('master.key tidak 32 bytes — akan digenerate ulang');
    SERVER_MASTER_KEY = crypto.randomBytes(32);
    fs.writeFileSync(MASTER_KEY_PATH, SERVER_MASTER_KEY);
  }
} else {
  SERVER_MASTER_KEY = crypto.randomBytes(32);
  fs.writeFileSync(MASTER_KEY_PATH, SERVER_MASTER_KEY);
}
console.log('MASTER KEY loaded.');

// ----- users persistence utility -----
let users = {};
if (fs.existsSync(USERS_PATH)) {
  try {
    const raw = fs.readFileSync(USERS_PATH, 'utf8');
    users = raw ? JSON.parse(raw) : {};
  } catch (err) {
    console.error('Gagal membaca users.json — memulai dengan kosong', err);
    users = {};
  }
}
function saveUsers() {
  fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2));
}

// ----- helper: encrypt private key with server master key (AES-256-CBC) -----
function encryptPrivateKey(privateKeyPem) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', SERVER_MASTER_KEY, iv);
  let encrypted = cipher.update(privateKeyPem, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encryptedHex: encrypted, ivHex: iv.toString('hex') };
}

function decryptPrivateKey(encryptedHex, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', SERVER_MASTER_KEY, iv);
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted; // PEM private key string
}

// ----- endpoints -----
// generate RSA keypair untuk user dan simpan public & private(encrypted)
app.post('/api/generateKey', (req, res) => {
  try {
    const { user } = req.body;
    if (!user) return res.status(400).json({ error: 'user required' });

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const { encryptedHex, ivHex } = encryptPrivateKey(privateKey);

    users[user] = {
      publicKey,
      privateKeyEncrypted: encryptedHex,
      privateKeyIv: ivHex,
      createdAt: new Date().toISOString()
    };
    saveUsers();

    return res.json({ publicKey });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// encrypt file (client kirim base64 file + user)
app.post('/api/encrypt', (req, res) => {
  try {
    const { user, data } = req.body; // data = base64 file content
    if (!user || !data) return res.status(400).json({ error: 'user and data required' });

    const u = users[user];
    if (!u || !u.publicKey) return res.status(400).json({ error: 'user not found or key missing' });

    // Generate AES key (32 bytes) dan IV untuk file
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    // Encrypt file bytes (AES-256-CBC)
    const fileBuffer = Buffer.from(data, 'base64');
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    const encryptedDataBuf = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);

    // Encrypt AES key dengan RSA public key (OAEP + SHA-256)
    const encryptedKeyBuf = crypto.publicEncrypt(
      {
        key: u.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      aesKey
    );

    return res.json({
      encryptedData: encryptedDataBuf.toString('base64'),
      encryptedKey: encryptedKeyBuf.toString('base64'),
      iv: iv.toString('base64')
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// decrypt file (server uses stored encrypted private key)
app.post('/api/decrypt', (req, res) => {
  try {
    const { user, encryptedData, encryptedKey, iv } = req.body;
    if (!user || !encryptedData || !encryptedKey || !iv) {
      return res.status(400).json({ error: 'user, encryptedData, encryptedKey, iv required' });
    }

    const u = users[user];
    if (!u || !u.privateKeyEncrypted || !u.privateKeyIv) {
      return res.status(400).json({ error: 'user private key not available' });
    }

    // decrypt private key first
    const privateKeyPem = decryptPrivateKey(u.privateKeyEncrypted, u.privateKeyIv);

    // decrypt AES key with RSA private key (OAEP + SHA-256)
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(encryptedKey, 'base64')
    );

    // decrypt file bytes
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(iv, 'base64'));
    const decryptedBuf = Buffer.concat([decipher.update(Buffer.from(encryptedData, 'base64')), decipher.final()]);

    return res.json({ data: decryptedBuf.toString('base64') });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// optional: endpoint untuk melihat user list (debug only — jangan aktifkan di production)
app.get('/api/_debug/users', (req, res) => {
  // hati-hati: ini akan mengembalikan publicKey, tapi privateKeyEncrypted tetap terenkripsi
  res.json(users);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SERVER RUNNING on port ${PORT}`));
