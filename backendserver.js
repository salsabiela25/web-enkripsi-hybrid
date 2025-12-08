const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());

// === DATABASE SEDERHANA (Memory map) — ganti nanti pakai MongoDB / MySQL ===
const users = {
  "user1": {
    publicKey: "",
    privateKeyEncrypted: ""
  }
};

// MASTER KEY UNTUK MENGENKRIP PRIVATE KEY DI SERVER
const SERVER_MASTER_KEY = crypto.randomBytes(32);

// GENERATE RSA KEYPAIR UNTUK USER
app.post("/api/generateKey", (req, res) => {
  const { user } = req.body;

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  // ENKRIP PRIVATE KEY DI SERVER
  const cipher = crypto.createCipheriv("aes-256-cbc", SERVER_MASTER_KEY, Buffer.alloc(16, 0));
  let encryptedKey = cipher.update(privateKey, "utf8", "hex");
  encryptedKey += cipher.final("hex");

  users[user] = {
    publicKey,
    privateKeyEncrypted: encryptedKey
  };

  res.json({ publicKey });
});

// ENKRIP FILE DI SERVER
app.post("/api/encrypt", (req, res) => {
  const { user, data } = req.body; // data = base64 file content
  const publicKey = users[user].publicKey;

  // Generate AES key for file
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  let encryptedData = cipher.update(Buffer.from(data, "base64"));
  encryptedData = Buffer.concat([encryptedData, cipher.final()]);

  // Encrypt AES key using RSA public key
  const encryptedKey = crypto.publicEncrypt(publicKey, aesKey).toString("base64");

  res.json({
    encryptedData: encryptedData.toString("base64"),
    encryptedKey,
    iv: iv.toString("base64")
  });
});

// DEKRIP FILE DI SERVER
app.post("/api/decrypt", (req, res) => {
  const { user, encryptedData, encryptedKey, iv } = req.body;

  // 🔥 ambil private key terenkripsi
  const encryptedPrivateKey = users[user].privateKeyEncrypted;

  // 🔥 dekripsi private key menggunakan MASTER SERVER KEY
  const decipher = crypto.createDecipheriv("aes-256-cbc", SERVER_MASTER_KEY, Buffer.alloc(16, 0));
  let privateKey = decipher.update(encryptedPrivateKey, "hex", "utf8");
  privateKey += decipher.final("utf8");

  // 🔥 dekripsi AES key
  const aesKey = crypto.privateDecrypt(privateKey, Buffer.from(encryptedKey, "base64"));

  // 🔥 dekripsi file
  const decipherData = crypto.createDecipheriv("aes-256-cbc", aesKey, Buffer.from(iv, "base64"));
  let decrypted = decipherData.update(Buffer.from(encryptedData, "base64"));
  decrypted = Buffer.concat([decrypted, decipherData.final()]);

  res.json({ data: decrypted.toString("base64") });
});

app.listen(3000, () => console.log("SERVER RUNNING on port 3000"));
