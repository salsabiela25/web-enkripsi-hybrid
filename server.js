const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// folder data
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

// ============================
// GENERATE RSA KEY PAIR
// ============================
app.post("/generate-keys", (req, res) => {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: "spki",
                format: "pem"
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem"
            }
        });

        fs.writeFileSync(path.join(DATA_DIR, "public.pem"), publicKey);
        fs.writeFileSync(path.join(DATA_DIR, "private.pem"), privateKey);

        res.json({
            success: true,
            message: "RSA key berhasil dibuat"
        });
    } catch (err) {
        console.error("Generate key error:", err);
        res.status(500).json({
            success: false,
            message: "Gagal generate key"
        });
    }
});

// ============================
app.listen(3000, "0.0.0.0", () => {
    console.log("Server running on port 3000");
});

// ============================
// DOWNLOAD PUBLIC KEY
// ============================
app.get("/download/public", (req, res) => {
    const filePath = path.join(DATA_DIR, "public.pem");
    if (!fs.existsSync(filePath)) {
        return res.status(404).send("Public key tidak ditemukan");
    }
    res.download(filePath, "public.pem");
});

// ============================
// DOWNLOAD PRIVATE KEY
// ============================
app.get("/download/private", (req, res) => {
    const filePath = path.join(DATA_DIR, "private.pem");
    if (!fs.existsSync(filePath)) {
        return res.status(404).send("Private key tidak ditemukan");
    }
    res.download(filePath, "private.pem");
});
