/* ================================
   KONFIGURASI SERVER
================================ */
const SERVER_IP = "http://192.168.56.20:3000";

/* ================================
   DOM READY
================================ */
document.addEventListener("DOMContentLoaded", () => {
    console.log("✅ webenkrip.js loaded");

    /* ================================
       AMBIL ELEMEN DOM
    ================================ */
    const fileInput = document.getElementById("fileInput");
    const encryptedPackageFile = document.getElementById("encryptedPackageFile");
    const privatePemTextarea = document.getElementById("privatePemTextarea");

    const btnGenerateKeys = document.getElementById("btnGenerateKeys");
    const btnExportPublic = document.getElementById("btnExportPublic");
    const btnExportPrivate = document.getElementById("btnExportPrivate");
    const btnEncryptNow = document.getElementById("btnEncryptNow");
    const btnImportPrivate = document.getElementById("btnImportPrivate");
    const btnDecryptNow = document.getElementById("btnDecryptNow");

    const downloadPublicLink = document.getElementById("downloadPublicLink");
    const downloadPrivateLink = document.getElementById("downloadPrivateLink");
    const downloadEncryptedLink = document.getElementById("downloadEncryptedLink");
    const downloadDecryptedLink = document.getElementById("downloadDecryptedLink");

    const canvasOriginal = document.getElementById("canvasOriginal");
    const canvasProcessed = document.getElementById("canvasProcessed");
    const canvasDecrypted = document.getElementById("canvasDecrypted");

    const psnrValue = document.getElementById("psnrValue");
    const mseValue = document.getElementById("mseValue");
    const cipherSize = document.getElementById("cipherSize");
    const resultBox = document.getElementById("result");

    /* ================================
       VAR GLOBAL
    ================================ */
    let selectedFile = null;
    let rsaKeyPair = null;
    let importedPrivateKey = null;
    let originalImageData = null;
    let decryptedImageData = null;

    /* ================================
       HELPER
    ================================ */
    function log(msg) {
        resultBox.innerText += "\n" + msg;
        console.log(msg);
    }

    function bufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }

    function base64ToBuffer(base64) {
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
    }

    function drawImageToCanvas(blob, canvas, saveData = false) {
        return new Promise(resolve => {
            const img = new Image();
            img.onload = () => {
                const ctx = canvas.getContext("2d");
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                if (saveData) originalImageData = imgData;
                resolve(imgData);
            };
            img.src = URL.createObjectURL(blob);
        });
    }

    /* ================================
       CEK SUPPORT CRYPTO
    ================================ */
    if (!window.crypto || !window.crypto.subtle) {
        alert("❌ Browser tidak mendukung Web Crypto API!\nJalankan file ini lewat server HTTP/HTTPS (misal localhost).");
        console.error("crypto.subtle tidak tersedia");
        return;
    }

    /* ================================
       1. PILIH FILE
    ================================ */
    fileInput?.addEventListener("change", async e => {
        selectedFile = e.target.files[0];
        if (!selectedFile) return;

        log("📂 File dipilih: " + selectedFile.name);

        await drawImageToCanvas(selectedFile, canvasOriginal, true);

        // prapemrosesan grayscale
        const ctx = canvasProcessed.getContext("2d");
        canvasProcessed.width = canvasOriginal.width;
        canvasProcessed.height = canvasOriginal.height;
        ctx.drawImage(canvasOriginal, 0, 0);
        const imgData = ctx.getImageData(0, 0, canvasProcessed.width, canvasProcessed.height);

        for (let i = 0; i < imgData.data.length; i += 4) {
            const avg = (imgData.data[i] + imgData.data[i+1] + imgData.data[i+2]) / 3;
            imgData.data[i] = imgData.data[i+1] = imgData.data[i+2] = avg;
        }
        ctx.putImageData(imgData, 0, 0);

        btnEncryptNow.disabled = false;
    });

    /* ================================
       2. GENERATE RSA
    ================================ */
    btnGenerateKeys?.addEventListener("click", async () => {
        try {
            rsaKeyPair = await crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1,0,1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );
            btnExportPublic.disabled = false;
            btnExportPrivate.disabled = false;
            log("🔑 RSA-2048 berhasil dibuat");
        } catch (err) {
            console.error(err);
            alert("❌ Gagal generate RSA key");
        }
    });

    /* ================================
       3. EXPORT KEY
    ================================ */
    btnExportPublic?.addEventListener("click", async () => {
        if (!rsaKeyPair) return alert("RSA key belum dibuat!");
        const spki = await crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
        const pem = `-----BEGIN PUBLIC KEY-----\n${bufferToBase64(spki)}\n-----END PUBLIC KEY-----`;
        const blob = new Blob([pem]);
        downloadPublicLink.href = URL.createObjectURL(blob);
        downloadPublicLink.download = "public_key.pem";
        downloadPublicLink.click();
    });

    btnExportPrivate?.addEventListener("click", async () => {
        if (!rsaKeyPair) return alert("RSA key belum dibuat!");
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", rsaKeyPair.privateKey);
        const pem = `-----BEGIN PRIVATE KEY-----\n${bufferToBase64(pkcs8)}\n-----END PRIVATE KEY-----`;
        const blob = new Blob([pem]);
        downloadPrivateLink.href = URL.createObjectURL(blob);
        downloadPrivateLink.download = "private_key.pem";
        downloadPrivateLink.click();
    });

    /* ================================
    4. ENKRIPSI
    ================================ */
btnEncryptNow?.addEventListener("click", async () => {
    if (!selectedFile) return alert("Pilih file terlebih dahulu!");
    if (!rsaKeyPair) return alert("Buat RSA key dulu!");

    // 1. Buat AES Key
    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-CBC", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(16));
    const buffer = await selectedFile.arrayBuffer();

    // 2. Enkripsi file dengan AES
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        aesKey,
        buffer
    );

    // 3. Enkripsi AES key dengan RSA
    const rawAes = await crypto.subtle.exportKey("raw", aesKey);
    const encryptedAes = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.publicKey,
        rawAes
    );

    // 4. Buat paket enkripsi
    const pkg = {
        iv: bufferToBase64(iv),
        key: bufferToBase64(encryptedAes),
        data: bufferToBase64(encryptedData)
    };

    // 5. Buat preview di canvasCipher (hanya untuk file gambar)
    try {
        const cipherCtx = canvasCipher.getContext("2d");
        canvasCipher.width = canvasOriginal.width;
        canvasCipher.height = canvasOriginal.height;

        const byteArr = new Uint8Array(encryptedData);
        const len = canvasOriginal.width * canvasOriginal.height * 4;
        const pixels = new Uint8ClampedArray(len);

        for (let i = 0; i < len; i++) {
            pixels[i] = byteArr[i % byteArr.length];
        }

        const cipherImgData = new ImageData(pixels, canvasOriginal.width, canvasOriginal.height);
        cipherCtx.putImageData(cipherImgData, 0, 0);
    } catch (err) {
        console.warn("⚠️ Tidak dapat tampilkan preview ciphertext:", err);
    }

    // 6. Buat file .bin untuk diunduh
    const blob = new Blob([JSON.stringify(pkg)], { type: "application/octet-stream" });
    downloadEncryptedLink.href = URL.createObjectURL(blob);
    downloadEncryptedLink.download = "encrypted_package.bin";
    downloadEncryptedLink.classList.remove("hidden");

    cipherSize.innerText = blob.size + " byte";
    log("🔒 Enkripsi selesai");
});

    /* ================================
       5. IMPORT PRIVATE KEY
    ================================ */
    btnImportPrivate?.addEventListener("click", async () => {
        try {
            const text = privatePemTextarea.value;
            if (!text) return alert("Masukkan private key!");
            const base64 = text.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
            const buffer = base64ToBuffer(base64);

            importedPrivateKey = await crypto.subtle.importKey(
                "pkcs8",
                buffer,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["decrypt"]
            );

            btnDecryptNow.disabled = false;
            log("🔓 Private key berhasil diimpor");
        } catch (err) {
            console.error(err);
            alert("❌ Gagal import private key");
        }
    });

   /* ================================
   6. DEKRIPSI
================================ */
btnDecryptNow?.addEventListener("click", async () => {
    if (!importedPrivateKey) return alert("Import private key dulu!");
    if (!encryptedPackageFile.files[0]) return alert("Pilih paket .bin!");

    try {
        // 1. Ambil paket enkripsi
        const pkg = JSON.parse(await encryptedPackageFile.files[0].text());

        // 2. Dekripsi AES key dengan RSA
        const aesRaw = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            importedPrivateKey,
            base64ToBuffer(pkg.key)
        );

        // 3. Import AES key
        const aesKey = await crypto.subtle.importKey(
            "raw",
            aesRaw,
            "AES-CBC",
            false,
            ["decrypt"]
        );

        // 4. Dekripsi data
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: base64ToBuffer(pkg.iv) },
            aesKey,
            base64ToBuffer(pkg.data)
        );

        // 5. Buat Blob untuk diunduh
        const blob = new Blob([decrypted]);
        const downloadLink = document.createElement("a");
        downloadLink.href = URL.createObjectURL(blob);

        // Gunakan nama file asli jika ada
        const originalName = selectedFile ? selectedFile.name : "decrypted_file";
        downloadLink.download = originalName;
        downloadLink.click();

        // 6. Jika file gambar, tampilkan di canvasDecrypted
        try {
            decryptedImageData = await drawImageToCanvas(blob, canvasDecrypted);
            hitungPSNR(); // Hanya untuk gambar
        } catch {
            log("⚠️ File bukan gambar, canvasDecrypted tidak ditampilkan");
        }

        log("✅ Dekripsi selesai");
    } catch (err) {
        console.error(err);
        alert("❌ Terjadi kesalahan saat dekripsi!");
        log("❌ Error dekripsi: " + err.message);
    }
});

    

    /* ================================
       7. PSNR & MSE
    ================================ */
    function hitungPSNR() {
        if (!originalImageData || !decryptedImageData) return;
        let mse = 0;
        const a = originalImageData.data;
        const b = decryptedImageData.data;

        for (let i = 0; i < a.length; i += 4) {
            mse += Math.pow(a[i] - b[i], 2);
        }
        mse /= (a.length / 4);
        const psnr = 10 * Math.log10((255 * 255) / mse);

        mseValue.innerText = mse.toFixed(4);
        psnrValue.innerText = psnr.toFixed(2) + " dB";
    }

    /* ================================
       DEFAULT DOWNLOAD LINK SERVER
    ================================ */
    downloadPublicLink.href = `${SERVER_IP}/download/public`;
    downloadPublicLink.classList.remove("hidden");

    downloadPrivateLink.href = `${SERVER_IP}/download/private`;
    downloadPrivateLink.classList.remove("hidden");
});
