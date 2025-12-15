// app.js — Part 1/4 (core constants, DOM refs, helpers)


const TARGET_SIZE = 256;
const AES_ALGO = { name: 'AES-CBC', length: 256 };
const RSA_ALGO = { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };


let rsaKeyPair = null;
let originalFile = null; // {name,type,size,payload:ArrayBuffer,isImage:boolean}
let encryptedPackageObject = null; // {encryptedAesKey(Uint8Array),iv(Uint8Array),ciphertext(Uint8Array),isImage,passphraseFlag}
let privateKeyLoaded = false;


// DOM refs
const fileToEncrypt = document.getElementById('fileToEncrypt');
const encPassphrase = document.getElementById('encPassphrase');
const btnGenerateKeys = document.getElementById('btnGenerateKeys');
const btnExportPublic = document.getElementById('btnExportPublic');
const btnExportPrivate = document.getElementById('btnExportPrivate');
const btnEncryptNow = document.getElementById('btnEncryptNow');
const downloadEncryptedLink = document.getElementById('downloadEncryptedLink');
const downloadPublicLink = document.getElementById('downloadPublicLink');
const downloadPrivateLink = document.getElementById('downloadPrivateLink');


const encryptedPackageFile = document.getElementById('encryptedPackageFile');
const privateKeyFileInput = document.getElementById('privateKeyFileInput');
const privatePemTextarea = document.getElementById('privatePemTextarea');
const btnImportPrivate = document.getElementById('btnImportPrivate');
const btnDecryptNow = document.getElementById('btnDecryptNow');
const decPassphrase = document.getElementById('decPassphrase');


const canvasOriginal = document.getElementById('canvasOriginal');
const canvasProcessed = document.getElementById('canvasProcessed');
const canvasCipher = document.getElementById('canvasCipher');
const canvasDecrypted = document.getElementById('canvasDecrypted');


const logArea = document.getElementById('logArea');
const psnrValue = document.getElementById('psnrValue');
const mseValue = document.getElementById('mseValue');
const cipherSize = document.getElementById('cipherSize');


// prepare canvases safely
[canvasOriginal, canvasProcessed, canvasCipher, canvasDecrypted].forEach(c => {
    if (c) {
        c.width = TARGET_SIZE;
        c.height = TARGET_SIZE;
    }
});


// Logging helper
function log(msg, type = 'info') {
    if (!logArea) return;
    const p = document.createElement('div');
    p.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    if (type === 'success') {
        p.style.color = '#16a34a';
        p.style.fontWeight = '600';
    }
    if (type === 'error') {
        p.style.color = '#dc2626';
        p.style.fontWeight = '600';
    }
    logArea.appendChild(p);
    logArea.scrollTop = logArea.scrollHeight;
}


// Base64/PEM helpers
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}


function base64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}


function pemFromArrayBuffer(buf, label) {
    const b64 = arrayBufferToBase64(buf);
    // split into lines of max 64 chars
    const lines = (b64.match(/.{1,64}/g) || []).join('\n');
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}


function stripPem(pem) {
    return pem.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
}


// draw placeholder (for non-image files)
function drawFilePlaceholder(canvas, file) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, TARGET_SIZE, TARGET_SIZE);
    ctx.fillStyle = '#f3f7fb';
    ctx.fillRect(0, 0, TARGET_SIZE, TARGET_SIZE);
    ctx.strokeStyle = '#e6eef8';
    ctx.strokeRect(6, 6, TARGET_SIZE - 12, TARGET_SIZE - 12);
    ctx.fillStyle = '#102a43';
    ctx.font = 'bold 14px Inter';
    ctx.textAlign = 'center';
    if (file && file.name) {
        const name = (file.name && file.name.length > 22) ? file.name.substring(0, 18) + '...' : (file.name || 'FILE');
        const size = (file.size != null) ? (file.size / 1024).toFixed(2) + ' KB' : '';
        ctx.fillText('FILE UPLOADED', TARGET_SIZE / 2, TARGET_SIZE / 3);
        ctx.font = '12px Inter';
        ctx.fillText(name, TARGET_SIZE / 2, TARGET_SIZE / 2 - 8);
        ctx.fillText(size, TARGET_SIZE / 2, TARGET_SIZE / 2 + 8);
    } else {
        ctx.fillText('NO FILE', TARGET_SIZE / 2, TARGET_SIZE / 2);
    }
}


// download helper
function makeDownloadLink(blob, filename, anchorElem) {
    const url = URL.createObjectURL(blob);
    anchorElem.href = url;
    anchorElem.download = filename;
    anchorElem.classList.remove('hidden');
}


// safe stringify for logs
function safeStringify(v) {
    try { return JSON.stringify(v); } catch (e) { return String(v); }
}
// app.js — Part 2/4 (key generation, export, file input handling)


// Key generation & export
btnGenerateKeys?.addEventListener('click', async () => {
    btnGenerateKeys.disabled = true;
    btnGenerateKeys.textContent = 'Membuat kunci...';
    try {
        if (!window.crypto || !crypto.subtle) throw new Error('WebCrypto API tidak tersedia pada environment ini.');
        rsaKeyPair = await crypto.subtle.generateKey(RSA_ALGO, true, ['encrypt', 'decrypt']);
        log('✅ Pasangan kunci RSA dibuat (disimpan di memori browser).', 'success');
        if (btnExportPublic) btnExportPublic.disabled = false;
        if (btnExportPrivate) btnExportPrivate.disabled = false;
        if (originalFile?.payload) btnEncryptNow.disabled = false;
    } catch (err) {
        log('Gagal membuat kunci: ' + (err.message || err), 'error');
        console.error(err);
        alert('Gagal membuat kunci: ' + (err.message || err));
    } finally {
        btnGenerateKeys.disabled = false;
        btnGenerateKeys.textContent = 'Buat Pasangan Kunci RSA';
    }
});


btnExportPublic?.addEventListener('click', async () => {
    if (!rsaKeyPair?.publicKey) return log('Kunci publik belum ada.', 'error');
    btnExportPublic.disabled = true;
    btnExportPublic.textContent = 'Mengekspor...';
    try {
        const pk = await crypto.subtle.exportKey('spki', rsaKeyPair.publicKey);
        const pem = pemFromArrayBuffer(pk, 'PUBLIC KEY');
        const blob = new Blob([pem], { type: 'application/x-pem-file' });
        if (downloadPublicLink) makeDownloadLink(blob, 'public_key.pem', downloadPublicLink);
        log('✅ Kunci publik diekspor (PEM).', 'success');
    } catch (err) {
        log('Gagal ekspor publik: ' + (err.message || err), 'error');
        console.error(err);
        alert('Gagal ekspor publik: ' + (err.message || err));
    } finally {
        btnExportPublic.disabled = false;
        btnExportPublic.textContent = 'Eksport Kunci Publik';
    }
});


btnExportPrivate?.addEventListener('click', async () => {
    if (!rsaKeyPair?.privateKey) return log('Kunci privat belum ada.', 'error');
    btnExportPrivate.disabled = true;
    btnExportPrivate.textContent = 'Mengekspor...';
    try {
        const sk = await crypto.subtle.exportKey('pkcs8', rsaKeyPair.privateKey);
        const pem = pemFromArrayBuffer(sk, 'PRIVATE KEY');
        const blob = new Blob([pem], { type: 'application/x-pem-file' });
        if (downloadPrivateLink) makeDownloadLink(blob, 'private_key.pem', downloadPrivateLink);
        log('✅ Kunci privat siap diunduh. Simpan aman!', 'success');
    } catch (err) {
        log('Gagal ekspor privat: ' + (err.message || err), 'error');
        console.error(err);
        alert('Gagal ekspor privat: ' + (err.message || err));
    } finally {
        btnExportPrivate.disabled = false;
        btnExportPrivate.textContent = 'Unduh Kunci Privat';
    }
});


// File input (supports any file type)
fileToEncrypt?.addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    originalFile = { name: f.name, type: f.type, size: f.size };
    const reader = new FileReader();


    if (f.type && f.type.startsWith('image/')) {
        reader.onload = (ev) => {
            const img = new Image();
            img.onload = () => {
                const ctx = canvasOriginal?.getContext('2d');
                if (ctx) {
                    ctx.clearRect(0, 0, TARGET_SIZE, TARGET_SIZE);
                    ctx.drawImage(img, 0, 0, TARGET_SIZE, TARGET_SIZE);
                }
                const ctx2 = canvasProcessed?.getContext('2d');
                if (ctx2) {
                    ctx2.clearRect(0, 0, TARGET_SIZE, TARGET_SIZE);
                    ctx2.drawImage(img, 0, 0, TARGET_SIZE, TARGET_SIZE);
                    const imageData = ctx2.getImageData(0, 0, TARGET_SIZE, TARGET_SIZE);
                    const data = imageData.data;
                    const gray = new Uint8Array(TARGET_SIZE * TARGET_SIZE);
                    let di = 0;
                    for (let i = 0; i < data.length; i += 4) {
                        const v = Math.round((data[i] + data[i + 1] + data[i + 2]) / 3);
                        data[i] = data[i + 1] = data[i + 2] = v;
                        data[i + 3] = 255;
                        gray[di++] = v;
                    }
                    ctx2.putImageData(imageData, 0, 0);
                    originalFile.payload = gray.buffer;
                    originalFile.isImage = true;
                    log('Gambar dipraproses menjadi grayscale 256×256 untuk enkripsi.', 'success');
                    if (rsaKeyPair?.publicKey) btnEncryptNow.disabled = false;
                }
            };
            img.src = ev.target.result;
        };
        reader.readAsDataURL(f);
    } else {
        reader.onload = (ev) => {
            originalFile.payload = ev.target.result;
            originalFile.isImage = false;
            drawFilePlaceholder(canvasOriginal, f);
            drawFilePlaceholder(canvasProcessed, { name: 'RAW DATA', size: f.size, type: 'BINARY' });
            log('File non-gambar siap untuk enkripsi.', 'success');
            if (rsaKeyPair?.publicKey) btnEncryptNow.disabled = false;
        };
        reader.readAsArrayBuffer(f);
    }
});
// app.js — Part 3/4 (encrypt flow + visualization)


btnEncryptNow?.addEventListener('click', async () => {
    if (!rsaKeyPair?.publicKey) return log('Buat kunci RSA terlebih dahulu.', 'error');
    if (!originalFile?.payload) return log('Pilih file terlebih dahulu.', 'error');
    btnEncryptNow.disabled = true;
    btnEncryptNow.textContent = 'Mengenkripsi...';
    try {
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const aesKey = await crypto.subtle.generateKey(AES_ALGO, true, ['encrypt', 'decrypt']);
        const payload = (originalFile.payload instanceof ArrayBuffer) ? originalFile.payload : (originalFile.payload && originalFile.payload.buffer) || originalFile.payload;
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, payload);
        const rawAes = await crypto.subtle.exportKey('raw', aesKey);
        const encryptedAes = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKeyPair.publicKey, rawAes);


        encryptedPackageObject = {
            encryptedAesKey: new Uint8Array(encryptedAes),
            iv: iv,
            ciphertext: new Uint8Array(ciphertext),
            isImage: !!originalFile.isImage,
            passphraseFlag: encPassphrase.value ? 1 : 0
        };


        const encKeyLen = encryptedPackageObject.encryptedAesKey.length;
        const ivLen = encryptedPackageObject.iv.length;
        const ctLen = encryptedPackageObject.ciphertext.length;
        const header = new ArrayBuffer(4 * 3 + 1);
        const hv = new DataView(header);
        hv.setUint32(0, encKeyLen, false);
        hv.setUint32(4, ivLen, false);
        hv.setUint32(8, ctLen, false);
        hv.setUint8(12, encryptedPackageObject.passphraseFlag);


        const total = header.byteLength + encKeyLen + ivLen + ctLen;
        const out = new Uint8Array(total);
        out.set(new Uint8Array(header), 0);
        let offset = header.byteLength;
        out.set(encryptedPackageObject.encryptedAesKey, offset);
        offset += encKeyLen;
        out.set(encryptedPackageObject.iv, offset);
        offset += ivLen;
        out.set(encryptedPackageObject.ciphertext, offset);


        const blob = new Blob([out.buffer], { type: 'application/octet-stream' });
        if (downloadEncryptedLink) makeDownloadLink(blob, `encrypted_${originalFile?.name?.replace(/\.[^/.]+$/, '') || 'file'}.bin`, downloadEncryptedLink);
        if (cipherSize) cipherSize.textContent = `${ctLen} bytes`;


        drawCiphertextVisualization(canvasCipher, encryptedPackageObject.ciphertext);
        log(`✅ Enkripsi berhasil — paket siap diunduh (ciphertext ${ctLen} bytes).`, 'success');
    } catch (err) {
        log('Gagal enkripsi: ' + (err.message || err), 'error');
        console.error(err);
        alert('Gagal enkripsi: ' + (err.message || err));
    } finally {
        btnEncryptNow.disabled = false;
        btnEncryptNow.textContent = 'Enkripsi & Buat Paket';
    }
});


function drawCiphertextVisualization(canvas, bytes) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const imgData = ctx.createImageData(TARGET_SIZE, TARGET_SIZE);
    const pixelCount = TARGET_SIZE * TARGET_SIZE;
    for (let i = 0; i < pixelCount; i++) {
        const b = bytes[i % bytes.length];
        const di = i * 4;
        imgData.data[di] = b;
        imgData.data[di + 1] = b;
        imgData.data[di + 2] = b;
        imgData.data[di + 3] = 255;
    }
    ctx.putImageData(imgData, 0, 0);
}


// Load .bin for decryption
encryptedPackageFile?.addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        const ab = ev.target.result;
        try {
            const dv = new DataView(ab);
            const encKeyLen = dv.getUint32(0, false);
            const ivLen = dv.getUint32(4, false);
            const ctLen = dv.getUint32(8, false);
            const passFlag = dv.getUint8(12);
            const offset = 13;
            const encKey = new Uint8Array(ab.slice(offset, offset + encKeyLen));
            const iv = new Uint8Array(ab.slice(offset + encKeyLen, offset + encKeyLen + ivLen));
            const ct = new Uint8Array(ab.slice(offset + encKeyLen + ivLen, offset + encKeyLen + ivLen + ctLen));
            encryptedPackageObject = { encryptedAesKey: encKey, iv: iv, ciphertext: ct, isImage: null, passphraseFlag: passFlag };
            log('📦 Paket .bin dimuat. Passphrase required? ' + (passFlag ? 'Ya' : 'Tidak'));
            if (btnDecryptNow) btnDecryptNow.disabled = !privateKeyLoaded && !rsaKeyPair?.privateKey;
            if (cipherSize) cipherSize.textContent = `${ct.length} bytes`;
        } catch (err) {
            log('Gagal membaca paket .bin: ' + (err.message || err), 'error');
            console.error(err);
            alert('Gagal membaca paket .bin: ' + (err.message || err));
        }
    };
    reader.readAsArrayBuffer(f);
});
// app.js — Part 4/4 (import private key, decrypt, metrics, UI updates)


// Import private key / paste
async function importPrivateKeyFromPem(pem) {
    try {
        const b64 = stripPem(pem);
        const ab = base64ToArrayBuffer(b64);
        const key = await crypto.subtle.importKey('pkcs8', ab, RSA_ALGO, true, ['decrypt']);
        rsaKeyPair = rsaKeyPair || {};
        rsaKeyPair.privateKey = key;
        privateKeyLoaded = true;
        if (btnDecryptNow) btnDecryptNow.disabled = false;
        log('🔐 Kunci privat berhasil diimpor.', 'success');
    } catch (err) {
        log('Gagal impor privat: ' + (err.message || err), 'error');
        console.error(err);
        alert('Gagal impor privat: ' + (err.message || err));
    }
}


privateKeyFileInput?.addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = (ev) => { privatePemTextarea.value = ev.target.result || ''; };
    reader.readAsText(f);
});


btnImportPrivate?.addEventListener('click', async () => {
    const pem = privatePemTextarea?.value?.trim();
    if (!pem) return log('Tempel PEM privat atau unggah file terlebih dahulu.', 'error');
    btnImportPrivate.disabled = true;
    btnImportPrivate.textContent = 'Mengimpor...';
    try { await importPrivateKeyFromPem(pem); } catch (err) { log('Gagal import privat: ' + (err.message || err), 'error'); } finally {
        btnImportPrivate.disabled = false;
        btnImportPrivate.textContent = 'Impor Kunci Privat';
    }
});


// Decrypt
btnDecryptNow?.addEventListener('click', async () => {
    if (!encryptedPackageObject) return log('Unggah paket .bin terlebih dahulu.', 'error');
    if (!rsaKeyPair?.privateKey) return log('Muat/Impor kunci privat dulu.', 'error');
    const pass = decPassphrase?.value || null;
    btnDecryptNow.disabled = true;
    btnDecryptNow.textContent = 'Mendekripsi...';
    try {
        if (encryptedPackageObject.passphraseFlag && !pass) throw new Error('Passphrase dibutuhkan untuk paket ini.');


        const decryptedAesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaKeyPair.privateKey, encryptedPackageObject.encryptedAesKey.buffer);
        const aesKey = await crypto.subtle.importKey('raw', decryptedAesRaw, AES_ALGO, true, ['decrypt']);
        const plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: encryptedPackageObject.iv }, aesKey, encryptedPackageObject.ciphertext.buffer);
        const plainBytes = new Uint8Array(plain);
        log('✅ Dekripsi berhasil.', 'success');


        const isImage = (encryptedPackageObject.isImage != null) ? encryptedPackageObject.isImage : (plainBytes.length === TARGET_SIZE * TARGET_SIZE);


        if (isImage) {
            const ctx = canvasDecrypted?.getContext('2d');
            if (ctx) {
                const imgData = ctx.createImageData(TARGET_SIZE, TARGET_SIZE);
                for (let i = 0; i < TARGET_SIZE * TARGET_SIZE; i++) {
                    const v = plainBytes[i] ?? 0;
                    const di = i * 4;
                    imgData.data[di] = v;
                    imgData.data[di + 1] = v;
                    imgData.data[di + 2] = v;
                    imgData.data[di + 3] = 255;
                }
                ctx.putImageData(imgData, 0, 0);
            }


            canvasDecrypted.toBlob((b) => {
                let dl = document.getElementById('downloadDecryptedLink');
                if (!dl) {
                    dl = document.createElement('a');
                    dl.id = 'downloadDecryptedLink';
                    dl.className = 'btn ghost';
                    dl.style.display = 'inline-block';
                    dl.style.marginTop = '8px';
                    dl.textContent = 'Unduh Hasil Dekripsi';
                    const decryptCard = document.getElementById('encryptedPackageFile')?.closest('.card');
                    if (decryptCard) decryptCard.appendChild(dl);
                    else document.body.appendChild(dl);
                }
                dl.href = URL.createObjectURL(b);
                dl.download = `decrypted_${originalFile?.name?.replace(/\.[^/.]+$/, '') || 'image'}.png`;
            });


            if (originalFile?.payload && originalFile.isImage) {
                const origArr = new Uint8Array(originalFile.payload);
                computeAndShowMetrics(origArr, plainBytes);
            } else {
                if (psnrValue) psnrValue.textContent = '-';
                if (mseValue) mseValue.textContent = '-';
                log('⚠️ Original data tidak tersedia lokal — PSNR/MSE tidak bisa dihitung.', 'info');
            }
        } else {
            const blob = new Blob([plain], { type: originalFile?.type || 'application/octet-stream' });
            let dl = document.getElementById('downloadDecryptedLink');
            if (!dl) {
                dl = document.createElement('a');
                dl.id = 'downloadDecryptedLink';
                dl.className = 'btn ghost';
                dl.style.display = 'inline-block';
                dl.style.marginTop = '8px';
                dl.textContent = 'Unduh Hasil Dekripsi';
                const decryptCard = document.getElementById('encryptedPackageFile')?.closest('.card');
                if (decryptCard) decryptCard.appendChild(dl);
                else document.body.appendChild(dl);
            }
            dl.href = URL.createObjectURL(blob);
            dl.download = `decrypted_${originalFile?.name || 'file'}`;
            if (psnrValue) psnrValue.textContent = '-';
            if (mseValue) mseValue.textContent = '-';
        }


    } catch (err) {
        log('❌ Dekripsi gagal: ' + (err.message || err), 'error');
        console.error(err);
        alert('Dekripsi gagal: ' + (err.message || err));
    } finally {
        btnDecryptNow.disabled = false;
        btnDecryptNow.textContent = 'Dekripsi Paket';
    }
});


// metrics
function computeAndShowMetrics(origUint8, decUint8) {
    const n = Math.min(origUint8.length, decUint8.length);
    if (n === 0) { if (psnrValue) psnrValue.textContent = '-'; if (mseValue) mseValue.textContent = '-'; return; }
    let mse = 0;
    for (let i = 0; i < n; i++) {
        const d = origUint8[i] - decUint8[i];
        mse += d * d;
    }
    mse = mse / n;
    let psnr;
    if (mse === 0) psnr = Infinity;
    else psnr = 10 * Math.log10((255 * 255) / mse);
    if (mseValue) mseValue.textContent = mse.toFixed(4);
    if (psnrValue) psnrValue.textContent = (psnr === Infinity) ? '∞ (identik)' : psnr.toFixed(2) + ' dB';
    log(`ℹ️ PSNR: ${(psnr === Infinity) ? '∞' : psnr.toFixed(2) + ' dB'} — MSE: ${mse.toFixed(4)}`, 'info');
}


// periodic UI updates & safeties
setInterval(() => {
    if (encryptedPackageObject && (privateKeyLoaded || rsaKeyPair?.privateKey)) { if (btnDecryptNow) btnDecryptNow.disabled = false; }
    if (encryptedPackageObject && cipherSize) cipherSize.textContent = `${encryptedPackageObject.ciphertext.length} bytes`;
    if (btnExportPublic) btnExportPublic.disabled = !rsaKeyPair?.publicKey;
    if (btnExportPrivate) btnExportPrivate.disabled = !rsaKeyPair?.privateKey;
}, 800);
// ===== Sidebar Toggle (Mobile) =====
document.addEventListener("DOMContentLoaded", () => {
    const toggle = document.querySelector(".menu-toggle");
    const sidebar = document.querySelector(".sidebar");

    if (toggle && sidebar) {
        toggle.addEventListener("click", () => {
            sidebar.classList.toggle("active");
        });
    }
});
