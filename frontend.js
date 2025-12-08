const API = "http://localhost:3000";

// GENERATE KEY DI SERVER
async function generateKeys(user) {
  const res = await fetch(API + "/api/generateKey", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user })
  });

  const data = await res.json();
  console.log("Public key:", data.publicKey);
}

// ENKRIPSI DI SERVER
async function encryptFile(user, file) {
  const content = await file.arrayBuffer();
  const base64 = btoa(String.fromCharCode(...new Uint8Array(content)));

  const res = await fetch(API + "/api/encrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user, data: base64 })
  });

  return await res.json();
}

// DEKRIPSI DI SERVER
async function decryptFile(user, encryptedData, encryptedKey, iv) {
  const res = await fetch(API + "/api/decrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user, encryptedData, encryptedKey, iv })
  });

  return await res.json();
}
