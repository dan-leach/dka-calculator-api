const crypto = require("crypto");

// Load RSA Public Key (for encrypting AES keys)
const rsaPublicKey = crypto.createPublicKey({
  key: Buffer.from(process.env.rsaPublicKey, "base64").toString("utf-8"),
  format: "pem",
});

// AES Encryption Function
function encryptDataWithAES(data) {
  const key = crypto.randomBytes(32); // 256-bit AES key
  const iv = crypto.randomBytes(16); // Initialization Vector
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(JSON.stringify(data), "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return { encrypted, key, iv: iv.toString("hex"), authTag };
}

// RSA Encryption for AES Key
function encryptAESKeyWithRSA(aesKey) {
  return crypto
    .publicEncrypt(
      {
        key: rsaPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      aesKey
    )
    .toString("base64");
}

// Encrypt Sensitive Columns Before Storing in Database
function encrypt(data) {
  const { encrypted, key, iv, authTag } = encryptDataWithAES(data);
  const encryptedKey = encryptAESKeyWithRSA(key);
  return { encryptedData: encrypted, encryptedKey, iv, authTag };
}

module.exports = { encrypt };
