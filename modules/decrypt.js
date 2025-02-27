const mysql = require("mysql2/promise");
const crypto = require("crypto");

// Load RSA Private Key (for decrypting AES keys)
const rsaPrivateKey = crypto.createPrivateKey({
  key: Buffer.from(process.env.rsaPrivateKey, "base64").toString("utf-8"),
  format: "pem",
});

// Function to decrypt data
function decryptData(encryptedAESKey, encryptedData, iv, authTag) {
  try {
    // Step 1: Decrypt the AES Key using RSA private key

    const decryptedAESKey = crypto.privateDecrypt(
      {
        key: rsaPrivateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encryptedAESKey, "base64")
    );

    // Step 2: Decrypt the data using AES-256-GCM
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      decryptedAESKey,
      Buffer.from(iv, "hex")
    );

    // Step 3: Set the authentication tag
    decipher.setAuthTag(Buffer.from(authTag, "hex"));

    // Step 4: Decrypt the data
    let decrypted = decipher.update(encryptedData, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return JSON.parse(decrypted); // Return decrypted object
  } catch (error) {
    console.error("Decryption failed:", error.message);
    return null;
  }
}

async function decryptTable(decryptID) {
  const connection = await mysql.createConnection({
    host: "localhost",
    user: process.env.selectUser,
    password: process.env.selectKey,
    database: "dkacalcu_dka_database",
  });

  // Fetch encrypted rows
  const query =
    decryptID === "all"
      ? "SELECT id, episodeType, auditID, appVersion, patientHash, legalAgreement, region, centre, clientDatetime, serverDatetime, clientUseragent, clientIP, encryptedData FROM tbl_data_dev"
      : "SELECT id, episodeType, auditID, appVersion, patientHash, legalAgreement, region, centre, clientDatetime, serverDatetime, clientUseragent, clientIP, encryptedData FROM tbl_data_dev WHERE auditID = ?";

  const [rows] = await connection.execute(
    query,
    decryptID === "all" ? [] : [decryptID]
  );

  for (const row of rows) {
    const {
      id,
      episodeType,
      auditID,
      appVersion,
      patientHash,
      legalAgreement,
      region,
      centre,
      clientDatetime,
      serverDatetime,
      clientUseragent,
      clientIP,
      encryptedData,
    } = row;

    if (!encryptedData) {
      console.error(`Skipping row ID ${id}: No encrypted data found.`);
      continue;
    }

    let parsedData;
    try {
      parsedData = JSON.parse(encryptedData);
    } catch (e) {
      console.error(
        `Failed to parse encryptedData for row ID ${id}:`,
        e.message
      );
      continue;
    }

    const { encryptedKey, encryptedData: encData, iv, authTag } = parsedData;

    // Decrypt the data
    const decryptedObject = decryptData(encryptedKey, encData, iv, authTag);

    if (!decryptedObject) {
      console.error(`Skipping row ID ${id}: Decryption failed.`);
      continue;
    }

    // Insert decrypted data into tbl_decrypt_dev
    await connection.execute(
      "INSERT INTO tbl_decrypt_dev (id, episodeType, auditID, appVersion, patientHash, legalAgreement, region, centre, clientDatetime, serverDatetime, clientUseragent, clientIP, decryptedData) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        id,
        episodeType,
        auditID,
        appVersion,
        patientHash,
        legalAgreement,
        region,
        centre,
        clientDatetime,
        serverDatetime,
        clientUseragent,
        clientIP,
        decryptedObject,
      ]
    );

    console.log(`Successfully decrypted and stored data for row ID ${id}`);
  }

  await connection.end();
}

async function decrypt(decryptID) {
  if (!decryptID) {
    throw new Error("No decryptID provided.");
  }
  const errorTime = new Date().toISOString();
  console.error(errorTime, "Decrypt.js running...");
  decryptTable(decryptID);
}

module.exports = { decrypt };
