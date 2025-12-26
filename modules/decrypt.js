/**
 * Decryption module for retrieving and combining sensitive data from encrypted storage.
 *
 * usage https://dev-api.dka-calculator.co.uk/decrypt?decryptID={auditID}&centre={centre}
 * replace auditID with the auditID to decrypt just that record, or "all" to decrypt all records.
 * replace centre with the centre name to decrypt records just for that centre, or "all" to decrypt all centres.
 *
 * @module decrypt
 * @summary Provides decryption of AES-encrypted data using RSA for AES key decryption, retrieving from calculate and update tables, and combining into a single decrypt table entry per auditID.
 *
 * @description This module decrypts data encrypted using AES-256-GCM. The AES key itself is decrypted using an RSA private key. It retrieves encrypted data from the 'calculate' table, decrypts it, and inserts into the 'decrypt' table. Then, for each auditID, it retrieves the most recent encrypted data from the 'update' table, decrypts it, and updates the corresponding row in the 'decrypt' table with additional fields. Supports filtering by auditID and/or centre.
 *
 * @requires crypto - Node.js built-in module for cryptographic operations.
 * @requires mysql2/promise - MySQL client for executing database queries.
 * @requires process.env.rsaPrivateKey - Environment variable containing the RSA private key in base64 format.
 *
 * @exports decrypt - Function that retrieves and decrypts data based on a given decryptID and centre.
 */
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const config = require("../config");

// Load RSA Private Key (for decrypting AES keys)
const rsaPrivateKey = crypto.createPrivateKey({
  key: Buffer.from(process.env.rsaPrivateKey, "base64").toString("utf-8"),
  format: "pem",
});

/**
 * Decrypts AES-encrypted data using the decrypted AES key.
 *
 * @param {string} encryptedAESKey - The RSA-encrypted AES key.
 * @param {string} encryptedData - The AES-encrypted data.
 * @param {string} iv - The initialization vector used in AES encryption.
 * @param {string} authTag - The authentication tag used in AES-GCM.
 * @returns {object|null} - The decrypted data as an object, or null if decryption fails.
 */
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

/**
 * Retrieves encrypted data from the database and decrypts it.
 *
 * @param {string} decryptID - The audit ID of the data to decrypt, or "all" to decrypt all records.
 * @param {string} centre - The centre to filter by, or "all" to include all centres.
 * @param {boolean} forceLiveTables - Whether to force using live tables even in development environment.
 * @returns {Promise<void>} - Resolves when decryption and storage are complete.
 */
async function decryptTable(decryptID, centre, forceLiveTables) {
  const connection = await mysql.createConnection({
    host: "localhost",
    user: process.env.selectUser,
    password: process.env.selectKey,
    database: "dkacalcu_dka_database",
  });

  // Map to assign incremental numbers to unique patientHashes
  const patientHashMap = new Map();

  // Fetch encrypted rows
  let query = `SELECT id, episodeType, auditID, retrospectivePatientHash, retrospectiveEpisode, appVersion, patientHash, legalAgreement, region, centre, clientDatetime, serverDatetime, clientUseragent, clientIP, encryptedData FROM ${
    process.env.NODE_ENV === "development" && !forceLiveTables
      ? config.api.tables.calculateDev
      : config.api.tables.calculate
  }`;
  let params = [];

  if (decryptID) {
    query += " WHERE auditID = ?";
    params.push(decryptID);
  }

  if (centre) {
    query += (params.length > 0 ? " AND" : " WHERE") + " centre = ?";
    params.push(centre);
  }

  const [rows] = await connection.execute(query, params);

  for (const row of rows) {
    const {
      id,
      episodeType,
      auditID,
      retrospectivePatientHash,
      retrospectiveEpisode,
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
    } catch (error) {
      console.error(
        `Failed to parse encryptedData for row ID ${id}:`,
        error.message
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

    // Assign patient number for redaction
    let patientNumber = null;
    if (patientHash) {
      if (!patientHashMap.has(patientHash)) {
        patientHashMap.set(patientHash, patientHashMap.size + 1);
      }
      patientNumber = patientHashMap.get(patientHash);
    }

    // Insert decrypted data into tbl_decrypt
    await connection.execute(
      `INSERT INTO ${config.api.tables.decrypt} (id, episodeType, auditID, retrospectivePatientHash, retrospectiveEpisode, appVersion, patientNumber, legalAgreement, region, centre, clientDatetime, serverDatetime, clientUseragent, clientIP, protocolStartDatetime, patientAge, patientSex, pH, bicarbonate, glucose, ketones, calculations, weightLimitOverride, use2SD, shockPresent, insulinRate, preExistingDiabetes, insulinDeliveryMethod, ethnicGroup, ethnicSubgroup, preventableFactors, imdDecile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        episodeType,
        auditID,
        retrospectivePatientHash,
        retrospectiveEpisode,
        appVersion,
        patientNumber,
        legalAgreement,
        region,
        centre,
        clientDatetime,
        serverDatetime,
        clientUseragent,
        clientIP,
        decryptedObject.protocolStartDatetime,
        decryptedObject.patientAge,
        decryptedObject.patientSex,
        decryptedObject.pH,
        decryptedObject.bicarbonate,
        decryptedObject.glucose,
        decryptedObject.ketones,
        decryptedObject.calculations,
        decryptedObject.weightLimitOverride,
        decryptedObject.use2SD,
        decryptedObject.shockPresent,
        decryptedObject.insulinRate,
        decryptedObject.preExistingDiabetes,
        decryptedObject.insulinDeliveryMethod,
        decryptedObject.ethnicGroup,
        decryptedObject.ethnicSubgroup,
        decryptedObject.preventableFactors,
        decryptedObject.imdDecile,
      ]
    );

    console.log(`Successfully decrypted and stored data for row ID ${id}`);
  }

  // Now handle update table
  const updateQuery = !decryptID
    ? `SELECT * FROM ${
        process.env.NODE_ENV === "development" && !forceLiveTables
          ? config.api.tables.updateDev
          : config.api.tables.update
      } WHERE (auditID, serverDatetime) IN (SELECT auditID, MAX(serverDatetime) FROM ${
        process.env.NODE_ENV === "development" && !forceLiveTables
          ? config.api.tables.updateDev
          : config.api.tables.update
      } GROUP BY auditID)`
    : `SELECT * FROM ${
        process.env.NODE_ENV === "development" && !forceLiveTables
          ? config.api.tables.updateDev
          : config.api.tables.update
      } WHERE auditID = ? AND serverDatetime = (SELECT MAX(serverDatetime) FROM ${
        process.env.NODE_ENV === "development" && !forceLiveTables
          ? config.api.tables.updateDev
          : config.api.tables.update
      } WHERE auditID = ?)`;

  const [updateRows] = await connection.execute(
    updateQuery,
    !decryptID ? [] : [decryptID, decryptID]
  );

  for (const row of updateRows) {
    const {
      id,
      auditID,
      serverDatetime,
      clientUseragent,
      clientIP,
      appVersion,
      encryptedData,
    } = row;

    if (!encryptedData) {
      console.error(`Skipping update row ID ${id}: No encrypted data found.`);
      continue;
    }

    let parsedData;
    try {
      parsedData = JSON.parse(encryptedData);
    } catch (error) {
      console.error(
        `Failed to parse encryptedData for update row ID ${id}:`,
        error.message
      );
      continue;
    }

    const { encryptedKey, encryptedData: encData, iv, authTag } = parsedData;

    // Decrypt the data
    const decryptedObject = decryptData(encryptedKey, encData, iv, authTag);

    if (!decryptedObject) {
      console.error(`Skipping update row ID ${id}: Decryption failed.`);
      continue;
    }

    // Update decrypted data into tbl_decrypt for the matching auditID
    await connection.execute(
      `UPDATE ${config.api.tables.decrypt} SET auditTableID = ?,auditProtocolEndDatetime = ?, auditPreExistingDiabetes = ?, auditPreventableFactors = ?, auditCerebralOedemaConcern = ?, auditCerebralOedemaImaging = ?, auditCerebralOedemaTreatment = ?, auditServerDatetime = ?, auditClientUseragent = ?, auditClientIP = ?, auditAppVersion = ?, auditEthnicGroup = ?, auditEthnicSubgroup = ?, auditImdDecile = ? WHERE auditID = ?`,
      [
        id,
        (decryptedObject.protocolEndDatetime ||
          decryptedObject.protocolStartDatetime) ??
          null,
        decryptedObject.preExistingDiabetes ?? null,
        decryptedObject.preventableFactors
          ? JSON.stringify(decryptedObject.preventableFactors)
          : null,
        decryptedObject.cerebralOedema?.concern ?? null,
        decryptedObject.cerebralOedema?.imaging ?? null,
        decryptedObject.cerebralOedema?.treatment
          ? JSON.stringify(decryptedObject.cerebralOedema.treatment)
          : null,
        serverDatetime,
        clientUseragent,
        clientIP,
        appVersion,
        decryptedObject.ethnicGroup ?? null,
        decryptedObject.ethnicSubgroup ?? null,
        decryptedObject.imdDecile ?? null,
        auditID,
      ]
    );

    console.log(
      `Successfully decrypted and updated data for auditID ${auditID}`
    );
  }

  await connection.end();
}

/**
 * Creates a streamlined version of the decrypt table with deduplicated data.
 * Only includes records where episodeType = 'real'.
 * Deduplicates by patientNumber: if multiple episodes exist for the same patient,
 * and their protocolStartDatetimes are within 24 hours, selects one record,
 * preferring those with audit data (auditTableID not null), then the most recent by serverDatetime.
 * If protocolStartDatetimes span more than 24 hours, or if only one episode, inserts all applicable records.
 *
 * @returns {Promise<void>} - Resolves when the streamlined table is populated.
 */
async function outputStreamlined(includeTests) {
  const connection = await mysql.createConnection({
    host: "localhost",
    user: process.env.selectUser,
    password: process.env.selectKey,
    database: "dkacalcu_dka_database",
  });

  // Build query conditionally
  let query = `SELECT * FROM ${config.api.tables.decrypt}`;
  if (!includeTests) {
    query += " WHERE episodeType = 'real'";
  }

  const [rows] = await connection.execute(query);

  // Separate rows with null patientNumber
  const nullPatientRows = rows.filter((row) => row.patientNumber === null);
  const nonNullRows = rows.filter((row) => row.patientNumber !== null);

  // Group by patientNumber for non-null
  const groups = {};
  for (const row of nonNullRows) {
    const patientNumber = row.patientNumber;
    if (!groups[patientNumber]) {
      groups[patientNumber] = [];
    }
    groups[patientNumber].push(row);
  }

  // Process each group
  for (const patientNumber in groups) {
    const group = groups[patientNumber];
    let recordsToInsert;
    if (group.length === 1) {
      // Only one episode, insert it
      recordsToInsert = group;
    } else {
      // Multiple episodes, check if within 24 hours
      const datetimes = group
        .map((row) => new Date(row.protocolStartDatetime))
        .filter((d) => !isNaN(d.getTime()));
      let within24 = false;
      if (datetimes.length > 1) {
        const minTime = Math.min(...datetimes.map((d) => d.getTime()));
        const maxTime = Math.max(...datetimes.map((d) => d.getTime()));
        const spanHours = (maxTime - minTime) / (1000 * 60 * 60);
        within24 = spanHours <= 24;
      } else if (datetimes.length === 1) {
        within24 = true; // If only one valid date, consider within
      }

      if (within24) {
        // Deduplicate: prefer audit data, then most recent serverDatetime
        const sorted = group.sort((a, b) => {
          // First, prefer those with auditTableID not null
          const aHasAudit = a.auditTableID !== null;
          const bHasAudit = b.auditTableID !== null;
          if (aHasAudit && !bHasAudit) return -1;
          if (!aHasAudit && bHasAudit) return 1;
          // Then by serverDatetime descending
          return new Date(b.serverDatetime) - new Date(a.serverDatetime);
        });
        recordsToInsert = [sorted[0]];
      } else {
        // Do not deduplicate: insert all
        recordsToInsert = group;
      }
    }

    // Insert the records
    for (const record of recordsToInsert) {
      // Determine deduplicatedAuditIDs
      let deduplicatedAuditIDs = null;
      if (recordsToInsert.length === 1 && group.length > 1) {
        deduplicatedAuditIDs = group
          .filter((r) => r.auditID !== record.auditID)
          .map((r) => r.auditID);
      }

      await connection.execute(
        `INSERT INTO ${config.api.tables.decryptStreamlined} (dataGrade, patientNumber, auditID, protocolStartDatetime, protocolEndDatetime, patientAge, patientSex, pH, bicarbonate, glucose, ketones, shockPresent, insulinRate, preExistingDiabetes, insulinDeliveryMethod, ethnicGroup, ethnicSubgroup, preventableFactors, imdDecile, cerebralOedemaConcern, cerebralOedemaImaging, cerebralOedemaTreatment, region, centre, calculations, deduplicatedAuditIDs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          record.auditTableID ? "A" : "B", // Data grade A if audit data exists, else B
          record.patientNumber,
          record.auditID,
          record.protocolStartDatetime,
          record.auditProtocolEndDatetime,
          record.patientAge,
          record.patientSex,
          record.pH,
          record.bicarbonate,
          record.glucose,
          record.ketones,
          record.shockPresent,
          record.insulinRate,
          record.auditPreExistingDiabetes
            ? record.auditPreExistingDiabetes
            : record.preExistingDiabetes,
          record.insulinDeliveryMethod,
          record.auditEthnicGroup
            ? record.auditEthnicGroup
            : record.ethnicGroup,
          record.auditEthnicSubgroup
            ? record.auditEthnicSubgroup
            : record.ethnicSubgroup,
          record.auditPreventableFactors
            ? record.auditPreventableFactors
            : record.preventableFactors,
          record.auditImdDecile ? record.auditImdDecile : record.imdDecile,
          record.auditCerebralOedemaConcern,
          record.auditCerebralOedemaImaging,
          record.auditCerebralOedemaTreatment,
          record.region,
          record.centre,
          record.calculations,
          deduplicatedAuditIDs ? JSON.stringify(deduplicatedAuditIDs) : null,
        ]
      );
    }
  }

  // Insert all records with null patientNumber without grouping
  for (const record of nullPatientRows) {
    await connection.execute(
      `INSERT INTO ${config.api.tables.decryptStreamlined} (dataGrade, auditID, protocolStartDatetime, patientAge, patientSex, pH, bicarbonate, glucose, ketones, shockPresent, insulinRate, preExistingDiabetes, insulinDeliveryMethod, ethnicGroup, ethnicSubgroup, preventableFactors, imdDecile, region, centre, calculations) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        "C", // Data grade C as cannot deduplicate without patientHash
        record.auditID,
        record.protocolStartDatetime,
        record.patientAge,
        record.patientSex,
        record.pH,
        record.bicarbonate,
        record.glucose,
        record.ketones,
        record.shockPresent,
        record.insulinRate,
        record.preExistingDiabetes,
        record.insulinDeliveryMethod,
        record.ethnicGroup,
        record.ethnicSubgroup,
        record.preventableFactors,
        record.imdDecile,
        record.region,
        record.centre,
        record.calculations,
      ]
    );
  }

  await connection.end();
  console.log("Streamlined table populated successfully.");
}

/**
 * Handles the decryption process by calling decryptTable.
 *
 * @param {string} decryptID - The audit ID to decrypt, or undefined for all records.
 * @param {boolean} includeTests - Whether to include test episodes in the streamlined output.
 * @param {string} centre - The centre to filter by, or undefined for all centres.
 * @param {boolean} forceLiveTables - Whether to force using live tables even in development environment.
 */
async function decrypt(decryptID, centre, includeTests, forceLiveTables) {
  const decryptTime = new Date().toISOString();
  console.error(
    decryptTime,
    "Decrypt.js running...     ",
    "decryptID:",
    decryptID,
    "centre:",
    centre,
    "includeTests:",
    includeTests,
    "forceLiveTables:",
    forceLiveTables
  );
  await decryptTable(decryptID, centre, forceLiveTables);
  await outputStreamlined(includeTests);
}

module.exports = { decrypt };
