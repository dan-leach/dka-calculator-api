const mysql = require("mysql2/promise");
const config = require("../config");
const e = require("express");

/**
 * Inserts audit data into the database.
 * @param {Object} data - The submitted data to be inserted.
 * @param {Object} encryptedData - The encrypted data and decryption variables.
 * @param {string} auditID - Audit ID.
 * @param {string} patientHash - Patient hash.
 * @param {string} clientIP - Client IP address.
 * @throws {Error} If an error occurs during the database operation.
 */
async function insertCalculateData(
  data,
  encryptedData,
  auditID,
  patientHash,
  clientIP
) {
  try {
    const connection = await mysql.createConnection({
      host: "localhost",
      user: process.env.insertUser,
      password: process.env.insertKey,
      database: "dkacalcu_dka_database",
    });

    // Prepare SQL statement
    const sql = `
      INSERT INTO ${config.api.tables.calculate} (
        encryptedData, legalAgreement, episodeType, region, centre, auditID, patientHash, clientDatetime, clientUseragent, clientIP, appVersion) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Execute SQL statement
    const [result] = await connection.execute(sql, [
      encryptedData,
      data.legalAgreement,
      data.episodeType,
      data.region,
      data.centre,
      auditID,
      patientHash,
      data.clientDatetime,
      data.clientUseragent,
      clientIP,
      data.appVersion,
    ]);

    if (result.affectedRows === 0) {
      throw new Error("Audit data could not be logged: No rows affected");
    }
  } catch (error) {
    throw new Error(`Audit data could not be logged: ${error.message}`);
  } finally {
    try {
      await connection.end();
    } catch {
      //no connection to close
    }
  }
}

/**
 * Updates the preventableFactors audit data in the database.
 * @param {Object} data - The submitted data including the auditID of the session and the updated preventableFactors array to be inserted.
 * @throws {Error} If an error occurs during the database operation.
 */
async function insertUpdateData(data, cerebralOedema, clientIP) {
  try {
    const connection = await mysql.createConnection({
      host: "localhost",
      user: process.env.insertUser,
      password: process.env.insertKey,
      database: "dkacalcu_dka_database",
    });

    // Prepare SQL statement for update
    const sql = `INSERT INTO ${config.api.tables.update} (
        auditID, protocolEndDatetime, preExistingDiabetes, preventableFactors, cerebralOedema, clientUseragent, clientIP, appVersion
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Execute SQL statement
    const [result] = await connection.execute(sql, [
      data.auditID,
      data.protocolEndDatetime,
      data.preExistingDiabetes,
      data.preventableFactors,
      cerebralOedema,
      data.clientUseragent,
      clientIP,
      data.appVersion,
    ]);

    if (result.affectedRows === 0) {
      throw new Error("Audit data could not be updated: No rows affected");
    }
  } catch (error) {
    throw new Error(`Audit data could not be updated: ${error.message}`);
  } finally {
    try {
      await connection.end();
    } catch {
      //no connection to close
    }
  }
}

async function insertSodiumOsmoData(data, calculations, clientIP) {
  try {
    const connection = await mysql.createConnection({
      host: "localhost",
      user: process.env.insertUser,
      password: process.env.insertKey,
      database: "dkacalcu_dka_database",
    });

    // Prepare SQL statement for update
    const sql = `INSERT INTO ${config.api.tables.sodiumOsmo} (
        sodium, glucose, calculations, clientUseragent, clientIP, appVersion
      ) VALUES (?, ?, ?, ?, ?, ?)
    `;

    // Execute SQL statement
    const [result] = await connection.execute(sql, [
      data.sodium,
      data.glucose,
      calculations,
      data.clientUseragent,
      clientIP,
      data.appVersion,
    ]);

    if (result.affectedRows === 0) {
      throw new Error("Data log could not be updated: No rows affected");
    }
  } catch (error) {
    throw new Error(`Data log could not be updated: ${error.message}`);
  } finally {
    try {
      await connection.end();
    } catch {
      //no connection to close
    }
  }
}

module.exports = {
  insertCalculateData,
  insertUpdateData,
  insertSodiumOsmoData,
};
