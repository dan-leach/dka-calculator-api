const mysql = require("mysql2/promise");

/**
 * Inserts audit data into the database.
 * @param {Object} data - The submitted data to be inserted.
 * @param {string} imdDecile - IMD Decile value.
 * @param {string} auditID - Audit ID.
 * @param {string} patientHash - Patient hash.
 * @param {string} clientIP - Client IP address.
 * @param {Object} calculations - Output of calculateVariables.
 * @throws {Error} If an error occurs during the database operation.
 */
async function insertCalculateData(
  data,
  imdDecile,
  auditID,
  patientHash,
  clientIP,
  calculations
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
      INSERT INTO tbl_data_v2 (
        legalAgreement, patientAge, patientSex, protocolStartDatetime, pH, bicarbonate, glucose, ketones, weight, weightLimitOverride, use2SD,
        shockPresent, insulinRate, preExistingDiabetes, insulinDeliveryMethod, episodeType, region, centre, ethnicGroup, ethnicSubgroup,
        preventableFactors, imdDecile, auditID, patientHash, clientDatetime, clientUseragent, clientIP, appVersion, calculations
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Execute SQL statement
    const [result] = await connection.execute(sql, [
      data.legalAgreement,
      data.patientAge,
      data.patientSex,
      data.protocolStartDatetime,
      data.pH,
      data.bicarbonate,
      data.glucose,
      data.ketones,
      data.weight,
      data.weightLimitOverride,
      data.use2SD,
      data.shockPresent,
      data.insulinRate,
      data.preExistingDiabetes,
      data.insulinDeliveryMethod,
      data.episodeType,
      data.region,
      data.centre,
      data.ethnicGroup,
      data.ethnicSubgroup,
      data.preventableFactors,
      imdDecile,
      auditID,
      patientHash,
      data.clientDatetime,
      data.clientUseragent,
      clientIP,
      data.appVersion,
      calculations,
    ]);

    if (result.affectedRows === 0) {
      throw new Error("Audit data could not be logged: No rows affected");
    }
  } catch (error) {
    console.error(error);
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
    const sql = `INSERT INTO tbl_update_v2 (
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
    console.error(error);
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
    const sql = `INSERT INTO tbl_sodiumOsmo_v2 (
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
    console.error(error);
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
