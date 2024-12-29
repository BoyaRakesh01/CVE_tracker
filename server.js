
// Import required modules
const express = require("express");
const { Sequelize, DataTypes } = require("sequelize");
const axios = require("axios");
const cron = require("node-cron");

// Initialize Express app and database connection
const app = express();
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: "./cve_data.db",
});

// Define the CVE model
const CVE = sequelize.define("CVE", {
  cve_id: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  score: {
    type: DataTypes.FLOAT,
    allowNull: true,
  },
  last_modified: {
    type: DataTypes.STRING,
    allowNull: true,
  },
});

// Function to fetch and store CVE data
const fetchAndStoreCVEData = async () => {
  const apiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  let startIndex = 0;
  const resultsPerPage = 100;

  try {
    while (true) {
      const response = await axios.get(apiUrl, {
        params: { resultsPerPage, startIndex },
      });

      if (response.status !== 200) {
        console.error("Failed to fetch data from the API");
        break;
      }

      const data = response.data;
      const vulnerabilities = data.vulnerabilities || [];

      for (const item of vulnerabilities) {
        const cveData = item.cve;
        if (!cveData) continue;

        const cveId = cveData.id;
        const description = cveData.descriptions?.[0]?.value || "";
        const score =
          cveData.metrics?.cvssMetricV3?.[0]?.cvssData?.baseScore || null;
        const lastModified = cveData.lastModified || "";

        // Update or insert CVE in the database
        await CVE.upsert({
          cve_id: cveId,
          description,
          score,
          last_modified: lastModified,
        });
      }

      if (vulnerabilities.length < resultsPerPage) break;
      startIndex += resultsPerPage;
    }
  } catch (error) {
    console.error("Error fetching CVE data:", error);
  }
};

// API route to get CVEs
app.get("/cves", async (req, res) => {
  const { cve_id, year, score, days } = req.query;

  let whereClause = {};
  if (cve_id) {
    whereClause.cve_id = cve_id;
  }
  if (year) {
    whereClause.last_modified = { [Sequelize.Op.like]: `${year}-%` };
  }
  if (score) {
    whereClause.score = { [Sequelize.Op.gte]: parseFloat(score) };
  }
  if (days) {
    const date = new Date();
    date.setDate(date.getDate() - parseInt(days));
    whereClause.last_modified = { [Sequelize.Op.gte]: date.toISOString().split("T")[0] };
  }

  try {
    const cves = await CVE.findAll({ where: whereClause });
    res.json(cves);
  } catch (error) {
    console.error("Error retrieving CVEs:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Schedule daily synchronization
cron.schedule("0 0 * * *", fetchAndStoreCVEData);

// Initialize the database and start the server
const startServer = async () => {
  try {
    await sequelize.sync();
    console.log("Database synchronized.");
    fetchAndStoreCVEData(); // Initial data fetch
    app.listen(3000, () => {
      console.log("Server is running on http://localhost:3000");
    });
  } catch (error) {
    console.error("Error starting server:", error);
  }
};

startServer();
