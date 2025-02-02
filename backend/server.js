require("dotenv").config();
const authenticateToken = require("./authMiddleware");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const PDFDocument = require("pdfkit");
const path = require("path");
const { createObjectCsvWriter } = require("csv-writer");
const fs = require("fs");
const cron = require("node-cron");
const axios = require("axios");
const puppeteer = require("puppeteer");

const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = "Shobika&16";

// Log all incoming requests
app.use((req, res, next) => {
    console.log(`Incoming Request: ${req.method} ${req.url}`);
    next();
});

// Middleware to parse JSON
app.use(bodyParser.json());
// User Registration
app.post("/api/register", async (req, res) => {
    const { username, password, role } = req.body;

    // Validate input
    if (!username || !password || !role) {
        return res.status(400).send("All fields are required.");
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const query = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        db.query(query, [username, hashedPassword, role], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error registering user.");
            }
            res.status(201).send("User registered successfully.");
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Server error.");
    }
});

// User Login
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).send("All fields are required.");
    }

    // Check if the user exists
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Server error.");
        }

        if (results.length === 0) {
            return res.status(401).send("Invalid username or password.");
        }

        const user = results[0];

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send("Invalid username or password.");
        }

        // Generate JWT
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "1h" });
        res.status(200).json({ token });
    });
});

// Protected route: Accessible only with a valid token
app.get("/api/protected", authenticateToken, (req, res) => {
    res.send(`Welcome, user with role: ${req.user.role}`);
});

// Create a Portfolio
app.post("/api/portfolio", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the token
    const { name } = req.body;

    if (!name) {
        return res.status(400).send("Portfolio name is required.");
    }

    const query = "INSERT INTO portfolios (user_id, name) VALUES (?, ?)";
    db.query(query, [userId, name], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to create portfolio.");
        }
        res.status(201).send("Portfolio created successfully.");
    });
});

// View All Portfolios
app.get("/api/portfolio", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the token

    const query = "SELECT * FROM portfolios WHERE user_id = ?";
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to fetch portfolios.");
        }
        res.status(200).json(results);
    });
});

// Update a Portfolio
app.put("/api/portfolio/:id", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the token
    const { id } = req.params; // Portfolio ID
    const { name } = req.body;

    if (!name) {
        return res.status(400).send("Portfolio name is required.");
    }

    const query = "UPDATE portfolios SET name = ? WHERE id = ? AND user_id = ?";
    db.query(query, [name, id, userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to update portfolio.");
        }
        if (results.affectedRows === 0) {
            return res.status(404).send("Portfolio not found or not authorized.");
        }
        res.status(200).send("Portfolio updated successfully.");
    });
});

// Delete a Portfolio
app.delete("/api/portfolio/:id", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the token
    const { id } = req.params; // Portfolio ID

    const query = "DELETE FROM portfolios WHERE id = ? AND user_id = ?";
    db.query(query, [id, userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to delete portfolio.");
        }
        if (results.affectedRows === 0) {
            return res.status(404).send("Portfolio not found or not authorized.");
        }
        res.status(200).send("Portfolio deleted successfully.");
    });
});

// Add an Asset
app.post("/api/asset", authenticateToken, (req, res) => {
    const { portfolio_id, asset_type, asset_name, quantity, purchase_date, current_value } = req.body;

    if (!portfolio_id || !asset_type || !asset_name || !quantity || !purchase_date) {
        return res.status(400).send("All fields are required.");
    }

    const query = `
        INSERT INTO assets (portfolio_id, asset_type, asset_name, quantity, purchase_date, current_value)
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(query, [portfolio_id, asset_type, asset_name, quantity, purchase_date, current_value], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to add asset.");
        }
        res.status(201).send("Asset added successfully.");
    });
});

// View All Assets in a Portfolio
app.get("/api/asset/:portfolio_id", authenticateToken, (req, res) => {
    const { portfolio_id } = req.params;

    const query = "SELECT * FROM assets WHERE portfolio_id = ?";
    db.query(query, [portfolio_id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to fetch assets.");
        }
        res.status(200).json(results);
    });
});

// Update an Asset
app.put("/api/asset/:id", authenticateToken, (req, res) => {
    const { id } = req.params;
    const { asset_name, quantity, current_value } = req.body;

    if (!asset_name || !quantity || !current_value) {
        return res.status(400).send("All fields are required.");
    }

    const query = `
        UPDATE assets
        SET asset_name = ?, quantity = ?, current_value = ?
        WHERE id = ?
    `;
    db.query(query, [asset_name, quantity, current_value, id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to update asset.");
        }
        if (results.affectedRows === 0) {
            return res.status(404).send("Asset not found.");
        }
        res.status(200).send("Asset updated successfully.");
    });
});

// Delete an Asset
app.delete("/api/asset/:id", authenticateToken, (req, res) => {
    const { id } = req.params;

    const query = "DELETE FROM assets WHERE id = ?";
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to delete asset.");
        }
        if (results.affectedRows === 0) {
            return res.status(404).send("Asset not found.");
        }
        res.status(200).send("Asset deleted successfully.");
    });
});

// Add a Transaction
app.post("/api/transaction", authenticateToken, (req, res) => {
    const { portfolio_id, asset_type, asset_name, quantity, purchase_date, current_value } = req.body;

    if (!portfolio_id || !asset_type || !asset_name || !quantity || !purchase_date || !current_value) {
        return res.status(400).send("All fields are required.");
    }

    // Validate Portfolio Existence
    const portfolioQuery = "SELECT * FROM portfolios WHERE id = ?";
    db.query(portfolioQuery, [portfolio_id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Error checking portfolio.");
        }

        if (results.length === 0) {
            return res.status(404).send("Portfolio not found.");
        }

        // Check for Over-Allocation
        const checkAssetQuery = `
            SELECT SUM(quantity) AS total_quantity
            FROM transactions
            WHERE portfolio_id = ? AND asset_name = ? AND asset_type = ?
        `;
        db.query(checkAssetQuery, [portfolio_id, asset_name, asset_type], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error checking asset quantity.");
            }

            const totalQuantity = results[0]?.total_quantity || 0;

            if (quantity < 0 && Math.abs(quantity) > totalQuantity) {
                return res.status(400).send("Not enough assets to sell.");
            }

            // Insert the transaction
            const transactionQuery = `
                INSERT INTO transactions (portfolio_id, asset_type, asset_name, quantity, purchase_date, current_value)
                VALUES (?, ?, ?, ?, ?, ?)
            `;
            db.query(transactionQuery, [portfolio_id, asset_type, asset_name, quantity, purchase_date, current_value], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send("Failed to add transaction.");
                }
                res.status(201).send("Transaction added successfully.");
            });
        });
    });
});

// View Transactions for a Portfolio
app.get("/api/transactions/:portfolio_id", authenticateToken, (req, res) => {
    const { portfolio_id } = req.params;

    const query = "SELECT * FROM transactions WHERE portfolio_id = ?";
    db.query(query, [portfolio_id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to fetch transactions.");
        }
        res.status(200).json(results);
    });
});

// Generate PDF Report for Portfolio
app.get("/api/report/pdf/:portfolio_id", authenticateToken, async (req, res) => {
    const { portfolio_id } = req.params;

    const query = `
        SELECT portfolios.name AS portfolio_name, assets.asset_name, assets.asset_type, assets.quantity, assets.current_value
        FROM portfolios
        JOIN assets ON portfolios.id = assets.portfolio_id
        WHERE portfolios.id = ? AND portfolios.user_id = ?
    `;

    db.query(query, [portfolio_id, req.user.id], async (err, results) => {
        if (err) {
            console.error("Error fetching portfolio data:", err);
            return res.status(500).send("Failed to fetch portfolio data.");
        }

        if (results.length === 0) {
            return res.status(404).send("Portfolio not found or no assets available.");
        }

        try {
            const browser = await puppeteer.launch();
            const page = await browser.newPage();

            // Create an HTML string for the report
            const html = `
            <html>
            <head>
                <title>Portfolio Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    ul { list-style-type: none; padding: 0; }
                    li { margin-bottom: 10px; }
                </style>
            </head>
            <body>
                <h1>Portfolio Report</h1>
                <h2>Portfolio Name: ${results[0].portfolio_name}</h2>
                <ul>
                    ${results
                        .map(
                            (asset) =>
                                `<li>${asset.asset_name} (${asset.asset_type}): Quantity = ${asset.quantity}, Current Value = $${asset.current_value}</li>`
                        )
                        .join("")}
                </ul>
            </body>
            </html>
            `;
            await page.setContent(html);
            const pdfBuffer = await page.pdf({ format: "A4" });
            // Write the PDF buffer to a file for verification
            const filePath = `Portfolio_${portfolio_id}.pdf`;
            fs.writeFileSync(filePath, pdfBuffer);
            console.log(`PDF file saved at: ${filePath}`);

            await browser.close();

            res.setHeader("Content-Type", "application/pdf");
            res.setHeader(
                "Content-Disposition",
                `attachment; filename="Portfolio_${portfolio_id}.pdf"`
            );
            console.log("PDF Buffer Size Before Response:", pdfBuffer.length);
            res.end(pdfBuffer, 'binary');
        } catch (error) {
            console.error("Error generating PDF:", error);
            res.status(500).send("Failed to generate PDF.");
        }
    });
});


// Generate CSV Report for Transactions
app.get("/api/report/csv/:portfolio_id", authenticateToken, (req, res) => {
    const { portfolio_id } = req.params;

    // Query to fetch transaction data
    const query = `
        SELECT transactions.asset_name, transactions.asset_type, transactions.quantity, transactions.transaction_date
        FROM transactions
        WHERE transactions.portfolio_id = ?
    `;

    db.query(query, [portfolio_id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Failed to fetch transaction data.");
        }

        if (results.length === 0) {
            return res.status(404).send("No transactions found for this portfolio.");
        }

        const fileName = `Transactions_Portfolio_${portfolio_id}.csv`;
        const filePath = path.join(__dirname, "reports", fileName);

        // Ensure the reports directory exists
        if (!fs.existsSync(path.join(__dirname, "reports"))) {
            fs.mkdirSync(path.join(__dirname, "reports"));
        }

        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: "asset_name", title: "Asset Name" },
                { id: "asset_type", title: "Asset Type" },
                { id: "quantity", title: "Quantity" },
                { id: "transaction_date", title: "Transaction Date" },
            ],
        });

        csvWriter
            .writeRecords(results)
            .then(() => {
                // Send the CSV file as a response
                res.download(filePath, fileName, (err) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send("Failed to generate CSV report.");
                    }

                    // Cleanup: Remove the file after download
                    fs.unlinkSync(filePath);
                });
            })
            .catch((err) => {
                console.error(err);
                res.status(500).send("Failed to generate CSV report.");
            });
    });
});

// Fetch Current Market Value for an Asset
const getCurrentMarketValue = async (assetType, assetName) => {
    try {
        let apiUrl;

        if (assetType === "Stock") {
            apiUrl = `https://finnhub.io/api/v1/quote?symbol=${assetName}&token=${process.env.FINNHUB_API_KEY}`;
        } else if (assetType === "Crypto") {
            apiUrl = `https://api.coingecko.com/api/v3/simple/price?ids=${assetName.toLowerCase()}&vs_currencies=usd`;
        } else {
            return 100; // Mock value for unsupported asset types
        }

        const response = await axios.get(apiUrl);
        if (assetType === "Stock") return response.data.c || 0;
        if (assetType === "Crypto") return response.data[assetName.toLowerCase()]?.usd || 0;

        return 0;
    } catch (error) {
        console.error(`Error fetching market value for ${assetName}:`, error.message);
        return 0;
    }
};

// Batch Process for Recalculating Portfolio Values
const recalculatePortfolioValues = async (isTestMode = false) => {
    console.log("Starting portfolio value recalculation...");

    const query = `
        SELECT portfolios.id AS portfolio_id, portfolios.critical_threshold, portfolios.user_email,
               assets.asset_type, assets.asset_name, assets.quantity
        FROM portfolios
        JOIN assets ON portfolios.id = assets.portfolio_id
    `;

    db.query(query, async (err, results) => {
        if (err) {
            console.error("Error fetching portfolio data:", err);
            return;
        }

        const portfolioValues = {};
        const portfolioThresholds = {};

        console.log("Fetched portfolio data:", results);

        for (const row of results) {
            const marketValue = await getCurrentMarketValue(row.asset_type, row.asset_name);
            const assetValue = marketValue * row.quantity;

            if (!portfolioValues[row.portfolio_id]) {
                portfolioValues[row.portfolio_id] = 0;
                portfolioThresholds[row.portfolio_id] = {
                    threshold: row.critical_threshold,
                    email: row.user_email,
                    triggered: false,
                };
            }

            portfolioValues[row.portfolio_id] += assetValue;
        }

        console.log("Calculated portfolio values:", portfolioValues);

        Object.entries(portfolioValues).forEach(([portfolioId, totalValue]) => {
            const { threshold, email, triggered } = portfolioThresholds[portfolioId];

            if (!isTestMode) {
                const updateQuery = "UPDATE portfolios SET total_value = ? WHERE id = ?";
                db.query(updateQuery, [totalValue, portfolioId], (updateErr) => {
                    if (updateErr) {
                        console.error(`Error updating portfolio ${portfolioId}:`, updateErr);
                    }
                });
            }

            if (totalValue < threshold && !triggered) {
                console.log(`⚠️ Alert: Portfolio ${portfolioId} value dropped below threshold!`);

                if (email) {
                    sendEmail(
                        email,
                        "⚠️ Portfolio Alert: Critical Threshold Breached",
                        `Your portfolio (ID: ${portfolioId}) value has dropped below your set threshold.\n\nCurrent Value: $${totalValue}\nThreshold: $${threshold}`
                    );
                }

                portfolioThresholds[portfolioId].triggered = true;
            } else {
                console.log(`No alert triggered for Portfolio ${portfolioId}`);
                console.log(`Portfolio Value: $${totalValue}, Threshold: $${threshold}`);
            }
        });
    });
};

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Send Email Notifications
const sendEmail = (to, subject, text) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        text,
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.error("Error sending email:", err);
        } else {
            console.log("Email sent successfully:", info.response);
        }
    });
};

// Schedule the Batch Process
cron.schedule("*/5 * * * *", recalculatePortfolioValues, {
    scheduled: true,
    timezone: "America/New_York", // Use a timezone for clarity
});

recalculatePortfolioValues(true); // Testing mode

// Start the Server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
