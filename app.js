const express = require('express');
const https = require('https');
const sslChecker = require('./sslChecker'); // Correctly import the sslChecker function
const app = express();

app.get('/ssl-info', async (req, res) => { // Make the handler function async
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain parameter is required' });
    }

    try {
        const sslInfo = await sslChecker(domain); // Await the sslChecker function
        res.json({
            domain: domain,
            ssl_info: sslInfo,
            status: sslInfo.valid ? 'valid' : 'invalid'
        });
    } catch (error) {
        res.status(500).json({ error: 'Request error', details: error.message });
    }
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});